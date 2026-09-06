// Command aegis is the single CLI entry point described by SPEC §8.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	aegisassets "github.com/aegis-dev/aegis"
	"github.com/aegis-dev/aegis/internal/agent"
	"github.com/aegis-dev/aegis/internal/approval"
	"github.com/aegis-dev/aegis/internal/candidates"
	"github.com/aegis-dev/aegis/internal/console"
	"github.com/aegis-dev/aegis/internal/credentials"
	"github.com/aegis-dev/aegis/internal/doctor"
	"github.com/aegis-dev/aegis/internal/evidence"
	"github.com/aegis-dev/aegis/internal/inventory"
	"github.com/aegis-dev/aegis/internal/journal"
	"github.com/aegis-dev/aegis/internal/llm"
	"github.com/aegis-dev/aegis/internal/orchestrator"
	"github.com/aegis-dev/aegis/internal/orchestrator/budget"
	"github.com/aegis-dev/aegis/internal/orchestrator/snapshot"
	"github.com/aegis-dev/aegis/internal/packs"
	"github.com/aegis-dev/aegis/internal/redaction"
	"github.com/aegis-dev/aegis/internal/reporting"
	"github.com/aegis-dev/aegis/internal/sandbox"
	"github.com/aegis-dev/aegis/internal/schemav"
	"github.com/aegis-dev/aegis/internal/settings"
	"github.com/aegis-dev/aegis/internal/triage"
	"github.com/aegis-dev/aegis/internal/tui"
)

//go:embed prompts/prover-v1.txt
var proverSystemPrompt string

func main() {
	if err := newRoot().Execute(); err != nil {
		// Cobra already prints usage for syntax errors. Runtime failures use the
		// three-line contract in runStage instead of exposing a stack trace.
		os.Exit(1)
	}
}

func newRoot() *cobra.Command {
	root := &cobra.Command{Use: "aegis", Short: "Aegis code security review agent harness", SilenceUsage: true,
		Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			return runConsole(cmd.Context(), cmd.InOrStdin(), cmd.OutOrStdout())
		}}
	root.AddCommand(newConsole(), newReview(), newStage("scan", "scan the target repo (Stage 0-2)"), newStage("prove", "run proofs against findings"), newStage("report", "generate the review report"), newStage("replay", "revalidate an evidence bundle offline"))
	return root
}

// newReview 是一般使用者的單一入口。scan/prove/replay/report 仍保留給 CI、
// 除錯與斷點續跑，但不要求操作者手動搬運 run-dir 或逐段編排。
func newReview() *cobra.Command {
	var target, targetSubdir, runDir, packDir string
	var watch, approveBuild bool
	var hypotheses int
	c := &cobra.Command{
		Use:   "review [repo root]",
		Short: "scan, prove, replay, and report in one command",
		Args:  cobra.MaximumNArgs(1),
	}
	c.Flags().StringVar(&target, "target", ".", "repo root")
	c.Flags().StringVar(&targetSubdir, "target-subdir", "", "limit review to a subtree")
	c.Flags().StringVar(&runDir, "run-dir", "", "use a specific new run directory")
	c.Flags().StringVar(&packDir, "pack", "packs/python-web", "pack directory")
	c.Flags().BoolVar(&watch, "watch", false, "show the AI workflow, response summaries, and tool activity")
	c.Flags().IntVar(&hypotheses, "hypotheses", 0, "override the hypothesis limit")
	c.Flags().BoolVar(&approveBuild, "approve-build", false, "preapprove proof image builds required by this review (for CI)")
	c.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) == 1 {
			if cmd.Flags().Changed("target") {
				return stageError("review", errors.New("repo root cannot use both a positional argument and --target"))
			}
			target = args[0]
		}
		if hypotheses < 0 {
			return stageError("review", errors.New("--hypotheses must not be negative"))
		}
		scanRoot := target
		if targetSubdir != "" {
			scanRoot = filepath.Join(target, targetSubdir)
		}
		if runDir == "" {
			runDir = filepath.Join(scanRoot, "out", "run-"+time.Now().UTC().Format("20060102-150405.000000000"))
		}
		fmt.Fprintf(cmd.OutOrStdout(), "\n◆ Review workflow started\n  target: %s\n  run: %s\n", scanRoot, runDir)

		run := func(stageArgs ...string) error {
			root := newRoot()
			root.SetArgs(stageArgs)
			root.SetOut(cmd.OutOrStdout())
			root.SetErr(cmd.ErrOrStderr())
			root.SilenceErrors = true
			return root.ExecuteContext(cmd.Context())
		}
		scanArgs := []string{"scan", "--target", target, "--run-dir", runDir, "--pack", packDir}
		if targetSubdir != "" {
			scanArgs = append(scanArgs, "--target-subdir", targetSubdir)
		}
		if watch {
			scanArgs = append(scanArgs, "--watch")
		}
		fmt.Fprintln(cmd.OutOrStdout(), "\n[1/5] SCAN — snapshot, inventory, detectors, and AI review")
		if err := run(scanArgs...); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "✓ [1/5] SCAN complete")

		data, err := os.ReadFile(filepath.Join(runDir, "findings.json"))
		if err != nil {
			return stageError("review", err)
		}
		var findings []reporting.Finding
		if err := decodeJSON(data, &findings); err != nil {
			return stageError("review", err)
		}
		environmentReady := true
		var verificationErr error
		fmt.Fprintln(cmd.OutOrStdout(), "\n[2/5] ENVIRONMENT — preparing an approved, pinned runtime")
		if len(findings) > 0 {
			if envErr := prepareRunEnvironment(cmd, runDir, packDir, findings, approveBuild); envErr != nil {
				environmentReady = false
				verificationErr = envErr
				fmt.Fprintf(cmd.OutOrStdout(), "○ [2/5] ENVIRONMENT not ready — %v\n", envErr)
			} else if _, statErr := os.Stat(filepath.Join(runDir, "environment.json")); statErr == nil {
				fmt.Fprintln(cmd.OutOrStdout(), "✓ [2/5] ENVIRONMENT ready — isolated source compile check passed")
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "○ [2/5] ENVIRONMENT skipped — no supported source-runtime check")
			}
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "○ [2/5] ENVIRONMENT skipped — no candidate findings")
		}
		supportedCount := 0
		for _, finding := range findings {
			if proofSupported(finding) {
				supportedCount++
			}
		}
		if supportedCount > 0 && environmentReady {
			fmt.Fprintf(cmd.OutOrStdout(), "\n[3/5] PROVE — validating %d oracle-supported finding(s)\n", supportedCount)
			proveArgs := []string{"prove", "--target", target, "--run-dir", runDir, "--pack", packDir}
			if targetSubdir != "" {
				proveArgs = append(proveArgs, "--target-subdir", targetSubdir)
			}
			if watch {
				proveArgs = append(proveArgs, "--watch")
			}
			if hypotheses > 0 {
				proveArgs = append(proveArgs, "--hypotheses", fmt.Sprint(hypotheses))
			}
			if approveBuild {
				proveArgs = append(proveArgs, "--approve-build")
			}
			if err := run(proveArgs...); err != nil {
				verificationErr = err
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "✓ [3/5] PROVE complete")
				if _, err := os.Stat(filepath.Join(runDir, "evidence")); err == nil {
					fmt.Fprintln(cmd.OutOrStdout(), "\n[4/5] REPLAY — independently checking evidence")
					if err := run("replay", "--target", scanRoot, "--run-dir", runDir, "--pack", packDir); err != nil {
						verificationErr = err
					} else {
						fmt.Fprintln(cmd.OutOrStdout(), "✓ [4/5] REPLAY complete")
					}
				} else {
					fmt.Fprintln(cmd.OutOrStdout(), "○ [4/5] REPLAY skipped — no evidence bundle")
				}
			}
		} else if !environmentReady {
			fmt.Fprintln(cmd.OutOrStdout(), "○ [3/5] PROVE skipped — proof environment was not approved or failed validation")
			fmt.Fprintln(cmd.OutOrStdout(), "○ [4/5] REPLAY skipped — no evidence bundle")
		} else if len(findings) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "○ [3/5] PROVE skipped — no candidate findings")
			fmt.Fprintln(cmd.OutOrStdout(), "○ [4/5] REPLAY skipped — no evidence bundle")
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "○ [3/5] PROVE skipped — %d finding(s), but no matching trusted oracle\n", len(findings))
			fmt.Fprintln(cmd.OutOrStdout(), "○ [4/5] REPLAY skipped — no evidence bundle")
		}
		fmt.Fprintln(cmd.OutOrStdout(), "\n[5/5] REPORT — generating final security report")
		reportArgs := []string{"report", "--target", scanRoot, "--run-dir", runDir}
		if watch {
			reportArgs = append(reportArgs, "--watch")
		}
		if err := run(reportArgs...); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "✓ [5/5] REPORT complete")
		absoluteRunDir := absolutePath(runDir)
		if verificationErr != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "\n✗ REVIEW INCOMPLETE — report generated, but verification failed\n  artifacts: %s\n  report: %s\n", absoluteRunDir, filepath.Join(absoluteRunDir, "report.md"))
			return verificationErr
		}
		fmt.Fprintf(cmd.OutOrStdout(), "\n✓ REVIEW COMPLETE\n  artifacts: %s\n  report: %s\n", absoluteRunDir, filepath.Join(absoluteRunDir, "report.md"))
		return nil
	}
	return c
}

func newConsole() *cobra.Command {
	return &cobra.Command{
		Use: "console", Short: "enter interactive mode",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runConsole(cmd.Context(), cmd.InOrStdin(), cmd.OutOrStdout())
		},
	}
}

func runConsole(ctx context.Context, in io.Reader, out io.Writer) error {
	credentialPath, err := credentials.DefaultFilePath()
	if err != nil {
		return err
	}
	settingsPath := filepath.Join(filepath.Dir(credentialPath), "settings.toml")
	deps := console.Deps{
		Context: ctx, In: in, Out: out, UserConfigPath: settingsPath, CredentialsPath: credentialPath,
		Keyring: credentials.NewOSKeyring(), ReadSecret: readSecret,
		Doctor: func(checkCtx context.Context) []doctor.Check {
			options, optionErr := defaultDoctorOptions(".", "packs/python-web", settingsPath, credentialPath)
			if optionErr != nil {
				return []doctor.Check{{Name: "configuration", OK: false, Detail: optionErr.Error()}}
			}
			return doctor.Run(checkCtx, options)
		},
		RunCommand: runInteractiveCommand,
	}
	// Use the full-screen TUI only when both streams are attached to a terminal.
	// Pipes, CI jobs, and tests retain the stable plain-text console behavior.
	if outputFile, ok := out.(*os.File); ok && term.IsTerminal(int(outputFile.Fd())) {
		if inputFile, ok := in.(*os.File); ok && term.IsTerminal(int(inputFile.Fd())) {
			return tui.Run(deps)
		}
	}
	return console.Run(deps)
}

// runInteractiveCommand 使用全新的 command tree 執行一次 pipeline，確保每次
// REPL 呼叫都有乾淨的 flag 狀態，且與一次性 CLI 共用完全相同的實作。
func runInteractiveCommand(ctx context.Context, args []string, out io.Writer) error {
	root := newRoot()
	root.SetArgs(args)
	root.SetOut(out)
	root.SetErr(out)
	root.SilenceErrors = true
	return root.ExecuteContext(ctx)
}

func defaultDoctorOptions(repoRoot, packDir, userSettings, credentialPath string) (doctor.Options, error) {
	user, err := settings.Load(userSettings)
	if err != nil {
		return doctor.Options{}, err
	}
	repo, err := settings.Load(filepath.Join(repoRoot, "aegis.toml"))
	if err != nil {
		return doctor.Options{}, err
	}
	providers := map[string]settings.Provider{}
	models := map[string]string{}
	for name, provider := range user.Providers {
		providers[name] = provider
	}
	for name, provider := range repo.Providers {
		providers[name] = provider
	}
	for _, role := range []string{settings.RoleRecon, settings.RoleReviewer, settings.RoleTriager, settings.RoleProver, settings.RoleReporter} {
		if ref, _, resolveErr := settings.ResolveModel(repo, user, role); resolveErr == nil {
			models[role] = ref
		}
	}
	cacheDir, err := aegisCacheDir()
	if err != nil {
		return doctor.Options{}, err
	}
	packDir, err = resolvePackDir(packDir, cacheDir)
	if err != nil {
		return doctor.Options{}, err
	}
	absPack, err := filepath.Abs(packDir)
	if err != nil {
		return doctor.Options{}, err
	}
	manager := &credentials.Manager{Keyring: credentials.NewOSKeyring(), File: &credentials.FileStore{Path: credentialPath}}
	schemasDir, err := projectSchemasDir()
	if err != nil {
		return doctor.Options{}, err
	}
	return doctor.Options{PackDirs: []string{absPack}, SchemasDir: schemasDir, CachePath: filepath.Join(cacheDir, "images.json"), Providers: providers, Models: models,
		ResolveKey: func(name string) (string, string, error) {
			provider, ok := providers[name]
			if !ok {
				return "", "", fmt.Errorf("unknown provider %q", name)
			}
			return manager.Resolve(name, credentials.ProviderType(provider.Type))
		}}, nil
}

func readSecret(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stdout, prompt)
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("stdin is not a terminal, cannot hide input")
	}
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stdout)
	return b, err
}

func newStage(name, short string) *cobra.Command {
	var target, targetSubdir string
	var runDir string
	var specPath, packDir string
	var dispositions []string
	var watch, approveBuild bool
	var hypotheses int
	c := &cobra.Command{Use: name, Short: short, Args: cobra.ArbitraryArgs}
	c.Flags().StringVar(&target, "target", ".", "repo root")
	c.Flags().StringVar(&runDir, "run-dir", "", "use a specific run directory")
	if name == "scan" || name == "prove" {
		c.Flags().StringVar(&targetSubdir, "target-subdir", "", "limit the scan to a subtree")
	}
	if name == "scan" || name == "prove" || name == "replay" {
		c.Flags().StringVar(&packDir, "pack", "packs/python-web", "pack directory")
	}
	if name == "scan" || name == "prove" || name == "report" {
		c.Flags().BoolVar(&watch, "watch", false, "show the AI workflow, response summaries, and tool activity")
	}
	if name == "prove" {
		c.Flags().StringVar(&specPath, "spec", "", "WitnessSpec JSON")
		c.Flags().IntVar(&hypotheses, "hypotheses", 0, "override the hypothesis limit (defaults to [budget], or 3 if unset)")
		c.Flags().BoolVar(&approveBuild, "approve-build", false, "preapprove the proof image build (for CI)")
	}
	if name == "report" {
		c.Flags().StringArrayVar(&dispositions, "set-disposition", nil, "set a finding disposition (F-####=OPEN|FALSE_POSITIVE|ACCEPTED_RISK|FIXED)")
	}
	c.RunE = func(cmd *cobra.Command, args []string) error {
		if name != "prove" {
			if len(args) > 1 {
				return stageError(name, errors.New("at most one positional argument (repo root)"))
			}
			if len(args) == 1 {
				if cmd.Flags().Changed("target") {
					return stageError(name, errors.New("repo root cannot use both a positional argument and --target"))
				}
				target = args[0]
			}
		}
		if name == "scan" {
			root := target
			if targetSubdir != "" {
				root = filepath.Join(root, targetSubdir)
			}
			if watch {
				fmt.Fprintf(cmd.OutOrStdout(), "◆ SCAN STARTED — %s\n▶ Creating immutable snapshot…\n", root)
			}
			// Snapshot is the first repository read. All later scan stages consume
			// the immutable copy so provenance cannot drift under worktree edits.
			cacheDir, err := snapshotCacheDir()
			if err != nil {
				return stageError(name, err)
			}
			snap, err := snapshot.Create(root, cacheDir, inventory.DefaultExcludes)
			if err != nil {
				return stageError(name, err)
			}
			if watch {
				fmt.Fprintf(cmd.OutOrStdout(), "✓ Snapshot ready — %s\n▶ Building repository inventory…\n", snap.ID)
			}
			inv, err := inventory.Build(snap.Dir)
			if err != nil {
				return stageError(name, err)
			}
			inv.SnapshotID = snap.ID
			if watch {
				fmt.Fprintf(cmd.OutOrStdout(), "✓ Inventory ready — %d files, %d entrypoints\n", len(inv.Files), len(inv.Entrypoints))
			}
			packDir, err = resolvePackDir(packDir, cacheDir)
			if err != nil {
				return stageError(name, err)
			}
			pack, err := loadPackForCLI(packDir)
			if err != nil {
				return stageError(name, err)
			}
			reviewerConfigured := roleConfigured(root, settings.RoleReviewer)
			if err := ensurePackCoversInventory(pack, inv, reviewerConfigured); err != nil {
				return stageError(name, err)
			}
			if runDir == "" {
				outDir := filepath.Join(root, "out")
				if err := os.MkdirAll(outDir, 0o755); err != nil {
					return stageError(name, err)
				}
				runDir = filepath.Join(outDir, "run-"+time.Now().UTC().Format("20060102-150405.000000000"))
				if err := os.Mkdir(runDir, 0o755); err != nil {
					return stageError(name, fmt.Errorf("creating unique run directory: %w", err))
				}
			} else if err := os.MkdirAll(runDir, 0o755); err != nil {
				return stageError(name, err)
			}
			j, err := journal.Open(filepath.Join(runDir, "journal.sqlite"))
			if err != nil {
				return stageError(name, err)
			}
			defer j.Close()
			trace, err := openAITrace(runDir, cmd.OutOrStdout(), watch)
			if err != nil {
				return stageError(name, err)
			}
			defer trace.Close()
			scanCtx := withAITrace(cmd.Context(), trace, "scan")
			if _, err := j.Append("run_started", "", map[string]any{"stage": "scan"}); err != nil {
				return stageError(name, err)
			}
			if _, err := j.Append("snapshot_created", "", map[string]any{"snapshot_id": snap.ID, "tree_hash": snap.TreeHash}); err != nil {
				return stageError(name, err)
			}
			coverage := packCoverage(pack, inv, reviewerConfigured)
			if len(coverage.UncoveredExtensions) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "note: LLM discovery still reviews %s; the current proof runtime %s@%s only accepts %s and cannot run witnesses for these languages. The Semgrep detector is only a candidate source, not the cause of this limit.\n",
					strings.Join(coverage.UncoveredExtensions, ", "), coverage.PackID, coverage.PackVersion, displayCLIList(coverage.ProofRuntimeExtensions))
			}
			data, err := json.MarshalIndent(inv, "", "  ")
			if err != nil {
				return stageError(name, err)
			}
			if err := redaction.WriteFile(filepath.Join(runDir, "inventory.json"), append(data, '\n'), 0o644); err != nil {
				return stageError(name, err)
			}
			if _, err := j.Append("stage_completed", "", map[string]any{"stage": "inventory", "artifact": "inventory.json"}); err != nil {
				return stageError(name, err)
			}
			var detectorResults [][]candidates.Candidate
			if len(pack.Manifest.Detectors) > 0 {
				if watch {
					fmt.Fprintf(cmd.OutOrStdout(), "▶ Running %d deterministic detector(s)…\n", len(pack.Manifest.Detectors))
				}
				if _, err := exec.LookPath("semgrep"); err != nil {
					if !reviewerConfigured {
						return stageError(name, fmt.Errorf("semgrep not found and no reviewer configured to take over: %w", err))
					}
					coverage.DetectorNotes = append(coverage.DetectorNotes, "semgrep unavailable; LLM fallback used")
					fmt.Fprintln(cmd.OutOrStdout(), "warning: semgrep not found; continuing with LLM global review")
				} else {
					for _, det := range pack.Manifest.Detectors {
						group, runErr := candidates.Run(cmd.Context(), snap.Dir, filepath.Join(packDir, det.Path), det.ID, "semgrep")
						if runErr != nil {
							if !reviewerConfigured {
								return stageError(name, runErr)
							}
							coverage.DetectorNotes = append(coverage.DetectorNotes, det.ID+": execution failed; LLM fallback used")
							fmt.Fprintf(cmd.OutOrStdout(), "warning: detector %s failed; LLM global review continues\n", det.ID)
							continue
						}
						coverage.ExecutedDetectorIDs = append(coverage.ExecutedDetectorIDs, det.ID)
						detectorResults = append(detectorResults, group)
					}
				}
			}
			coverageData, err := json.MarshalIndent(coverage, "", "  ")
			if err != nil {
				return stageError(name, err)
			}
			if err := redaction.WriteFile(filepath.Join(runDir, "coverage.json"), append(coverageData, '\n'), 0o644); err != nil {
				return stageError(name, err)
			}
			if reviewerConfigured {
				// Always show the stage boundary. Without --watch the detailed
				// agent/tool stream stays quiet, but the operator must still know
				// that the process is waiting on the recon/reviewer LLM call.
				fmt.Fprintln(cmd.OutOrStdout(), "▶ Starting global AI code review…")
				llmCandidates, reviewErr := runLLMScan(scanCtx, root, snap.Dir, runDir, packDir, inv, pack)
				if reviewErr != nil {
					return stageError(name, reviewErr)
				}
				detectorResults = append(detectorResults, llmCandidates)
				fmt.Fprintf(cmd.OutOrStdout(), "LLM recon/reviewer review complete: added %d candidate(s)\n", len(llmCandidates))
			}
			cs := candidates.Merge(detectorResults...)
			cb, err := json.MarshalIndent(cs, "", "  ")
			if err != nil {
				return stageError(name, err)
			}
			if err := redaction.WriteFile(filepath.Join(runDir, "candidates.json"), append(cb, '\n'), 0o644); err != nil {
				return stageError(name, err)
			}
			for _, c := range cs {
				if err := validateSchema("candidate", c); err != nil {
					return stageError(name, err)
				}
			}
			if _, err := j.Append("stage_completed", "", map[string]any{"stage": "candidates", "artifact": "candidates.json", "count": len(cs)}); err != nil {
				return stageError(name, err)
			}
			findings := make([]reporting.Finding, 0, len(cs))
			triages := make([]triage.Result, 0, len(cs))
			for _, c := range cs {
				fid, err := j.NextID("F")
				if err != nil {
					return stageError(name, err)
				}
				t := triage.EvaluateAt(c, inv, snap.Dir)
				if roleConfigured(root, settings.RoleTriager) {
					comment, triageErr := runLLMTriage(scanCtx, root, c, t)
					if triageErr != nil {
						return stageError(name, fmt.Errorf("triager failed: %w", triageErr))
					}
					t.Rationale += "；LLM triager：" + strings.TrimSpace(comment)
					fmt.Fprintf(cmd.OutOrStdout(), "LLM triager review complete: %s\n", c.ID)
				}
				triages = append(triages, t)
				sources := make([]any, 0, len(c.Sources))
				for _, source := range c.Sources {
					sources = append(sources, map[string]any{"origin": source.Origin, "rule": source.Rule})
				}
				impact, _ := pack.Impact(c.Sink.Type)
				proofSupported := packCanProve(pack, c.Sink.Type)
				if !proofSupported {
					impact = c.Impact
					if impact != "high" && impact != "medium" && impact != "low" {
						impact = impactForPriority(c.PriorityHint)
					}
				}
				proofNote := fmt.Sprintf("pack %s@%s can run a sandbox/oracle proof for this type", pack.Manifest.PackID, pack.Manifest.Version)
				if !proofSupported {
					proofNote = fmt.Sprintf("found by global code review, but pack %s@%s has no sandbox/oracle for %s; the finding is kept and not claimed as proven", pack.Manifest.PackID, pack.Manifest.Version, c.Sink.Type)
				}
				f := reporting.Finding{"id": fid, "sink": map[string]any{"file": c.Sink.File, "line": c.Sink.Line, "symbol": c.Sink.Symbol, "type": c.Sink.Type}, "sources": sources, "reachability": t.Reachability, "verification": "NOT_RUN", "proof_supported": proofSupported, "proof_note": proofNote, "disposition": "OPEN", "snapshot_id": snap.ID, "severity": triage.Severity(impact, t.Reachability), "confidence": triage.Confidence("NOT_RUN", t.Mode, 0, 0), "rationale": c.Rationale + "; reachability: " + t.Rationale}
				if c.CWE != "" {
					f["cwe"] = c.CWE
				}
				if len(c.Evidence) > 0 {
					f["review_evidence"] = c.Evidence
				}
				if len(c.Chain) > 0 {
					f["chain"] = c.Chain
				}
				if t.Mode != "" {
					f["mode"] = t.Mode
				}
				if len(t.MissingLinks) > 0 {
					links := make([]string, 0, len(t.MissingLinks))
					for _, link := range t.MissingLinks {
						links = append(links, link["link"]+": "+link["evidence"])
					}
					f["missing_links"] = links
				}
				findings = append(findings, f)
				if _, err := j.Append("candidate_created", fid, map[string]any{"candidate": c}); err != nil {
					return stageError(name, err)
				}
				if len(c.Sources) > 1 {
					if _, err := j.Append("candidate_merged", fid, map[string]any{"candidate": c, "source_count": len(c.Sources)}); err != nil {
						return stageError(name, err)
					}
				}
				if _, err := j.Append("triage_updated", fid, map[string]any{"triage": t}); err != nil {
					return stageError(name, err)
				}
				if _, err := j.Append("finding_created", fid, map[string]any{"finding": f}); err != nil {
					return stageError(name, err)
				}
			}
			tb, err := json.MarshalIndent(triages, "", "  ")
			if err != nil {
				return stageError(name, err)
			}
			if err := redaction.WriteFile(filepath.Join(runDir, "triage.json"), append(tb, '\n'), 0o644); err != nil {
				return stageError(name, err)
			}
			for _, t := range triages {
				if err := validateSchema("triage", t); err != nil {
					return stageError(name, err)
				}
			}
			for _, f := range findings {
				if err := validateSchema("finding", f); err != nil {
					return stageError(name, err)
				}
			}
			if _, err := j.Append("stage_completed", "", map[string]any{"stage": "triage", "artifact": "triage.json"}); err != nil {
				return stageError(name, err)
			}
			fb, err := json.MarshalIndent(findings, "", "  ")
			if err != nil {
				return stageError(name, err)
			}
			if err := redaction.WriteFile(filepath.Join(runDir, "findings.json"), append(fb, '\n'), 0o644); err != nil {
				return stageError(name, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "scan complete: %d file(s), %d entrypoint(s), %d candidate(s)\nartifacts: %s\n", len(inv.Files), len(inv.Entrypoints), len(cs), absolutePath(runDir))
			return nil
		}
		if name == "report" {
			if runDir == "" {
				runDir = latestRunDir(target)
			}
			if runDir == "" {
				return stageError(name, errors.New("no run directory to report on; run aegis scan first"))
			}
			findings := []reporting.Finding{}
			if data, err := os.ReadFile(filepath.Join(runDir, "findings.json")); err == nil {
				if err := json.Unmarshal(data, &findings); err != nil {
					return stageError(name, err)
				}
			}
			if len(dispositions) > 0 {
				for _, item := range dispositions {
					parts := strings.SplitN(item, "=", 2)
					if len(parts) != 2 || !validDisposition(parts[1]) {
						return stageError(name, fmt.Errorf("invalid disposition %q", item))
					}
					found := false
					for _, f := range findings {
						if f["id"] == parts[0] {
							f["disposition"] = parts[1]
							found = true
						}
					}
					if !found {
						return stageError(name, fmt.Errorf("finding %s not found", parts[0]))
					}
				}
			}
			j, err := journal.Open(filepath.Join(runDir, "journal.sqlite"))
			if err != nil {
				return stageError(name, err)
			}
			defer j.Close()
			for _, item := range dispositions {
				parts := strings.SplitN(item, "=", 2)
				if _, err := j.Append("disposition_updated", parts[0], map[string]any{"disposition": parts[1]}); err != nil {
					return stageError(name, err)
				}
			}
			if _, err := reporting.WriteFindings(runDir, findings); err != nil {
				return stageError(name, err)
			}
			if _, err := reporting.WriteSARIF(runDir, findings); err != nil {
				return stageError(name, err)
			}
			path, err := reporting.WriteReportMD(runDir, findings, runDir, time.Now().UTC())
			if err != nil {
				return stageError(name, err)
			}
			// 空 findings 不交給模型自由發揮。沒有逐項證據時，模型很容易
			// 杜撰未執行的 SAST/DAST/合規方法，確定性模板才是可信輸出。
			if len(findings) > 0 && roleConfigured(target, settings.RoleReporter) {
				trace, traceErr := openAITrace(runDir, cmd.OutOrStdout(), watch)
				if traceErr != nil {
					return stageError(name, traceErr)
				}
				defer trace.Close()
				path, err = writeLLMReport(withAITrace(cmd.Context(), trace, "report"), target, runDir, findings)
				if err != nil {
					return stageError(name, fmt.Errorf("reporter failed: %w", err))
				}
				fmt.Fprintln(cmd.OutOrStdout(), "LLM reporter finished writing")
			}
			artifacts := []string{"findings.json", "findings.sarif", "report.md"}
			if _, statErr := os.Stat(filepath.Join(runDir, "environment.json")); statErr == nil {
				artifacts = append(artifacts, "environment.json")
			}
			if _, err := j.Append("report_written", "", map[string]any{"artifacts": artifacts}); err != nil {
				return stageError(name, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "report complete: %s\n", absolutePath(path))
			return nil
		}
		if name == "replay" {
			if runDir == "" {
				runDir = latestRunDir(target)
			}
			if runDir == "" {
				return stageError(name, errors.New("run directory not found"))
			}
			cacheDir, cacheErr := aegisCacheDir()
			if cacheErr != nil {
				return stageError(name, cacheErr)
			}
			resolvedPackDir, resolveErr := resolvePackDir(packDir, cacheDir)
			if resolveErr != nil {
				return stageError(name, resolveErr)
			}
			pack, err := loadPackForCLI(resolvedPackDir)
			if err != nil {
				return stageError(name, err)
			}
			if err := orchestrator.ReplayBundle(pack, runDir); err != nil {
				return stageError(name, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "replay verification passed: %s\n", runDir)
			return nil
		}
		if name == "prove" {
			return runProveCommand(cmd, args, proveOptions{target: target, targetSubdir: targetSubdir,
				runDir: runDir, specPath: specPath, packDir: packDir, watch: watch, hypotheses: hypotheses, approveBuild: approveBuild})
		}
		_ = args
		_ = watch
		_ = hypotheses
		return stageError(name, fmt.Errorf("%s pipeline not wired (produce scan run artifacts first)", name))
	}
	return c
}

type proveOptions struct {
	target, targetSubdir, runDir, specPath, packDir string
	watch, approveBuild                             bool
	hypotheses                                      int
}

func runProveCommand(cmd *cobra.Command, args []string, opts proveOptions) error {
	if len(args) > 1 {
		return stageError("prove", errors.New("at most one finding ID; omit it to prove all findings in this run in order"))
	}
	if opts.specPath != "" && len(args) != 1 {
		return stageError("prove", errors.New("offline --spec mode requires exactly one finding ID"))
	}
	if opts.hypotheses < 0 {
		return stageError("prove", errors.New("--hypotheses must be at least 1"))
	}
	scanRoot := opts.target
	if opts.targetSubdir != "" {
		scanRoot = filepath.Join(scanRoot, opts.targetSubdir)
	}
	if opts.runDir == "" {
		opts.runDir = latestRunDir(scanRoot)
	}
	if opts.runDir == "" {
		return stageError("prove", errors.New("no scan run found; run aegis scan first"))
	}

	cacheDir, err := aegisCacheDir()
	if err != nil {
		return stageError("prove", err)
	}
	opts.packDir, err = resolvePackDir(opts.packDir, cacheDir)
	if err != nil {
		return stageError("prove", err)
	}
	pack, err := loadPackForCLI(opts.packDir)
	if err != nil {
		return stageError("prove", err)
	}
	proverSchemasDir, err := projectSchemasDir()
	if err != nil {
		return stageError("prove", err)
	}
	configuredBudget, err := proveBudget(scanRoot)
	if err != nil {
		return stageError("prove", err)
	}
	if opts.hypotheses > 0 {
		configuredBudget.MaxHypotheses = opts.hypotheses
	}
	findingsData, err := os.ReadFile(filepath.Join(opts.runDir, "findings.json"))
	if err != nil {
		return stageError("prove", err)
	}
	var findings []reporting.Finding
	if err := decodeJSON(findingsData, &findings); err != nil {
		return stageError("prove", err)
	}
	if err := prepareRunEnvironment(cmd, opts.runDir, opts.packDir, findings, opts.approveBuild); err != nil {
		return stageError("prove", err)
	}
	selected := make([]reporting.Finding, 0, len(findings))
	for _, finding := range findings {
		matches := len(args) == 0 || finding["id"] == args[0]
		if matches && proofSupported(finding) {
			selected = append(selected, finding)
		}
	}
	if len(selected) == 0 {
		if len(args) == 0 {
			return stageError("prove", errors.New("this run has no finding the current pack can mechanically prove; unsupported items remain in the report"))
		}
		for _, finding := range findings {
			if finding["id"] == args[0] && !proofSupported(finding) {
				return stageError("prove", fmt.Errorf("finding %s of type %s has no sandbox/oracle proof support yet", args[0], stringValue(mapValue(finding["sink"])["type"])))
			}
		}
		return stageError("prove", fmt.Errorf("finding %s does not exist in this run", args[0]))
	}

	j, err := journal.Open(filepath.Join(opts.runDir, "journal.sqlite"))
	if err != nil {
		return stageError("prove", err)
	}
	defer j.Close()
	events, err := j.Events()
	if err != nil {
		return stageError("prove", err)
	}
	store, err := evidence.NewStore(opts.runDir)
	if err != nil {
		return stageError("prove", err)
	}
	helper, ok := pack.Manifest.Images["helper/alpine"]
	if !ok {
		return stageError("prove", errors.New("pack is missing the helper/alpine digest"))
	}
	imageCachePath := filepath.Join(cacheDir, "images.json")

	var manualSpec map[string]any
	if opts.specPath != "" {
		data, readErr := os.ReadFile(opts.specPath)
		if readErr != nil {
			return stageError("prove", readErr)
		}
		if err := decodeJSON(data, &manualSpec); err != nil {
			return stageError("prove", fmt.Errorf("WitnessSpec JSON：%w", err))
		}
	}

	var adapter llm.Adapter
	var model string
	var toolDefs []llm.ToolDef
	var registry *schemav.Registry
	var toolsRegistry *agent.ToolRegistry
	var audit *agent.AuditLog
	proveCtx := cmd.Context()
	if manualSpec == nil {
		adapter, model, err = proverAdapter(scanRoot)
		if err != nil {
			return stageError("prove", err)
		}
		schemasDir, schemaErr := projectSchemasDir()
		if schemaErr != nil {
			return stageError("prove", schemaErr)
		}
		toolsSchema, readErr := os.ReadFile(filepath.Join(schemasDir, "tools.schema.json"))
		if readErr != nil {
			return stageError("prove", readErr)
		}
		specSchema, readErr := os.ReadFile(filepath.Join(schemasDir, "witness_spec.schema.json"))
		if readErr != nil {
			return stageError("prove", readErr)
		}
		toolDefs, err = agent.NewToolDefs(llm.RoleProver, toolsSchema, specSchema, map[string]string{
			"read_code": "read a file and line range inside the snapshot (read-only)", "search_code": "search the snapshot with RE2 (read-only)",
			"semgrep": "scan the snapshot with pack-registered rules (read-only)", "submit_witness_spec": "submit a schema-constrained WitnessSpec",
		})
		if err != nil {
			return stageError("prove", err)
		}
		registry = schemav.New()
		if err := registry.LoadDir(schemasDir); err != nil {
			return stageError("prove", err)
		}
		rules := map[string]string{}
		for _, detector := range pack.Manifest.Detectors {
			rules[detector.ID] = filepath.Join(opts.packDir, detector.Path)
		}
		toolsRegistry = &agent.ToolRegistry{Rules: rules}
		audit, err = agent.OpenAuditLog(opts.runDir)
		if err != nil {
			return stageError("prove", err)
		}
		defer audit.Close()
		toolsRegistry.SetAudit(audit)
		trace, traceErr := openAITrace(opts.runDir, cmd.OutOrStdout(), opts.watch)
		if traceErr != nil {
			return stageError("prove", traceErr)
		}
		defer trace.Close()
		proveCtx = withAITrace(cmd.Context(), trace, "prove")
		toolsRegistry.SetObserver(func(event agent.ToolEvent) {
			kind := "tool_" + event.Kind
			content := fmt.Sprintf("%s %s", event.Tool, event.Content)
			if event.IsError {
				content = "ERROR " + content
			}
			emitAITrace(proveCtx, string(event.Role), kind, content)
		})
	}

	for _, finding := range selected {
		findingID, _ := finding["id"].(string)
		snapshotID, _ := finding["snapshot_id"].(string)
		reachability, _ := finding["reachability"].(string)
		cacheDir, cacheErr := snapshotCacheDir()
		if cacheErr != nil {
			return stageError("prove", cacheErr)
		}
		snapshotDir := filepath.Join(cacheDir, "snapshots", snapshotID)
		if stat, statErr := os.Stat(snapshotDir); statErr != nil || !stat.IsDir() {
			return stageError("prove", fmt.Errorf("scan snapshot %s does not exist; refusing to fall back to the live worktree", snapshotID))
		}
		repoTreeHash := snapshotTreeHash(events, snapshotID)
		if repoTreeHash == "" {
			return stageError("prove", fmt.Errorf("journal is missing the tree hash for snapshot %s", snapshotID))
		}
		if err := snapshot.Verify(snapshotDir, snapshotID, repoTreeHash); err != nil {
			return stageError("prove", err)
		}
		b := configuredBudget
		p := &orchestrator.Prover{Runner: &sandbox.Runner{HelperImage: helper}, Journal: j, Store: store, Pack: pack, PackDir: opts.packDir, SchemasDir: proverSchemasDir,
			SnapshotID: snapshotID, SnapshotDir: snapshotDir, RunDir: opts.runDir, RepoTreeHash: repoTreeHash, CachePath: imageCachePath, Budget: b}

		if opts.watch {
			fmt.Fprintf(cmd.OutOrStdout(), "prove started: %s (up to %d hypotheses)\n", findingID, b.MaxHypotheses)
		}
		if manualSpec != nil {
			res, proveErr := p.Prove(cmd.Context(), orchestrator.ProveInput{FindingID: findingID, Reachability: reachability, Spec: manualSpec})
			if proveErr != nil {
				return stageError("prove", proveErr)
			}
			finding["verification"] = string(res.Verification)
			if len(res.Runs) > 0 {
				setEvidenceID(finding, res.Runs[len(res.Runs)-1].EvidenceID)
			}
			if _, err := j.Append("verification_updated", findingID, map[string]any{"verification": string(res.Verification), "mode": "manual_spec"}); err != nil {
				return stageError("prove", err)
			}
		} else {
			sink := mapValue(finding["sink"])
			contextText, contextErr := sinkContext(snapshotDir, stringValue(sink["file"]), intValue(sink["line"]), 200)
			if contextErr != nil {
				return stageError("prove", contextErr)
			}
			toolsRegistry.SnapshotDir = snapshotDir
			ap := &orchestrator.AgentProver{Prove: p.Prove, Journal: j, Adapter: adapter, Tools: toolsRegistry, ToolDefs: toolDefs,
				ValidateSpec: func(spec map[string]any) error {
					data, marshalErr := json.Marshal(spec)
					if marshalErr != nil {
						return marshalErr
					}
					return registry.Validate("witness_spec", data)
				}, Model: model, System: proverSystemPrompt,
				Finding: orchestrator.FindingContext{FindingID: findingID, Reachability: reachability, TargetSymbol: stringValue(sink["symbol"]),
					OracleID: oracleForSink(pack, stringValue(sink["type"])), SnapshotID: snapshotID, Context: contextText},
				Budget: b, RunDir: opts.runDir,
				OnResponse: func(turn int, response llm.Response) {
					var reply strings.Builder
					for _, block := range response.Content {
						if block.Type == "text" {
							reply.WriteString(block.Text)
						}
						if block.Type == "tool_use" && block.ToolUse != nil {
							fmt.Fprintf(&reply, "\n→ tool %s %s", block.ToolUse.Name, block.ToolUse.Input)
						}
					}
					emitAITrace(withAIPhase(proveCtx, fmt.Sprintf("prove-%s-turn-%d", findingID, turn)), string(llm.RoleProver), "response", reply.String())
				}}
			res, proveErr := ap.Run(proveCtx)
			if proveErr != nil {
				return stageError("prove", proveErr)
			}
			finding["verification"] = string(res.Verification)
			if res.NotProvenReason != "" {
				finding["not_proven_reason"] = string(res.NotProvenReason)
			} else {
				delete(finding, "not_proven_reason")
			}
			if res.Scope != nil {
				finding["reject_scope"] = res.Scope
			}
			for i := len(res.Attempts) - 1; i >= 0; i-- {
				if n := len(res.Attempts[i].Runs); n > 0 {
					setEvidenceID(finding, res.Attempts[i].Runs[n-1].EvidenceID)
					break
				}
			}
			if opts.watch {
				fmt.Fprintf(cmd.OutOrStdout(), "prove attempts: %s, %d total\n", findingID, len(res.Attempts))
			}
		}
		mode, _ := finding["mode"].(string)
		finding["confidence"] = triage.Confidence(stringValue(finding["verification"]), mode, sliceLen(finding["assumptions"]), 1)
		fmt.Fprintf(cmd.OutOrStdout(), "prove complete: %s = %s\n", findingID, finding["verification"])
	}
	if _, err := reporting.WriteFindings(opts.runDir, findings); err != nil {
		return stageError("prove", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "artifacts: %s\n", absolutePath(opts.runDir))
	return nil
}

func absolutePath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

type environmentRecord struct {
	SnapshotID string `json:"snapshot_id"`
	Pack       string `json:"pack"`
	Runtime    string `json:"runtime"`
	Image      string `json:"image,omitempty"`
	Status     string `json:"status"`
	Check      string `json:"check"`
	Network    string `json:"network"`
	Detail     string `json:"detail,omitempty"`
}

var (
	preparePacksForRun     = doctor.PreparePacks
	checkEnvironmentForRun = func(ctx context.Context, spec sandbox.EnvironmentCheckSpec) ([]byte, error) {
		return (&sandbox.Runner{}).CheckEnvironment(ctx, spec)
	}
)

// prepareRunEnvironment is intentionally independent from vulnerability oracle
// support. A Python finding can therefore establish that its immutable source
// compiles in the pinned runtime even when its vulnerability family remains
// NOT_RUN because no trusted oracle exists yet.
func prepareRunEnvironment(cmd *cobra.Command, runDir, packDir string, findings []reporting.Finding, preapproved bool) error {
	var snapshotID string
	pythonApplicable := false
	for _, finding := range findings {
		if snapshotID == "" {
			snapshotID = stringValue(finding["snapshot_id"])
		}
		if strings.EqualFold(filepath.Ext(stringValue(mapValue(finding["sink"])["file"])), ".py") {
			pythonApplicable = true
		}
	}
	if !pythonApplicable || snapshotID == "" {
		return nil
	}
	environmentPath := filepath.Join(runDir, "environment.json")
	if data, err := os.ReadFile(environmentPath); err == nil {
		var existing environmentRecord
		if decodeJSON(data, &existing) == nil && existing.SnapshotID == snapshotID && existing.Status == "SOURCE_COMPILED" {
			return nil
		}
	}
	cacheDir, err := aegisCacheDir()
	if err != nil {
		return err
	}
	packDir, err = resolvePackDir(packDir, cacheDir)
	if err != nil {
		return err
	}
	pack, err := loadPackForCLI(packDir)
	if err != nil {
		return err
	}
	if pack.Manifest.PackID != "python-web" {
		return nil
	}
	schemasDir, err := projectSchemasDir()
	if err != nil {
		return err
	}
	imageCache := filepath.Join(cacheDir, "images.json")
	checks := preparePacksForRun(cmd.Context(), doctor.Options{
		PackDirs: []string{packDir}, SchemasDir: schemasDir, CachePath: imageCache,
		ApproveBuild: commandBuildApprover(cmd, preapproved),
	})
	for _, check := range checks {
		if !check.OK {
			record := environmentRecord{SnapshotID: snapshotID, Pack: pack.Manifest.PackID + "@" + pack.Manifest.Version, Runtime: "python", Status: "NOT_READY", Check: "Python compile() over /target/**/*.py", Network: "none", Detail: check.Detail}
			if writeErr := writeEnvironmentRecord(environmentPath, record); writeErr != nil {
				return fmt.Errorf("proof environment preparation failed (%s): %s; could not record environment status: %v", check.Name, check.Detail, writeErr)
			}
			return fmt.Errorf("proof 環境準備失敗（%s）：%s", check.Name, check.Detail)
		}
	}
	if len(pack.Manifest.Templates) == 0 {
		return errors.New("python-web pack 沒有 runtime template")
	}
	templateID := ""
	for _, candidate := range pack.Manifest.Templates {
		for _, ext := range candidate.AllowedFiles {
			if strings.EqualFold(ext, ".py") {
				templateID = candidate.TemplateID
				break
			}
		}
		if templateID != "" {
			break
		}
	}
	if templateID == "" {
		return errors.New("python-web pack 沒有允許 Python 檔案的 runtime template")
	}
	tmpl, err := orchestrator.NewPackView(pack, imageCache).Template(templateID)
	if err != nil {
		return err
	}
	snapshotDir := filepath.Join(cacheDir, "snapshots", snapshotID)
	j, err := journal.Open(filepath.Join(runDir, "journal.sqlite"))
	if err != nil {
		return err
	}
	events, eventsErr := j.Events()
	closeErr := j.Close()
	if eventsErr != nil {
		return eventsErr
	}
	if closeErr != nil {
		return closeErr
	}
	treeHash := snapshotTreeHash(events, snapshotID)
	if treeHash == "" {
		return fmt.Errorf("journal 缺少 snapshot %s 的 tree hash", snapshotID)
	}
	if err := snapshot.Verify(snapshotDir, snapshotID, treeHash); err != nil {
		return err
	}
	const pythonCompileCheck = "import pathlib\nfor p in pathlib.Path('/target').rglob('*.py'):\n compile(p.read_bytes(), str(p), 'exec')"
	_, err = checkEnvironmentForRun(cmd.Context(), sandbox.EnvironmentCheckSpec{
		RunID: "ENV-CHECK", SnapshotID: snapshotID, SnapshotDir: snapshotDir,
		Image: tmpl.Image, Seccomp: filepath.Join(packDir, "sandbox", "seccomp.json"),
		Cmd: []string{"python", "-c", pythonCompileCheck}, TimeoutSec: 120,
	})
	record := environmentRecord{SnapshotID: snapshotID, Pack: pack.Manifest.PackID + "@" + pack.Manifest.Version, Runtime: "python", Image: tmpl.Image, Check: "Python compile() over /target/**/*.py", Network: "none"}
	if err != nil {
		record.Status, record.Detail = "COMPILE_FAILED", err.Error()
		_ = writeEnvironmentRecord(environmentPath, record)
		return fmt.Errorf("Python snapshot compile check 失敗：%w", err)
	}
	record.Status = "SOURCE_COMPILED"
	return writeEnvironmentRecord(environmentPath, record)
}

func writeEnvironmentRecord(path string, record environmentRecord) error {
	if err := validateSchema("environment", record); err != nil {
		return err
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return redaction.WriteFile(path, append(data, '\n'), 0o644)
}

func commandBuildApprover(cmd *cobra.Command, preapproved bool) approval.Approver {
	allowAll := preapproved
	inherited := approval.FromContext(cmd.Context())
	return func(req approval.BuildRequest) (approval.Decision, error) {
		if allowAll {
			return approval.AllowRun, nil
		}
		if inherited != nil {
			decision, err := inherited(req)
			if decision == approval.AllowRun {
				allowAll = true
			}
			return decision, err
		}
		inFile, inOK := cmd.InOrStdin().(*os.File)
		outFile, outOK := cmd.OutOrStdout().(*os.File)
		if !inOK || !outOK || !term.IsTerminal(int(inFile.Fd())) || !term.IsTerminal(int(outFile.Fd())) {
			return approval.Deny, errors.New("非互動環境不會自動建立 image；請加 --approve-build 明確核准")
		}
		decision, err := approval.Prompt(inFile, outFile, req)
		if decision == approval.AllowRun {
			allowAll = true
		}
		return decision, err
	}
}

func proofSupported(finding reporting.Finding) bool {
	value, exists := finding["proof_supported"]
	if !exists {
		return true // 舊 run 在引入此欄位前全部來自 pack。
	}
	supported, _ := value.(bool)
	return supported
}

func packCanProve(pack *packs.Pack, sinkType string) bool {
	if _, ok := pack.Impact(sinkType); !ok {
		return false
	}
	family := ""
	for _, sink := range pack.Manifest.SinkTypes {
		if sink.Type == sinkType {
			family = sink.Family
			break
		}
	}
	if family == "" {
		return false
	}
	hasTemplate, hasOracle := false, false
	for _, tmpl := range pack.Manifest.Templates {
		hasTemplate = hasTemplate || tmpl.Family == family
	}
	for _, oracle := range pack.Manifest.Oracles {
		hasOracle = hasOracle || oracle.Family == family && oracle.Touch != nil
	}
	return hasTemplate && hasOracle
}

func proverAdapter(repoRoot string) (llm.Adapter, string, error) {
	userPath, err := settings.DefaultUserPath()
	if err != nil {
		return nil, "", err
	}
	credentialPath, err := settings.DefaultCredentialsPath()
	if err != nil {
		return nil, "", err
	}
	user, err := settings.Load(userPath)
	if err != nil {
		return nil, "", err
	}
	repo, err := settings.Load(filepath.Join(repoRoot, "aegis.toml"))
	if err != nil {
		return nil, "", err
	}
	ref, _, err := settings.ResolveModel(repo, user, settings.RoleProver)
	if err != nil {
		return nil, "", fmt.Errorf("prover model not configured; run /provider add -> /key set -> /model set in order: %w", err)
	}
	if err := settings.ValidateRef(ref); err != nil {
		return nil, "", err
	}
	providerName, model, _ := strings.Cut(ref, "/")
	provider, ok := repo.Providers[providerName]
	if !ok {
		provider, ok = user.Providers[providerName]
	}
	if !ok {
		return nil, "", fmt.Errorf("prover provider %q not configured; run /provider add", providerName)
	}
	manager := &credentials.Manager{Keyring: credentials.NewOSKeyring(), File: &credentials.FileStore{Path: credentialPath}}
	key, _, err := manager.Resolve(providerName, credentials.ProviderType(provider.Type))
	if err != nil {
		return nil, "", fmt.Errorf("prover provider %q is missing a key; run /key set: %w", providerName, err)
	}
	switch credentials.ProviderType(provider.Type) {
	case credentials.ProviderTypeAnthropic:
		return llm.NewAnthropic(key, provider.BaseURL), model, nil
	case credentials.ProviderTypeOpenAICompat:
		if provider.BaseURL == "" {
			return nil, "", fmt.Errorf("openai-compat provider %q is missing base_url", providerName)
		}
		return llm.NewOpenAICompat(providerName, provider.BaseURL, key, model), model, nil
	default:
		return nil, "", fmt.Errorf("provider %q has unsupported type %q", providerName, provider.Type)
	}
}

func proveBudget(repoRoot string) (budget.Budget, error) {
	userPath, err := settings.DefaultUserPath()
	if err != nil {
		return budget.Budget{}, err
	}
	user, err := settings.Load(userPath)
	if err != nil {
		return budget.Budget{}, err
	}
	repo, err := settings.Load(filepath.Join(repoRoot, "aegis.toml"))
	if err != nil {
		return budget.Budget{}, err
	}
	resolved := settings.ResolveBudget(repo, user)
	return budget.Budget{MaxEnv: resolved.MaxEnvFixesPerFinding, MaxHarness: resolved.MaxHarnessFixesPerFinding,
		MaxHypotheses: resolved.MaxHypothesesPerFinding, MaxSandboxMinutes: resolved.MaxSandboxMinutesPerFinding}, nil
}

func decodeJSON(data []byte, target any) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	if err := dec.Decode(target); err != nil {
		return err
	}
	return nil
}

func projectSchemasDir() (string, error) {
	cacheDir, err := aegisCacheDir()
	if err != nil {
		return "", err
	}
	schemasDir, _, err := aegisassets.Materialize(cacheDir)
	return schemasDir, err
}

func resolvePackDir(packDir, cacheRoot string) (string, error) {
	if packDir != "packs/python-web" {
		return packDir, nil
	}
	_, bundledPack, err := aegisassets.Materialize(cacheRoot)
	if err != nil {
		return "", err
	}
	return bundledPack, nil
}

func loadPackForCLI(packDir string) (*packs.Pack, error) {
	schemasDir, err := projectSchemasDir()
	if err != nil {
		return nil, err
	}
	return packs.LoadWithSchemas(packDir, schemasDir, false)
}

func snapshotCacheDir() (string, error) {
	return aegisCacheDir()
}

func aegisCacheDir() (string, error) {
	if configured := os.Getenv("AEGIS_CACHE_DIR"); configured != "" {
		if !filepath.IsAbs(configured) {
			return "", errors.New("AEGIS_CACHE_DIR must be an absolute path")
		}
		return filepath.Clean(configured), nil
	}
	root, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolving snapshot cache: %w", err)
	}
	return filepath.Join(root, "aegis"), nil
}

func snapshotTreeHash(events []journal.Event, snapshotID string) string {
	for _, event := range events {
		if event.Type == "snapshot_created" && event.Payload["snapshot_id"] == snapshotID {
			value, _ := event.Payload["tree_hash"].(string)
			return value
		}
	}
	return ""
}

func sinkContext(snapshotDir, rel string, line, radius int) (string, error) {
	clean := filepath.Clean(rel)
	if rel == "" || filepath.IsAbs(rel) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("finding sink path escapes the snapshot: %q", rel)
	}
	data, err := os.ReadFile(filepath.Join(snapshotDir, clean))
	if err != nil {
		return "", fmt.Errorf("reading sink context: %w", err)
	}
	lines := strings.Split(string(data), "\n")
	start, end := line-radius, line+radius
	if start < 1 {
		start = 1
	}
	if end > len(lines) {
		end = len(lines)
	}
	var b strings.Builder
	for i := start; i <= end; i++ {
		fmt.Fprintf(&b, "%d: %s\n", i, lines[i-1])
	}
	return b.String(), nil
}

func oracleForSink(pack *packs.Pack, sinkType string) string {
	family := ""
	for _, sink := range pack.Manifest.SinkTypes {
		if sink.Type == sinkType {
			family = sink.Family
			break
		}
	}
	for _, oracle := range pack.Manifest.Oracles {
		if oracle.Family == family && oracle.Touch != nil {
			return oracle.OracleID
		}
	}
	return ""
}

func mapValue(value any) map[string]any {
	result, _ := value.(map[string]any)
	return result
}

func stringValue(value any) string {
	result, _ := value.(string)
	return result
}

func intValue(value any) int {
	switch n := value.(type) {
	case json.Number:
		v, _ := n.Int64()
		return int(v)
	case float64:
		return int(n)
	case int:
		return n
	default:
		return 0
	}
}

func sliceLen(value any) int {
	if values, ok := value.([]any); ok {
		return len(values)
	}
	return 0
}

func setEvidenceID(finding reporting.Finding, id string) {
	if id != "" {
		finding["evidence_id"] = id
	}
}

func validDisposition(s string) bool {
	switch s {
	case "OPEN", "FALSE_POSITIVE", "ACCEPTED_RISK", "FIXED":
		return true
	default:
		return false
	}
}

func validateSchema(name string, value any) error {
	dir, err := projectSchemasDir()
	if err != nil {
		return err
	}
	r := schemav.New()
	if err := r.LoadDir(dir); err != nil {
		return err
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return r.Validate(name, b)
}

func findingID(candidateID string) string { return "F-" + strings.TrimPrefix(candidateID, "C-") }

// ensurePackCoversInventory prevents a successful-looking zero-result run when
// the selected proof pack cannot execute any source file in the target repo.
// allowed_files is part of the trusted pack ABI and therefore a stronger
// compatibility signal than a pack name convention such as "python-web".
func ensurePackCoversInventory(pack *packs.Pack, inv *inventory.Inventory, reviewerConfigured bool) error {
	coverage := packCoverage(pack, inv, reviewerConfigured)
	if reviewerConfigured {
		return nil
	}
	if len(coverage.DetectorIDs) == 0 {
		return errors.New("discovery coverage is zero: no LLM reviewer configured and the pack has no detector")
	}
	detectorLanguages := stringSliceMap(coverage.DetectorLanguages)
	for _, language := range coverage.TargetLanguages {
		if detectorLanguages[language] {
			return nil
		}
	}
	return fmt.Errorf("discovery coverage is zero: no LLM reviewer configured, Semgrep detector languages are %s, target languages are %s; refusing to produce a \"0 vulnerabilities\" report. Configure a reviewer or provide a matching detector",
		displayCLIList(coverage.DetectorLanguages), displayCLIList(coverage.TargetLanguages))
}

type coverageRecord struct {
	PackID                 string   `json:"pack_id"`
	PackVersion            string   `json:"pack_version"`
	VerifiableExtensions   []string `json:"verifiable_extensions"`
	ProofRuntimeExtensions []string `json:"proof_runtime_extensions"`
	TargetExtensions       []string `json:"target_extensions"`
	TargetLanguages        []string `json:"target_languages"`
	MatchedExtensions      []string `json:"matched_extensions"`
	UncoveredExtensions    []string `json:"uncovered_extensions,omitempty"`
	DetectorIDs            []string `json:"detector_ids"`
	DetectorLanguages      []string `json:"detector_languages"`
	ExecutedDetectorIDs    []string `json:"executed_detector_ids"`
	DetectorNotes          []string `json:"detector_notes,omitempty"`
	SinkTypes              []string `json:"sink_types"`
	ProofFamilies          []string `json:"proof_families"`
	LLMReviewerConfigured  bool     `json:"llm_reviewer_configured"`
	DiscoveryMode          string   `json:"discovery_mode"`
}

func packCoverage(pack *packs.Pack, inv *inventory.Inventory, reviewer bool) coverageRecord {
	allowed, target, targetLanguages := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, tmpl := range pack.Manifest.Templates {
		for _, ext := range tmpl.AllowedFiles {
			allowed[strings.ToLower(ext)] = true
		}
	}
	for _, file := range inv.Files {
		if file.Language == "other" || file.Language == "toml" || file.Language == "go-module" {
			continue
		}
		if ext := strings.ToLower(filepath.Ext(file.Path)); ext != "" {
			target[ext] = true
			targetLanguages[file.Language] = true
		}
	}
	matched, uncovered := map[string]bool{}, map[string]bool{}
	for ext := range target {
		if allowed[ext] {
			matched[ext] = true
		} else {
			uncovered[ext] = true
		}
	}
	record := coverageRecord{PackID: pack.Manifest.PackID, PackVersion: pack.Manifest.Version,
		VerifiableExtensions: stringsToSortedSlice(allowed), ProofRuntimeExtensions: stringsToSortedSlice(allowed), TargetExtensions: stringsToSortedSlice(target), TargetLanguages: stringsToSortedSlice(targetLanguages),
		MatchedExtensions: stringsToSortedSlice(matched), UncoveredExtensions: stringsToSortedSlice(uncovered),
		LLMReviewerConfigured: reviewer, DiscoveryMode: "detectors-only"}
	if reviewer {
		record.DiscoveryMode = "llm-global-review+detectors"
	}
	for _, detector := range pack.Manifest.Detectors {
		record.DetectorIDs = append(record.DetectorIDs, detector.ID)
		record.DetectorLanguages = append(record.DetectorLanguages, detector.Languages...)
	}
	for _, sink := range pack.Manifest.SinkTypes {
		record.SinkTypes = append(record.SinkTypes, sink.Type)
	}
	proofFamilies := map[string]bool{}
	for _, tmpl := range pack.Manifest.Templates {
		for _, oracle := range pack.Manifest.Oracles {
			if tmpl.Family == oracle.Family && oracle.Touch != nil {
				proofFamilies[tmpl.Family] = true
			}
		}
	}
	record.ProofFamilies = stringsToSortedSlice(proofFamilies)
	sort.Strings(record.DetectorIDs)
	record.DetectorLanguages = stringsToSortedSlice(stringSliceMap(record.DetectorLanguages))
	sort.Strings(record.SinkTypes)
	return record
}

func displayCLIList(values []string) string {
	if len(values) == 0 {
		return "(none)"
	}
	return strings.Join(values, ", ")
}

func stringSliceMap(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}

func stringsToSortedSlice(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func latestRunDir(root string) string {
	entries, err := os.ReadDir(filepath.Join(root, "out"))
	if err != nil {
		return ""
	}
	var latest string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "run-") && e.Name() > filepath.Base(latest) {
			latest = filepath.Join(root, "out", e.Name())
		}
	}
	return latest
}

func stageError(stage string, err error) error {
	return fmt.Errorf("✗ STAGE FAILED: %s\njournal: %s\nnext step: %s\ncause: %s", stage, "(not created yet, or shown by the workflow above)", "fix the cause and retry; success prints ✓ COMPLETE explicitly", err)
}
