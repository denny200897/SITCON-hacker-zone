// Command aegis is the single CLI entry point described by SPEC §8.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	aegisassets "github.com/aegis-dev/aegis"
	"github.com/aegis-dev/aegis/internal/agent"
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
	root := &cobra.Command{Use: "aegis", Short: "Aegis 程式碼資安審查 Agent Harness", SilenceUsage: true,
		Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return runConsole(cmd.Context()) }}
	root.AddCommand(newConsole(), newStage("scan", "掃描目標 repo（Stage 0–2）"), newStage("prove", "對 finding 執行證明"), newStage("report", "產生審查報告"), newStage("replay", "離線重驗 evidence bundle"))
	return root
}

func newConsole() *cobra.Command {
	return &cobra.Command{
		Use: "console", Short: "進入互動模式",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runConsole(cmd.Context())
		},
	}
}

func runConsole(ctx context.Context) error {
	credentialPath, err := credentials.DefaultFilePath()
	if err != nil {
		return err
	}
	settingsPath := filepath.Join(filepath.Dir(credentialPath), "settings.toml")
	return console.Run(console.Deps{
		In: os.Stdin, Out: os.Stdout, UserConfigPath: settingsPath, CredentialsPath: credentialPath,
		Keyring: credentials.NewOSKeyring(), ReadSecret: readSecret,
		Doctor: func(checkCtx context.Context) []doctor.Check {
			options, optionErr := defaultDoctorOptions(".", "packs/python-web", settingsPath, credentialPath)
			if optionErr != nil {
				return []doctor.Check{{Name: "configuration", OK: false, Detail: optionErr.Error()}}
			}
			return doctor.Run(checkCtx, options)
		},
	})
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
	for name, provider := range user.Providers {
		providers[name] = provider
	}
	for name, provider := range repo.Providers {
		providers[name] = provider
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
	return doctor.Options{PackDirs: []string{absPack}, SchemasDir: schemasDir, CachePath: filepath.Join(cacheDir, "images.json"), Providers: providers,
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
		return nil, errors.New("stdin 不是終端機，無法隱藏輸入")
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
	var watch bool
	var hypotheses int
	c := &cobra.Command{Use: name, Short: short, Args: cobra.ArbitraryArgs}
	c.Flags().StringVar(&target, "target", ".", "repo root")
	c.Flags().StringVar(&targetSubdir, "target-subdir", "", "限制掃描子樹")
	c.Flags().StringVar(&runDir, "run-dir", "", "指定既有 run 目錄（report）")
	c.Flags().StringVar(&specPath, "spec", "", "WitnessSpec JSON（prove）")
	c.Flags().StringVar(&packDir, "pack", "packs/python-web", "pack 目錄（prove）")
	c.Flags().StringArrayVar(&dispositions, "set-disposition", nil, "設定 finding disposition（F-####=OPEN|FALSE_POSITIVE|ACCEPTED_RISK|FIXED）")
	c.Flags().BoolVar(&watch, "watch", false, "逐行顯示進度")
	c.Flags().IntVar(&hypotheses, "hypotheses", 0, "覆寫假設上限（預設讀 [budget]，未設定為 3）")
	c.RunE = func(cmd *cobra.Command, args []string) error {
		if name == "scan" {
			root := target
			if targetSubdir != "" {
				root = filepath.Join(root, targetSubdir)
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
			inv, err := inventory.Build(snap.Dir)
			if err != nil {
				return stageError(name, err)
			}
			inv.SnapshotID = snap.ID
			packDir, err = resolvePackDir(packDir, cacheDir)
			if err != nil {
				return stageError(name, err)
			}
			pack, err := loadPackForCLI(packDir)
			if err != nil {
				return stageError(name, err)
			}
			if runDir == "" {
				outDir := filepath.Join(root, "out")
				if err := os.MkdirAll(outDir, 0o755); err != nil {
					return stageError(name, err)
				}
				runDir = filepath.Join(outDir, "run-"+time.Now().UTC().Format("20060102-150405.000000000"))
				if err := os.Mkdir(runDir, 0o755); err != nil {
					return stageError(name, fmt.Errorf("建立唯一 run 目錄：%w", err))
				}
			} else if err := os.MkdirAll(runDir, 0o755); err != nil {
				return stageError(name, err)
			}
			j, err := journal.Open(filepath.Join(runDir, "journal.sqlite"))
			if err != nil {
				return stageError(name, err)
			}
			defer j.Close()
			if _, err := j.Append("run_started", "", map[string]any{"stage": "scan"}); err != nil {
				return stageError(name, err)
			}
			if _, err := j.Append("snapshot_created", "", map[string]any{"snapshot_id": snap.ID, "tree_hash": snap.TreeHash}); err != nil {
				return stageError(name, err)
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
				if _, err := exec.LookPath("semgrep"); err != nil {
					return stageError(name, fmt.Errorf("找不到 semgrep：%w", err))
				}
				for _, det := range pack.Manifest.Detectors {
					group, runErr := candidates.Run(cmd.Context(), snap.Dir, filepath.Join(packDir, det.Path), det.ID, "semgrep")
					if runErr != nil {
						return stageError(name, runErr)
					}
					detectorResults = append(detectorResults, group)
				}
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
				triages = append(triages, t)
				sources := make([]any, 0, len(c.Sources))
				for _, source := range c.Sources {
					sources = append(sources, map[string]any{"origin": source.Origin, "rule": source.Rule})
				}
				impact, ok := pack.Impact(c.Sink.Type)
				if !ok {
					return stageError(name, fmt.Errorf("pack %s 未定義 sink type %q 的 impact；拒絕由 core 猜測", pack.Manifest.PackID, c.Sink.Type))
				}
				f := reporting.Finding{"id": fid, "sink": map[string]any{"file": c.Sink.File, "line": c.Sink.Line, "symbol": c.Sink.Symbol, "type": c.Sink.Type}, "sources": sources, "reachability": t.Reachability, "verification": "NOT_RUN", "disposition": "OPEN", "snapshot_id": snap.ID, "severity": triage.Severity(impact, t.Reachability), "confidence": triage.Confidence("NOT_RUN", t.Mode, 0, 0), "rationale": t.Rationale}
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
			fmt.Fprintf(cmd.OutOrStdout(), "scan 完成：%d 個檔案、%d 個入口、%d 個 candidate\n產物：%s\n", len(inv.Files), len(inv.Entrypoints), len(cs), runDir)
			return nil
		}
		if name == "report" {
			if runDir == "" {
				runDir = latestRunDir(target)
			}
			if runDir == "" {
				return stageError(name, errors.New("找不到可報告的 run 目錄，請先執行 aegis scan"))
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
						return stageError(name, fmt.Errorf("無效 disposition %q", item))
					}
					found := false
					for _, f := range findings {
						if f["id"] == parts[0] {
							f["disposition"] = parts[1]
							found = true
						}
					}
					if !found {
						return stageError(name, fmt.Errorf("找不到 finding %s", parts[0]))
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
			if _, err := j.Append("report_written", "", map[string]any{"artifacts": []string{"findings.json", "findings.sarif", "report.md"}}); err != nil {
				return stageError(name, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "report 完成：%s\n", path)
			return nil
		}
		if name == "replay" {
			if runDir == "" {
				runDir = latestRunDir(target)
			}
			if runDir == "" {
				return stageError(name, errors.New("找不到 run 目錄"))
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
			fmt.Fprintf(cmd.OutOrStdout(), "replay 驗證通過：%s\n", runDir)
			return nil
		}
		if name == "prove" {
			return runProveCommand(cmd, args, proveOptions{target: target, targetSubdir: targetSubdir,
				runDir: runDir, specPath: specPath, packDir: packDir, watch: watch, hypotheses: hypotheses})
		}
		_ = args
		_ = watch
		_ = hypotheses
		return stageError(name, fmt.Errorf("%s pipeline 尚未接線（請先完成 scan 的 run 產物）", name))
	}
	return c
}

type proveOptions struct {
	target, targetSubdir, runDir, specPath, packDir string
	watch                                           bool
	hypotheses                                      int
}

func runProveCommand(cmd *cobra.Command, args []string, opts proveOptions) error {
	if len(args) > 1 {
		return stageError("prove", errors.New("finding ID 最多一個；省略時依序證明此 run 的全部 findings"))
	}
	if opts.specPath != "" && len(args) != 1 {
		return stageError("prove", errors.New("離線 --spec 模式必須指定恰好一個 finding ID"))
	}
	if opts.hypotheses < 0 {
		return stageError("prove", errors.New("--hypotheses 必須至少為 1"))
	}
	scanRoot := opts.target
	if opts.targetSubdir != "" {
		scanRoot = filepath.Join(scanRoot, opts.targetSubdir)
	}
	if opts.runDir == "" {
		opts.runDir = latestRunDir(scanRoot)
	}
	if opts.runDir == "" {
		return stageError("prove", errors.New("找不到 scan run；請先執行 aegis scan"))
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
	selected := make([]reporting.Finding, 0, len(findings))
	for _, finding := range findings {
		if len(args) == 0 || finding["id"] == args[0] {
			selected = append(selected, finding)
		}
	}
	if len(selected) == 0 {
		if len(args) == 0 {
			return stageError("prove", errors.New("此 run 沒有可證明的 finding"))
		}
		return stageError("prove", fmt.Errorf("finding %s 不存在於此 run", args[0]))
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
		return stageError("prove", errors.New("pack 缺 helper/alpine digest"))
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
			"read_code": "讀取 snapshot 內指定檔案與行範圍（唯讀）", "search_code": "以 RE2 搜尋 snapshot（唯讀）",
			"semgrep": "以 pack 登錄的規則掃描 snapshot（唯讀）", "submit_witness_spec": "提交受 schema 約束的 WitnessSpec",
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
			return stageError("prove", fmt.Errorf("scan snapshot %s 不存在；拒絕改用 live worktree", snapshotID))
		}
		repoTreeHash := snapshotTreeHash(events, snapshotID)
		if repoTreeHash == "" {
			return stageError("prove", fmt.Errorf("journal 缺少 snapshot %s 的 tree hash", snapshotID))
		}
		if err := snapshot.Verify(snapshotDir, snapshotID, repoTreeHash); err != nil {
			return stageError("prove", err)
		}
		b := configuredBudget
		p := &orchestrator.Prover{Runner: &sandbox.Runner{HelperImage: helper}, Journal: j, Store: store, Pack: pack, PackDir: opts.packDir, SchemasDir: proverSchemasDir,
			SnapshotID: snapshotID, SnapshotDir: snapshotDir, RunDir: opts.runDir, RepoTreeHash: repoTreeHash, CachePath: imageCachePath, Budget: b}

		if opts.watch {
			fmt.Fprintf(cmd.OutOrStdout(), "prove 開始：%s（最多 %d 個假設）\n", findingID, b.MaxHypotheses)
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
				Budget: b, RunDir: opts.runDir}
			res, proveErr := ap.Run(cmd.Context())
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
				fmt.Fprintf(cmd.OutOrStdout(), "prove 嘗試：%s 共 %d 次\n", findingID, len(res.Attempts))
			}
		}
		mode, _ := finding["mode"].(string)
		finding["confidence"] = triage.Confidence(stringValue(finding["verification"]), mode, sliceLen(finding["assumptions"]), 1)
		fmt.Fprintf(cmd.OutOrStdout(), "prove 完成：%s = %s\n", findingID, finding["verification"])
	}
	if _, err := reporting.WriteFindings(opts.runDir, findings); err != nil {
		return stageError("prove", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "產物：%s\n", opts.runDir)
	return nil
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
		return nil, "", fmt.Errorf("prover 模型尚未設定；請依序執行 /provider add → /key set → /model set：%w", err)
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
		return nil, "", fmt.Errorf("prover provider %q 未設定；請執行 /provider add", providerName)
	}
	manager := &credentials.Manager{Keyring: credentials.NewOSKeyring(), File: &credentials.FileStore{Path: credentialPath}}
	key, _, err := manager.Resolve(providerName, credentials.ProviderType(provider.Type))
	if err != nil {
		return nil, "", fmt.Errorf("prover provider %q 缺少金鑰；請執行 /key set：%w", providerName, err)
	}
	switch credentials.ProviderType(provider.Type) {
	case credentials.ProviderTypeAnthropic:
		return llm.NewAnthropic(key, provider.BaseURL), model, nil
	case credentials.ProviderTypeOpenAICompat:
		if provider.BaseURL == "" {
			return nil, "", fmt.Errorf("openai-compat provider %q 缺 base_url", providerName)
		}
		return llm.NewOpenAICompat(providerName, provider.BaseURL, key, model), model, nil
	default:
		return nil, "", fmt.Errorf("provider %q 的 type %q 不受支援", providerName, provider.Type)
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
			return "", errors.New("AEGIS_CACHE_DIR 必須是絕對路徑")
		}
		return filepath.Clean(configured), nil
	}
	root, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("解析 snapshot cache：%w", err)
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
		return "", fmt.Errorf("finding sink path 越出 snapshot：%q", rel)
	}
	data, err := os.ReadFile(filepath.Join(snapshotDir, clean))
	if err != nil {
		return "", fmt.Errorf("讀取 sink context：%w", err)
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
	return fmt.Errorf("已完成的 stage：%s\njournal 位置：%s\n下一步建議：%s\n原因：%s", stage, "（本次尚未建立）", "檢查設定後重試", err)
}
