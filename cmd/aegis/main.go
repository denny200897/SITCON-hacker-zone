// Command aegis is the single CLI entry point described by SPEC §8.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/aegis-dev/aegis/internal/candidates"
	"github.com/aegis-dev/aegis/internal/console"
	"github.com/aegis-dev/aegis/internal/credentials"
	"github.com/aegis-dev/aegis/internal/doctor"
	"github.com/aegis-dev/aegis/internal/evidence"
	"github.com/aegis-dev/aegis/internal/inventory"
	"github.com/aegis-dev/aegis/internal/journal"
	"github.com/aegis-dev/aegis/internal/orchestrator"
	"github.com/aegis-dev/aegis/internal/orchestrator/budget"
	"github.com/aegis-dev/aegis/internal/orchestrator/snapshot"
	"github.com/aegis-dev/aegis/internal/packs"
	"github.com/aegis-dev/aegis/internal/reporting"
	"github.com/aegis-dev/aegis/internal/sandbox"
	"github.com/aegis-dev/aegis/internal/schemav"
	"github.com/aegis-dev/aegis/internal/triage"
)

func main() {
	if err := newRoot().Execute(); err != nil {
		// Cobra already prints usage for syntax errors. Runtime failures use the
		// three-line contract in runStage instead of exposing a stack trace.
		os.Exit(1)
	}
}

func newRoot() *cobra.Command {
	root := &cobra.Command{Use: "aegis", Short: "Aegis 程式碼資安審查 Agent Harness", SilenceUsage: true}
	root.AddCommand(newConsole(), newStage("scan", "掃描目標 repo（Stage 0–2）"), newStage("prove", "對 finding 執行證明"), newStage("report", "產生審查報告"))
	return root
}

func newConsole() *cobra.Command {
	return &cobra.Command{
		Use: "console", Short: "進入互動模式",
		RunE: func(cmd *cobra.Command, _ []string) error {
			user, err := credentials.DefaultFilePath()
			if err != nil {
				return err
			}
			settingsPath := filepath.Join(filepath.Dir(user), "settings.toml")
			return console.Run(console.Deps{
				In: os.Stdin, Out: os.Stdout,
				UserConfigPath: settingsPath, CredentialsPath: user,
				Keyring:    credentials.NewOSKeyring(),
				ReadSecret: readSecret,
				Doctor:     func(ctx context.Context) []doctor.Check { return doctor.Run(ctx, doctor.Options{}) },
			})
		},
	}
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
	c.Flags().IntVar(&hypotheses, "hypotheses", 3, "假設上限")
	c.RunE = func(cmd *cobra.Command, args []string) error {
		if name == "scan" {
			root := target
			if targetSubdir != "" {
				root = filepath.Join(root, targetSubdir)
			}
			inv, err := inventory.Build(root)
			if err != nil {
				return stageError(name, err)
			}
			snap, err := snapshot.Create(root, filepath.Join(root, ".aegis", "cache"), inventory.DefaultExcludes)
			if err != nil {
				return stageError(name, err)
			}
			inv.SnapshotID = snap.ID
			pack, err := packs.Load(packDir, false)
			if err != nil {
				return stageError(name, err)
			}
			if runDir == "" {
				runDir = filepath.Join(root, "out", "run-"+time.Now().UTC().Format("20060102-150405"))
			}
			if err := os.MkdirAll(runDir, 0o755); err != nil {
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
			if err := os.WriteFile(filepath.Join(runDir, "inventory.json"), append(data, '\n'), 0o644); err != nil {
				return stageError(name, err)
			}
			if _, err := j.Append("stage_completed", "", map[string]any{"stage": "inventory", "artifact": "inventory.json"}); err != nil {
				return stageError(name, err)
			}
			var cs []candidates.Candidate
			if len(pack.Manifest.Detectors) > 0 {
				det := pack.Manifest.Detectors[0]
				if _, err := exec.LookPath("semgrep"); err != nil {
					return stageError(name, fmt.Errorf("找不到 semgrep：%w", err))
				}
				cs, err = candidates.Run(cmd.Context(), root, filepath.Join(packDir, det.Path), det.ID, "semgrep")
				if err != nil {
					return stageError(name, err)
				}
			}
			cb, err := json.MarshalIndent(cs, "", "  ")
			if err != nil {
				return stageError(name, err)
			}
			if err := os.WriteFile(filepath.Join(runDir, "candidates.json"), append(cb, '\n'), 0o644); err != nil {
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
				t := triage.Evaluate(c, inv)
				triages = append(triages, t)
				f := reporting.Finding{"id": fid, "sink": map[string]any{"file": c.Sink.File, "line": c.Sink.Line, "symbol": c.Sink.Symbol, "type": c.Sink.Type}, "sources": []any{map[string]any{"origin": "semgrep", "rule": c.Sources[0].Rule}}, "reachability": t.Reachability, "verification": "NOT_RUN", "disposition": "OPEN", "snapshot_id": snap.ID, "severity": "high", "confidence": 0.5, "rationale": t.Rationale}
				if t.Mode != "" {
					f["mode"] = t.Mode
				}
				if len(t.MissingLinks) > 0 {
					f["missing_links"] = []string{"entrypoint: inventory 未找到同檔案入口"}
				}
				findings = append(findings, f)
				if _, err := j.Append("candidate_created", fid, map[string]any{"candidate": c}); err != nil {
					return stageError(name, err)
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
			if err := os.WriteFile(filepath.Join(runDir, "triage.json"), append(tb, '\n'), 0o644); err != nil {
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
			if err := os.WriteFile(filepath.Join(runDir, "findings.json"), append(fb, '\n'), 0o644); err != nil {
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
				if _, err := reporting.WriteFindings(runDir, findings); err != nil {
					return stageError(name, err)
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
		if name == "prove" {
			if len(args) > 1 {
				return stageError(name, errors.New("最多指定一個 finding ID"))
			}
			if specPath == "" {
				return stageError(name, errors.New("缺少 --spec WitnessSpec JSON"))
			}
			data, err := os.ReadFile(specPath)
			if err != nil {
				return stageError(name, err)
			}
			var spec map[string]any
			if err := json.Unmarshal(data, &spec); err != nil {
				return stageError(name, err)
			}
			pack, err := packs.Load(packDir, false)
			if err != nil {
				return stageError(name, err)
			}
			snap, err := snapshot.Create(target, filepath.Join(target, ".aegis", "cache"), inventory.DefaultExcludes)
			if err != nil {
				return stageError(name, err)
			}
			if runDir == "" {
				runDir = filepath.Join(target, "out", "run-"+time.Now().UTC().Format("20060102-150405"))
			}
			if err := os.MkdirAll(runDir, 0o755); err != nil {
				return stageError(name, err)
			}
			j, err := journal.Open(filepath.Join(runDir, "journal.sqlite"))
			if err != nil {
				return stageError(name, err)
			}
			defer j.Close()
			store, err := evidence.NewStore(runDir)
			if err != nil {
				return stageError(name, err)
			}
			helper, ok := pack.Manifest.Images["helper/alpine"]
			if !ok {
				return stageError(name, errors.New("pack 缺 helper/alpine digest"))
			}
			findingID := "F-0001"
			if len(args) == 1 {
				findingID = args[0]
			}
			p := &orchestrator.Prover{Runner: &sandbox.Runner{HelperImage: helper}, Journal: j, Store: store, Pack: pack, PackDir: packDir,
				SnapshotID: snap.ID, SnapshotDir: snap.Dir, RunDir: runDir, RepoTreeHash: snap.TreeHash, Budget: budget.Default()}
			res, err := p.Prove(cmd.Context(), orchestrator.ProveInput{FindingID: findingID, Reachability: "D2", Spec: spec})
			if err != nil {
				return stageError(name, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "prove 完成：%s\n產物：%s\n", res.Verification, runDir)
			return nil
		}
		_ = args
		_ = watch
		_ = hypotheses
		return stageError(name, fmt.Errorf("%s pipeline 尚未接線（請先完成 scan 的 run 產物）", name))
	}
	return c
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
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return errors.New("無法定位 schemas")
	}
	r := schemav.New()
	if err := r.LoadDir(filepath.Join(filepath.Dir(file), "..", "..", "schemas")); err != nil {
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
