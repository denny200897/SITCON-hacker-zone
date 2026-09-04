// M0c prover 迴圈 E2E（SPEC §22 M0c 驗收）：假 adapter（腳本化工具呼叫與
// submit_witness_spec）驅動 AgentProver，決定性三控制 run 為真容器——
// 驗證「tool loop → 閘 (b) → 三控制 run → PROVEN」整鏈，以及閘拒收路徑
// （missing_nonce_placeholder）不耗預算、迴圈續跑後收斂。
// docker 不可用時 skip（與 M0b E2E 同前提）。
package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aegis-dev/aegis/internal/agent"
	"github.com/aegis-dev/aegis/internal/domain"
	"github.com/aegis-dev/aegis/internal/journal"
	"github.com/aegis-dev/aegis/internal/llm"
	"github.com/aegis-dev/aegis/internal/orchestrator"
	"github.com/aegis-dev/aegis/internal/orchestrator/budget"
	"github.com/aegis-dev/aegis/internal/schemav"
)

// setupProverE2E 以 setupE2E 的真容器管線組 AgentProver：
// ProveFunc = (*Prover).Prove（單次預算，ADR 0002）；預算計數器在迴圈級。
func setupProverE2E(t *testing.T) (*orchestrator.AgentProver, string, *journal.Journal) {
	t.Helper()
	prover, findingID := setupE2E(t)

	// schemas 真源載入（§23-11：不得 struct-tag 生成）。
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	schemasDir := filepath.Join(repoRoot, "schemas")
	toolsSchema, err := os.ReadFile(filepath.Join(schemasDir, "tools.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	specSchema, err := os.ReadFile(filepath.Join(schemasDir, "witness_spec.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	defs, err := agent.NewToolDefs(llm.RoleProver, toolsSchema, specSchema, map[string]string{
		"read_code":          "讀 snapshot 內檔案（唯讀）",
		"search_code":        "regex 搜 snapshot（RE2）",
		"semgrep":            "以 pack 登錄規則掃 snapshot",
		"submit_witness_spec": "提交 WitnessSpec（含 {{NONCE}} payload）",
	})
	if err != nil {
		t.Fatal(err)
	}

	// 閘 (b) 的 schema 驗證（schemav 綁 witness_spec.schema.json）。
	reg := schemav.New()
	if err := reg.LoadDir(schemasDir); err != nil {
		t.Fatal(err)
	}

	tools := &agent.ToolRegistry{SnapshotDir: prover.SnapshotDir}
	audit, err := agent.OpenAuditLog(prover.RunDir)
	if err != nil {
		t.Fatal(err)
	}
	tools.SetAudit(audit)
	t.Cleanup(func() { audit.Close() })

	ap := &orchestrator.AgentProver{
		Prove:   prover.Prove,
		Journal: prover.Journal,
		Adapter: nil, // 由測試注入
		Tools:   tools,
		ToolDefs:      defs,
		ValidateSpec: func(spec map[string]any) error {
			b, err := json.Marshal(spec)
			if err != nil {
				return err
			}
			return reg.Validate("witness_spec", b)
		},
		Model: "fake-prover",
		System: "Aegis prover（測試用假模型）",
		Finding: orchestrator.FindingContext{
			FindingID:    findingID,
			Reachability: "D0",
			TargetSymbol: "app.UserRepo.find_by_name",
			OracleID:     "sqli.error/v1",
			SnapshotID:   prover.SnapshotID,
			Context:      "def find_by_name(self, name):\n    return self.cur.execute(f'SELECT * FROM users WHERE name = \"{name}\"')",
		},
		Budget: budget.Budget{MaxEnv: 2, MaxHarness: 4, MaxHypotheses: 3, MaxSandboxMinutes: 10},
		RunDir: prover.RunDir,
	}
	return ap, findingID, prover.Journal
}

// auditFile 提供 audit log 檔案路徑（OpenAuditLog 已建檔；斷言用）。
func auditFile(t *testing.T, runDir string) string {
	t.Helper()
	return filepath.Join(runDir, "audit.jsonl")
}

// scriptAdapter（e2e 版）：平面腳本逐次回應。
type scriptAdapter struct {
	script []llm.Response
	i      int
}

func (s *scriptAdapter) Chat(_ context.Context, req llm.ChatRequest) (llm.Response, error) {
	if s.i >= len(s.script) {
		return llm.Response{}, errors.New("script exhausted")
	}
	r := s.script[s.i]
	s.i++
	return r, nil
}
func (s *scriptAdapter) Provider() string { return "script" }

// readCodeThenSubmit：假模型先以 read_code 看 sink 檔，再提交正確 spec，最後 end_turn。
func readCodeThenSubmit(t *testing.T, spec map[string]any) []llm.Response {
	t.Helper()
	specJSON, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	return []llm.Response{
		{StopReason: llm.StopToolUse, Content: []llm.ContentBlock{
			{Type: "text", Text: "先讀 sink 所在檔。"},
			{Type: "tool_use", ToolUse: &llm.ToolUse{ID: "r1", Name: "read_code",
				Input: json.RawMessage(`{"path":"app.py"}`)}},
		}},
		{StopReason: llm.StopToolUse, Content: []llm.ContentBlock{
			{Type: "text", Text: "提交假設。"},
			{Type: "tool_use", ToolUse: &llm.ToolUse{ID: "s1", Name: "submit_witness_spec",
				Input: specJSON}},
		}},
		{StopReason: llm.StopEndTurn, Content: []llm.ContentBlock{
			{Type: "text", Text: "已提交，等 harness 結果。"}},
		},
	}
}

// TestM0cProverLoopProvenE2E：tool loop → 閘 → 三控制 run → PROVEN（§22 M0c 主線）。
func TestM0cProverLoopProvenE2E(t *testing.T) {
	ap, findingID, _ := setupProverE2E(t)
	ad := &scriptAdapter{script: readCodeThenSubmit(t, sqliWitnessSpec(t))}
	ap.Adapter = ad

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	res, err := ap.Run(ctx)
	if err != nil {
		t.Fatalf("AgentProver.Run 失敗：%v", err)
	}
	if res.Verification != domain.VerificationProven {
		t.Fatalf("預期 PROVEN，得 %s（failure=%s attempts=%+v）",
			res.Verification, res.FailureClass, res.Attempts)
	}
	if len(res.Attempts) != 1 {
		t.Fatalf("應恰一次嘗試，得 %d", len(res.Attempts))
	}
	_ = findingID
}

// TestM0cProverLoopGateRejectionThenProvenE2E：缺 {{NONCE}} 的 spec 被閘拒收
//（witness_spec_rejected 落檔、不耗預算），迴圈續跑後正確 spec 達 PROVEN。
func TestM0cProverLoopGateRejectionThenProvenE2E(t *testing.T) {
	ap, _, j := setupProverE2E(t)
	bad := sqliWitnessSpec(t)
	bad["payload"] = "no placeholder here" // missing_nonce_placeholder

	ad := &scriptAdapter{script: append(
		[]llm.Response{
			{StopReason: llm.StopToolUse, Content: []llm.ContentBlock{
				{Type: "tool_use", ToolUse: &llm.ToolUse{ID: "bad", Name: "submit_witness_spec",
					Input: mustJSON(t, bad)}}},
			}},
		// 拒收的 tool_result 回填後，模型改交正確 spec（此時尚無 operator 回饋，不需 preamble）。
		readCodeThenSubmit(t, sqliWitnessSpec(t))...,
	)}
	ap.Adapter = ad

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	res, err := ap.Run(ctx)
	if err != nil {
		t.Fatalf("AgentProver.Run 失敗：%v", err)
	}
	if res.Verification != domain.VerificationProven {
		t.Fatalf("拒收後應收斂至 PROVEN，得 %s（attempts=%+v）", res.Verification, res.Attempts)
	}
	// journal 應有 missing_nonce_placeholder 的拒收事件，且只跑一次 Prove。
	rejected := false
	for _, e := range mustEvents(t, j) {
		if e.Type == "witness_spec_rejected" {
			if r, ok := e.Payload["reason"].(string); ok && strings.HasPrefix(r, "missing_nonce_placeholder") {
				rejected = true
			}
		}
	}
	if !rejected {
		t.Fatal("journal 缺 missing_nonce_placeholder 拒收事件")
	}
	if len(res.Attempts) != 1 || res.Attempts[0].Verification != string(domain.VerificationProven) {
		t.Fatalf("應恰一次有效 Prove（PROVEN）：%+v", res.Attempts)
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustEvents(t *testing.T, j *journal.Journal) []journal.Event {
	t.Helper()
	evs, err := j.Events()
	if err != nil {
		t.Fatal(err)
	}
	return evs
}