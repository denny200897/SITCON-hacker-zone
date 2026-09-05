package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aegis-dev/aegis/internal/agent"
	"github.com/aegis-dev/aegis/internal/domain"
	"github.com/aegis-dev/aegis/internal/journal"
	"github.com/aegis-dev/aegis/internal/llm"
	"github.com/aegis-dev/aegis/internal/orchestrator/budget"
	"github.com/aegis-dev/aegis/internal/orchestrator/policy"
)

// ---- 測試替身 ----

// scriptAdapter 依腳本逐次回應（平面腳本：Runtime 內部 tool loop 與迴圈級
// session 重建都依序消費——submit 核可後模型回 end_turn，迴圈級 operator 回饋
// 後的下一個 Chat 接續腳本，順序與腳本排列一致）。
type scriptAdapter struct {
	script []llm.Response
	i      int
	reqs   []llm.ChatRequest
}

type cancelAdapter struct{}

func (cancelAdapter) Chat(context.Context, llm.ChatRequest) (llm.Response, error) {
	return llm.Response{}, context.Canceled
}
func (cancelAdapter) Provider() string { return "cancel" }

func (s *scriptAdapter) Chat(_ context.Context, req llm.ChatRequest) (llm.Response, error) {
	s.reqs = append(s.reqs, req)
	if s.i >= len(s.script) {
		return llm.Response{}, errors.New("script exhausted")
	}
	r := s.script[s.i]
	s.i++
	return r, nil
}
func (s *scriptAdapter) Provider() string { return "script" }

func textBlk(s string) llm.ContentBlock { return llm.ContentBlock{Type: "text", Text: s} }

func submitResp(id, payload string, preamble string) llm.Response {
	in := map[string]any{"payload": payload, "template_id": "py/http-endpoint/v3", "oracle_id": "sqli.error/v1"}
	if payload == "" {
		delete(in, "payload")
	}
	b, _ := json.Marshal(in)
	return llm.Response{StopReason: llm.StopToolUse, Content: []llm.ContentBlock{
		textBlk(preamble),
		{Type: "tool_use", ToolUse: &llm.ToolUse{ID: id, Name: "submit_witness_spec", Input: b}},
	}}
}

func endResp(text string) llm.Response {
	return llm.Response{StopReason: llm.StopEndTurn, Content: []llm.ContentBlock{textBlk(text)}}
}

// fakeProve 依序回傳腳本結果；錯誤以 error 形式排入。
type fakeProve struct {
	results []*ProveResult
	errs    []error
	i       int
	specs   []map[string]any
}

func (f *fakeProve) Prove(_ context.Context, in ProveInput) (*ProveResult, error) {
	f.specs = append(f.specs, in.Spec)
	if f.i < len(f.errs) && f.errs[f.i] != nil {
		e := f.errs[f.i]
		f.i++
		return nil, e
	}
	if f.i >= len(f.results) {
		return nil, errors.New("prove script exhausted")
	}
	r := f.results[f.i]
	f.i++
	return r, nil
}

func missResult() *ProveResult {
	return &ProveResult{Verification: domain.VerificationHypothesisRej,
		FailureClass: domain.FailureControlledMiss, OracleID: "sqli.error/v1"}
}

func harnessResult(exit int) *ProveResult {
	return &ProveResult{Verification: domain.VerificationNotProven,
		NotProvenReason: domain.NotProvenHarnessBudget, FailureClass: domain.FailureHarness,
		Runs: []RunRecord{{RunID: "R-x", Kind: "positive", Exit: exit}}}
}

// newAgentProver 組裝迴圈（journal 落暫存目錄）。
func newAgentProver(t *testing.T, ad llm.Adapter, prove ProveFunc, b budget.Budget) (*AgentProver, *journal.Journal) {
	t.Helper()
	dir := t.TempDir()
	j, err := journal.Open(filepath.Join(dir, "journal.db"))
	if err != nil {
		t.Fatal(err)
	}
	tools := &agent.ToolRegistry{SnapshotDir: t.TempDir()}
	audit, err := agent.OpenAuditLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	tools.SetAudit(audit)
	ap := &AgentProver{
		Prove: prove, Journal: j, Adapter: ad, Tools: tools,
		Model: "test-model", System: "sys",
		Finding: FindingContext{FindingID: "F-0001", Reachability: "D1",
			TargetSymbol: "query_user", OracleID: "sqli.error/v1", SnapshotID: "S-0001",
			Context: "def query_user(u):\n    return db.execute('SELECT * FROM u WHERE n=' + u)"},
		Budget: b, RunDir: dir,
		ValidateSpec: func(map[string]any) error { return nil },
	}
	t.Cleanup(func() { _ = j.Close(); _ = audit.Close() })
	return ap, j
}

// journalEvents 讀全部事件。
func journalEvents(t *testing.T, j *journal.Journal) []journal.Event {
	t.Helper()
	evs, err := j.Events()
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

// ---- §22 M0c：失敗分類計數器 ----

// TestAgentProverEnvExhausted：env 用盡 → ENV_ERROR（附嘗試日誌）。
func TestAgentProverEnvExhausted(t *testing.T) {
	ad := &scriptAdapter{script: []llm.Response{
		submitResp("s1", "{{NONCE}}'", ""),
		submitResp("s2", "{{NONCE}}'", "學到：環境失敗\n改：環境已修正，spec 不變\n預期：可重新執行"),
	}}
	prove := &fakeProve{errs: []error{errors.New("docker unavailable"), errors.New("docker unavailable")}}
	ap, j := newAgentProver(t, ad, prove.Prove, budget.Budget{MaxEnv: 2, MaxHarness: 4, MaxHypotheses: 3})

	res, err := ap.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verification != domain.VerificationEnvError {
		t.Fatalf("env 用盡應 ENV_ERROR，得 %s", res.Verification)
	}
	if len(res.Attempts) != 2 {
		t.Fatalf("應有 2 次嘗試日誌，得 %d", len(res.Attempts))
	}
	// 環境失敗後允許原樣重跑同一 spec，不被 duplicate_spec 擋住。
	if prove.i != 2 {
		t.Fatalf("應執行 2 次 Prove，得 %d", prove.i)
	}
	// journal 有 verification_updated。
	found := false
	for _, e := range journalEvents(t, j) {
		if e.Type == "verification_updated" && e.Payload["verification"] == string(domain.VerificationEnvError) {
			found = true
		}
	}
	if !found {
		t.Fatal("journal 缺 verification_updated(ENV_ERROR)")
	}
}

// TestAgentProverHypothesesExhausted：3 假設全數否證 → fresh-eyes 一輪後
// HYPOTHESIS_REJECTED（scope 與 rationale 落檔，§9.3）。
func TestAgentProverHypothesesExhausted(t *testing.T) {
	// round1-3：各提交不同 payload（需 preamble，因為有 feedback）；
	// fresh round：新 session 不需 preamble，提交第 4 個假設。
	pre := "學到：x\n改：y\n預期：z"
	ad := &scriptAdapter{script: []llm.Response{
		submitResp("s1", "{{NONCE}}'", ""),
		submitResp("s2", "{{NONCE}}'-or-1", pre),
		submitResp("s3", "{{NONCE}}\"-or-2", pre),
		submitResp("s4", "{{NONCE}}`-or-3", ""),
	}}
	prove := &fakeProve{results: []*ProveResult{missResult(), missResult(), missResult(), missResult()}}
	ap, j := newAgentProver(t, ad, prove.Prove, budget.Budget{MaxEnv: 2, MaxHarness: 4, MaxHypotheses: 3})

	res, err := ap.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verification != domain.VerificationHypothesisRej {
		t.Fatalf("3 假設全否證應 HYPOTHESIS_REJECTED，得 %s", res.Verification)
	}
	if prove.i != 4 {
		t.Fatalf("fresh-eyes 輪應執行第 4 次 Prove，得 %d", prove.i)
	}
	if res.Scope == nil || res.Scope["target_symbol"] != "query_user" || res.Scope["finding_id"] != "F-0001" {
		t.Fatalf("scope 應含 target_symbol／finding_id：%#v", res.Scope)
	}
	if len(res.Rationale) == 0 {
		t.Fatal("rationale 不應為空（§9.3 逐條否證）")
	}
	hasAttempt := false
	for _, r := range res.Rationale {
		if strings.Contains(r, "attempt 1") {
			hasAttempt = true
		}
	}
	if !hasAttempt {
		t.Fatalf("rationale 應含各 attempt 對照 run：%#v", res.Rationale)
	}
	// journal 落 scope/rationale。
	var scopeDoc map[string]any
	for _, e := range journalEvents(t, j) {
		if e.Type == "verification_updated" {
			scopeDoc = e.Payload
		}
	}
	if scopeDoc == nil || scopeDoc["scope"] == nil || scopeDoc["rationale"] == nil {
		t.Fatalf("verification_updated 應落 scope/rationale：%#v", scopeDoc)
	}
}

// TestAgentProverHarnessBudget：harness 用盡 → NOT_PROVEN(harness_budget)。
func TestAgentProverHarnessBudget(t *testing.T) {
	pre := "學到：x\n改：y\n預期：z"
	ad := &scriptAdapter{script: []llm.Response{
		submitResp("s1", "{{NONCE}}'", ""),
		submitResp("s2", "{{NONCE}}'-a", pre),
	}}
	prove := &fakeProve{results: []*ProveResult{
		{Verification: domain.VerificationNotProven, NotProvenReason: domain.NotProvenHarnessBudget,
			FailureClass: domain.FailureHarness, Runs: []RunRecord{{RunID: "R-p", Kind: "positive", Exit: 2}}},
		{Verification: domain.VerificationNotProven, NotProvenReason: domain.NotProvenHarnessBudget,
			FailureClass: domain.FailureHarness, Runs: []RunRecord{{RunID: "R-p2", Kind: "positive", Exit: 3}}},
	}}
	ap, _ := newAgentProver(t, ad, prove.Prove, budget.Budget{MaxEnv: 2, MaxHarness: 2, MaxHypotheses: 3})

	res, err := ap.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verification != domain.VerificationNotProven || res.NotProvenReason != domain.NotProvenHarnessBudget {
		t.Fatalf("harness 用盡應 NOT_PROVEN(harness_budget)，得 %s/%s", res.Verification, res.NotProvenReason)
	}
	if len(res.Attempts) != 2 {
		t.Fatalf("應含完整嘗試日誌，得 %d", len(res.Attempts))
	}
}

// TestAgentProverOscillation：連續 2 次 harness 失敗簽名相同 → NOT_PROVEN(oscillation)。
func TestAgentProverOscillation(t *testing.T) {
	pre := "學到：x\n改：y\n預期：z"
	ad := &scriptAdapter{script: []llm.Response{
		submitResp("s1", "{{NONCE}}'", ""),
		submitResp("s2", "{{NONCE}}'-a", pre),
	}}
	// 兩次 harness 失敗、artifacts run.log 內容相同（nonce 不同但會被紅線）→ 同簽名。
	prove := &fakeProve{results: []*ProveResult{
		{Verification: domain.VerificationNotProven, FailureClass: domain.FailureHarness,
			Runs: []RunRecord{{RunID: "R-o1", Kind: "positive", Exit: 2, Nonce: "nonce-aaa"}}},
		{Verification: domain.VerificationNotProven, FailureClass: domain.FailureHarness,
			Runs: []RunRecord{{RunID: "R-o2", Kind: "positive", Exit: 2, Nonce: "nonce-bbb"}}},
	}}
	ap, _ := newAgentProver(t, ad, prove.Prove, budget.Budget{MaxEnv: 2, MaxHarness: 5, MaxHypotheses: 3})
	runDir := ap.RunDir
	// 寫 artifacts：兩次 run.log 內容「除 nonce 外」相同。
	for _, r := range []struct{ id, nonce string }{{"R-o1", "nonce-aaa"}, {"R-o2", "nonce-bbb"}} {
		dir := filepath.Join(runDir, "evidence", "runs", r.id)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		content := fmt.Sprintf("service failed\ncmd: psql --nonce %s\n", r.nonce)
		if err := os.WriteFile(filepath.Join(dir, "run.log"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	res, err := ap.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verification != domain.VerificationNotProven || res.NotProvenReason != domain.NotProvenOscillation {
		t.Fatalf("同簽名振盪應 NOT_PROVEN(oscillation)，得 %s/%s", res.Verification, res.NotProvenReason)
	}
}

// TestAgentProverOscillationDifferentSig：簽名不同（exit code 不同）→ 不算振盪。
func TestAgentProverOscillationDifferentSig(t *testing.T) {
	pre := "學到：x\n改：y\n預期：z"
	ad := &scriptAdapter{script: []llm.Response{
		submitResp("s1", "{{NONCE}}'", ""),
		submitResp("s2", "{{NONCE}}'-a", pre),
		submitResp("s3", "{{NONCE}}'-b", pre),
	}}
	prove := &fakeProve{results: []*ProveResult{
		{Verification: domain.VerificationNotProven, FailureClass: domain.FailureHarness,
			Runs: []RunRecord{{RunID: "R-1", Kind: "positive", Exit: 2}}},
		{Verification: domain.VerificationNotProven, FailureClass: domain.FailureHarness,
			Runs: []RunRecord{{RunID: "R-2", Kind: "positive", Exit: 3}}},
		{Verification: domain.VerificationNotProven, FailureClass: domain.FailureHarness,
			Runs: []RunRecord{{RunID: "R-3", Kind: "positive", Exit: 2}}},
	}}
	ap, _ := newAgentProver(t, ad, prove.Prove, budget.Budget{MaxEnv: 2, MaxHarness: 3, MaxHypotheses: 3})
	res, err := ap.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.NotProvenReason != domain.NotProvenHarnessBudget {
		t.Fatalf("簽名互異時不應記振盪，得 %s/%s", res.Verification, res.NotProvenReason)
	}
}

// ---- §22 M0c：拒絕路徑 ----

// TestAgentProverGateRejections：duplicate_spec／missing_preamble／missing_nonce。
func TestAgentProverGateRejections(t *testing.T) {
	pre := "學到：x\n改：y\n預期：z"
	// round1: 提交（成功）→ miss；round2: 同 hash 重送（拒）→ 改帶 preamble 重送不同 payload → miss；round3: 缺 preamble → 拒 → 正確重送 → miss
	ad := &scriptAdapter{script: []llm.Response{
		submitResp("s1", "{{NONCE}}'", ""),
		// 同 hash 重送 → duplicate_spec；再正確提交
		submitResp("s2", "{{NONCE}}'", ""), submitResp("s3", "{{NONCE}}'-a", pre),
		// 缺 {{NONCE}} → missing_nonce_placeholder；缺 preamble → missing_preamble；再正確提交
		submitResp("s4", "no-placeholder", pre), submitResp("s5", "{{NONCE}}'-b", ""), submitResp("s6", "{{NONCE}}'-c", pre),
		endResp("無後續假設"), // 第一次明示觸發獨立確認
		endResp("無後續假設"), // 唯一一行再次確認後才收斂
	}}
	prove := &fakeProve{results: []*ProveResult{missResult(), missResult(), missResult()}}
	ap, j := newAgentProver(t, ad, prove.Prove, budget.Budget{MaxEnv: 2, MaxHarness: 4, MaxHypotheses: 9})

	res, err := ap.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if prove.i != 3 {
		t.Fatalf("三次有效提交應各跑一次 Prove，得 %d", prove.i)
	}
	if res.Verification != domain.VerificationHypothesisRej {
		t.Fatalf("明示無後續假設應 HYPOTHESIS_REJECTED，得 %s", res.Verification)
	}
	// journal 應有三次 witness_spec_rejected：duplicate_spec、missing_nonce_placeholder、missing_preamble。
	reasons := map[string]bool{}
	for _, e := range journalEvents(t, j) {
		if e.Type == "witness_spec_rejected" {
			if r, ok := e.Payload["reason"].(string); ok {
				reasons[classifyRejection(r)] = true
			}
		}
	}
	for _, want := range []string{"duplicate_spec", "missing_nonce_placeholder", "missing_preamble"} {
		if !reasons[want] {
			t.Fatalf("journal 缺 %s 拒收事件：%#v", want, reasons)
		}
	}
}

// classifyRejection 從 feedback 文字抽 reason 前綴。
func classifyRejection(fb string) string {
	for _, p := range []string{"duplicate_spec", "missing_nonce_placeholder", "missing_preamble", "invalid_spec"} {
		if strings.HasPrefix(fb, p) {
			return p
		}
	}
	return "other"
}

// TestAgentProverProven：第一輪 PROVEN → 終態。
func TestAgentProverProven(t *testing.T) {
	ad := &scriptAdapter{script: []llm.Response{
		submitResp("s1", "{{NONCE}}'", ""),
	}}
	prove := &fakeProve{results: []*ProveResult{{Verification: domain.VerificationProven, OracleID: "sqli.error/v1"}}}
	ap, _ := newAgentProver(t, ad, prove.Prove, budget.Default())

	res, err := ap.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verification != domain.VerificationProven {
		t.Fatalf("應 PROVEN，得 %s", res.Verification)
	}
	if prove.i != 1 {
		t.Fatalf("應只跑一次 Prove，得 %d", prove.i)
	}
}

// TestAgentProverNoSpecSession：必須先有 controlled miss，且以獨立回合精確
// 確認「無後續假設」，才能進 HYPOTHESIS_REJECTED。
func TestAgentProverNoSpecAndMarker(t *testing.T) {
	ad := &scriptAdapter{script: []llm.Response{
		submitResp("s1", "{{NONCE}}'", ""),
		endResp("無後續假設"),
		endResp("無後續假設"),
	}}
	prove := &fakeProve{results: []*ProveResult{missResult()}}
	ap, _ := newAgentProver(t, ad, prove.Prove, budget.Budget{MaxEnv: 2, MaxHarness: 4, MaxHypotheses: 3})

	res, err := ap.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verification != domain.VerificationHypothesisRej {
		t.Fatalf("明示無後續假設應 HYPOTHESIS_REJECTED，得 %s", res.Verification)
	}
	if prove.i != 1 {
		t.Fatalf("應先完成一次 controlled miss，得 %d", prove.i)
	}
}

func TestAgentProverNoMoreMarkerDoesNotMatchQuotedOrNegatedText(t *testing.T) {
	pre := "學到：x\n改：y\n預期：z"
	ad := &scriptAdapter{script: []llm.Response{
		submitResp("s1", "{{NONCE}}'", ""),
		endResp("不代表無後續假設，我會繼續"),
		submitResp("s2", "{{NONCE}}'-next", pre),
	}}
	prove := &fakeProve{results: []*ProveResult{missResult(), {Verification: domain.VerificationProven}}}
	ap, _ := newAgentProver(t, ad, prove.Prove, budget.Budget{MaxEnv: 2, MaxHarness: 4, MaxHypotheses: 3})
	res, err := ap.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verification != domain.VerificationProven {
		t.Fatalf("否定句不得提前終止，得 %s", res.Verification)
	}
}

func TestAgentProverPolicyRejectionDoesNotConsumeEnvBudget(t *testing.T) {
	pre := "學到：target symbol 不存在\n改：改用真實 symbol\n預期：policy 接受"
	ad := &scriptAdapter{script: []llm.Response{
		submitResp("bad", "{{NONCE}}'", ""),
		submitResp("good", "{{NONCE}}'-fixed", pre),
	}}
	prove := &fakeProve{
		errs:    []error{fmt.Errorf("compile: %w", &policy.SpecError{Reason: policy.ReasonTargetSymbolMissing}), nil},
		results: []*ProveResult{nil, {Verification: domain.VerificationProven}},
	}
	ap, j := newAgentProver(t, ad, prove.Prove, budget.Budget{MaxEnv: 1, MaxHarness: 2, MaxHypotheses: 2})
	res, err := ap.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verification != domain.VerificationProven {
		t.Fatalf("policy 拒收不應耗盡 env budget，得 %s", res.Verification)
	}
	found := false
	for _, event := range journalEvents(t, j) {
		if event.Type == "witness_spec_rejected" && event.Payload["reason"] == policy.ReasonTargetSymbolMissing {
			found = true
		}
	}
	if !found {
		t.Fatal("缺 witness_spec_rejected(target_symbol_missing)")
	}
}

func TestAgentProverUserCancellationIsNotEnvironmentFailure(t *testing.T) {
	prove := &fakeProve{}
	ap, _ := newAgentProver(t, cancelAdapter{}, prove.Prove, budget.Default())
	res, err := ap.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verification != domain.VerificationNotProven || res.NotProvenReason != domain.NotProvenUserCancelled {
		t.Fatalf("cancel terminal = %s/%s", res.Verification, res.NotProvenReason)
	}
}

// TestAgentProverFreshEyesNoSpec：fresh-eyes 輪未提交 → 仍進 HYPOTHESIS_REJECTED。
func TestAgentProverFreshEyesNoSpec(t *testing.T) {
	ad := &scriptAdapter{script: []llm.Response{
		submitResp("s1", "{{NONCE}}'", ""),
		endResp("我放棄了"), // fresh 輪未提交
	}}
	prove := &fakeProve{results: []*ProveResult{missResult()}}
	ap, _ := newAgentProver(t, ad, prove.Prove, budget.Budget{MaxEnv: 2, MaxHarness: 4, MaxHypotheses: 1})

	res, err := ap.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verification != domain.VerificationHypothesisRej {
		t.Fatalf("fresh 輪未提交應進 HYPOTHESIS_REJECTED，得 %s", res.Verification)
	}
	// fresh 輪失敗不扣計數（不會再迴圈）。
	if prove.i != 1 {
		t.Fatalf("應只跑 1 次 Prove，得 %d", prove.i)
	}
}

// TestAgentProverFreshEyesProven：fresh-eyes 輪 PROVEN → 終態 PROVEN（§9.3）。
func TestAgentProverFreshEyesProven(t *testing.T) {
	ad := &scriptAdapter{script: []llm.Response{
		submitResp("s1", "{{NONCE}}'", ""),
		submitResp("s2", "{{NONCE}}'-new", ""),
	}}
	prove := &fakeProve{results: []*ProveResult{
		missResult(),
		{Verification: domain.VerificationProven, OracleID: "sqli.error/v1"},
	}}
	ap, _ := newAgentProver(t, ad, prove.Prove, budget.Budget{MaxEnv: 2, MaxHarness: 4, MaxHypotheses: 1})

	res, err := ap.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verification != domain.VerificationProven {
		t.Fatalf("fresh 輪 PROVEN 應為終態，得 %s", res.Verification)
	}
}

// TestAgentProverDuplicateNotCounted：同款重試不計也不收（§9.3）——
// 拒收不進 Prove、不扣預算。
func TestAgentProverDuplicateNotCounted(t *testing.T) {
	// round1 提交 A → miss；round2：重送 A（拒）→ 提交 B → miss；round3 重送 B（拒）→ 提交 C → miss
	pre := "學到：x\n改：y\n預期：z"
	ad := &scriptAdapter{script: []llm.Response{
		submitResp("s1", "{{NONCE}}'", ""),
		submitResp("s2", "{{NONCE}}'", ""), submitResp("s3", "{{NONCE}}'-b", pre),
		submitResp("s3b", "{{NONCE}}'-b", pre), submitResp("s4", "{{NONCE}}'-c", pre),
	}}
	prove := &fakeProve{results: []*ProveResult{missResult(), missResult(), missResult()}}
	ap, _ := newAgentProver(t, ad, prove.Prove, budget.Budget{MaxEnv: 2, MaxHarness: 4, MaxHypotheses: 3})

	res, err := ap.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if prove.i != 3 {
		t.Fatalf("同款重試不收：應恰 3 次 Prove，得 %d", prove.i)
	}
	// 三個不同假設耗盡 → HYPOTHESIS_REJECTED（fresh-eyes 未設——本測試 budget 剛好 3）
	if res.Verification != domain.VerificationHypothesisRej {
		t.Fatalf("應 HYPOTHESIS_REJECTED，得 %s", res.Verification)
	}
}

// TestOperatorFeedbackBounded：回饋含 budget 欄位、tails 有界、nonce 紅線。
func TestOperatorFeedbackBounded(t *testing.T) {
	ap, _ := newAgentProver(t, &scriptAdapter{}, func(context.Context, ProveInput) (*ProveResult, error) {
		return nil, errors.New("x")
	}, budget.Default())
	res := &ProveResult{Verification: domain.VerificationHypothesisRej,
		FailureClass: domain.FailureControlledMiss,
		Runs:         []RunRecord{{RunID: "R-9", Kind: "exploit", Exit: 0, Nonce: "SECRETNONCE123"}}}
	// 假 artifacts 含 nonce 與超長內容。
	dir := filepath.Join(ap.RunDir, "evidence", "runs", "R-9")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("x", 10000) + " SECRETNONCE123 "
	if err := os.WriteFile(filepath.Join(dir, "run.log"), []byte(long), 0o644); err != nil {
		t.Fatal(err)
	}
	msg := ap.operatorRunOutcome(res, budget.Counters{EnvLeft: 1, HarnessLeft: 2, HypothesesLeft: 3})
	if !strings.Contains(msg, "<operator>") || !strings.Contains(msg, "\"hypotheses_left\": 3") {
		t.Fatalf("回饋缺固定欄位：%s", msg)
	}
	if strings.Contains(msg, "SECRETNONCE123") {
		t.Fatal("nonce 不得出現在回饋（§18.2）")
	}
	var doc map[string]any
	start := strings.Index(msg, "{")
	end := strings.LastIndex(msg[:strings.Index(msg, "</operator>")], "}")
	if err := json.Unmarshal([]byte(msg[start:end+1]), &doc); err != nil {
		t.Fatalf("operator 訊息非合法 JSON：%v", err)
	}
	if tail, _ := doc["hints"].(map[string]any)["run_log_tail"].(string); len([]rune(tail)) > 4200 {
		t.Fatalf("run_log_tail 超界：%d", len([]rune(tail)))
	}
}
