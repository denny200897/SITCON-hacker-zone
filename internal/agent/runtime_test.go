package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aegis-dev/aegis/internal/llm"
)

// fakeAdapter 依腳本逐輪回應（測 tool loop）。
type fakeAdapter struct {
	script []llm.Response
	i      int
	reqs   []llm.ChatRequest
}

func (f *fakeAdapter) Chat(_ context.Context, req llm.ChatRequest) (llm.Response, error) {
	if f.i >= len(f.script) {
		return llm.Response{}, errors.New("script exhausted")
	}
	f.reqs = append(f.reqs, req)
	r := f.script[f.i]
	f.i++
	return r, nil
}
func (f *fakeAdapter) Provider() string { return "fake" }

func textBlock(s string) llm.ContentBlock    { return llm.ContentBlock{Type: "text", Text: s} }
func stopToolUse() llm.StopReason            { return llm.StopToolUse }
func stopEndTurn() llm.StopReason            { return llm.StopEndTurn }

// TestRuntimeToolLoop：tool_use → 過閘執行 → tool_result 回填 user 訊息 → 終態。
func TestRuntimeToolLoop(t *testing.T) {
	dir := t.TempDir()
	reg := newTestRegistry(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "a.py"), []byte("target()\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	script := []llm.Response{
		{StopReason: stopToolUse(), Content: []llm.ContentBlock{
			textBlock("先讀檔。"),
			{Type: "tool_use", ToolUse: &llm.ToolUse{ID: "t1", Name: "read_code",
				Input: json.RawMessage(`{"path":"a.py"}`)}},
		}},
		{StopReason: stopEndTurn(), Content: []llm.ContentBlock{textBlock("done")}},
	}
	ad := &fakeAdapter{script: script}
	rt := &Runtime{Adapter: ad, Tools: reg, MaxTurns: 5}
	resp, _, err := rt.Run(context.Background(), llm.ChatRequest{Role: llm.RoleProver})
	if err != nil {
		t.Fatalf("loop 失敗：%v", err)
	}
	if resp.StopReason != llm.StopEndTurn {
		t.Fatalf("終態應 end_turn，得 %s", resp.StopReason)
	}
	// 第二輪 req 最後一條應是 user/tool_result，內容含 read_code 輸出。
	last := ad.reqs[1].Messages[len(ad.reqs[1].Messages)-1]
	if last.Role != "user" || len(last.Content) != 1 || last.Content[0].Type != "tool_result" {
		t.Fatalf("回填訊息不符：%#v", last)
	}
	if last.Content[0].ToolResult == nil || !strings.Contains(last.Content[0].ToolResult.Content, "target()") {
		t.Fatalf("tool_result 內容不符：%#v", last.Content[0].ToolResult)
	}
	if last.Content[0].ToolResult.ID != "t1" {
		t.Fatalf("tool_result id 應回呼 t1")
	}
}

// TestRuntimeSubmitAccepted：submit 核可 → handler 收到 assistant 文字（preamble 驗證素材）。
func TestRuntimeSubmitAccepted(t *testing.T) {
	dir := t.TempDir()
	reg := newTestRegistry(t, dir)
	var gotText string
	reg.OnSubmit = func(_ context.Context, spec map[string]any, text string) (bool, string) {
		gotText = text
		if spec["payload"] != "{{NONCE}}'" {
			return false, "bad payload"
		}
		return true, "accepted"
	}
	script := []llm.Response{
		{StopReason: stopToolUse(), Content: []llm.ContentBlock{
			textBlock("學到：X\n改：Y\n預期：Z"),
			{Type: "tool_use", ToolUse: &llm.ToolUse{ID: "s1", Name: "submit_witness_spec",
				Input: json.RawMessage(`{"payload":"{{NONCE}}'"}`)}},
		}},
		{StopReason: stopEndTurn(), Content: []llm.ContentBlock{textBlock("ok")}},
	}
	ad := &fakeAdapter{script: script}
	rt := &Runtime{Adapter: ad, Tools: reg, MaxTurns: 5}
	if _, _, err := rt.Run(context.Background(), llm.ChatRequest{Role: llm.RoleProver}); err != nil {
		t.Fatalf("loop 失敗：%v", err)
	}
	if !strings.Contains(gotText, "學到：") {
		t.Fatalf("handler 未收到 assistant 文字（preamble 驗證素材）：%q", gotText)
	}
}

// TestRuntimeSubmitRejected：submit 被拒 → tool_result 為 error 且迴圈繼續（模型可重試）。
func TestRuntimeSubmitRejected(t *testing.T) {
	dir := t.TempDir()
	reg := newTestRegistry(t, dir)
	reg.OnSubmit = func(_ context.Context, _ map[string]any, _ string) (bool, string) {
		return false, "duplicate_spec"
	}
	script := []llm.Response{
		{StopReason: stopToolUse(), Content: []llm.ContentBlock{
			{Type: "tool_use", ToolUse: &llm.ToolUse{ID: "s1", Name: "submit_witness_spec",
				Input: json.RawMessage(`{"payload":"x"}`)}},
		}},
		{StopReason: stopToolUse(), Content: []llm.ContentBlock{
			{Type: "tool_use", ToolUse: &llm.ToolUse{ID: "s2", Name: "submit_witness_spec",
				Input: json.RawMessage(`{"payload":"x"}`)}},
		}},
		{StopReason: stopEndTurn()},
	}
	ad := &fakeAdapter{script: script}
	rt := &Runtime{Adapter: ad, Tools: reg, MaxTurns: 5}
	resp, _, err := rt.Run(context.Background(), llm.ChatRequest{Role: llm.RoleProver})
	if err != nil {
		t.Fatalf("拒收後迴圈應可繼續：%v", err)
	}
	if resp.StopReason != llm.StopEndTurn {
		t.Fatalf("終態不符：%s", resp.StopReason)
	}
	// 第二輪回填的 tool_result 應是 error。
	last := ad.reqs[1].Messages[len(ad.reqs[1].Messages)-1]
	if last.Content[0].ToolResult == nil || !last.Content[0].ToolResult.IsError {
		t.Fatalf("拒收 tool_result 應為 error：%#v", last.Content[0].ToolResult)
	}
}

// TestRuntimeMaxTurns：無終態回應時耗盡上限 → MaxTurnsExceededError。
func TestRuntimeMaxTurns(t *testing.T) {
	dir := t.TempDir()
	reg := newTestRegistry(t, dir)
	loop := llm.Response{StopReason: stopToolUse(), Content: []llm.ContentBlock{
		{Type: "tool_use", ToolUse: &llm.ToolUse{ID: "t", Name: "read_code",
			Input: json.RawMessage(`{"path":"a.py"}`)}},
	}}
	var script []llm.Response
	for i := 0; i < 10; i++ {
		script = append(script, loop)
	}
	ad := &fakeAdapter{script: script}
	rt := &Runtime{Adapter: ad, Tools: reg, MaxTurns: 3}
	if _, _, err := rt.Run(context.Background(), llm.ChatRequest{Role: llm.RoleProver}); !errors.Is(err, MaxTurnsExceededError) {
		t.Fatalf("應得 MaxTurnsExceededError，得 %v", err)
	}
}

// TestRuntimeWhitelistEnforced：reporter 呼叫 search_code → tool_result policy_denied。
func TestRuntimeWhitelistEnforced(t *testing.T) {
	dir := t.TempDir()
	reg := newTestRegistry(t, dir)
	script := []llm.Response{
		{StopReason: stopToolUse(), Content: []llm.ContentBlock{
			{Type: "tool_use", ToolUse: &llm.ToolUse{ID: "t1", Name: "search_code",
				Input: json.RawMessage(`{"query":"x"}`)}},
		}},
		{StopReason: stopEndTurn()},
	}
	ad := &fakeAdapter{script: script}
	rt := &Runtime{Adapter: ad, Tools: reg, MaxTurns: 5}
	if _, _, err := rt.Run(context.Background(), llm.ChatRequest{Role: llm.RoleReporter}); err != nil {
		t.Fatalf("loop 失敗：%v", err)
	}
	last := ad.reqs[1].Messages[len(ad.reqs[1].Messages)-1]
	tr := last.Content[0].ToolResult
	if tr == nil || !tr.IsError || !strings.Contains(tr.Content, "policy_denied") {
		t.Fatalf("reporter 的 search_code 應 policy_denied：%#v", tr)
	}
}

// TestNewToolDefs：schema 真源載入；prover 含 submit_witness_spec 且用 witness_spec schema。
func TestNewToolDefs(t *testing.T) {
	toolsSchema := []byte(`{"definitions":{
		"read_code":{"type":"object","properties":{"path":{"type":"string"}}},
		"search_code":{"type":"object","properties":{"query":{"type":"string"}}},
		"semgrep":{"type":"object","properties":{"rule":{"type":"string"}}}
	}}`)
	specSchema := []byte(`{"type":"object","properties":{"payload":{"type":"string"}}}`)
	desc := map[string]string{"read_code": "讀檔"}

	defs, err := NewToolDefs(llm.RoleProver, toolsSchema, specSchema, desc)
	if err != nil {
		t.Fatalf("NewToolDefs 失敗：%v", err)
	}
	if len(defs) != 4 {
		t.Fatalf("prover 應有 4 工具，得 %d", len(defs))
	}
	last := defs[len(defs)-1]
	if last.Name != "submit_witness_spec" {
		t.Fatalf("最後應是 submit_witness_spec：%#v", last)
	}
	if !strings.Contains(string(last.InputSchema), "payload") {
		t.Fatalf("submit 應用 witness_spec schema：%s", last.InputSchema)
	}
	if defs[0].Description != "讀檔" {
		t.Fatalf("描述應注入：%q", defs[0].Description)
	}
	// reporter 只有 read_code。
	rdefs, err := NewToolDefs(llm.RoleReporter, toolsSchema, specSchema, desc)
	if err != nil || len(rdefs) != 1 || rdefs[0].Name != "read_code" {
		t.Fatalf("reporter 應只有 read_code：%v %#v", err, rdefs)
	}
	// schema 缺 definition → 錯誤（拿掉 semgrep 的 definition 再試 recon）。
	broken := []byte(`{"definitions":{
		"read_code":{"type":"object"},
		"search_code":{"type":"object"}
	}}`)
	if _, err := NewToolDefs(llm.RoleRecon, broken, specSchema, desc); err == nil {
		t.Fatal("缺 semgrep definition 時應報錯")
	}
}