package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aegis-dev/aegis/internal/llm"
)

func newTestRegistry(t *testing.T, snapshotDir string) *ToolRegistry {
	t.Helper()
	al, err := OpenAuditLog(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = al.Close() })
	return &ToolRegistry{SnapshotDir: snapshotDir, audit: al}
}

// TestPathInSnapshot：越界（".."、絕對路徑外、symlink 逃逸）一律拒絕（§18.1）。
func TestPathInSnapshot(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.py"), []byte("x = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "b.py"), []byte("y = 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// symlink 逃逸：指向 snapshot 外。
	outside := filepath.Join(t.TempDir(), "outside.py")
	if err := os.WriteFile(outside, []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "leak.py")); err != nil {
		t.Fatal(err)
	}

	if _, err := pathInSnapshot(root, "a.py"); err != nil {
		t.Errorf("snapshot 內合法路徑被拒：%v", err)
	}
	if _, err := pathInSnapshot(root, "sub/../a.py"); err != nil {
		t.Errorf("snapshot 內正規化路徑被拒：%v", err)
	}
	for _, bad := range []string{"../outside.py", "", "/etc/passwd", "leak.py"} {
		if _, err := pathInSnapshot(root, bad); err == nil {
			t.Errorf("越界路徑 %q 應被拒", bad)
		}
	}
}

// TestExecuteWhitelist：白名單外的工具一律 denied，且記 audit（§18.1 閘 a）。
func TestExecuteWhitelist(t *testing.T) {
	dir := t.TempDir()
	reg := newTestRegistry(t, dir)
	al, err := OpenAuditLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer al.Close()
	reg.SetAudit(al)

	res := reg.Execute(context.Background(), llm.RoleReporter, "search_code", json.RawMessage(`{"query":"x"}`), "")
	if !res.IsError || res.Content[:13] != "policy_denied" {
		t.Fatalf("reporter 不得用 search_code，得 %+v", res)
	}
	// audit 應記一筆 denied。
	assertAudit(t, al, "search_code", AuditDenied)
}

// TestExecuteReadCodeRange：合法讀取與行切片；越界路徑 denied。
func TestExecuteReadCode(t *testing.T) {
	dir := t.TempDir()
	content := "l1\nl2\nl3\n"
	if err := os.WriteFile(filepath.Join(dir, "a.py"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	reg := newTestRegistry(t, dir)

	res := reg.Execute(context.Background(), llm.RoleProver, "read_code",
		json.RawMessage(`{"path":"a.py","start":2,"end":3}`), "")
	if res.IsError {
		t.Fatalf("read_code 失敗：%s", res.Content)
	}
	if res.Content != "1: l1\n2: l2\n3: l3\n"[3:] { // 從第 2 行起
		// start=2 時輸出應自 "2: l2" 開始
		if want := "2: l2\n3: l3\n"; res.Content != want {
			t.Fatalf("行切片不符：got %q want %q", res.Content, want)
		}
	}
	res = reg.Execute(context.Background(), llm.RoleProver, "read_code",
		json.RawMessage(`{"path":"../etc/passwd"}`), "")
	if !res.IsError || res.Content[:13] != "policy_denied" {
		t.Fatalf("越界路徑應 policy_denied，得 %+v", res)
	}
}

// TestExecuteSearchCode：RE2 lookahead 拒絕、命中格式、上限 50。
func TestExecuteSearchCode(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 60; i++ {
		name := filepath.Join(dir, "f"+string(rune('a'+i%26))+"_go.py")
		_ = os.WriteFile(name, []byte("target_call("+jsonInt(i)+")\n"), 0o644)
	}
	reg := newTestRegistry(t, dir)

	// lookahead → policy_denied
	res := reg.Execute(context.Background(), llm.RoleProver, "search_code",
		json.RawMessage(`{"query":"a(?=b)"}`), "")
	if !res.IsError || res.Content[:13] != "policy_denied" {
		t.Fatalf("lookahead 應 policy_denied，得 %+v", res)
	}
	// 合法 query → 最多 50 筆
	res = reg.Execute(context.Background(), llm.RoleProver, "search_code",
		json.RawMessage(`{"query":"target_call"}`), "")
	if res.IsError {
		t.Fatalf("search_code 失敗：%s", res.Content)
	}
	var hits []map[string]any
	if err := json.Unmarshal([]byte(res.Content), &hits); err != nil {
		t.Fatalf("輸出非 JSON 陣列：%v", err)
	}
	if len(hits) > MaxSearchHits {
		t.Fatalf("超過上限 %d：得 %d", MaxSearchHits, len(hits))
	}
	if _, ok := hits[0]["path"]; !ok {
		t.Fatalf("命中格式缺 path 欄位：%#v", hits[0])
	}
}

// TestExecuteSemgrepRuleGate：未登錄規則 id → policy_denied（§18.1）。
func TestExecuteSemgrepRuleGate(t *testing.T) {
	dir := t.TempDir()
	reg := newTestRegistry(t, dir)
	reg.Rules = map[string]string{} // 空：無任何登錄規則

	res := reg.Execute(context.Background(), llm.RoleProver, "semgrep",
		json.RawMessage(`{"rule":"py/evil"}`), "")
	if !res.IsError || res.Content[:13] != "policy_denied" {
		t.Fatalf("未登錄規則應 policy_denied，得 %+v", res)
	}
}

// TestExecuteSubmitGate：handler 拒收 → spec_rejected；核可 → accepted。
func TestExecuteSubmitGate(t *testing.T) {
	dir := t.TempDir()
	reg := newTestRegistry(t, dir)
	spec := map[string]any{"payload": "{{NONCE}}'"}

	reg.OnSubmit = func(ctx context.Context, s map[string]any, text string) (bool, string) {
		return false, "duplicate_spec"
	}
	res := reg.Execute(context.Background(), llm.RoleProver, "submit_witness_spec", json.RawMessage(`{"payload":"{{NONCE}}"}`), "")
	if !res.IsError || res.Content[:13] != "spec_rejected" {
		t.Fatalf("拒收應回 spec_rejected，得 %+v", res)
	}

	reg.OnSubmit = func(ctx context.Context, s map[string]any, text string) (bool, string) {
		if s["payload"] != "{{NONCE}}" {
			t.Errorf("handler 收到的 spec 不符：%#v", s)
		}
		return true, "accepted"
	}
	res = reg.Execute(context.Background(), llm.RoleProver, "submit_witness_spec", json.RawMessage(`{"payload":"{{NONCE}}"}`), "")
	if res.IsError {
		t.Fatalf("核可路徑不應錯誤：%s", res.Content)
	}
	_ = spec
}

// TestAuditJSONL：逐筆為合法 JSON、欄位閉合。
func TestAuditJSONL(t *testing.T) {
	dir := t.TempDir()
	al, err := OpenAuditLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	al.Append(llm.RoleProver, "read_code", json.RawMessage(`{"path":"a.py"}`), AuditAllowed, "")
	// nil-safe
	var nilLog *AuditLog
	nilLog.Append(llm.RoleProver, "x", nil, AuditDenied, "r")
	if err := al.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		t.Fatal("audit.jsonl 應有一筆")
	}
	var e AuditEntry
	if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
		t.Fatalf("audit 行非法：%v", err)
	}
	if e.Tool != "read_code" || e.Decision != AuditAllowed || e.Role != string(llm.RoleProver) {
		t.Fatalf("audit 內容不符：%#v", e)
	}
}

// assertAudit 讀最後一筆 audit 行比對 tool／decision。
func assertAudit(t *testing.T, al *AuditLog, tool string, want AuditDecision) {
	t.Helper()
	data, err := os.ReadFile(al.f.Name())
	if err != nil {
		t.Fatal(err)
	}
	lines := nonEmptyLines(string(data))
	last := lines[len(lines)-1]
	var e AuditEntry
	if err := json.Unmarshal([]byte(last), &e); err != nil {
		t.Fatalf("audit 行非法：%v（%q）", err, last)
	}
	if e.Tool != tool || e.Decision != want {
		t.Fatalf("audit 不符：tool=%q decision=%q，want %q/%q", e.Tool, e.Decision, tool, want)
	}
}

func nonEmptyLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '\n' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func jsonInt(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
