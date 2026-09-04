package evidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreChainAndVerify(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, h1, err := s.Write(map[string]any{"kind": "negative", "n": int64(1)}, "EV-0001")
	if err != nil {
		t.Fatal(err)
	}
	_, h2, err := s.Write(map[string]any{"kind": "positive", "n": int64(2)}, "EV-0002")
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h2 {
		t.Fatal("hashes identical")
	}

	// 落檔內容：EV-0002 的 prev = EV-0001 自身 hash
	b, _ := os.ReadFile(filepath.Join(dir, "evidence", "EV-0002.json"))
	if !strings.Contains(string(b), h1) {
		t.Fatalf("EV-0002 missing prev hash %s", h1)
	}

	if err := VerifyChain(filepath.Join(dir, "evidence")); err != nil {
		t.Fatalf("chain verify failed: %v", err)
	}
}

func TestStoreVerifyDetectsTamper(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = s.Write(map[string]any{"kind": "exploit", "n": int64(1)}, "EV-0001")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = s.Write(map[string]any{"kind": "exploit", "n": int64(2)}, "EV-0002")
	if err != nil {
		t.Fatal(err)
	}

	// 篡改 EV-0001 內容（誠實語意：hash 證明內容變了）
	p1 := filepath.Join(dir, "evidence", "EV-0001.json")
	b, _ := os.ReadFile(p1)
	_ = os.WriteFile(p1, []byte(strings.Replace(string(b), `"n":1`, `"n":99`, 1)), 0o644)
	if err := VerifyChain(filepath.Join(dir, "evidence")); err == nil {
		t.Fatal("tampered evidence passed chain verify")
	}
}

func TestStoreResumeFromExisting(t *testing.T) {
	dir := t.TempDir()
	s1, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, h1, err := s1.Write(map[string]any{"kind": "negative"}, "EV-0001")
	if err != nil {
		t.Fatal(err)
	}

	// 模擬重啟：新 store 回放鏈尾
	s2, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = s2.Write(map[string]any{"kind": "positive"}, "EV-0002")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "evidence", "EV-0002.json"))
	if !strings.Contains(string(b), h1) {
		t.Fatal("resumed store did not link to previous tail")
	}
	if err := VerifyChain(filepath.Join(dir, "evidence")); err != nil {
		t.Fatal(err)
	}
}

func TestStoreCanonicalOnDisk(t *testing.T) {
	// 落檔即 canonical 序列化——重算才一致（§5.3）
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, h, err := s.Write(map[string]any{"kind": "exploit", "expr": "a < b & c"}, "EV-0001")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "evidence", "EV-0001.json"))
	m, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := Hash(m)
	if err != nil {
		t.Fatal(err)
	}
	if h != h2 { // 相同文件兩次 hash 相等（§22 M0a byte-equal 驗證）
		t.Fatalf("on-disk doc rehash mismatch: %s vs %s", h, h2)
	}
	if !strings.Contains(string(b), `<`) {
		t.Fatal("canonical bytes missing literal '<' (SetEscapeHTML(false) 契約)")
	}
	if strings.Contains(string(b), `u003c`) {
		t.Fatal("HTML escape leaked into canonical bytes (SetEscapeHTML(false) 契約)")
	}
}

func TestRunDirFor(t *testing.T) {
	dir := t.TempDir()
	d, err := RunDirFor(dir, "R-0001")
	if err != nil {
		t.Fatal(err)
	}
	if d != filepath.Join(dir, "evidence", "runs", "R-0001") {
		t.Fatalf("got %s", d)
	}
}