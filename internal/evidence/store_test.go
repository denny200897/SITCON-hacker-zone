package evidence

import (
	"fmt"
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
	if err := VerifyBundle(filepath.Join(dir, "evidence")); err != nil {
		t.Fatalf("bundle verify failed: %v", err)
	}
}

func TestStoreAllowsJournalAllocationGapWithoutPoisoningBundle(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	// EV-0001 可在檔案落地前因 fail-closed 而被 journal 消耗；後續證據仍須可用。
	if _, _, err := s.Write(map[string]any{"kind": "negative"}, "EV-0002"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Write(map[string]any{"kind": "positive"}, "EV-0003"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(filepath.Join(dir, "evidence")); err != nil {
		t.Fatalf("含配置 gap 的 bundle 應可驗證：%v", err)
	}
}

func TestBundleManifestDetectsTailDeletionAndAddition(t *testing.T) {
	for _, mutation := range []string{"tail", "delete", "add"} {
		t.Run(mutation, func(t *testing.T) {
			dir := t.TempDir()
			store, err := NewStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			for i := 1; i <= 3; i++ {
				if _, _, err := store.Write(map[string]any{"kind": "exploit", "n": int64(i)}, fmt.Sprintf("EV-%04d", i)); err != nil {
					t.Fatal(err)
				}
			}
			evidenceDir := filepath.Join(dir, "evidence")
			switch mutation {
			case "tail":
				path := filepath.Join(evidenceDir, "EV-0003.json")
				data, _ := os.ReadFile(path)
				if err := os.WriteFile(path, []byte(strings.Replace(string(data), `"n":3`, `"n":9`, 1)), 0o644); err != nil {
					t.Fatal(err)
				}
			case "delete":
				if err := os.Remove(filepath.Join(evidenceDir, "EV-0002.json")); err != nil {
					t.Fatal(err)
				}
			case "add":
				if err := os.WriteFile(filepath.Join(evidenceDir, "EV-0004.json"), []byte(`{"id":"EV-0004","prev_evidence_hash":null}`), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := VerifyBundle(evidenceDir); err == nil {
				t.Fatal("mutated bundle verified")
			}
		})
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

// ---- P2-3 adversarial tests（先寫、先驗證在現行實作上失敗，再修復；docs/acceptance-m0a-m0c.md） ----

// TestStoreWriteRefusesOverwrite：append-only 語意（§5.3）——同 id 不得覆寫既有 EV。
func TestStoreWriteRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = s.Write(map[string]any{"kind": "negative", "n": int64(1)}, "EV-0001")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "evidence", "EV-0001.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// 同 id 重寫：必須被拒（O_EXCL），既有檔案不得被改動。
	if _, _, err := s.Write(map[string]any{"kind": "negative", "n": int64(999)}, "EV-0001"); err == nil {
		t.Fatal("同 id 的 Write 未被拒絕：evidence store 可被覆寫（P2-3）")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("被拒的 Write 仍改動了既有 EV 檔")
	}
	if err := VerifyChain(filepath.Join(dir, "evidence")); err != nil {
		t.Fatalf("覆寫嘗試後鏈驗證失敗: %v", err)
	}
	// 被拒後鏈尾狀態不得污染：下一筆仍能正常 append。
	if _, _, err := s.Write(map[string]any{"kind": "positive", "n": int64(2)}, "EV-0002"); err != nil {
		t.Fatalf("被拒後正常 append 失敗: %v", err)
	}
	if err := VerifyChain(filepath.Join(dir, "evidence")); err != nil {
		t.Fatal(err)
	}
}

// TestStoreRejectsBadID：id 必須符合 ^EV-[0-9]{4}$（§21.2 閉集格式）。
func TestStoreRejectsBadID(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"EV-1", "EV-00012", "EV-abcd", "ev-0001", "EV-0001x", "R-0001", ""} {
		if _, _, err := s.Write(map[string]any{"kind": "negative"}, bad); err == nil {
			t.Fatalf("非法 id %q 未被拒絕", bad)
		}
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "evidence"))
	if len(entries) != 0 {
		t.Fatalf("非法 id 不應落檔，得 %d 個檔案", len(entries))
	}
}

// TestNewStoreFailsOnCorruptedMiddle：開啟 store 必須驗整條既有鏈，
// 中段被篡改時不得接受（P2-3：只 hash 最後一筆無法偵測）。
func TestNewStoreFailsOnCorruptedMiddle(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i, n := range []int64{1, 2, 3} {
		if _, _, err := s.Write(map[string]any{"kind": "negative", "n": n}, fmt.Sprintf("EV-%04d", i+1)); err != nil {
			t.Fatal(err)
		}
	}
	// 篡改中段 EV-0002。
	mid := filepath.Join(dir, "evidence", "EV-0002.json")
	b, err := os.ReadFile(mid)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(b), `"n":2`, `"n":99`, 1)
	if tampered == string(b) {
		t.Fatal("測試前提失效：未成功改寫 EV-0002 內容")
	}
	if err := os.WriteFile(mid, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(dir); err == nil {
		t.Fatal("NewStore 接受了中段被篡改的鏈（P2-3：未驗整條 chain）")
	}
}
