// evidence store：content-addressed bundle（SPEC §5.3、§10）。
// EV-*.json 以 canonical JSON + sha256 鏈結（prev_evidence_hash = 前一筆 EV 自身 hash）；
// bundle manifest 可離線重算全串。本機 hash 證明「內容未變」，不證明「檔案不可變」
// ——evidence 目錄以 append-only journal 管理（誠實語意，§5.3）。
package evidence

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Store 管理 <runDir>/evidence/ 目錄的 append-only 寫入。
type Store struct {
	mu    sync.Mutex
	dir   string // <runDir>/evidence
	prev  string // 前一筆 EV 自身 hash；空字串表示鏈首
	count int
}

var evidenceIDPattern = regexp.MustCompile(`^EV-[0-9]{4}$`)

// NewStore 開啟（或建立）runDir/evidence；重啟時從既有檔案回放鏈尾。
func NewStore(runDir string) (*Store, error) {
	dir := filepath.Join(runDir, "evidence")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("evidence: mkdir %s: %w", dir, err)
	}
	s := &Store{dir: dir}
	// 回放：找出既有 EV 檔，取最後一筆的自身 hash（鏈首 prev 為 null）
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("evidence: read dir: %w", err)
	}
	ids := []string{}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "EV-") && strings.HasSuffix(name, ".json") {
			ids = append(ids, strings.TrimSuffix(strings.TrimPrefix(name, "EV-"), ".json"))
		}
	}
	sort.Strings(ids)
	if len(ids) > 0 {
		if err := VerifyChain(dir); err != nil {
			return nil, fmt.Errorf("evidence: existing chain invalid: %w", err)
		}
		last := filepath.Join(dir, "EV-"+ids[len(ids)-1]+".json")
		data, err := os.ReadFile(last)
		if err != nil {
			return nil, fmt.Errorf("evidence: read %s: %w", last, err)
		}
		m, err := Decode(data)
		if err != nil {
			return nil, err
		}
		h, err := Hash(m)
		if err != nil {
			return nil, err
		}
		s.prev = h
		fmt.Sscanf(ids[len(ids)-1], "%d", &s.count)
	}
	return s, nil
}

// Write 依 §5.3 補齊鏈結欄位後落檔，回傳 evidence id 與自身 hash。
// doc 必須為 map[string]any（canonical 路徑契約，§21.4）；
// id 欄位（如 "EV-0001"）與 prev_evidence_hash 由 store 管理。
func (s *Store) Write(doc map[string]any, id string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !evidenceIDPattern.MatchString(id) {
		return "", "", fmt.Errorf("evidence: invalid id %q", id)
	}
	doc["id"] = id
	doc["prev_evidence_hash"] = s.prev
	if s.prev == "" {
		doc["prev_evidence_hash"] = nil
	}
	h, err := Hash(doc)
	if err != nil {
		return "", "", err
	}
	// 以 canonical JSON 落檔——bundle manifest 重算才會一致
	cb, err := canonical(doc)
	if err != nil {
		return "", "", err
	}
	path := filepath.Join(s.dir, id+".json")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", "", fmt.Errorf("evidence: write %s: %w", path, err)
	}
	if _, err := f.Write(append(cb, '\n')); err != nil {
		_ = f.Close()
		return "", "", fmt.Errorf("evidence: write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return "", "", fmt.Errorf("evidence: close %s: %w", path, err)
	}
	s.prev = h
	s.count++
	return id, h, nil
}

// VerifyChain 離線重算：依檔名順序逐筆驗 hash 鏈（§5.3 bundle manifest 重算全串）。
func VerifyChain(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("evidence: read dir: %w", err)
	}
	names := []string{}
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, "EV-") && strings.HasSuffix(n, ".json") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	var prev string
	for _, n := range names {
		data, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return fmt.Errorf("evidence: read %s: %w", n, err)
		}
		m, err := Decode(data)
		if err != nil {
			return fmt.Errorf("evidence: decode %s: %w", n, err)
		}
		if len(names) > 1 || m["prev_evidence_hash"] != nil {
			// 鏈首 prev 為 null；其後每筆 prev = 前筆自身 hash
			if (prev == "" && m["prev_evidence_hash"] != nil && names[0] == n) ||
				(prev != "" && m["prev_evidence_hash"] != prev) {
				return fmt.Errorf("evidence: chain broken at %s", n)
			}
		}
		h, err := Hash(m)
		if err != nil {
			return fmt.Errorf("evidence: hash %s: %w", n, err)
		}
		prev = h
	}
	return nil
}

// Dir 回傳 evidence 目錄路徑。
func (s *Store) Dir() string { return s.dir }

// RunDirFor 建立 <runDir>/evidence/runs/R-#### 目錄（witness 原始碼、exploit、log、fs_diff，§10）。
func RunDirFor(runDir, runID string) (string, error) {
	d := filepath.Join(runDir, "evidence", "runs", runID)
	if err := os.MkdirAll(d, 0o755); err != nil {
		return "", fmt.Errorf("evidence: mkdir run dir: %w", err)
	}
	return d, nil
}
