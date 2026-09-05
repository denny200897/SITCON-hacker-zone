// Package snapshot 實作目標 repo 的 content snapshot（SPEC §4「Snapshot 與執行一致性」、§16「Snapshot 實作」）。
//
// 掃描開始時以 filepath.WalkDir 實體複製 repo（排除 .git 與 exclude 清單）到
// cacheDir/snapshots/<snapshot_id>/；symlink 以 os.Lstat 判定、os.Symlink 原樣重鏈、
// 不跟隨（跟隨會把 repo 外的檔案複製進 snapshot；filepath.WalkDir 本身不跟隨 symlink）。
// 複製後即計 tree hash，此後來源 repo 改動不影響本次 run。
//
// snapshot_id 是內容位址（§21.2）：SN-<tree hash 前 12 hex>；同 snapshot_id 已存在時
// 直接重用、不重複複製（§16）。本套件只管 content snapshot；dirty worktree manifest
// 屬 git 層，不在本套件。
package snapshot

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aegis-dev/aegis/internal/evidence"
)

// Snapshot 是一次 content snapshot 的結果。
type Snapshot struct {
	// ID 為 "SN-" + tree hash 前 12 hex（內容位址，§21.2）。
	ID string
	// Dir 為快照實體目錄（cacheDir/snapshots/<ID>）。
	Dir string
	// TreeHash 為 "sha256:<hex>" 形式的 tree hash（§21.4 前綴規則）。
	TreeHash string
}

// entry 是 tree hash 的最小單位：相對路徑 + 內容 sha256。
// symlink 的「內容」定義為 link target 字串的 sha256（決定性、文件化於此）。
type entry struct {
	Path   string // repo 內相對路徑，恆以 "/" 分隔（filepath.ToSlash）
	Sha256 string // "sha256:<hex>"
}

// Create 建立（或重用）repoRoot 的 content snapshot。
//
// 流程：
//  1. 第一輪 WalkDir 只讀取內容計 hash（不寫入）——若對應 snapshot_id 已存在則直接重用，
//     不重複複製（§16）。
//  2. 不存在時第二輪 WalkDir 實體複製到 cacheDir 下暫存目錄，邊複製邊重算 hash；
//     複製完成後以「實際複製內容」的 hash 定址（來源 repo 若在複製期間變動，
//     ID 仍與複製進去的內容一致，不會出現 ID 與內容不符的快照）。
//  3. 暫存目錄原子 rename 到 cacheDir/snapshots/<ID>；若目的地已存在則丟棄暫存、重用既有目錄。
func Create(repoRoot, cacheDir string, excludes []string) (Snapshot, error) {
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		return Snapshot{}, fmt.Errorf("snapshot: 解析 repo 根目錄: %w", err)
	}
	fi, err := os.Stat(root)
	if err != nil {
		return Snapshot{}, fmt.Errorf("snapshot: 讀取 repo 根目錄 %s: %w", root, err)
	}
	if !fi.IsDir() {
		return Snapshot{}, fmt.Errorf("snapshot: %s 不是目錄", root)
	}
	exs, err := normalizeExcludes(excludes)
	if err != nil {
		return Snapshot{}, err
	}
	if cacheDir == "" {
		return Snapshot{}, errors.New("snapshot: cacheDir 不可為空")
	}

	// 第一輪：只計 hash（不複製），供「同 snapshot_id 直接重用」判斷。
	first, err := collect(root, "", exs)
	if err != nil {
		return Snapshot{}, err
	}
	h1, err := treeHash(first)
	if err != nil {
		return Snapshot{}, err
	}
	id1, err := snapshotID(h1)
	if err != nil {
		return Snapshot{}, err
	}
	dir1 := filepath.Join(cacheDir, "snapshots", id1)
	if st, statErr := os.Stat(dir1); statErr == nil && st.IsDir() {
		if err := Verify(dir1, id1, h1); err != nil {
			return Snapshot{}, err
		}
		return Snapshot{ID: id1, Dir: dir1, TreeHash: h1}, nil // 重用，不重複複製
	} else if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
		return Snapshot{}, fmt.Errorf("snapshot: 檢查既有快照 %s: %w", dir1, statErr)
	}

	// 第二輪：實體複製到暫存目錄，邊複製邊重算 hash（以實際複製內容為準）。
	if err := os.MkdirAll(filepath.Join(cacheDir, "snapshots"), 0o755); err != nil {
		return Snapshot{}, fmt.Errorf("snapshot: 建立快照根目錄: %w", err)
	}
	staging, err := os.MkdirTemp(filepath.Join(cacheDir, "snapshots"), ".staging-")
	if err != nil {
		return Snapshot{}, fmt.Errorf("snapshot: 建立暫存目錄: %w", err)
	}
	// 任何中途失敗都要清掉暫存，不留孤兒目錄。
	defer func() {
		if staging != "" {
			_ = os.RemoveAll(staging)
		}
	}()

	second, err := collect(root, staging, exs)
	if err != nil {
		return Snapshot{}, err
	}
	h2, err := treeHash(second)
	if err != nil {
		return Snapshot{}, err
	}
	id2, err := snapshotID(h2)
	if err != nil {
		return Snapshot{}, err
	}
	dir2 := filepath.Join(cacheDir, "snapshots", id2)

	// MkdirTemp 建 0700；快照之後要被 inventory／sandbox 掛載讀取，放寬到 0755。
	if err := os.Chmod(staging, 0o755); err != nil {
		return Snapshot{}, fmt.Errorf("snapshot: 調整暫存目錄權限: %w", err)
	}

	if st, statErr := os.Stat(dir2); statErr == nil && st.IsDir() {
		if err := Verify(dir2, id2, h2); err != nil {
			return Snapshot{}, err
		}
		return Snapshot{ID: id2, Dir: dir2, TreeHash: h2}, nil // 重用，不重複複製
	}
	if err := os.Rename(staging, dir2); err != nil {
		// rename 失敗最常見原因是目的地已被佔用（併發建立）；確認後仍視為重用。
		if st, statErr := os.Stat(dir2); statErr == nil && st.IsDir() {
			if err := Verify(dir2, id2, h2); err != nil {
				return Snapshot{}, err
			}
			return Snapshot{ID: id2, Dir: dir2, TreeHash: h2}, nil
		}
		return Snapshot{}, fmt.Errorf("snapshot: 落地快照 %s: %w", dir2, err)
	}
	staging = "" // 已 rename，交由 defer 前的清空避免誤刪
	return Snapshot{ID: id2, Dir: dir2, TreeHash: h2}, nil
}

// Verify 重算既有 snapshot 的內容位址。任何竄改、損毀或目錄名稱與內容
// 不一致都 fail closed；呼叫端應在掛載 snapshot 前再次驗證。
func Verify(dir, expectedID, expectedTreeHash string) error {
	entries, err := collect(dir, "", nil)
	if err != nil {
		return fmt.Errorf("snapshot: 驗證既有快照 %s: %w", dir, err)
	}
	actualHash, err := treeHash(entries)
	if err != nil {
		return err
	}
	actualID, err := snapshotID(actualHash)
	if err != nil {
		return err
	}
	if actualHash != expectedTreeHash || actualID != expectedID || filepath.Base(dir) != expectedID {
		return fmt.Errorf("snapshot: 既有快照內容不符（dir=%s id=%s hash=%s；預期 id=%s hash=%s）",
			dir, actualID, actualHash, expectedID, expectedTreeHash)
	}
	return nil
}

// collect 走訪 root（filepath.WalkDir，不跟隨 symlink），排除 .git 與 excludes。
// dst 為空時是「只計 hash」的一輪；dst 非空時把每個項目複製到 dst/<相對路徑>，
// 並收集 tree hash 所需的 {path, sha256} 項目。
func collect(root, dst string, exs []string) ([]entry, error) {
	entries := []entry{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, fs.ErrPermission) {
				return fmt.Errorf("snapshot: 走訪 %s 權限不足: %w", path, walkErr)
			}
			return fmt.Errorf("snapshot: 走訪 %s: %w", path, walkErr)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("snapshot: 計算相對路徑 %s: %w", path, err)
		}
		relSlash := filepath.ToSlash(rel)
		// 根目錄本身（rel == "."）不套用排除規則。
		if relSlash != "." && excluded(relSlash, exs) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		// .git 一律排除（目錄則整支剪掉；worktree 的 .git 檔也排除）。
		if relSlash != "." && d.Name() == ".git" {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// 判定一律用 Lstat（d.Info() 同為 lstat 語意；明列 os.Lstat 以符合 §16 文字），
		// 絕不可用 Stat——Stat 會跟隨 symlink，把 repo 外檔案納入判定。
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("snapshot: Lstat %s: %w", path, err)
		}

		switch {
		case info.IsDir():
			if dst != "" && relSlash != "." {
				if err := os.MkdirAll(filepath.Join(dst, rel), 0o755); err != nil {
					return fmt.Errorf("snapshot: 建立快照目錄 %s: %w", rel, err)
				}
			}
			return nil
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return fmt.Errorf("snapshot: 讀取 symlink %s: %w", path, err)
			}
			resolved := target
			if !filepath.IsAbs(resolved) {
				resolved = filepath.Join(filepath.Dir(path), resolved)
			}
			resolved, err = filepath.Abs(resolved)
			if err != nil {
				return fmt.Errorf("snapshot: 解析 symlink %s: %w", path, err)
			}
			if resolved != root && !strings.HasPrefix(resolved, root+string(filepath.Separator)) {
				return fmt.Errorf("snapshot: symlink %s 指向 snapshot 外（%s）", rel, target)
			}
			if dst != "" {
				if err := os.Symlink(target, filepath.Join(dst, rel)); err != nil {
					return fmt.Errorf("snapshot: 重鏈 symlink %s: %w", rel, err)
				}
			}
			sum := sha256.Sum256([]byte(target)) // symlink 內容 = link target 字串（決定性）
			entries = append(entries, entry{Path: relSlash, Sha256: "sha256:" + fmt.Sprintf("%x", sum)})
			return nil
		case info.Mode().IsRegular():
			sum, err := fileSHA256(path, dst, rel, info.Mode().Perm())
			if err != nil {
				return err
			}
			entries = append(entries, entry{Path: relSlash, Sha256: sum})
			return nil
		default:
			// FIFO、socket、device 等特殊檔不屬於內容快照，跳過（不進 hash）。
			return nil
		}
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

// fileSHA256 串流計算檔案 sha256；dst 非空時邊讀邊把同樣 byte 寫入快照副本。
func fileSHA256(src, dst, rel string, perm fs.FileMode) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", fmt.Errorf("snapshot: 開啟 %s: %w", src, err)
	}
	defer in.Close() //nolint:errcheck // 唯讀關閉

	h := sha256.New()
	var out io.Writer = h
	if dst != "" {
		dstPath := filepath.Join(dst, rel)
		if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
			return "", fmt.Errorf("snapshot: 建立快照上層目錄 %s: %w", filepath.Dir(rel), err)
		}
		f, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
		if err != nil {
			return "", fmt.Errorf("snapshot: 建立快照檔 %s: %w", rel, err)
		}
		defer f.Close() //nolint:errcheck // 由 Copy 錯誤主導
		out = io.MultiWriter(f, h)
	}
	if _, err := io.Copy(out, in); err != nil {
		return "", fmt.Errorf("snapshot: 複製 %s: %w", rel, err)
	}
	return "sha256:" + fmt.Sprintf("%x", h.Sum(nil)), nil
}

// treeHash 以 canonical JSON（§21.4，全工具唯一序列化路徑）對項目做決定性組合：
// 項目先依相對路徑（"/" 分隔、byte 序）排序，再組成
// {"canonical_version": <evidence.CanonicalVersion>, "entries": [{"path":…, "sha256":…}, …]}
// 經 evidence.Hash 計 sha256。陣列順序即排序後順序、map 鍵由 encoding/json 保證排序，
// 故同內容恆得同 hash。
func treeHash(entries []entry) (string, error) {
	sorted := make([]entry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	items := make([]any, 0, len(sorted))
	for _, e := range sorted {
		items = append(items, map[string]any{"path": e.Path, "sha256": e.Sha256})
	}
	obj := map[string]any{
		"canonical_version": evidence.CanonicalVersion,
		"entries":           items,
	}
	h, err := evidence.Hash(obj)
	if err != nil {
		return "", fmt.Errorf("snapshot: 計算 tree hash: %w", err)
	}
	return h, nil
}

// snapshotID 由 tree hash 取前 12 hex 組成 "SN-…"（內容位址，§21.2）。
func snapshotID(treeHash string) (string, error) {
	const hexLen = 12
	hex := strings.TrimPrefix(treeHash, "sha256:")
	if len(hex) < hexLen {
		return "", fmt.Errorf("snapshot: tree hash 長度不足: %q", treeHash)
	}
	return "SN-" + hex[:hexLen], nil
}

// excluded 回報 rel（"/" 分隔相對路徑）是否命中 exclude 規則。
// 規則為「路徑前綴比對」但以路徑段為界：exclude "build" 命中 "build" 與 "build/x.go"，
// 不命中 "build.go"／"builder"。
func excluded(rel string, exs []string) bool {
	base := filepath.Base(rel)
	if strings.HasSuffix(base, ".pyc") {
		return true
	}
	for _, suffix := range []string{".pem", ".key", ".p12", ".pfx", ".jks"} {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	for _, name := range []string{"id_rsa", "id_ed25519", "id_ecdsa", "credentials.json"} {
		if base == name {
			return true
		}
	}
	for _, e := range exs {
		if rel == e || strings.HasPrefix(rel, e+"/") {
			return true
		}
	}
	return false
}

// normalizeExcludes 正規化 exclude 清單：去空白、ToSlash、去 "./" 前綴與結尾 "/"，
// 丟棄空字串。正規化後才能與相對路徑穩定比對。
func normalizeExcludes(excludes []string) ([]string, error) {
	out := make([]string, 0, len(excludes))
	for _, e := range excludes {
		e = strings.TrimSpace(filepath.ToSlash(e))
		e = strings.TrimPrefix(e, "./")
		e = strings.TrimSuffix(e, "/")
		if e == "" || e == "." {
			continue
		}
		// 防路徑逃逸：exclude 規則不該指向快照外。
		if strings.HasPrefix(e, "/") || strings.HasPrefix(e, "../") || strings.Contains(e, "/../") {
			return nil, fmt.Errorf("snapshot: 不合法的 exclude 規則 %q", e)
		}
		out = append(out, e)
	}
	return out, nil
}
