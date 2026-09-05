package snapshot

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hashFile 計算檔案內容的 sha256 hex（測試比對 ID 是否隨內容變動用）。
func hashFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀取 %s: %v", path, err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

// writeRepo 在 dir 建出固定 fixture：根檔案 + 巢狀目錄 + 內容可預期。
func writeRepo(t *testing.T, dir string) {
	t.Helper()
	mk := func(rel, content string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("建目錄 %s: %v", rel, err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("寫檔 %s: %v", rel, err)
		}
	}
	mk("README.md", "hello aegis")
	mk("src/main.py", "print('hi')\n")
	mk("src/pkg/util.py", "def f():\n    return 1\n")
	mk("docs/guide.md", "# guide\n")
}

// walkSnapshot 收集快照目錄內的相對路徑清單（含 symlink，型態一併回報）。
func walkSnapshot(t *testing.T, root string) map[string]os.FileMode {
	t.Helper()
	out := map[string]os.FileMode{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		info, err := os.Lstat(p) // 測試也用 Lstat，不跟隨
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = info.Mode()
		return nil
	})
	if err != nil {
		t.Fatalf("走訪快照 %s: %v", root, err)
	}
	return out
}

func TestCreateCopiesFilesAndNestedDirs(t *testing.T) {
	repo := t.TempDir()
	writeRepo(t, repo)
	cache := t.TempDir()

	s, err := Create(repo, cache, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !strings.HasPrefix(s.ID, "SN-") || len(s.ID) != len("SN-")+12 {
		t.Errorf("snapshot ID 格式錯誤: %q", s.ID)
	}
	if !strings.HasPrefix(s.TreeHash, "sha256:") {
		t.Errorf("tree hash 前綴錯誤: %q", s.TreeHash)
	}
	if s.Dir != filepath.Join(cache, "snapshots", s.ID) {
		t.Errorf("Dir = %q, 期望 cacheDir/snapshots/<ID>", s.Dir)
	}
	got := walkSnapshot(t, s.Dir)
	want := map[string]os.FileMode{
		"README.md":       0o644,
		"src":             os.ModeDir,
		"src/main.py":     0o644,
		"src/pkg":         os.ModeDir,
		"src/pkg/util.py": 0o644,
		"docs":            os.ModeDir,
		"docs/guide.md":   0o644,
	}
	for p, m := range want {
		gm, ok := got[p]
		if !ok {
			t.Errorf("快照缺少 %q", p)
			continue
		}
		if m.IsDir() != gm.IsDir() {
			t.Errorf("%q 型態不符: 期望 dir=%v got %v", p, m.IsDir(), gm)
		}
	}
	if len(got) != len(want) {
		t.Errorf("快照項目數 = %d, 期望 %d（多出: %v）", len(got), len(want), diffKeys(got, want))
	}
	if c := hashFile(t, filepath.Join(s.Dir, "src", "pkg", "util.py")); c != hashFile(t, filepath.Join(repo, "src", "pkg", "util.py")) {
		t.Error("巢狀檔案內容未正確複製")
	}
}

func TestCreateExcludesGitAndExcludeList(t *testing.T) {
	repo := t.TempDir()
	writeRepo(t, repo)
	mk := func(rel, content string) {
		p := filepath.Join(repo, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk(".git/HEAD", "ref: refs/heads/main\n")
	mk(".env", "SECRET=1\n")
	mk("build/out.bin", "binary")
	mk("src/gen/tables.go", "generated")
	cache := t.TempDir()

	s, err := Create(repo, cache, []string{".env", "build", "src/gen"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got := walkSnapshot(t, s.Dir)
	for _, banned := range []string{".git", ".git/HEAD", ".env", "build", "build/out.bin", "src/gen", "src/gen/tables.go"} {
		if _, ok := got[banned]; ok {
			t.Errorf("%q 不應出現在快照", banned)
		}
	}
	if _, ok := got["src/main.py"]; !ok {
		t.Error("exclude 不應誤傷未排除檔案（src/main.py 缺失）")
	}
}

func TestCreateExcludePrefixIsSegmentAware(t *testing.T) {
	repo := t.TempDir()
	mk := func(rel, content string) {
		p := filepath.Join(repo, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("build/keep.txt", "in build")     // 應被排除
	mk("build.go", "sibling")            // 不應被 "build" 排除
	mk("builder/keep.txt", "in builder") // 不應被 "build" 排除
	mk("a/b/deep.txt", "deep")           // 應被 "a/b" 排除
	mk("a/bc/keep.txt", "in a/bc")       // 不應被 "a/b" 排除
	cache := t.TempDir()

	s, err := Create(repo, cache, []string{"build", "a/b"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got := walkSnapshot(t, s.Dir)
	if _, ok := got["build/keep.txt"]; ok {
		t.Error("build/keep.txt 應被排除")
	}
	for _, want := range []string{"build.go", "builder/keep.txt", "a/bc/keep.txt"} {
		if _, ok := got[want]; !ok {
			t.Errorf("%q 不應被前綴規則誤傷", want)
		}
	}
	if _, ok := got["a/b/deep.txt"]; ok {
		t.Error("a/b/deep.txt 應被排除")
	}
}

func TestCreateRejectsExternalSymlinkAndPreservesInternalSymlink(t *testing.T) {
	repo := t.TempDir()
	writeRepo(t, repo)
	// repo 外的檔案，供 symlink 指向——若實作跟隨 symlink 就會把外部內容複製進快照。
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outside, []byte("TOP SECRET"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(repo, "link.txt")); err != nil {
		t.Skipf("host cannot create symlinks: %v", err)
	}
	// repo 內相對 symlink 也要原樣保留。
	if err := os.WriteFile(filepath.Join(repo, "target.txt"), []byte("inside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target.txt", filepath.Join(repo, "rel-link.txt")); err != nil {
		t.Fatal(err)
	}
	cache := t.TempDir()

	if _, err := Create(repo, cache, nil); err == nil {
		t.Fatal("指向 repo 外的 symlink 應 fail closed")
	}
	if err := os.Remove(filepath.Join(repo, "link.txt")); err != nil {
		t.Fatal(err)
	}
	s, err := Create(repo, cache, nil)
	if err != nil {
		t.Fatalf("移除外部 symlink 後 Create: %v", err)
	}

	// repo 內 symlink 仍是 symlink，target 原樣保留。
	link := filepath.Join(s.Dir, "rel-link.txt")
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("Lstat rel-link.txt: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("rel-link.txt 應為 symlink，實際 mode = %v（被跟隨成實體檔？）", info.Mode())
	}
	if got, err := os.Readlink(link); err != nil || got != "target.txt" {
		t.Errorf("link target = %q, err = %v, 期望原樣 target.txt", got, err)
	}
	// 外部檔案內容絕不可被實體複製進快照。
	entries := walkSnapshot(t, s.Dir)
	for p, m := range entries {
		if m.IsRegular() && strings.Contains(p, "secret") {
			t.Errorf("外部檔案被複製進快照: %q", p)
		}
	}
	if b, err := os.ReadFile(filepath.Join(s.Dir, "secret.txt")); err == nil && string(b) == "TOP SECRET" {
		t.Error("symlink 被跟隨：外部內容出現在快照中")
	}
	// symlink 本身仍在清單中且不會被當一般檔複製。
	if _, ok := entries["rel-link.txt"]; !ok {
		t.Error("rel-link.txt 應存在於快照")
	}
}

func TestCreateSameContentReusesSnapshot(t *testing.T) {
	repo := t.TempDir()
	writeRepo(t, repo)
	cache := t.TempDir()

	s1, err := Create(repo, cache, nil)
	if err != nil {
		t.Fatalf("第一次 Create: %v", err)
	}
	s2, err := Create(repo, cache, nil)
	if err != nil {
		t.Fatalf("第二次 Create: %v", err)
	}
	if s1.ID != s2.ID || s1.Dir != s2.Dir || s1.TreeHash != s2.TreeHash {
		t.Errorf("同內容應回相同 snapshot：s1=%+v s2=%+v", s1, s2)
	}
	// 暫存目錄不應殘留。
	rest, err := os.ReadDir(filepath.Join(cache, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range rest {
		if strings.HasPrefix(e.Name(), ".staging-") {
			t.Errorf("暫存目錄殘留: %s", e.Name())
		}
	}
}

func TestCreateIsPathIndependent(t *testing.T) {
	repoA := t.TempDir()
	writeRepo(t, repoA)
	repoB := t.TempDir()
	writeRepo(t, repoB)
	cacheA := t.TempDir()
	cacheB := t.TempDir()

	sa, err := Create(repoA, cacheA, nil)
	if err != nil {
		t.Fatalf("Create A: %v", err)
	}
	sb, err := Create(repoB, cacheB, nil)
	if err != nil {
		t.Fatalf("Create B: %v", err)
	}
	if sa.ID != sb.ID {
		t.Errorf("同內容不同路徑應得相同內容位址：%s vs %s", sa.ID, sb.ID)
	}
}

func TestCreateContentChangeChangesID(t *testing.T) {
	repo := t.TempDir()
	writeRepo(t, repo)
	cache := t.TempDir()

	s1, err := Create(repo, cache, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "src", "main.py"), []byte("print('changed')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s2, err := Create(repo, cache, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s1.ID == s2.ID {
		t.Error("內容改動後 snapshot ID 不應相同")
	}
	if s1.TreeHash == s2.TreeHash {
		t.Error("內容改動後 tree hash 不應相同")
	}
	// 兩個快照各自存在：舊快照保留改動前內容，新快照是新內容。
	old, new := hashFile(t, filepath.Join(s1.Dir, "src", "main.py")), hashFile(t, filepath.Join(s2.Dir, "src", "main.py"))
	if old == new {
		t.Error("新舊快照的檔案內容應不同")
	}
}

func TestCreateRejectsTamperedReusableSnapshot(t *testing.T) {
	repo := t.TempDir()
	writeRepo(t, repo)
	cache := t.TempDir()
	s, err := Create(repo, cache, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Dir, "src", "main.py"), []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(repo, cache, nil); err == nil {
		t.Fatal("遭竄改的同 ID snapshot 不得重用")
	}
}

func TestCreateEmptyRepo(t *testing.T) {
	repo := t.TempDir() // 空目錄
	cache := t.TempDir()

	s, err := Create(repo, cache, nil)
	if err != nil {
		t.Fatalf("空 repo Create: %v", err)
	}
	if !strings.HasPrefix(s.ID, "SN-") || len(s.ID) != 15 {
		t.Errorf("空 repo 的 ID 格式錯誤: %q", s.ID)
	}
	entries := walkSnapshot(t, s.Dir)
	if len(entries) != 0 {
		t.Errorf("空 repo 快照應為空，實際 %v", entries)
	}
	// 空 repo 的 ID 也是穩定的。
	s2, err := Create(repo, cache, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s2.ID != s.ID {
		t.Error("空 repo 兩次快照 ID 應相同")
	}
}

func TestCreateRejectsBadInputs(t *testing.T) {
	if _, err := Create(filepath.Join(t.TempDir(), "missing"), t.TempDir(), nil); err == nil {
		t.Error("不存在的 repoRoot 應回傳錯誤")
	}
	notDir := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(notDir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(notDir, t.TempDir(), nil); err == nil {
		t.Error("repoRoot 為檔案時應回傳錯誤")
	}
	repo := t.TempDir()
	writeRepo(t, repo)
	if _, err := Create(repo, t.TempDir(), []string{"../escape"}); err == nil {
		t.Error("指向快照外的 exclude 規則應被拒絕")
	}
	if _, err := Create(repo, "", nil); err == nil {
		t.Error("空 cacheDir 應回傳錯誤")
	}
}

func TestCreateNeverCopiesPrivateKeyFiles(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "server.pem"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "id_ed25519"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "app.py"), []byte("print('ok')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Create(repo, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "server.pem")); !os.IsNotExist(err) {
		t.Fatalf("server.pem 被複製：%v", err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "id_ed25519")); !os.IsNotExist(err) {
		t.Fatalf("id_ed25519 被複製：%v", err)
	}
}

func TestSnapshotIDIsDeterministicOnTreeHash(t *testing.T) {
	h := "sha256:abcdef0123456789ffffffffffffffffffffffffffffffffffffffffffff"
	id, err := snapshotID(h)
	if err != nil {
		t.Fatalf("snapshotID: %v", err)
	}
	if id != "SN-abcdef012345" {
		t.Errorf("snapshotID = %q, 期望 SN-abcdef012345", id)
	}
}

func diffKeys(a, b map[string]os.FileMode) []string {
	var out []string
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, k)
		}
	}
	return out
}
