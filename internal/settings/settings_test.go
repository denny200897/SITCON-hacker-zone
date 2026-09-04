package settings

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// loadMissingOK：檔案不存在 → 空 Config + nil error（§3.1 任一層缺檔非錯誤）。
func TestLoadMissingOK(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "aegis.toml"))
	if err != nil {
		t.Fatalf("Load missing file: err = %v, want nil", err)
	}
	if cfg == nil {
		t.Fatal("Load missing file: cfg = nil, want non-nil empty Config")
	}
	if len(cfg.Providers) != 0 || len(cfg.Models) != 0 {
		t.Fatalf("empty Config has entries: providers=%v models=%v", cfg.Providers, cfg.Models)
	}
	if cfg.Providers == nil || cfg.Models == nil {
		t.Fatal("empty Config maps must be non-nil so callers can write into them")
	}
}

// loadMalformedErr：TOML 語法錯誤必須回傳錯誤（不得靜默吞掉）。
func TestLoadMalformedErr(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aegis.toml")
	bad := "providers = [not closed\n[[models]]\nkey ="
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load malformed TOML: err = nil, want error")
	}
}

// saveUserMode：使用者層級檔權限必須為 0600（§3.3 credentials 同款 restrictive
// 慣例；此檔可能與憑證同目錄，測試鎖定）。
func TestSaveUserMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose POSIX mode bits")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "aegis", "settings.toml")
	if err := SaveUser(path, testConfig()); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("saved file perm = %o, want 600", got)
	}
}

// saveUserRoundtrip：Save → Load 往返一致（欄位值與 map 內容不變）。
func TestSaveUserRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.toml")
	want := testConfig()
	if err := SaveUser(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Providers) != len(want.Providers) || len(got.Models) != len(want.Models) {
		t.Fatalf("roundtrip size mismatch: got %d/%d want %d/%d",
			len(got.Providers), len(got.Models), len(want.Providers), len(want.Models))
	}
	for name, p := range want.Providers {
		if gp, ok := got.Providers[name]; !ok || gp != p {
			t.Fatalf("provider %q roundtrip = %+v (present=%t), want %+v", name, gp, ok, p)
		}
	}
	for role, ref := range want.Models {
		if gr, ok := got.Models[role]; !ok || gr != ref {
			t.Fatalf("model role %q roundtrip = %q (present=%t), want %q", role, gr, ok, ref)
		}
	}
}

// saveUserStableBytes：同一 cfg 存兩次 → 位元組完全相同（確定鍵序，§5.4）。
func TestSaveUserStableBytes(t *testing.T) {
	dir := t.TempDir()
	p1 := filepath.Join(dir, "one.toml")
	p2 := filepath.Join(dir, "two.toml")
	if err := SaveUser(p1, testConfig()); err != nil {
		t.Fatal(err)
	}
	if err := SaveUser(p2, testConfig()); err != nil {
		t.Fatal(err)
	}
	b1, err := os.ReadFile(p1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := os.ReadFile(p2)
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Fatalf("SaveUser not byte-stable:\n--- first ---\n%s\n--- second ---\n%s", b1, b2)
	}
	// 鍵序必須排序：字典序較前的供應商名應先出現（byte-stable 的真源）。
	one, two := strings.Index(string(b1), "anthropic"), strings.Index(string(b1), "my-ollama")
	if one == -1 || two == -1 || one > two {
		t.Fatalf("provider keys not sorted in output:\n%s", b1)
	}
}

// resolvePrecedence：repo aegis.toml > 使用者 settings.toml > 無（§3.1 解析序）。
func TestResolveModelPrecedence(t *testing.T) {
	repo := &Config{Models: map[string]string{RoleProver: "anthropic/claude-opus-5"}}
	user := &Config{Models: map[string]string{RoleProver: "my-ollama/qwen3:32b"}}

	ref, source, err := ResolveModel(repo, user, RoleProver)
	if err != nil || ref != "anthropic/claude-opus-5" || source != "repo" {
		t.Fatalf("repo precedence: (%q, %q, %v), want (anthropic/..., repo, nil)", ref, source, err)
	}

	ref, source, err = ResolveModel(nil, user, RoleProver)
	if err != nil || ref != "my-ollama/qwen3:32b" || source != "user" {
		t.Fatalf("user fallback: (%q, %q, %v), want (my-ollama/..., user, nil)", ref, source, err)
	}

	// 同層缺 role、另一層有 → 落到有定義的那層（只檢查實際需要的 role，§3.1）。
	repoOnly := &Config{Models: map[string]string{RoleProver: "anthropic/claude-opus-5"}}
	ref, source, err = ResolveModel(repoOnly, &Config{Models: map[string]string{RoleReporter: "x/y"}}, RoleProver)
	if err != nil || source != "repo" {
		t.Fatalf("per-role lookup: (%q, %q, %v), want repo value", ref, source, err)
	}
}

// resolveUnset：兩層皆無 → ("", "", ErrModelUnset) sentinel，errors.Is 可判別。
func TestResolveModelUnset(t *testing.T) {
	ref, source, err := ResolveModel(nil, nil, RoleTriager)
	if err == nil || ref != "" || source != "" {
		t.Fatalf("unset: (%q, %q, %v), want (\"\", \"\", ErrModelUnset)", ref, source, err)
	}
	if !errors.Is(err, ErrModelUnset) {
		t.Fatalf("err = %v, want errors.Is(ErrModelUnset)", err)
	}
}

// validateRefCases：§3.1 "<provider>/<model-id>" 語法的接受／拒絕閉集。
func TestValidateRefCases(t *testing.T) {
	valid := []string{
		"anthropic/claude-opus-5",
		"my-ollama/qwen3:32b",
		"a/b",                             // 兩段最短合法形
		"openrouter/deepseek/deepseek-r1", // ASK 註記：model-id 含 '/' 目前允許（首個 '/' 切分）
	}
	for _, ref := range valid {
		if err := ValidateRef(ref); err != nil {
			t.Errorf("ValidateRef(%q) = %v, want nil", ref, err)
		}
	}
	invalid := []string{
		"",                   // 空串
		"claude-opus-5",      // 無 '/'
		"/claude-opus-5",     // provider 空
		"anthropic/",         // model-id 空
		"anthropic/",         // 同上（重複保險）
		"/",                  // 兩段皆空
		"anthropic /claude",  // provider 內含空白
		"anthropic/claude 5", // model-id 內含空白
		" anthropic/claude",  // 前導空白
		"anthropic/claude\n", // 尾端換行
	}
	for _, ref := range invalid {
		if err := ValidateRef(ref); err == nil {
			t.Errorf("ValidateRef(%q) = nil, want error", ref)
		}
	}
}

// defaultUserDirXDG：XDG_CONFIG_HOME 覆寫必須生效（t.Setenv 隔離，不污染環境）。
func TestDefaultUserDirRespectsXDG(t *testing.T) {
	xdg := filepath.Join(t.TempDir(), "xdg-config")
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv("HOME", "/home/aegis-test")

	dir, err := DefaultUserDir()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(xdg, "aegis"); dir != want {
		t.Fatalf("DefaultUserDir() with XDG = %q, want %q", dir, want)
	}
	user, err := DefaultUserPath()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(xdg, "aegis", "settings.toml"); user != want {
		t.Fatalf("DefaultUserPath() = %q, want %q", user, want)
	}
	cred, err := DefaultCredentialsPath()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(xdg, "aegis", "credentials.toml"); cred != want {
		t.Fatalf("DefaultCredentialsPath() = %q, want %q", cred, want)
	}
}

// defaultUserDirHome：XDG 未設時退回 ~/.config（§3.3 固定路徑）。
func TestDefaultUserDirFallsBackToHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.UserHomeDir uses the Windows profile API")
	}
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "/home/aegis-test")

	dir, err := DefaultUserDir()
	if err != nil {
		t.Fatal(err)
	}
	if want := "/home/aegis-test/.config/aegis"; dir != want {
		t.Fatalf("DefaultUserDir() fallback = %q, want %q", dir, want)
	}
}

// testConfig 是測試用組態：鍵序刻意「非字典序」插入，鎖定排序輸出。
func testConfig() *Config {
	return &Config{
		Providers: map[string]Provider{
			"my-ollama": {Type: "openai-compat", BaseURL: "http://127.0.0.1:11434/v1"},
			"anthropic": {Type: "anthropic"},
		},
		Models: map[string]string{
			RoleReporter: "anthropic/claude-sonnet-5",
			RoleRecon:    "anthropic/claude-haiku-4-5",
			RoleProver:   "anthropic/claude-opus-5",
			RoleReviewer: "anthropic/claude-sonnet-5",
			RoleTriager:  "anthropic/claude-sonnet-5",
		},
	}
}
