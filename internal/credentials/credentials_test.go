package credentials

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeEnviron 產生注入 Manager 的假環境讀取函式（避免動到真實 process 環境）。
func fakeEnviron(env map[string]string) func(string) string {
	return func(name string) string { return env[name] }
}

// failingKeyring 是 Set／Get／Delete 一律失敗的 stub：模擬 keychain 不可用
//（§3.3 退回檔案模式的觸發條件），也確保測試永不觸碰真實 OS keychain。
type failingKeyring struct{ err error }

func (f failingKeyring) Get(string, string) (string, error)  { return "", f.err }
func (f failingKeyring) Set(string, string, string) error    { return f.err }
func (f failingKeyring) Delete(string, string) error         { return f.err }

// TestEnvVarNameNormalization 驗 §3.3 正規化：非英數字元一律轉 '_' 後全大寫，
// 前綴 AEGIS_、後綴 _API_KEY（spec 例：my-openrouter → AEGIS_MY_OPENROUTER_API_KEY）。
func TestEnvVarNameNormalization(t *testing.T) {
	cases := []struct{ in, want string }{
		{"my-openrouter", "AEGIS_MY_OPENROUTER_API_KEY"},
		{"openrouter", "AEGIS_OPENROUTER_API_KEY"},
		{"my_ollama", "AEGIS_MY_OLLAMA_API_KEY"},
		{"my.ollama:32b", "AEGIS_MY_OLLAMA_32B_API_KEY"},
		{"My Provider 2", "AEGIS_MY_PROVIDER_2_API_KEY"},
		{"", "AEGIS__API_KEY"},
	}
	for _, c := range cases {
		if got := EnvVarName(c.in); got != c.want {
			t.Errorf("EnvVarName(%q) = %q, want %q（§3.3 正規化）", c.in, got, c.want)
		}
	}
}

// TestCompatEnvVar 驗 §3.3 相容辨識的慣用環境變數名與閉集行為。
func TestCompatEnvVar(t *testing.T) {
	if got := CompatEnvVar(ProviderTypeAnthropic); got != "ANTHROPIC_API_KEY" {
		t.Errorf("anthropic compat = %q, want ANTHROPIC_API_KEY（§3.3）", got)
	}
	if got := CompatEnvVar(ProviderTypeOpenAICompat); got != "OPENAI_API_KEY" {
		t.Errorf("openai-compat compat = %q, want OPENAI_API_KEY（§3.3）", got)
	}
	if got := CompatEnvVar(ProviderType("nope")); got != "" {
		t.Errorf("未知類型 compat = %q, want 空字串（閉集外）", got)
	}
}

// TestResolveEnv 驗環境變數解析：正規化名優先，慣用相容名為後備（§3.3）。
func TestResolveEnv(t *testing.T) {
	// 正規化名命中。
	m := &Manager{Environ: fakeEnviron(map[string]string{"AEGIS_MY_OPENROUTER_API_KEY": "k1"})}
	key, source, err := m.Resolve("my-openrouter", ProviderTypeOpenAICompat)
	if err != nil || key != "k1" || source != "env" {
		t.Fatalf("Resolve = (%q, %q, %v), want (k1, env, nil)（§3.3 環境變數）", key, source, err)
	}
	// 相容名後備：正規化名缺席時用 ANTHROPIC_API_KEY。
	m = &Manager{Environ: fakeEnviron(map[string]string{"ANTHROPIC_API_KEY": "k2"})}
	key, source, err = m.Resolve("anthropic", ProviderTypeAnthropic)
	if err != nil || key != "k2" || source != "env" {
		t.Fatalf("Resolve = (%q, %q, %v), want (k2, env, nil)（§3.3 相容辨識）", key, source, err)
	}
	// 兩者並存時正規化名優先。
	m = &Manager{Environ: fakeEnviron(map[string]string{
		"AEGIS_ANTHROPIC_API_KEY": "norm",
		"ANTHROPIC_API_KEY":       "compat",
	})}
	key, _, err = m.Resolve("anthropic", ProviderTypeAnthropic)
	if err != nil || key != "norm" {
		t.Fatalf("Resolve key = %q, want norm（正規化名優先於相容名，§3.3）", key)
	}
}

// TestResolveOrder 驗解析優先序（§3.3）：環境變數 > OS keychain > 設定檔退回。
func TestResolveOrder(t *testing.T) {
	dir := t.TempDir()
	fs := &FileStore{Path: filepath.Join(dir, "credentials.toml")}
	if err := fs.Set("p1", "from-file"); err != nil {
		t.Fatalf("FileStore.Set: %v", err)
	}
	kr := NewMemoryKeyring()
	if err := kr.Set(KeyringService, "p1", "from-keychain"); err != nil {
		t.Fatalf("MemoryKeyring.Set: %v", err)
	}

	// 三層都在 → env。
	m := &Manager{Keyring: kr, File: fs, Environ: fakeEnviron(map[string]string{"AEGIS_P1_API_KEY": "from-env"})}
	if key, source, err := m.Resolve("p1", ProviderTypeOpenAICompat); err != nil || key != "from-env" || source != "env" {
		t.Fatalf("Resolve = (%q, %q, %v), want env 優先（§3.3）", key, source, err)
	}
	// 兩層都在（無 env）→ keychain。
	m = &Manager{Keyring: kr, File: fs}
	if key, source, err := m.Resolve("p1", ProviderTypeOpenAICompat); err != nil || key != "from-keychain" || source != "keychain" {
		t.Fatalf("Resolve = (%q, %q, %v), want keychain 次之（§3.3）", key, source, err)
	}
	// 只剩檔案（無 env、無 keychain）→ file。
	m = &Manager{File: fs}
	if key, source, err := m.Resolve("p1", ProviderTypeOpenAICompat); err != nil || key != "from-file" || source != "file" {
		t.Fatalf("Resolve = (%q, %q, %v), want file 退回（§3.3）", key, source, err)
	}
}

// TestResolveNotFound 驗三層皆缺時回傳 ErrKeyNotFound 且 source 為空。
func TestResolveNotFound(t *testing.T) {
	fs := &FileStore{Path: filepath.Join(t.TempDir(), "credentials.toml")}
	m := &Manager{Keyring: NewMemoryKeyring(), File: fs, Environ: fakeEnviron(nil)}
	key, source, err := m.Resolve("ghost", ProviderTypeOpenAICompat)
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("err = %v, want ErrKeyNotFound（§3.3）", err)
	}
	if key != "" || source != "" {
		t.Fatalf("(key, source) = (%q, %q), want 空（找不到時不得殘留內容）", key, source)
	}
}

// TestResolveKeychainUnavailable 驗 keychain 查詢故障（非「不存在」）時退回檔案
//（§3.3：無 keychain 環境退回設定檔——見 manager.go 的 ASK 註記）。
func TestResolveKeychainUnavailable(t *testing.T) {
	dir := t.TempDir()
	fs := &FileStore{Path: filepath.Join(dir, "credentials.toml")}
	if err := fs.Set("p1", "from-file"); err != nil {
		t.Fatalf("FileStore.Set: %v", err)
	}
	broken := failingKeyring{err: errors.New("keychain daemon down")}
	m := &Manager{Keyring: broken, File: fs}
	if key, source, err := m.Resolve("p1", ProviderTypeOpenAICompat); err != nil || key != "from-file" || source != "file" {
		t.Fatalf("Resolve = (%q, %q, %v), want 檔案退回（§3.3）", key, source, err)
	}
}

// TestMemoryKeyringSetGetDelete 驗記憶體 Keyring 的基本生命週期（測試專用後端，
// 不觸碰真實 OS keychain，§3.3）。
func TestMemoryKeyringSetGetDelete(t *testing.T) {
	kr := NewMemoryKeyring()
	if _, err := kr.Get(KeyringService, "p1"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("初始 Get err = %v, want ErrKeyNotFound", err)
	}
	if err := kr.Set(KeyringService, "p1", "tok"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if v, err := kr.Get(KeyringService, "p1"); err != nil || v != "tok" {
		t.Fatalf("Get = (%q, %v), want (tok, nil)", v, err)
	}
	// 覆寫。
	if err := kr.Set(KeyringService, "p1", "tok2"); err != nil {
		t.Fatalf("Set overwrite: %v", err)
	}
	if v, _ := kr.Get(KeyringService, "p1"); v != "tok2" {
		t.Fatalf("Get = %q, want tok2（覆寫）", v)
	}
	// Delete：存在 → 成功、其後不存在；不存在 → ErrKeyNotFound。
	if err := kr.Delete(KeyringService, "p1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := kr.Get(KeyringService, "p1"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Delete 後 Get err = %v, want ErrKeyNotFound", err)
	}
	if err := kr.Delete(KeyringService, "p1"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Delete 不存在 err = %v, want ErrKeyNotFound", err)
	}
}

// TestFileStorePermissionAndFormat 驗 §3.3：credentials.toml 權限 0600
//（Set 與 Delete 之後都是；放寬過的權限也會被收回）、檔案格式為 [keys] 表。
func TestFileStorePermissionAndFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.toml")
	fs := &FileStore{Path: path}
	if err := fs.Set("my-openrouter", "tok-1"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	assertPerm0600(t, path)
	// 故意放寬權限後再寫，0600 必須被收回（顯式 chmod，§3.3）。
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if err := fs.Set("other", "tok-2"); err != nil {
		t.Fatalf("Set second: %v", err)
	}
	assertPerm0600(t, path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), "[keys]") {
		t.Fatalf("檔案缺少 [keys] 表（§3.3 格式）:\n%s", data)
	}

	// Delete 之後仍維持 0600，且其他條目保留（§3.3）。
	if err := fs.Delete("my-openrouter"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	assertPerm0600(t, path)
	if v, err := fs.Get("other"); err != nil || v != "tok-2" {
		t.Fatalf("Get(other) = (%q, %v), want 保留其他條目", v, err)
	}
}

func assertPerm0600(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat %s: %v", path, err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("%s 權限 = %v, want 0600（§3.3 設定檔退回權限）", path, got)
	}
}

// TestFileStoreWarnOnce 驗 §3.3「使用時警告一次」：多於一次成功 Get 只發一次，
// 且警告訊息永不包含金鑰內容（§23 金鑰防洩）。
func TestFileStoreWarnOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.toml")
	var warn bytes.Buffer
	fs := &FileStore{Path: path, Warn: &warn}
	if err := fs.Set("p1", "super-secret-token"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := fs.Get("p1"); err != nil {
			t.Fatalf("Get #%d: %v", i, err)
		}
	}
	if got := strings.Count(warn.String(), "\n"); got != 1 {
		t.Fatalf("警告次數 = %d, want 1（§3.3 警告一次）", got)
	}
	msg := warn.String()
	if strings.Contains(msg, "super-secret-token") {
		t.Fatalf("警告訊息包含金鑰內容（§23 金鑰防洩）: %q", msg)
	}
	if !strings.Contains(msg, "credentials.toml") || !strings.Contains(msg, "0600") {
		t.Fatalf("警告訊息應含路徑與權限提示: %q", msg)
	}
	// Warn 為 nil 時不得 panic。
	fs2 := &FileStore{Path: path}
	if _, err := fs2.Get("p1"); err != nil {
		t.Fatalf("Get（無 Warn）: %v", err)
	}
}

// TestFileStoreMissing 驟檔案／條目缺漏回傳 ErrKeyNotFound。
func TestFileStoreMissing(t *testing.T) {
	fs := &FileStore{Path: filepath.Join(t.TempDir(), "credentials.toml")}
	if _, err := fs.Get("p1"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("無檔案 Get err = %v, want ErrKeyNotFound", err)
	}
	if err := fs.Delete("p1"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("無檔案 Delete err = %v, want ErrKeyNotFound", err)
	}
}

// TestSetFallsBackToFile 驗 Manager.Set：keychain 不可用時退回檔案模式
//（§3.3／§23 相依表）；檔案退回也失敗時錯誤包裝兩段細節。
func TestSetFallsBackToFile(t *testing.T) {
	dir := t.TempDir()
	fs := &FileStore{Path: filepath.Join(dir, "credentials.toml")}
	broken := failingKeyring{err: errors.New("keychain unavailable")}

	// keychain 失敗 + 檔案成功 → 金鑰落於檔案（退回模式）。
	m := &Manager{Keyring: broken, File: fs}
	if err := m.Set("p1", ProviderTypeOpenAICompat, "tok"); err != nil {
		t.Fatalf("Set（退回檔案）: %v", err)
	}
	if v, err := fs.Get("p1"); err != nil || v != "tok" {
		t.Fatalf("檔案退回後 Get = (%q, %v), want tok", v, err)
	}

	// keychain 失敗 + 無檔案儲存 → 回傳包裝 keychain 錯誤。
	m = &Manager{Keyring: broken}
	err := m.Set("p1", ProviderTypeOpenAICompat, "tok")
	if err == nil || !strings.Contains(err.Error(), "keychain unavailable") {
		t.Fatalf("Set err = %v, want 含 keychain 失敗細節", err)
	}

	// keychain 失敗 + 檔案也失敗（路徑中間被一般檔案擋住，MkdirAll 必敗）
	// → 錯誤含兩段細節。
	obstruction := filepath.Join(dir, "obstruction")
	if err := os.WriteFile(obstruction, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fsBad := &FileStore{Path: filepath.Join(obstruction, "x", "credentials.toml")}
	m = &Manager{Keyring: broken, File: fsBad}
	err = m.Set("p1", ProviderTypeOpenAICompat, "tok")
	if err == nil || !strings.Contains(err.Error(), "keychain") || !strings.Contains(err.Error(), "fallback") {
		t.Fatalf("Set err = %v, want 同時含 keychain 與 fallback 失敗細節", err)
	}

	// Keyring nil → 僅寫檔案（§3.3 設定檔退回）。
	m = &Manager{File: fs}
	if err := m.Set("p2", ProviderTypeOpenAICompat, "tok-nil"); err != nil {
		t.Fatalf("Set（僅檔案）: %v", err)
	}
	if v, _ := fs.Get("p2"); v != "tok-nil" {
		t.Fatalf("Get = %q, want tok-nil", v)
	}
}

// TestSetToKeychain 驟 keychain 可用時 Set 直寫 keychain、不落盤。
func TestSetToKeychain(t *testing.T) {
	kr := NewMemoryKeyring()
	fs := &FileStore{Path: filepath.Join(t.TempDir(), "credentials.toml")}
	m := &Manager{Keyring: kr, File: fs}
	if err := m.Set("p1", ProviderTypeAnthropic, "tok"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if v, err := kr.Get(KeyringService, "p1"); err != nil || v != "tok" {
		t.Fatalf("keychain Get = (%q, %v), want tok", v, err)
	}
	if _, err := fs.Get("p1"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("檔案不應有條目: err = %v", err)
	}
}

// TestClear 驟 Clear 同時清 keychain 與檔案，且對「不存在」冪等（§3.3 /key clear）。
func TestClear(t *testing.T) {
	kr := NewMemoryKeyring()
	fs := &FileStore{Path: filepath.Join(t.TempDir(), "credentials.toml")}
	m := &Manager{Keyring: kr, File: fs}
	if err := kr.Set(KeyringService, "p1", "kc"); err != nil {
		t.Fatalf("keychain Set: %v", err)
	}
	if err := fs.Set("p1", "file"); err != nil {
		t.Fatalf("file Set: %v", err)
	}
	if err := m.Clear("p1", ProviderTypeOpenAICompat); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if _, err := kr.Get(KeyringService, "p1"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("keychain 未清: err = %v", err)
	}
	if _, err := fs.Get("p1"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("檔案未清: err = %v", err)
	}
	// 再清一次（兩層都不存在）→ 仍為成功（ErrKeyNotFound 容忍）。
	if err := m.Clear("p1", ProviderTypeOpenAICompat); err != nil {
		t.Fatalf("Clear 冪等: %v", err)
	}
}

// TestStatusPresenceOnly 驟 Status 只回報有無與來源、永不回傳內容
//（§3.3 /provider list 只顯示有無）。
func TestStatusPresenceOnly(t *testing.T) {
	kr := NewMemoryKeyring()
	fs := &FileStore{Path: filepath.Join(t.TempDir(), "credentials.toml")}
	m := &Manager{Keyring: kr, File: fs, Environ: fakeEnviron(map[string]string{"AEGIS_P1_API_KEY": "secret-content"})}

	if set, source := m.Status("p1", ProviderTypeOpenAICompat); !set || source != "env" {
		t.Fatalf("Status = (%v, %q), want (true, env)（§3.3）", set, source)
	}
	m.Environ = fakeEnviron(nil)
	if err := kr.Set(KeyringService, "p1", "kc"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if set, source := m.Status("p1", ProviderTypeOpenAICompat); !set || source != "keychain" {
		t.Fatalf("Status = (%v, %q), want (true, keychain)", set, source)
	}
	if err := kr.Delete(KeyringService, "p1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := fs.Set("p1", "file-secret"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if set, source := m.Status("p1", ProviderTypeOpenAICompat); !set || source != "file" {
		t.Fatalf("Status = (%v, %q), want (true, file)", set, source)
	}
	if err := fs.Delete("p1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if set, source := m.Status("p1", ProviderTypeOpenAICompat); set || source != "" {
		t.Fatalf("Status = (%v, %q), want (false, \"\")（未設定）", set, source)
	}
}

// TestStatusNeverReturnsContent 驟 Status 回傳值中不出現任何金鑰字串
//（§3.3：永不顯示內容；對三種來源逐一檢查）。
func TestStatusNeverReturnsContent(t *testing.T) {
	kr := NewMemoryKeyring()
	fs := &FileStore{Path: filepath.Join(t.TempDir(), "credentials.toml")}
	m := &Manager{Keyring: kr, File: fs}
	if err := fs.Set("p1", "file-secret"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if set, _ := m.Status("p1", ProviderTypeOpenAICompat); !set {
		t.Fatal("file 來源 Status 應為 true")
	}
	if err := fs.Delete("p1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := kr.Set(KeyringService, "p1", "keychain-secret"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	set, source := m.Status("p1", ProviderTypeOpenAICompat)
	if !set || source != "keychain" {
		t.Fatalf("Status = (%v, %q), want (true, keychain)", set, source)
	}
	if strings.Contains(source, "secret") {
		t.Fatalf("source 含金鑰內容（§23）: %q", source)
	}
}