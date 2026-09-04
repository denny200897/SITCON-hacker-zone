package console

// 單元測試（SPEC §23：stdlib-only，同目錄 *_test.go）。以 strings.Reader 驅動
// Run 的輸入、bytes.Buffer 收輸出、credentials.MemoryKeyring 假 keychain、
// t.TempDir 放組態檔；不觸碰真實 OS keychain 與真實環境變數
//（t.Setenv 清空慣用金鑰變數，避免 host 環境干擾 §3.3 解析序的判定）。

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aegis-dev/aegis/internal/credentials"
	"github.com/aegis-dev/aegis/internal/doctor"
	"github.com/aegis-dev/aegis/internal/settings"
)

// newDeps 建構隔離的測試 Deps：全部路徑指向 t.TempDir、MemoryKeyring、
// 清空可能存在的慣用金鑰環境變數（§3.3 相容辨識 ANTHROPIC_API_KEY /
// OPENAI_API_KEY，測試不得被 host 環境影響）。
func newDeps(t *testing.T) (Deps, *bytes.Buffer, *credentials.MemoryKeyring) {
	t.Helper()
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "")
	dir := t.TempDir()
	out := &bytes.Buffer{}
	kr := credentials.NewMemoryKeyring()
	return Deps{
		Out:             out,
		RepoConfigPath:  filepath.Join(dir, "aegis.toml"),
		UserConfigPath:  filepath.Join(dir, "settings.toml"),
		CredentialsPath: filepath.Join(dir, "credentials.toml"),
		Keyring:         kr,
	}, out, kr
}

// run 以 input 驅動一次 REPL 會話（到 exit / EOF），回傳「本次」輸出內容。
// 多次呼叫共用同一 Deps（組態檔與 keyring 狀態延續），輸出以獨立 buffer 收集。
func run(t *testing.T, d Deps, input string) string {
	t.Helper()
	buf := &bytes.Buffer{}
	d.In = strings.NewReader(input)
	d.Out = buf
	if err := Run(d); err != nil {
		t.Fatalf("Run: err = %v, want nil", err)
	}
	return buf.String()
}

// flat 把輸出壓成單空白分隔（tabwriter 的欄位填充是不定寬度的空白，
// 斷言表格列時以壓平後的字串比對）。
func flat(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// assertAll 斷言 flat(out) 含每個 want 片段，缺任一即 Fatal。
func assertAll(t *testing.T, out string, want ...string) {
	t.Helper()
	f := flat(out)
	for _, w := range want {
		if !strings.Contains(f, w) {
			t.Fatalf("輸出缺少 %q:\n%s", w, out)
		}
	}
}

// assertNone 斷言 flat(out) 不含任一 want 片段。
func assertNone(t *testing.T, out string, want ...string) {
	t.Helper()
	f := flat(out)
	for _, w := range want {
		if strings.Contains(f, w) {
			t.Fatalf("輸出不應包含 %q:\n%s", w, out)
		}
	}
}

// secretFeeder 回傳一個依序吐出預設金鑰的 injected ReadSecret
//（§3.3 /key set 的 no-echo 輸入由 cmd 層接線，測試以佇列替代）。
// 佇列耗盡時讓測試失敗——表示腳本與指令序列不吻合。
func secretFeeder(t *testing.T, keys ...string) func(string) ([]byte, error) {
	t.Helper()
	i := 0
	return func(prompt string) ([]byte, error) {
		if i >= len(keys) {
			t.Fatalf("secretFeeder 佇列耗盡（prompt=%q）：測試腳本與指令序列不吻合", prompt)
		}
		k := keys[i]
		i++
		return []byte(k), nil
	}
}

// writeRepoConfig 寫入 repo 層 aegis.toml（§3.1：repo 層為唯讀真源，測試預置）。
func writeRepoConfig(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// providerRoundtrip：/provider add → list → remove 全循環；list 永不包含金鑰內容
//（§3.3：只顯示有無）。
func TestProviderAddListRemoveRoundtrip(t *testing.T) {
	d, _, _ := newDeps(t)
	run(t, d, "/provider add p1\nanthropic\n\n/provider add p2\nopenai-compat\nhttps://api.example.com/v1\n\n")

	list1 := run(t, d, "/provider list\nexit\n")
	assertAll(t, list1, "p1", "p2", "anthropic", "openai-compat", "https://api.example.com/v1", "未設", "user")
	assertNone(t, list1, "sk-") // §3.3：list 永不顯示金鑰內容。

	removeOut := run(t, d, "/provider remove p2\nexit\n")
	assertAll(t, removeOut, "已移除供應商")
	list2 := run(t, d, "/provider list\nexit\n")
	assertNone(t, list2, "p2")
	assertAll(t, list2, "p1")
	user, err := settings.Load(d.UserConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := user.Providers["p2"]; ok {
		t.Fatalf("移除後 p2 仍在 settings.toml: %v", user.Providers)
	}
	if _, ok := user.Providers["p1"]; !ok {
		t.Fatalf("移除後 p1 應保留: %v", user.Providers)
	}
}

// keySetStatus：/key set 經 injected ReadSecret 儲存至注入的 keyring；
// /status 顯示「已設」但輸出永不包含金鑰內容（§3.3、§23-6）。
func TestKeySetStoresViaReadSecretAndStatusShowsSet(t *testing.T) {
	d, _, kr := newDeps(t)
	const fakeKey = "sk-ant-fake-1234567890abcdef"
	d.ReadSecret = secretFeeder(t, fakeKey)
	run(t, d, "/provider add p\nanthropic\n\n")
	keyOut := run(t, d, "/key set p\nexit\n")
	out2 := run(t, d, "/provider list\n/status\nexit\n")

	// 金鑰實際存入 MemoryKeyring（§3.3 keychain 儲存路徑）。
	got, err := kr.Get(credentials.KeyringService, "p")
	if err != nil || got != fakeKey {
		t.Fatalf("keyring Get: got %q err %v, want %q nil", got, err, fakeKey)
	}
	// /key set 只印成功訊息與儲存位置，永不印內容（§23-6）。
	assertAll(t, keyOut, "已為供應商", "OS keychain")
	assertNone(t, keyOut, fakeKey)
	// list / status 顯示「已設（來源）」但永不顯示內容。
	assertAll(t, out2, "已設（keychain）")
	assertNone(t, out2, fakeKey)
}

// keySetNilReadSecretEchoesWarning：未注入 ReadSecret 時降級自 In 讀行，
// 且必須先警告「輸入將被回顯」（非終端機 no-echo 不可得；cmd 層會接真實 no-echo）。
func TestKeySetNilReadSecretEchoesWarning(t *testing.T) {
	d, _, kr := newDeps(t)
	// 故意不注入 ReadSecret（newDeps 未設定）：驗證降級路徑。
	o := run(t, d, "/provider add p\nanthropic\n\n/key set p\nsk-echoed-fake-key\nexit\n")
	if got, err := kr.Get(credentials.KeyringService, "p"); err != nil || got != "sk-echoed-fake-key" {
		t.Fatalf("降級讀取未存入金鑰: got %q err %v", got, err)
	}
	assertAll(t, o, "無法隱藏輸入")
}

// modelSetListReset：/model set 寫入使用者層級覆寫；/model list 顯示 repo >
// user 解析序與來源標記（§3.1）；/model reset 清空覆寫、保留供應商（§3.3）。
func TestModelSetListReset(t *testing.T) {
	d, _, _ := newDeps(t)
	writeRepoConfig(t, d.RepoConfigPath, `
[providers.anthropic]
type = "anthropic"

[models]
recon = "anthropic/claude-recon"
`)
	run(t, d, "/model set prover anthropic/claude-prover\nexit\n")
	list1 := run(t, d, "/model list\nexit\n")
	// prover 來自 user 覆寫、recon 來自 repo（§3.1 解析序）。
	assertAll(t, list1, "prover anthropic/claude-prover user", "recon anthropic/claude-recon repo")

	run(t, d, "/model reset\nexit\n")
	list2 := run(t, d, "/model list\nexit\n")
	assertAll(t, list2, "prover （未設定）")
	user, err := settings.Load(d.UserConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(user.Models) != 0 {
		t.Fatalf("reset 後使用者層 Models 應為空: %v", user.Models)
	}
	if _, ok := user.Providers["anthropic"]; !ok {
		t.Fatalf("reset 不應動到使用者層供應商定義: %v", user.Providers)
	}
}

// modelSetValidation：role 閉集、引用語法、供應商存在性三道驗證（§3.1、§3.3）。
func TestModelSetValidations(t *testing.T) {
	d, _, _ := newDeps(t)
	out := run(t, d, "/model set nosuchrole anthropic/claude-x\n/model set prover not-a-ref\n/model set prover unknown-provider/m1\nexit\n")
	assertAll(t, out, "未知的角色", "must be", "不存在")
	// 三道錯誤都不該寫出使用者設定檔。
	if _, err := os.Stat(d.UserConfigPath); !os.IsNotExist(err) {
		t.Fatalf("驗證失敗不應產生使用者設定檔, err = %v", err)
	}
}

// statusMarkers：/status 輸出含 已設／未設 標記與設定檔路徑（§3.3 /status），
// 且 Docker 探測不會讓指令失敗（CI 無 docker 亦然）。
func TestStatusShowsMarkers(t *testing.T) {
	d, _, _ := newDeps(t)
	run(t, d, "/provider add p\nanthropic\n\n")
	out := run(t, d, "/status\nexit\n")
	assertAll(t, out, "未設", d.UserConfigPath, d.RepoConfigPath, d.CredentialsPath, "docker")
}

// doctorRendersChecks：注入 Doctor 時逐項 render「OK/FAIL name — detail」；
// 未接線時回報 stub 訊息（不得假裝通過）。
func TestDoctorRendersChecks(t *testing.T) {
	d, _, _ := newDeps(t)
	d.Doctor = func(ctx context.Context) []doctor.Check {
		return []doctor.Check{
			{Name: "docker", OK: true, Detail: "server 24.0"},
			{Name: "image:sqls@v1", OK: false, Detail: "digest 未記錄（§17.10）"},
		}
	}
	out := run(t, d, "/doctor\nexit\n")
	assertAll(t, out, "OK docker — server 24.0", "FAIL image:sqls@v1 — digest 未記錄")

	d2, _, _ := newDeps(t)
	out2 := run(t, d2, "/doctor\nexit\n")
	assertAll(t, out2, "doctor 未接線")
}

// unknownCommandError：未知指令輸出一行錯誤並提示 /help（§3.3 分派）。
func TestUnknownCommandError(t *testing.T) {
	d, _, _ := newDeps(t)
	out := run(t, d, "/frobnicate x\nexit\n")
	assertAll(t, out, "未知指令", "/help")
}

// exitOnExit：輸入 "exit"（與 "quit"）立即結束、Run 回 nil；EOF 亦為 nil（§3.3）。
func TestExitOnExit(t *testing.T) {
	d, _, _ := newDeps(t)
	d.In = strings.NewReader("") // EOF（空輸入）→ nil
	if err := Run(d); err != nil {
		t.Fatalf("EOF: err = %v, want nil", err)
	}
	d2, _, _ := newDeps(t)
	d2.In = strings.NewReader("quit\n")
	if err := Run(d2); err != nil {
		t.Fatalf("quit: err = %v, want nil", err)
	}
	d3, _, _ := newDeps(t)
	d3.In = strings.NewReader("exit\n")
	if err := Run(d3); err != nil {
		t.Fatalf("exit: err = %v, want nil", err)
	}
}

// writeGuardRefusesLeakedKey：§23-6 金鑰防洩 guard——已登錄金鑰出現在待寫設定
//（此處：fake key 被貼進 provider base_url）時必須拒寫並輸出錯誤；
// settings.toml 不得被寫出。
func TestWriteGuardRefusesLeakedKey(t *testing.T) {
	d, _, kr := newDeps(t)
	const fakeKey = "sk-fake-leaked-key-abcdef"
	d.ReadSecret = secretFeeder(t, fakeKey)
	run(t, d, "/provider add p\nanthropic\n\n/key set p\nexit\n")
	out := run(t, d, "/provider add leak\nopenai-compat\nhttps://api.example.com/v1?token="+fakeKey+"\nexit\n")

	assertAll(t, out, "防洩檢查失敗")
	assertNone(t, out, fakeKey) // 錯誤路徑輸出亦不得洩漏金鑰內容（§23-6）。
	if _, err := kr.Get(credentials.KeyringService, "p"); err != nil {
		t.Fatalf("guard 不應影響已存金鑰: %v", err)
	}
	// 拒寫 → leak 不得進 settings.toml（p 已存在，guard 觸發於寫 leak 時）。
	if data, err := os.ReadFile(d.UserConfigPath); err == nil && bytes.Contains(data, []byte("leak")) {
		t.Fatalf("洩漏內容被寫入 settings.toml:\n%s", data)
	}
	// 對照：不含金鑰的合法 base_url 可正常寫入。
	out2 := run(t, d, "/provider add ok\nopenai-compat\nhttps://api.example.com/v1\nexit\n")
	assertNone(t, out2, "防洩檢查失敗")
	user, err := settings.Load(d.UserConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := user.Providers["ok"].BaseURL; got != "https://api.example.com/v1" {
		t.Fatalf("合法新增未落盤: %v", user.Providers)
	}
}

// keyClear：/key clear 移除已存金鑰（Manager.Clear 冪等；§3.3）。
func TestKeyClear(t *testing.T) {
	d, _, kr := newDeps(t)
	d.ReadSecret = secretFeeder(t, "sk-clear-me")
	run(t, d, "/provider add p\nanthropic\n\n/key set p\n/key clear p\nexit\n")
	if _, err := kr.Get(credentials.KeyringService, "p"); err == nil {
		t.Fatal("clear 後金鑰仍存在於 keyring")
	}
	list := run(t, d, "/provider list\nexit\n")
	assertAll(t, list, "未設")
}

// providerRemoveReferencedRequiresConfirm：仍被模型路由引用的供應商移除時，
// 必須警告並要求確認行 "yes"（§3.3 /provider remove 連同金鑰；任務規格）。
func TestProviderRemoveReferencedRequiresConfirm(t *testing.T) {
	d, _, kr := newDeps(t)
	d.ReadSecret = secretFeeder(t, "sk-remove-fake")
	run(t, d, "/provider add p\nanthropic\n\n/key set p\n/model set prover p/m1\nexit\n")
	out := run(t, d, "/provider remove p\nno\nexit\n")
	assertAll(t, out, "警告", "已取消移除")
	run(t, d, "/provider remove p\nyes\nexit\n")
	if _, err := kr.Get(credentials.KeyringService, "p"); err == nil {
		t.Fatal("確認移除後金鑰未一併清除（§3.3）")
	}
	user, err := settings.Load(d.UserConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := user.Providers["p"]; ok {
		t.Fatalf("確認移除後供應商仍在 settings.toml: %v", user.Providers)
	}
}

// providerAddValidation：type 不在閉集（§3.2）時拒絕；名稱撞 user 層時拒絕。
func TestProviderAddValidations(t *testing.T) {
	d, _, _ := newDeps(t)
	out := run(t, d, strings.Join([]string{
		"/provider add p", "gpt4-turbo", "",
		"/provider add p", "anthropic", "",
		"/provider add p", "anthropic", "",
		"exit",
	}, "\n"))
	assertAll(t, out, "不合法", "已存在")
}