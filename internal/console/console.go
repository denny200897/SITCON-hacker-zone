// Package console 是互動模式 REPL（SPEC §3.3）。
//
// 進入方式：無參數執行 aegis（或 aegis console）；slash 指令僅存在於此模式，
// 設定沒有一次性子命令（§3.3、§23：設定一律在互動模式完成，CI／腳本場景以
// 環境變數 + aegis.toml 替代）。
//
// 設計約束：
//   - 純 stdlib 輸出：fmt + text/tabwriter（§6 表格輸出；無 TUI、無色彩套件，
//     §23 相依表）。
//   - 金鑰防洩（§3.3、§23-6）：輸出只顯示金鑰「有無」與來源（credentials.Manager.Status），
//     永不顯示內容；任何落盤（settings.toml）寫入前以已登錄金鑰做 redaction 檢查
//     （internal/redaction），命中即拒寫。
//   - 依賴注入：In/Out/ReadSecret/Doctor 皆可注入；cmd 層接真實終端機（no-echo）
//     與真實 doctor，測試以 strings.Reader + bytes.Buffer + MemoryKeyring 驅動
//     （§23：單元測試 stdlib-only）。
//   - 組態讀取：每條指令執行時重新載入 repo aegis.toml 與使用者 settings.toml
//     （§3.1 解析序 repo > user；每命令重讀為刻意選擇，簡單且恆正確——外部修改
//     立即生效）。
package console

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/aegis-dev/aegis/internal/credentials"
	"github.com/aegis-dev/aegis/internal/doctor"
	"github.com/aegis-dev/aegis/internal/redaction"
	"github.com/aegis-dev/aegis/internal/settings"
)

// Deps 是互動模式的依賴注入點（cmd 層組裝；測試以假件替換）。
type Deps struct {
	// Context 控制互動模式及其啟動的長時間工作；nil 時使用 Background。
	Context context.Context
	// In 是 REPL 的輸入來源（真實情境為 stdin；測試為 strings.Reader）。
	In io.Reader
	// Out 是所有輸出的目的地（真實情境為 stdout；測試為 bytes.Buffer）。
	Out io.Writer
	// RepoConfigPath 是 repo 層組態檔（§3.1：./aegis.toml，可能不存在）。
	RepoConfigPath string
	// UserConfigPath 是使用者層級設定檔（§3.3：~/.config/aegis/settings.toml，
	// /model set、/provider add 的寫入處）。
	UserConfigPath string
	// CredentialsPath 是 keychain 不可用時的憑證退回檔（§3.3：credentials.toml，
	// 0600）。
	CredentialsPath string
	// Keyring 是 OS keychain 後端；nil 表示無 keychain 環境（僅檔案退回，§3.3）。
	Keyring credentials.Keyring
	// ReadSecret 是 no-echo 的 token 輸入（§3.3 /key set）；cmd 層接終端機實作。
	// nil 時使用降級實作：自 In 讀一行並警告「輸入將被回顯」（非終端機情境）。
	ReadSecret func(prompt string) ([]byte, error)
	// Doctor 是 /doctor 的檢查實作（§3.3：Docker、映像、供應商連通），由 cmd 層
	// 注入；nil 時以基本 stub 回報「doctor 未接線」。
	Doctor func(ctx context.Context) []doctor.Check
	// RunCommand 將 review/scan/prove/report/replay 交回 cmd 層的既有 CLI pipeline。
	// args 的第一個元素是子命令名稱，後續元素原樣沿用 CLI flags。
	RunCommand func(ctx context.Context, args []string, out io.Writer) error
}

// roles 是 §3.1 角色閉集（與 settings / llm 的 role 常數同值；閉集不得各自擴充，
// §23-4）。/model list 依此順序呈現。
var roles = []string{
	settings.RoleRecon,
	settings.RoleReviewer,
	settings.RoleTriager,
	settings.RoleProver,
	settings.RoleReporter,
}

// session 是單次 Run 的互動狀態。
type session struct {
	deps Deps
	ctx  context.Context
	out  io.Writer
	sc   *bufio.Scanner
}

// errUnknownCmd 標記「未知指令」——Run 以此區分提示文案（附 /help 提示）。
var errUnknownCmd = errors.New("unknown command")

// Run 進入互動模式（§3.3）：逐行讀 In，空行略過；"exit"/"quit"/EOF 結束；
// "/help" 或 "/" 前綴分派 slash 指令；未知輸入輸出一行錯誤並提示 /help。
// 指令執行錯誤只輸出、不中斷 REPL（設定是互動修正的循環）。
func Run(deps Deps) error {
	if deps.Out == nil {
		return errors.New("console: Deps.Out must not be nil")
	}
	if deps.In == nil {
		return errors.New("console: Deps.In must not be nil")
	}
	// 路徑補預設（§3.1 / §3.3）：cmd 層可顯式給，未給時用套件慣例路徑。
	if deps.RepoConfigPath == "" {
		deps.RepoConfigPath = "aegis.toml" // §3.1：repo 層固定為工作目錄的 aegis.toml
	}
	if deps.UserConfigPath == "" {
		p, err := settings.DefaultUserPath()
		if err != nil {
			return fmt.Errorf("console: resolving user config path: %w", err)
		}
		deps.UserConfigPath = p
	}
	if deps.CredentialsPath == "" {
		p, err := credentials.DefaultFilePath()
		if err != nil {
			return fmt.Errorf("console: resolving credentials fallback path: %w", err)
		}
		deps.CredentialsPath = p
	}

	ctx := deps.Context
	if ctx == nil {
		ctx = context.Background()
	}
	s := &session{deps: deps, ctx: ctx, out: deps.Out}
	s.sc = bufio.NewScanner(deps.In)

	fmt.Fprintln(s.out, "aegis interactive mode (§3.3): type /help for commands, exit to quit.")
	for s.sc.Scan() {
		line := strings.TrimSpace(s.sc.Text())
		switch {
		case line == "":
			continue
		case line == "exit" || line == "quit":
			return nil
		}
		if err := s.dispatch(line); err != nil {
			if errors.Is(err, errUnknownCmd) {
				fmt.Fprintf(s.out, "error: %v; type /help to see available commands.\n", err)
				continue
			}
			fmt.Fprintf(s.out, "error: %v\n", err)
		}
	}
	return s.sc.Err()
}

// dispatch 解析一行指令並分派（§3.3）。
func (s *session) dispatch(line string) error {
	fields, err := splitCommandLine(line)
	if err != nil {
		return err
	}
	cmd, args := fields[0], fields[1:]
	switch cmd {
	case "/help":
		s.cmdHelp()
		return nil
	case "/provider":
		if len(args) == 0 {
			return fmt.Errorf("/provider needs a subcommand: list | add <name> | remove <name>")
		}
		switch args[0] {
		case "list":
			return s.cmdProviderList()
		case "add":
			if len(args) != 2 {
				return errors.New("usage: /provider add <name>")
			}
			return s.cmdProviderAdd(args[1])
		case "remove":
			if len(args) != 2 {
				return errors.New("usage: /provider remove <name>")
			}
			return s.cmdProviderRemove(args[1])
		default:
			return fmt.Errorf("%w: %s (/provider subcommands are list | add | remove)", errUnknownCmd, line)
		}
	case "/key":
		if len(args) != 2 {
			return errors.New("usage: /key set <provider> or /key clear <provider>")
		}
		switch args[0] {
		case "set":
			return s.cmdKeySet(args[1])
		case "clear":
			return s.cmdKeyClear(args[1])
		default:
			return fmt.Errorf("%w: %s (/key subcommands are set | clear)", errUnknownCmd, line)
		}
	case "/model":
		if len(args) == 0 {
			return errors.New("/model needs a subcommand: list | set <role> <provider/model-id> | reset")
		}
		switch args[0] {
		case "list":
			return s.cmdModelList()
		case "set":
			if len(args) != 3 {
				return errors.New("usage: /model set <role|all> <provider/model-id>")
			}
			return s.cmdModelSet(args[1], args[2])
		case "reset":
			return s.cmdModelReset()
		default:
			return fmt.Errorf("%w: %s (/model subcommands are list | set | reset)", errUnknownCmd, line)
		}
	case "/status":
		return s.cmdStatus(s.ctx)
	case "/doctor":
		return s.cmdDoctor(s.ctx)
	case "/review", "/scan", "/prove", "/report", "/replay":
		if s.deps.RunCommand == nil {
			return errors.New("pipeline command not wired")
		}
		return s.deps.RunCommand(s.ctx, append([]string{strings.TrimPrefix(cmd, "/")}, args...), s.out)
	default:
		return fmt.Errorf("%w: %s", errUnknownCmd, cmd)
	}
}

// splitCommandLine 支援 REPL 中的單／雙引號與反斜線，讓 CLI flags 可原樣使用，
// 例如 /scan --target "repo with spaces"。這不是 shell，不展開變數或執行替換。
func splitCommandLine(line string) ([]string, error) {
	var fields []string
	var field strings.Builder
	var quote rune
	escaped, started := false, false
	flush := func() {
		if started {
			fields = append(fields, field.String())
			field.Reset()
			started = false
		}
	}
	for _, r := range line {
		if escaped {
			// 只把反斜線當作空白、引號與反斜線的跳脫；其餘情況保留，
			// 避免 C:\repo 之類的 Windows 路徑被改寫成 C:repo。
			if !strings.ContainsRune(" \t\r\n'\"\\", r) {
				field.WriteRune('\\')
			}
			field.WriteRune(r)
			started, escaped = true, false
			continue
		}
		if r == '\\' && quote != '\'' {
			escaped, started = true, true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				field.WriteRune(r)
			}
			started = true
			continue
		}
		switch r {
		case '\'', '"':
			quote, started = r, true
		case ' ', '\t', '\r', '\n':
			flush()
		default:
			field.WriteRune(r)
			started = true
		}
	}
	if escaped {
		field.WriteRune('\\')
	}
	if quote != 0 {
		return nil, errors.New("command has an unclosed quote")
	}
	flush()
	if len(fields) == 0 {
		return nil, errors.New("empty command")
	}
	return fields, nil
}

// loadConfigs 每次指令執行時重新載入兩層組態（§3.1：repo aegis.toml >
// 使用者 settings.toml；任一層缺檔不是錯誤，settings.Load 回傳空 Config）。
func (s *session) loadConfigs() (repo, user *settings.Config, err error) {
	repo, err = settings.Load(s.deps.RepoConfigPath)
	if err != nil {
		return nil, nil, err
	}
	user, err = settings.Load(s.deps.UserConfigPath)
	if err != nil {
		return nil, nil, err
	}
	return repo, user, nil
}

// manager 建構憑證管理器（§3.3 解析序：環境變數 > OS keychain > 設定檔退回）。
// FileStore 的一次性警告直接寫到 Out（訊息不含金鑰內容）。
func (s *session) manager() *credentials.Manager {
	return &credentials.Manager{
		Keyring: s.deps.Keyring,
		File:    &credentials.FileStore{Path: s.deps.CredentialsPath, Warn: s.out},
	}
}

// readSecret 取得 no-echo 金鑰輸入（§3.3 /key set）：優先用注入的實作；
// 否則降級為自 In 讀一行——非終端機情境無法 no-echo，先警告再讀
// （cmd 層會接真正的終端機 no-echo 實作）。
func (s *session) readSecret(prompt string) ([]byte, error) {
	if s.deps.ReadSecret != nil {
		return s.deps.ReadSecret(prompt)
	}
	fmt.Fprintln(s.out, "warning: input is not a terminal, so it cannot be hidden (no-echo); what you type will be echoed.")
	fmt.Fprint(s.out, prompt)
	if !s.sc.Scan() {
		if err := s.sc.Err(); err != nil {
			return nil, fmt.Errorf("console: reading key input: %w", err)
		}
		return nil, errors.New("console: input ended (EOF) before a key was provided")
	}
	return []byte(s.sc.Text()), nil
}

// promptLine 輸出提示後自 In 讀一行（互動追問：/provider add 的 type、base_url，
// /provider remove 的確認）。EOF 時回傳空字串（呼叫端以空值處理）。
func (s *session) promptLine(prompt string) string {
	fmt.Fprint(s.out, prompt)
	if !s.sc.Scan() {
		return ""
	}
	return strings.TrimSpace(s.sc.Text())
}

// cmdHelp 列出 slash 指令（§3.3 表）。
func (s *session) cmdHelp() {
	fmt.Fprint(s.out, `Commands (§3.3):
  /provider list                              list providers and whether a key is set (never shows the value)
  /provider add <name>                        add a provider (anthropic | openai-compat | openrouter shortcut)
  /provider remove <name>                     remove a provider (and its key)
  /key set <provider>                         enter an API key with hidden input and store it
  /key clear <provider>                       delete a stored key
  /model list                                 view role routing (repo > user, §3.1)
  /model set <role|all> <provider/model-id>   override role routing (all = set every role at once; written to user config)
  /model reset                                clear user-level model overrides
  /status                                     provider, key, routing, and Docker status
  /doctor                                     health check (Docker, images, provider connectivity)
  /review [repo] [flags]                      scan, prove, replay, and report in one command (recommended entry point)
  /scan [flags]                               scan the target repo only (advanced / debugging)
  /prove [F-ID] [flags]                       prove a finding; omit the ID to process all
  /report [flags]                             generate findings, SARIF, and the Markdown report
  /replay [flags]                             revalidate an evidence bundle offline
  exit | quit                                 leave interactive mode
`)
}

// writeUserChecked 是使用者層級設定檔的唯一寫入路徑：先做金鑰防洩檢查
// （§3.3、§23-6：任何落盤輸出寫入前，以已登錄金鑰做 redaction），命中即拒寫，
// 再交 settings.SaveUser（0600、父目錄 0700）。
//
// 檢查方式：把待寫 TOML 先編成位元組，對「已登錄金鑰清單」（credentials.Manager
// 自環境變數／keychain／檔案退回解析出的全部金鑰）逐一比對——redaction.Redact
// 以字面比對遮蔽，遮蔽前後內容不同即代表有待寫內容含有金鑰片段。
// 註：此處刻意只檢查「已登錄金鑰」，不跑 redaction.Scan 樣式掃描——合法的
// base_url 可能含 token=/password= 等查詢參數字樣，樣式掃描會誤擋；
// 樣式掃描屬落盤輸出（報告／evidence）的 gate（§7.2），不屬設定檔寫入。
func (s *session) writeUserChecked(repo, user *settings.Config) error {
	var buf bytes.Buffer
	doc := struct {
		Providers map[string]settings.Provider `toml:"providers"`
		Models    map[string]string            `toml:"models"`
	}{Providers: user.Providers, Models: user.Models}
	if err := toml.NewEncoder(&buf).Encode(doc); err != nil {
		return fmt.Errorf("console: encoding user config: %w", err)
	}
	text := buf.String()
	if redaction.Redact(text, s.resolvedKeys(repo, user)) != text {
		return errors.New("pre-write leak check failed: the config contains a registered key fragment (§23-6); write refused. Check whether a key was pasted into fields like base_url")
	}
	return settings.SaveUser(s.deps.UserConfigPath, user)
}

// resolvedKeys 收集兩層組態中所有供應商目前可解析到的金鑰內容
// （§3.3 解析序：env > keychain > file）。內容只用於 redaction 比對，
// 永不輸出。
func (s *session) resolvedKeys(repo, user *settings.Config) []string {
	mgr := s.manager()
	seen := map[string]bool{}
	var keys []string
	collect := func(cfg *settings.Config) {
		for name, p := range cfg.Providers {
			k, _, err := mgr.Resolve(name, credentials.ProviderType(p.Type))
			if err == nil && k != "" && !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
	}
	collect(repo)
	collect(user)
	return keys
}
