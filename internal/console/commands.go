package console

// Slash 指令實作（SPEC §3.3 表列 10 條）。輸出一律 fmt + text/tabwriter
//（§6；無 TUI、無色彩套件，§23 相依表）；金鑰只顯示「有無 + 來源」，
// 永不顯示內容（§3.3、§23-6）。

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/aegis-dev/aegis/internal/credentials"
	"github.com/aegis-dev/aegis/internal/settings"
)

// newTable 建構 tabwriter（minwidth 0、tabwidth 4、padding 2、' ' 填充）。
// 呼叫端寫完後必須 Flush。
func (s *session) newTable() *tabwriter.Writer {
	return tabwriter.NewWriter(s.out, 0, 4, 2, ' ', 0)
}

// keyCell 把 Manager.Status 轉成顯示儲存格：「已設（來源）」或「未設」。
// 永不含金鑰內容（§3.3 /provider list 只顯示有無）。
func keyCell(set bool, source string) string {
	if !set {
		return "not set"
	}
	if source == "" {
		return "set"
	}
	return "set (" + source + ")"
}

// cmdProviderList 列出供應商：名稱、類型、base_url、金鑰有無（§3.3）。
// 同名供應商可能在 repo 與 user 兩層各有一筆定義（§3.1 解析序 user 層覆寫
// repo 層），各輸出一列並標註層級。
func (s *session) cmdProviderList() error {
	repo, user, err := s.loadConfigs()
	if err != nil {
		return err
	}
	s.renderProviders(repo, user)
	return nil
}

// renderProviders 輸出供應商表（/provider list 與 /status 共用）。
func (s *session) renderProviders(repo, user *settings.Config) {
	mgr := s.manager()
	w := s.newTable()
	fmt.Fprintln(w, "name\tlayer\ttype\tbase_url\tkey")
	row := func(name, layer string, p settings.Provider) {
		set, source := mgr.Status(name, credentials.ProviderType(p.Type))
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", name, layer, p.Type, p.BaseURL, keyCell(set, source))
	}
	for _, name := range sortedNames(repo.Providers) {
		row(name, "repo", repo.Providers[name])
	}
	for _, name := range sortedNames(user.Providers) {
		row(name, "user", user.Providers[name])
	}
	w.Flush()
}

// sortedNames 回傳供應商名的升冪排序（輸出確定性，不依賴 map 迭代序）。
func sortedNames[V any](m map[string]V) []string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	// 簡單插入排序避免再引一個 sort（僅數量級為個位數的供應商清單）。
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	return names
}

// openRouterBaseURL 是 /provider add 的 openrouter 捷徑預設端點（§3.3）。
// 僅為互動預設值；落盤的 type 恆為 openai-compat（§3.2 轉接器閉集不變）。
const openRouterBaseURL = "https://openrouter.ai/api/v1"

// cmdProviderAdd 互動新增供應商（§3.3）：追問 type（anthropic | openai-compat |
// openrouter 捷徑）。前兩者為 §3.2 轉接器閉集；openrouter 為便捷預設——仍以
// openai-compat 轉接器寫入，base_url 直接 Enter 即採 openRouterBaseURL（§3.2
// 已明列 OpenRouter 為 openai-compat 涵蓋範圍，此處只是免背端點的快捷輸入）。
// openai-compat 再追問 base_url（留空 = 不設定）。寫入使用者層級
// settings.toml（§3.3：供應商定義無內建，全在使用者層管理）。
//
// ASK（§23-9）：兩個互動細節 spec 未規定——
//   (1) 名稱已存在（user 層或與 repo aegis.toml 撞名）時：採「拒絕並提示先
//       remove」；選項 (b) 覆寫既有定義、(c) 要求確認後覆寫。
//   (2) type 輸入不在閉集時：採「輸出錯誤、中止本次 add（不迴圈追問）」，
//       避免 EOF／管道情境卡死；選項 (b) 迴圈重問直到合法或 EOF。
func (s *session) cmdProviderAdd(name string) error {
	if name == "" || strings.ContainsAny(name, " \t") {
		return errors.New("provider name must not be empty or contain whitespace")
	}
	repo, user, err := s.loadConfigs()
	if err != nil {
		return err
	}
	if _, ok := user.Providers[name]; ok {
		return fmt.Errorf("provider %q already exists in user config; remove it first with /provider remove %s, then add again", name, name)
	}
	if _, ok := repo.Providers[name]; ok {
		return fmt.Errorf("name %q is already used by repo aegis.toml; the user layer must not shadow it — rename or edit aegis.toml", name)
	}

	pt := credentials.ProviderType(s.promptLine("provider type (anthropic | openai-compat | openrouter): "))
	baseURL := ""
	switch pt {
	case credentials.ProviderTypeAnthropic:
		// Valid (§3.2 closed set); uses the official endpoint, no base_url prompt.
	case credentials.ProviderTypeOpenAICompat:
		baseURL = s.promptLine("base_url (leave empty to skip): ")
	case "openrouter":
		// Convenience default (§3.3): OpenRouter is an openai-compat endpoint;
		// the stored type stays openai-compat so the §3.2 adapter set does not
		// grow a third member. Empty = official endpoint; a custom endpoint
		// (proxy/mirror) may also be pasted.
		pt = credentials.ProviderTypeOpenAICompat
		baseURL = s.promptLine("base_url (press Enter = " + openRouterBaseURL + "): ")
		if baseURL == "" {
			baseURL = openRouterBaseURL
		}
	default:
		return fmt.Errorf("provider type %q is not valid (only anthropic | openai-compat | openrouter are accepted, §3.2); add cancelled", string(pt))
	}

	user.Providers[name] = settings.Provider{Type: string(pt), BaseURL: baseURL}
	if err := s.writeUserChecked(repo, user); err != nil {
		return err
	}
	fmt.Fprintf(s.out, "added provider %q (type=%s) to %s; next: /key set %s.\n", name, string(pt), s.deps.UserConfigPath, name)
	return nil
}

// cmdProviderRemove 移除供應商（§3.3：連同其 keychain 金鑰）。僅能移除使用者層
// 定義——repo 層供應商由 aegis.toml 管理（§3.1，互動模式不寫 repo 檔）。
// 仍有任何角色路由（repo 或 user）引用該供應商時：警告並要求輸入 "yes" 確認。
func (s *session) cmdProviderRemove(name string) error {
	repo, user, err := s.loadConfigs()
	if err != nil {
		return err
	}
	p, ok := user.Providers[name]
	if !ok {
		if _, inRepo := repo.Providers[name]; inRepo {
			return fmt.Errorf("provider %q is defined in repo aegis.toml; interactive mode does not modify the repo file — edit %s directly", name, s.deps.RepoConfigPath)
		}
		return fmt.Errorf("provider %q does not exist (see /provider list)", name)
	}

	// 路由引用檢查：任何 role 的引用 <provider>/<model-id> 其 <provider> 段等於
	// 待移除供應商即為「仍被引用」。
	var using []string
	scan := func(layer string, models map[string]string) {
		for role, ref := range models {
			if prov, _, _ := strings.Cut(ref, "/"); prov == name {
				using = append(using, layer+"/"+role)
			}
		}
	}
	scan("repo", repo.Models)
	scan("user", user.Models)
	if len(using) > 0 {
		fmt.Fprintf(s.out, "warning: provider %q is still referenced by these model routes: %s.\n", name, strings.Join(using, ", "))
		ans := s.promptLine("type yes to confirm removal (anything else cancels): ")
		if ans != "yes" {
			fmt.Fprintln(s.out, "removal cancelled.")
			return nil
		}
	}

	if err := s.manager().Clear(name, credentials.ProviderType(p.Type)); err != nil {
		return fmt.Errorf("failed to clear key: %w", err)
	}
	delete(user.Providers, name)
	if err := s.writeUserChecked(repo, user); err != nil {
		return err
	}
	fmt.Fprintf(s.out, "removed provider %q and its key (cleared from both keychain and file fallback).\n", name)
	return nil
}

// cmdKeySet 隱藏輸入金鑰並儲存（§3.3 /key set）：ReadSecret 取 token（永不回顯、
// 輸出永不印內容），credentials.Manager.Set 寫 OS keychain、不可用時退回檔案
//（0600）。只印成功訊息與儲存位置。
func (s *session) cmdKeySet(providerName string) error {
	repo, user, err := s.loadConfigs()
	if err != nil {
		return err
	}
	p, ok := lookupProvider(repo, user, providerName)
	if !ok {
		return fmt.Errorf("provider %q does not exist; add it first with /provider add %s (§3.3 first-run flow)", providerName, providerName)
	}
	secret, err := s.readSecret(fmt.Sprintf("[aegis] API key for %s: ", providerName))
	if err != nil {
		return err
	}
	key := strings.TrimRight(string(secret), "\r\n")
	if strings.TrimSpace(key) == "" {
		return errors.New("no key entered; cancelled")
	}
	if err := s.manager().Set(providerName, credentials.ProviderType(p.Type), key); err != nil {
		return fmt.Errorf("failed to store key: %w", err)
	}
	// 儲存位置：keychain 命中即 keychain；否則為檔案退回（0600，附一次性警告，
	// §3.3）。位置訊息不含金鑰內容（§23-6）。
	loc := "OS keychain"
	if s.deps.Keyring == nil {
		loc = "file fallback " + s.deps.CredentialsPath + " (mode 0600; prefer the OS keychain)"
	} else if _, err := s.deps.Keyring.Get(credentials.KeyringService, providerName); err != nil {
		loc = "file fallback " + s.deps.CredentialsPath + " (mode 0600; used when the keychain is unavailable, §3.3)"
	}
	fmt.Fprintf(s.out, "set key for provider %q; stored at: %s.\n", providerName, loc)
	return nil
}

// cmdKeyClear 刪除已存金鑰（§3.3 /key clear；Manager.Clear 冪等，keychain 與
// 檔案退回皆清）。
func (s *session) cmdKeyClear(providerName string) error {
	repo, user, err := s.loadConfigs()
	if err != nil {
		return err
	}
	p, ok := lookupProvider(repo, user, providerName)
	if !ok {
		return fmt.Errorf("provider %q does not exist (see /provider list)", providerName)
	}
	if err := s.manager().Clear(providerName, credentials.ProviderType(p.Type)); err != nil {
		return fmt.Errorf("failed to clear key: %w", err)
	}
	fmt.Fprintf(s.out, "cleared the key for provider %q.\n", providerName)
	return nil
}

// lookupProvider 供兩層查供應商定義（§3.1 解析序：user 覆寫 repo；查存在性時
// 兩層皆可）。type 以 user 層為準（覆寫可能連 type 一起換）。
func lookupProvider(repo, user *settings.Config, name string) (settings.Provider, bool) {
	if user != nil {
		if p, ok := user.Providers[name]; ok {
			return p, true
		}
	}
	if repo != nil {
		if p, ok := repo.Providers[name]; ok {
			return p, true
		}
	}
	return settings.Provider{}, false
}

// cmdModelList 檢視角色路由（§3.3）：每個 role 顯示解析後的引用與來源層
//（§3.1：repo aegis.toml > 使用者 settings.toml；兩層皆無 → 未設定）。
func (s *session) cmdModelList() error {
	repo, user, err := s.loadConfigs()
	if err != nil {
		return err
	}
	s.renderModels(repo, user)
	return nil
}

// renderModels 輸出模型路由表（/model list 與 /status 共用）。
func (s *session) renderModels(repo, user *settings.Config) {
	w := s.newTable()
	fmt.Fprintln(w, "role\tmodel ref\tsource")
	for _, role := range roles {
		ref, source, err := settings.ResolveModel(repo, user, role)
		if err != nil {
			ref, source = "(not set)", "—"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", role, ref, source)
	}
	w.Flush()
}

// modelSetAll 是 /model set 的萬用字元：role 給 "all" 時，同一個引用一次寫入
// §3.1 全部五個角色（§3.3）。不是一個 role——只作為指令輸入的選項，不得進入
// 設定檔的 [models] 鍵。
const modelSetAll = "all"

// cmdModelSet 覆寫角色路由（§3.3：寫入使用者層級設定）。驗證序：
// role 閉集（§3.1 五角色；或 "all" 一次設定全部五角色）→ settings.ValidateRef
//（§3.1 引用語法）→ 供應商必須存在於 repo 或 user 任一層。
// "all" 僅展開成五個角色鍵寫入，同一引用對每個角色皆相同——成本分層（§3.1：
// 機械性工作用便宜模型、證明用最強模型）的使用者之後仍可逐一覆寫單一角色。
func (s *session) cmdModelSet(role, ref string) error {
	targets := []string{role}
	if role != modelSetAll {
		validRole := false
		for _, r := range roles {
			if r == role {
				validRole = true
				break
			}
		}
		if !validRole {
			return fmt.Errorf("unknown role %q (available: recon, reviewer, triager, prover, reporter, or all to set every role at once, §3.1)", role)
		}
	} else {
		// 展開萬用字元為 §3.1 角色閉集（固定順序，輸出與寫入皆確定）。
		targets = append([]string(nil), roles...)
	}
	if err := settings.ValidateRef(ref); err != nil {
		return err
	}
	repo, user, err := s.loadConfigs()
	if err != nil {
		return err
	}
	prov, _, _ := strings.Cut(ref, "/")
	if _, ok := lookupProvider(repo, user, prov); !ok {
		return fmt.Errorf("referenced provider %q does not exist (in neither repo nor user config); add it first with /provider add", prov)
	}
	for _, target := range targets {
		user.Models[target] = ref
	}
	if err := s.writeUserChecked(repo, user); err != nil {
		return err
	}
	if role == modelSetAll {
		fmt.Fprintf(s.out, "routed all %d roles (%s) to %s (user-level override; /model reset restores).\n", len(targets), strings.Join(targets, ", "), ref)
	} else {
		fmt.Fprintf(s.out, "routed role %q to %s (user-level override; /model reset restores).\n", role, ref)
	}
	return nil
}

// cmdModelReset 清空使用者層級模型覆寫（§3.3：reset 清空覆寫、回到 repo
// aegis.toml 的定義），保留供應商定義。
func (s *session) cmdModelReset() error {
	repo, user, err := s.loadConfigs()
	if err != nil {
		return err
	}
	user.Models = map[string]string{}
	if err := s.writeUserChecked(repo, user); err != nil {
		return err
	}
	fmt.Fprintln(s.out, "cleared user-level model overrides; role routing falls back to repo aegis.toml (§3.1).")
	return nil
}

// cmdStatus 總覽（§3.3）：設定檔路徑、供應商與金鑰狀態、解析後路由、
// Docker 可用性。
func (s *session) cmdStatus(ctx context.Context) error {
	repo, user, err := s.loadConfigs()
	if err != nil {
		return err
	}
	fmt.Fprintln(s.out, "== config files ==")
	fmt.Fprintf(s.out, "repo aegis.toml        %s (%s)\n", s.deps.RepoConfigPath, fileExistsLabel(s.deps.RepoConfigPath))
	fmt.Fprintf(s.out, "user settings.toml     %s (%s; where /model set and /provider add write, §3.3)\n", s.deps.UserConfigPath, fileExistsLabel(s.deps.UserConfigPath))
	fmt.Fprintf(s.out, "credentials.toml       %s (%s; keychain fallback file, 0600, §3.3)\n", s.deps.CredentialsPath, fileExistsLabel(s.deps.CredentialsPath))
	fmt.Fprintln(s.out, "== providers ==")
	s.renderProviders(repo, user)
	fmt.Fprintln(s.out, "== model routing ==")
	s.renderModels(repo, user)
	fmt.Fprintln(s.out, "== Docker ==")
	fmt.Fprintf(s.out, "docker: %s\n", dockerStatus(ctx))
	return nil
}

// fileExistsLabel 回傳檔案存在性的人類可讀標籤。
func fileExistsLabel(path string) string {
	if _, err := os.Stat(path); err == nil {
		return "exists"
	}
	return "missing"
}

// dockerStatus 以「docker version」做快速可用性探測（§3.3 /status）。
// 3 秒逾時；失敗訊息截斷，避免 daemon 錯誤全文灌進輸出。
func dockerStatus(ctx context.Context) string {
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(c, "docker", "version", "--format", "{{.Server.Version}}").Output()
	if err != nil {
		return "unavailable (docker command not found or daemon not running)"
	}
	v := strings.TrimSpace(string(out))
	if v == "" {
		return "available"
	}
	return "available (server " + v + ")"
}

// cmdDoctor 執行體檢（§3.3：Docker、pre-baked 映像、供應商連通）。檢查實作由
// cmd 層注入；未接線時回報 stub 訊息而非假裝檢查通過。
func (s *session) cmdDoctor(ctx context.Context) error {
	if s.deps.Doctor == nil {
		fmt.Fprintln(s.out, "doctor not wired (the cmd layer injected no Doctor implementation; this mode only provides the interface, §3.3).")
		return nil
	}
	checks := s.deps.Doctor(ctx)
	if len(checks) == 0 {
		fmt.Fprintln(s.out, "doctor: no checks to run.")
		return nil
	}
	for _, c := range checks {
		status := "OK"
		if !c.OK {
			status = "FAIL"
		}
		fmt.Fprintf(s.out, "%s %s — %s\n", status, c.Name, c.Detail)
	}
	return nil
}
