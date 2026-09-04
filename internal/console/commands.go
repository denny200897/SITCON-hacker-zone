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
		return "未設"
	}
	if source == "" {
		return "已設"
	}
	return "已設（" + source + "）"
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
	fmt.Fprintln(w, "名稱\t層級\t類型\tbase_url\t金鑰")
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

// cmdProviderAdd 互動新增供應商（§3.3）：追問 type（anthropic | openai-compat，
// 閉集 §3.2）；openai-compat 再追問 base_url（留空 = 不設定）。寫入使用者層級
// settings.toml（§3.3：供應商定義無內建，全在使用者層管理）。
//
// ASK（§23-9）：兩個互動細節 spec 未規定——
//   (1) 名稱已存在（user 層或與 repo aegis.toml 撞名）時：採「拒絕並提示先
//       remove」；選項 (b) 覆寫既有定義、(c) 要求確認後覆寫。
//   (2) type 輸入不在閉集時：採「輸出錯誤、中止本次 add（不迴圈追問）」，
//       避免 EOF／管道情境卡死；選項 (b) 迴圈重問直到合法或 EOF。
func (s *session) cmdProviderAdd(name string) error {
	if name == "" || strings.ContainsAny(name, " \t") {
		return errors.New("供應商名稱不可為空或含空白")
	}
	repo, user, err := s.loadConfigs()
	if err != nil {
		return err
	}
	if _, ok := user.Providers[name]; ok {
		return fmt.Errorf("供應商 %q 已存在於使用者設定；先以 /provider remove %s 移除再新增", name, name)
	}
	if _, ok := repo.Providers[name]; ok {
		return fmt.Errorf("名稱 %q 已被 repo aegis.toml 使用；使用者層不得同名遮蔽，請改名或改 aegis.toml", name)
	}

	pt := credentials.ProviderType(s.promptLine("供應商類型（anthropic | openai-compat）: "))
	switch pt {
	case credentials.ProviderTypeAnthropic, credentials.ProviderTypeOpenAICompat:
		// 合法（§3.2 閉集）。
	default:
		return fmt.Errorf("供應商類型 %q 不合法（僅 accept anthropic | openai-compat，§3.2）；已取消新增", string(pt))
	}

	baseURL := ""
	if pt == credentials.ProviderTypeOpenAICompat {
		baseURL = s.promptLine("base_url（留空則不設定）: ")
	}

	user.Providers[name] = settings.Provider{Type: string(pt), BaseURL: baseURL}
	if err := s.writeUserChecked(repo, user); err != nil {
		return err
	}
	fmt.Fprintf(s.out, "已新增供應商 %q（type=%s）至 %s；下一步：/key set %s。\n", name, string(pt), s.deps.UserConfigPath, name)
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
			return fmt.Errorf("供應商 %q 定義於 repo aegis.toml，互動模式不修改 repo 檔；請直接編輯 %s", name, s.deps.RepoConfigPath)
		}
		return fmt.Errorf("供應商 %q 不存在（/provider list 查看）", name)
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
		fmt.Fprintf(s.out, "警告：供應商 %q 仍被以下模型路由引用：%s。\n", name, strings.Join(using, ", "))
		ans := s.promptLine("輸入 yes 確認移除（其他輸入則取消）: ")
		if ans != "yes" {
			fmt.Fprintln(s.out, "已取消移除。")
			return nil
		}
	}

	if err := s.manager().Clear(name, credentials.ProviderType(p.Type)); err != nil {
		return fmt.Errorf("清除金鑰失敗: %w", err)
	}
	delete(user.Providers, name)
	if err := s.writeUserChecked(repo, user); err != nil {
		return err
	}
	fmt.Fprintf(s.out, "已移除供應商 %q 及其金鑰（keychain 與檔案退回皆已清）。\n", name)
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
		return fmt.Errorf("供應商 %q 不存在；先以 /provider add %s 新增（§3.3 首次執行流程）", providerName, providerName)
	}
	secret, err := s.readSecret(fmt.Sprintf("[aegis] API key for %s: ", providerName))
	if err != nil {
		return err
	}
	key := strings.TrimRight(string(secret), "\r\n")
	if strings.TrimSpace(key) == "" {
		return errors.New("未輸入金鑰；已取消")
	}
	if err := s.manager().Set(providerName, credentials.ProviderType(p.Type), key); err != nil {
		return fmt.Errorf("儲存金鑰失敗: %w", err)
	}
	// 儲存位置：keychain 命中即 keychain；否則為檔案退回（0600，附一次性警告，
	// §3.3）。位置訊息不含金鑰內容（§23-6）。
	loc := "OS keychain"
	if s.deps.Keyring == nil {
		loc = "檔案退回 " + s.deps.CredentialsPath + "（權限 0600；建議改用 OS keychain）"
	} else if _, err := s.deps.Keyring.Get(credentials.KeyringService, providerName); err != nil {
		loc = "檔案退回 " + s.deps.CredentialsPath + "（權限 0600；keychain 不可用時的退回，§3.3）"
	}
	fmt.Fprintf(s.out, "已為供應商 %q 設定金鑰；儲存位置：%s。\n", providerName, loc)
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
		return fmt.Errorf("供應商 %q 不存在（/provider list 查看）", providerName)
	}
	if err := s.manager().Clear(providerName, credentials.ProviderType(p.Type)); err != nil {
		return fmt.Errorf("清除金鑰失敗: %w", err)
	}
	fmt.Fprintf(s.out, "已清除供應商 %q 的金鑰。\n", providerName)
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
	fmt.Fprintln(w, "角色\t模型引用\t來源")
	for _, role := range roles {
		ref, source, err := settings.ResolveModel(repo, user, role)
		if err != nil {
			ref, source = "（未設定）", "—"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", role, ref, source)
	}
	w.Flush()
}

// cmdModelSet 覆寫角色路由（§3.3：寫入使用者層級設定）。驗證序：
// role 閉集（§3.1 五角色）→ settings.ValidateRef（§3.1 引用語法）→
// 供應商必須存在於 repo 或 user 任一層。
func (s *session) cmdModelSet(role, ref string) error {
	validRole := false
	for _, r := range roles {
		if r == role {
			validRole = true
			break
		}
	}
	if !validRole {
		return fmt.Errorf("未知的角色 %q（可用：recon, reviewer, triager, prover, reporter，§3.1）", role)
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
		return fmt.Errorf("引用的供應商 %q 不存在（repo 或使用者設定皆無）；先以 /provider add 新增", prov)
	}
	user.Models[role] = ref
	if err := s.writeUserChecked(repo, user); err != nil {
		return err
	}
	fmt.Fprintf(s.out, "已將角色 %q 路由設為 %s（使用者層級覆寫；/model reset 可還原）。\n", role, ref)
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
	fmt.Fprintln(s.out, "已清空使用者層級模型覆寫；角色路由回到 repo aegis.toml 的定義（§3.1）。")
	return nil
}

// cmdStatus 總覽（§3.3）：設定檔路徑、供應商與金鑰狀態、解析後路由、
// Docker 可用性。
func (s *session) cmdStatus(ctx context.Context) error {
	repo, user, err := s.loadConfigs()
	if err != nil {
		return err
	}
	fmt.Fprintln(s.out, "== 設定檔 ==")
	fmt.Fprintf(s.out, "repo aegis.toml        %s（%s）\n", s.deps.RepoConfigPath, fileExistsLabel(s.deps.RepoConfigPath))
	fmt.Fprintf(s.out, "user settings.toml     %s（%s；/model set、/provider add 寫入處，§3.3）\n", s.deps.UserConfigPath, fileExistsLabel(s.deps.UserConfigPath))
	fmt.Fprintf(s.out, "credentials.toml       %s（%s；keychain 退回檔，0600，§3.3）\n", s.deps.CredentialsPath, fileExistsLabel(s.deps.CredentialsPath))
	fmt.Fprintln(s.out, "== 供應商 ==")
	s.renderProviders(repo, user)
	fmt.Fprintln(s.out, "== 模型路由 ==")
	s.renderModels(repo, user)
	fmt.Fprintln(s.out, "== Docker ==")
	fmt.Fprintf(s.out, "docker：%s\n", dockerStatus(ctx))
	return nil
}

// fileExistsLabel 回傳檔案存在性的人類可讀標籤。
func fileExistsLabel(path string) string {
	if _, err := os.Stat(path); err == nil {
		return "存在"
	}
	return "不存在"
}

// dockerStatus 以「docker version」做快速可用性探測（§3.3 /status）。
// 3 秒逾時；失敗訊息截斷，避免 daemon 錯誤全文灌進輸出。
func dockerStatus(ctx context.Context) string {
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(c, "docker", "version", "--format", "{{.Server.Version}}").Output()
	if err != nil {
		return "不可用（找不到 docker 指令或 daemon 未啟動）"
	}
	v := strings.TrimSpace(string(out))
	if v == "" {
		return "可用"
	}
	return "可用（server " + v + "）"
}

// cmdDoctor 執行體檢（§3.3：Docker、pre-baked 映像、供應商連通）。檢查實作由
// cmd 層注入；未接線時回報 stub 訊息而非假裝檢查通過。
func (s *session) cmdDoctor(ctx context.Context) error {
	if s.deps.Doctor == nil {
		fmt.Fprintln(s.out, "doctor 未接線（cmd 層未注入 Doctor 檢查實作；本模式僅提供介面，§3.3）。")
		return nil
	}
	checks := s.deps.Doctor(ctx)
	if len(checks) == 0 {
		fmt.Fprintln(s.out, "doctor：無檢查項目。")
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