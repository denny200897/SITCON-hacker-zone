// Package settings 載入／寫入頂層組態（§3.1、§5.4、§16）。
//
// 兩個組態檔共用同一形狀：repo 層的 aegis.toml 與使用者層的
// ~/.config/aegis/settings.toml（§3.3：/model set 的寫入處）。
// 解析序：repo aegis.toml > 使用者 settings.toml > 無（§3.1，無任何內建預設）。
//
// 金鑰防洩（§23-6）：金鑰不進 aegis.toml、不進 settings.toml——本包只處理
// providers/models 路由，憑證走環境變數 > OS keychain > credentials.toml（§3.3，
// 由 internal/credentials 處理，不在本包）。
//
// TOML 讀寫固定用 github.com/BurntSushi/toml（§16 固定決策，不得替換）。
package settings

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// Role 是 §3.1 角色閉集的字串常數——與 internal/llm 的 llm.Role 值一致
// （llm.RoleRecon = "recon" 等，見 internal/llm/llm.go）。設定檔的 [models]
// 以 role 為鍵，故此處以字串常數重述同一閉集；兩包不得各自擴充。
const (
	RoleRecon    = "recon"
	RoleReviewer = "reviewer"
	RoleTriager  = "triager"
	RoleProver   = "prover"
	RoleReporter = "reporter"
)

// ErrModelUnset 是 ResolveModel 在 repo 與 user 兩層皆無該 role 定義時回傳的
// sentinel（§3.1：無任何內建預設，缺定義不是錯誤路徑而是「未設定」狀態，
// 呼叫端以 errors.Is 判別後導向 /model set 或 aegis.toml 的提示）。
var ErrModelUnset = errors.New("settings: model unset for role")

// Provider 是單一供應商定義（§5.4）。無內建供應商（§3.3），
// 全由使用者以 /provider add 新增，以 map 鍵（供應商名）存放。
type Provider struct {
	Type    string `toml:"type"`     // "anthropic" | "openai-compat"（§3.2 閉集）
	BaseURL string `toml:"base_url"` // openai-compat 必填；anthropic 可空（走官方端點）
}

// Config 是 aegis.toml 與 settings.toml 共用的頂層組態形狀（§5.4 的
// providers/models 兩節；檔內其他節如 [budget]/[sandbox] 由各自的包解析，
// 本包解碼時忽略未知鍵，故同一 Load 可用於兩種檔）。
//
// Models 以 role 為鍵、值為 "<provider>/<model-id>" 引用（§3.1 模型引用語法）。
type Config struct {
	Providers map[string]Provider `toml:"providers"`
	Models    map[string]string   `toml:"models"`
	Budget    Budget              `toml:"budget"`
}

// Budget 對應 [budget]；0 表示該層未設定，由較低優先層或規格預設補上。
type Budget struct {
	MaxEnvFixesPerFinding       int `toml:"max_env_fixes_per_finding"`
	MaxHarnessFixesPerFinding   int `toml:"max_harness_fixes_per_finding"`
	MaxHypothesesPerFinding     int `toml:"max_hypotheses_per_finding"`
	MaxSandboxMinutesPerFinding int `toml:"max_sandbox_minutes_per_finding"`
}

// ResolveBudget 套用 repo > user > SPEC 預設值。各欄可獨立覆寫。
func ResolveBudget(repo, user *Config) Budget {
	result := Budget{MaxEnvFixesPerFinding: 5, MaxHarnessFixesPerFinding: 8,
		MaxHypothesesPerFinding: 3, MaxSandboxMinutesPerFinding: 10}
	apply := func(value Budget) {
		if value.MaxEnvFixesPerFinding > 0 {
			result.MaxEnvFixesPerFinding = value.MaxEnvFixesPerFinding
		}
		if value.MaxHarnessFixesPerFinding > 0 {
			result.MaxHarnessFixesPerFinding = value.MaxHarnessFixesPerFinding
		}
		if value.MaxHypothesesPerFinding > 0 {
			result.MaxHypothesesPerFinding = value.MaxHypothesesPerFinding
		}
		if value.MaxSandboxMinutesPerFinding > 0 {
			result.MaxSandboxMinutesPerFinding = value.MaxSandboxMinutesPerFinding
		}
	}
	if user != nil {
		apply(user.Budget)
	}
	if repo != nil {
		apply(repo.Budget)
	}
	return result
}

// Load 讀取 path 的組態檔。檔案不存在 → 回傳空 Config + nil error
// （§3.1：解析序中任一層缺檔不是錯誤）；TOML 格式錯誤 → 回傳錯誤。
// 回傳的 Config 的兩個 map 恆為非 nil，呼叫端可直接寫入。
func Load(path string) (*Config, error) {
	cfg := &Config{
		Providers: map[string]Provider{},
		Models:    map[string]string{},
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return nil, fmt.Errorf("settings: read %s: %w", path, err)
	}
	// 非嚴格解碼：aegis.toml 內的 [budget]/[sandbox]/[sink_packs] 等節
	//（§5.4）由各自的包負責，此處靜默略過未知鍵。
	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("settings: parse %s: %w", path, err)
	}
	if cfg.Providers == nil {
		cfg.Providers = map[string]Provider{}
	}
	if cfg.Models == nil {
		cfg.Models = map[string]string{}
	}
	return cfg, nil
}

// SaveUser 將 cfg 以 TOML 寫入 path（使用者層級檔，如 settings.toml）。
//
//   - 先 MkdirAll 父目錄（~/.config/aegis 可能尚不存在，§3.3 首次執行流程）。
//   - 檔案權限 0600：使用者層級檔可能與 credentials.toml 同目錄，取 restrictive
//     慣例（§3.3 credentials.toml 亦為 0600）；測試鎖定此 mode。
//   - 鍵序確定性：BurntSushi/toml 的 Encoder 對 map 鍵一律排序輸出，故同一
//     cfg 兩次寫出位元組相同；本包另以 sort 明確排序 provider/model 名再交由
//     Encoder（見 encodeSorted），保證 byte-stable 不依賴函式庫實作細節。
func SaveUser(path string, c *Config) error {
	if c == nil {
		c = &Config{}
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("settings: mkdir %s: %w", dir, err)
		}
	}
	out, err := encodeSorted(c)
	if err != nil {
		return fmt.Errorf("settings: encode %s: %w", path, err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return fmt.Errorf("settings: write %s: %w", path, err)
	}
	return nil
}

// encodeSorted 以「排序後的鍵序」把 c 編成 TOML 位元組。
// 作法：先按鍵排序組出確定順序的 map（BurntSushi Encoder 本身會排序 map 鍵，
// 此處顯式排序僅為把確定性寫進本包契約，不依賴函式庫行為），再交 Encoder。
// 空的 providers/models 不輸出任何節，檔案保持最小。
func encodeSorted(c *Config) ([]byte, error) {
	providers := map[string]Provider{}
	for _, name := range sortedKeys(c.Providers) {
		providers[name] = c.Providers[name]
	}
	models := map[string]string{}
	for _, role := range sortedKeys(c.Models) {
		models[role] = c.Models[role]
	}
	doc := struct {
		Providers map[string]Provider `toml:"providers"`
		Models    map[string]string   `toml:"models"`
		Budget    Budget              `toml:"budget,omitempty"`
	}{Providers: providers, Models: models, Budget: c.Budget}
	var buf strings.Builder
	if err := toml.NewEncoder(&buf).Encode(doc); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

// sortedKeys 回傳 map 的鍵、升冪排序（byte-stable 輸出的真源）。
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ResolveModel 依 §3.1 解析序回傳 role 的模型引用：
// repo aegis.toml > 使用者 settings.toml > 無。
// 回傳值 ref 為 "<provider>/<model-id>"，source 為 "repo" | "user" | ""；
// 兩層皆無定義時回傳 ("", "", ErrModelUnset)。
//
// ASK（§23-9）：spec 未規定 repo/user 層「已設定但引用不合法」時的行為。
// 目前採不驗證、原樣回傳，由呼叫端自行以 ValidateRef 檢查（選項：
// (a) 維持現狀——ResolveModel 純查表；(b) 在此先跑 ValidateRef、不合法即回錯；
// (c) 回傳 ref 並附第二個 error 欄位）。待人類決定後調整。
func ResolveModel(repo, user *Config, role string) (ref string, source string, err error) {
	if repo != nil {
		if r, ok := repo.Models[role]; ok {
			return r, "repo", nil
		}
	}
	if user != nil {
		if r, ok := user.Models[role]; ok {
			return r, "user", nil
		}
	}
	return "", "", fmt.Errorf("settings: %w (role=%q)", ErrModelUnset, role)
}

// ValidateRef 檢查 ref 是否為 §3.1 模型引用語法 "<provider>/<model-id>"：
// 必須含一個 '/' 分隔符，provider 與 model-id 兩段皆非空，且整串無任何空白。
// ASK（§23-9）：model-id 內是否允許再含 '/'（如 OpenRouter 的
// "vendor/family/name" 深層 id）spec 未定義。目前採以「第一個 '/'」切分、
// model-id 段可含 '/'（寬鬆，不誤擋合法 id）；若人類決定閉集單層，改為
// strings.Count == 1 即可。
func ValidateRef(ref string) error {
	if strings.TrimSpace(ref) != ref || strings.ContainsAny(ref, " \t\n\r\v\f") {
		return fmt.Errorf("settings: model ref %q must not contain whitespace", ref)
	}
	provider, modelID, ok := strings.Cut(ref, "/")
	if !ok || provider == "" || modelID == "" {
		return fmt.Errorf("settings: model ref %q must be \"<provider>/<model-id>\"", ref)
	}
	return nil
}

// DefaultUserDir 回傳使用者層級設定目錄（§3.3：~/.config/aegis）：
// $XDG_CONFIG_HOME（需為絕對路徑，依 XDG 規範相對值視同未設）或
// ~/.config（經 os.UserHomeDir，HOME 變動即生效），再接 "aegis"。
func DefaultUserDir() (string, error) {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" && filepath.IsAbs(xdg) {
		return filepath.Join(xdg, "aegis"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("settings: resolve user config dir: %w", err)
	}
	return filepath.Join(home, ".config", "aegis"), nil
}

// DefaultUserPath 回傳使用者層級設定檔路徑（§3.3：settings.toml，
// /model set 的寫入處）。
func DefaultUserPath() (string, error) {
	dir, err := DefaultUserDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "settings.toml"), nil
}

// DefaultCredentialsPath 回傳 keychain 不可用時的憑證退回檔路徑
// （§3.3：credentials.toml，0600）。本包只定路徑，不讀寫內容。
func DefaultCredentialsPath() (string, error) {
	dir, err := DefaultUserDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "credentials.toml"), nil
}
