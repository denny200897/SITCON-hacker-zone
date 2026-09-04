// Package credentials 是 BYOK 金鑰管理（SPEC §3.3）。
//
// 憑證解析優先序（§3.3）：環境變數 > OS keychain > 設定檔退回
//（~/.config/aegis/credentials.toml，權限 0600，使用時警告一次）。
//
// 金鑰防洩規則（§3.3、§23）：金鑰永不寫入 aegis.toml、永不進沙箱、永不進報告；
// /provider list 只顯示有無（Manager.Status 不回傳內容）。任何落盤輸出寫入前，
// 由 redaction 套件以本包解析出的金鑰做遮蔽。
package credentials

import (
	"errors"
	"os"
	"strings"
	"unicode"
)

// ProviderType 是供應商轉接器類型閉集（§3.2）：anthropic 與 openai-compat 兩種。
type ProviderType string

const (
	ProviderTypeAnthropic    ProviderType = "anthropic"
	ProviderTypeOpenAICompat ProviderType = "openai-compat"
)

// ErrKeyNotFound 是「金鑰不存在」的統一哨兵錯誤（§3.3 解析序各層 miss 的訊號；
// go-keyring 的 ErrNotFound 與檔案缺漏都正規化到本錯誤）。
var ErrKeyNotFound = errors.New("credentials: key not found")

// KeyringService 是本工具在 OS keychain 中的固定 service 名稱（§3.3 keychain 儲存）。
const KeyringService = "aegis"

// Keyring 是金鑰儲存後端介面（§3.3）：OS keychain（NewOSKeyring）與
// 測試／無 keychain 環境用記憶體實作（MemoryKeyring）共用。
type Keyring interface {
	Get(service, user string) (string, error)
	Set(service, user, password string) error
	Delete(service, user string) error
}

// EnvVarName 依 §3.3 正規化供應商名為環境變數名：非英數字元一律轉 '_' 後全大寫，
// 前綴 "AEGIS_"、後綴 "_API_KEY"。例：my-openrouter → AEGIS_MY_OPENROUTER_API_KEY。
func EnvVarName(providerName string) string {
	var b strings.Builder
	b.WriteString("AEGIS_")
	for _, r := range providerName {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(unicode.ToUpper(r))
		} else {
			b.WriteByte('_')
		}
	}
	b.WriteString("_API_KEY")
	return b.String()
}

// CompatEnvVar 回傳 §3.3 相容辨識的慣用環境變數名：
// anthropic → ANTHROPIC_API_KEY、openai-compat → OPENAI_API_KEY；
// 其他類型無慣用名，回傳空字串。
func CompatEnvVar(pt ProviderType) string {
	switch pt {
	case ProviderTypeAnthropic:
		return "ANTHROPIC_API_KEY"
	case ProviderTypeOpenAICompat:
		return "OPENAI_API_KEY"
	default:
		return ""
	}
}

// envCandidates 依 §3.3 解析序回傳應查詢的環境變數名：正規化名優先，
// 慣用相容名其後（兩者相同時只查一次）。
func envCandidates(providerName string, pt ProviderType) []string {
	names := []string{EnvVarName(providerName)}
	if compat := CompatEnvVar(pt); compat != "" && compat != names[0] {
		names = append(names, compat)
	}
	return names
}

// getenv 讀環境變數：Environ 為 nil 時用 os.Getenv（測試可注入假環境，
// 避免動到真實 process 環境）。
func (m *Manager) getenv(name string) string {
	if m.Environ == nil {
		return os.Getenv(name)
	}
	return m.Environ(name)
}