package credentials

import (
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"
)

// osKeyring 以 github.com/zalando/go-keyring 包裝 OS keychain（§23 相依表：
// 統一 macOS Keychain / Linux libsecret / Windows Credential Manager；
// 不可用時由 Manager.Set 退回 §3.3 的檔案模式）。macOS 走 `security`
// 子指令、無 cgo，可直接建置。service 名固定為 KeyringService（"aegis"）。
type osKeyring struct{}

// NewOSKeyring 回傳 OS keychain 後端（§3.3 keychain 儲存）。
// go-keyring 的 ErrNotFound 一律正規化為本包的 ErrKeyNotFound。
func NewOSKeyring() Keyring { return osKeyring{} }

func (osKeyring) Get(service, user string) (string, error) {
	v, err := keyring.Get(service, user)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", ErrKeyNotFound
	}
	return v, err
}

func (osKeyring) Set(service, user, password string) error {
	return keyring.Set(service, user, password)
}

func (osKeyring) Delete(service, user string) error {
	err := keyring.Delete(service, user)
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrKeyNotFound
	}
	return err
}

// Manager 統合 §3.3 的憑證解析序：環境變數 > OS keychain > 設定檔退回。
// 金鑰內容只經 Resolve 回傳一次給呼叫端（host 端 adapter 使用），
// Status 只回報有無與來源、永不回傳內容（§3.3 /provider list）。
type Manager struct {
	// Keyring 為 OS keychain 後端；nil 表示無 keychain 環境（僅檔案退回）。
	Keyring Keyring
	// File 為設定檔退回儲存（§3.3 credentials.toml，0600）；可為 nil。
	File *FileStore
	// Environ 為環境變數讀取函式；nil 時使用 os.Getenv（測試可注入假環境）。
	Environ func(string) string
}

// Resolve 依 §3.3 解析序取金鑰：環境變數（正規化名優先、慣用相容名其後）>
// OS keychain（若 Keyring != nil）> 檔案退回（若 File != nil）。
// source ∈ "env" | "keychain" | "file"；找不到時 key 與 source 為空、
// err = ErrKeyNotFound。
func (m *Manager) Resolve(providerName string, pt ProviderType) (key string, source string, err error) {
	// 1) 環境變數（§3.3：AEGIS_<供應商大寫>_API_KEY，並相容辨識慣用名）。
	for _, name := range envCandidates(providerName, pt) {
		if v := m.getenv(name); v != "" {
			return v, "env", nil
		}
	}
	// 2) OS keychain（§3.3）。
	if m.Keyring != nil {
		k, err := m.Keyring.Get(KeyringService, providerName)
		if err == nil {
			return k, "keychain", nil
		}
		if !errors.Is(err, ErrKeyNotFound) {
			// ASK: keychain 查詢失敗（非「不存在」）時的處理。採 (a) 視同 miss、
			// 續查檔案退回——符合 §3.3「無 keychain 環境退回設定檔」的精神，
			// 且解析失敗不該因單一後端故障而中斷。選項 (b)：直接回傳該錯誤中斷解析
			//（較早暴露後端故障，但無 keychain 機器的整條解析會硬失敗）。
		}
	}
	// 3) 設定檔退回（§3.3：credentials.toml，0600，使用時警告一次）。
	if m.File != nil {
		k, err := m.File.Get(providerName)
		if err == nil {
			return k, "file", nil
		}
		if !errors.Is(err, ErrKeyNotFound) {
			// 非「不存在」的錯誤（檔案損毀、無權限）如實上拋——靜默吞掉會讓
			// 呼叫端誤判為「未設定金鑰」。
			return "", "", err
		}
	}
	return "", "", ErrKeyNotFound
}

// Set 依 §3.3 寫入 OS keychain（/key set）；keychain 不可用（Set 回傳任何錯誤）
// 時退回檔案模式（§23 相依表：不可用時退回 §3.3 的檔案模式）。
// Keyring 為 nil 時僅寫檔案。
func (m *Manager) Set(providerName string, pt ProviderType, key string) error {
	if m.Keyring != nil {
		err := m.Keyring.Set(KeyringService, providerName, key)
		if err == nil {
			return nil
		}
		if m.File == nil {
			return fmt.Errorf("credentials: keychain set failed: %w", err)
		}
		if ferr := m.File.Set(providerName, key); ferr != nil {
			return fmt.Errorf("credentials: keychain set failed (%v); file fallback failed: %w", err, ferr)
		}
		// ASK: keychain 失敗但檔案退回成功時的回傳值。採 (a) 回傳 nil——
		// 金鑰已成功落盤，呼叫端不應視為失敗；使用檔案時 FileStore 會在使用時
		// 自行警告一次（§3.3）。選項 (b)：仍回傳包裝 keychain 錯誤的非 nil 值，
		// 讓互動模式能把「已退回檔案模式」提示給使用者（需呼叫端容忍
		// 「非 nil 但其實已寫入」的語意）。
		return nil
	}
	// 無 keychain（Keyring nil）→ 僅寫檔案（§3.3 設定檔退回）。
	if m.File == nil {
		return errors.New("credentials: no keyring and no file store configured")
	}
	return m.File.Set(providerName, key)
}

// Clear 刪除已存 token（§3.3 /key clear、/provider remove 連同 keychain 金鑰）：
// keychain 與檔案退回都清；「不存在」視為成功（冪等）。其他錯誤回傳第一個。
func (m *Manager) Clear(providerName string, pt ProviderType) error {
	var firstErr error
	if m.Keyring != nil {
		if err := m.Keyring.Delete(KeyringService, providerName); err != nil && !errors.Is(err, ErrKeyNotFound) && firstErr == nil {
			firstErr = err
		}
	}
	if m.File != nil {
		if err := m.File.Delete(providerName); err != nil && !errors.Is(err, ErrKeyNotFound) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Status 回報金鑰是否已設定及其來源，永不回傳金鑰內容
//（§3.3 /provider list 只顯示有無，永不顯示內容）。
func (m *Manager) Status(providerName string, pt ProviderType) (set bool, source string) {
	key, source, err := m.Resolve(providerName, pt)
	if err != nil {
		return false, ""
	}
	_ = key // 內容即棄：本方法的合約是不外洩金鑰（§3.3）。
	return true, source
}