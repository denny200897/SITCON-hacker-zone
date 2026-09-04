package credentials

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/BurntSushi/toml"
)

// credentialsFile 是 credentials.toml 的磁碟格式（§3.3 設定檔退回）：
//
//	[keys]
//	<provider> = "<token>"
type credentialsFile struct {
	Keys map[string]string `toml:"keys"`
}

// FileStore 是 §3.3 的設定檔退回儲存：~/.config/aegis/credentials.toml、
// 權限 0600、使用時警告一次。TOML [keys] 表儲存；警告訊息永不包含金鑰內容
//（§23 金鑰防洩）。僅在無 keychain 環境使用（Manager.Set 的退回路徑）。
type FileStore struct {
	// Path 為 TOML 檔案路徑（§3.3 固定：~/.config/aegis/credentials.toml，
	// 見 DefaultFilePath）。
	Path string
	// Warn 為一次性警告輸出（可為 nil：不輸出）。訊息永不包含金鑰內容。
	Warn io.Writer

	// warnOnce 保證每個 FileStore 實例只發一次警告（§3.3：使用時警告一次）。
	warnOnce sync.Once
}

// DefaultFilePath 回傳 §3.3 固定的設定檔退回路徑：
// ~/.config/aegis/credentials.toml。
func DefaultFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("credentials: 無法取得家目錄: %w", err)
	}
	return filepath.Join(home, ".config", "aegis", "credentials.toml"), nil
}

// Get 取 provider 的金鑰；檔案或條目不存在回傳 ErrKeyNotFound。
// 每個實例第一次成功命中時發出一次警告（§3.3），訊息不含金鑰內容。
func (f *FileStore) Get(provider string) (string, error) {
	data, err := os.ReadFile(f.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrKeyNotFound
		}
		return "", fmt.Errorf("credentials: 讀取 %s 失敗: %w", f.Path, err)
	}
	var cf credentialsFile
	if err := toml.Unmarshal(data, &cf); err != nil {
		return "", fmt.Errorf("credentials: 解析 %s 失敗: %w", f.Path, err)
	}
	key, ok := cf.Keys[provider]
	if !ok || key == "" {
		return "", ErrKeyNotFound
	}
	// §3.3：使用時警告一次——警告文案不含金鑰（§23 金鑰防洩規則）。
	f.warnOnce.Do(func() {
		if f.Warn != nil {
			fmt.Fprintf(f.Warn,
				"credentials: API 金鑰由設定檔退回讀取（%s，權限 0600）；建議改用 OS keychain。金鑰內容不予顯示。\n",
				f.Path)
		}
	})
	return key, nil
}

// Set 寫入 provider 的金鑰（保留其他既有條目），檔案權限固定 0600
//（§3.3；顯式 chmod，umask 不影響）。
func (f *FileStore) Set(provider, key string) error {
	cf, err := f.load()
	if err != nil {
		return err
	}
	if cf.Keys == nil {
		cf.Keys = map[string]string{}
	}
	cf.Keys[provider] = key
	return f.write(cf)
}

// Delete 移除 provider 的條目（保留其他條目），並維持檔案權限 0600（§3.3）。
// 檔案或條目不存在回傳 ErrKeyNotFound。
func (f *FileStore) Delete(provider string) error {
	cf, err := f.load()
	if err != nil {
		return err
	}
	if _, ok := cf.Keys[provider]; !ok {
		return ErrKeyNotFound
	}
	delete(cf.Keys, provider)
	return f.write(cf)
}

// load 讀入現有 TOML 內容（檔案不存在視為空表）。解析失敗如實上拋：
// 靜默忽略會在 Set 時整檔覆寫、吞掉使用者其他金鑰條目。
func (f *FileStore) load() (credentialsFile, error) {
	var cf credentialsFile
	data, err := os.ReadFile(f.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return cf, nil
		}
		return cf, fmt.Errorf("credentials: 讀取 %s 失敗: %w", f.Path, err)
	}
	if err := toml.Unmarshal(data, &cf); err != nil {
		return cf, fmt.Errorf("credentials: 解析 %s 失敗: %w", f.Path, err)
	}
	return cf, nil
}

// write 序列化 [keys] 表並落盤：建立 0600、寫入後顯式 chmod 0600
//（§3.3 權限 0600；確保既有檔案被放寬過的權限也一併收回）。父目錄 0700。
func (f *FileStore) write(cf credentialsFile) error {
	dir := filepath.Dir(f.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("credentials: 建立目錄 %s 失敗: %w", dir, err)
	}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(cf); err != nil {
		return fmt.Errorf("credentials: 編碼 TOML 失敗: %w", err)
	}
	fh, err := os.OpenFile(f.Path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("credentials: 寫入 %s 失敗: %w", f.Path, err)
	}
	if _, err := fh.Write(buf.Bytes()); err != nil {
		fh.Close()
		return fmt.Errorf("credentials: 寫入 %s 失敗: %w", f.Path, err)
	}
	if err := fh.Close(); err != nil {
		return fmt.Errorf("credentials: 關閉 %s 失敗: %w", f.Path, err)
	}
	if err := os.Chmod(f.Path, 0o600); err != nil {
		return fmt.Errorf("credentials: chmod 0600 %s 失敗: %w", f.Path, err)
	}
	return nil
}