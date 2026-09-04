package credentials

import "sync"

// MemoryKeyring 是純記憶體 Keyring（map + mutex）：單元測試與無 keychain
// 環境使用；不落盤、不觸碰真實 OS keychain（測試一律用此實作，§3.3）。
// 零值不可用，請經 NewMemoryKeyring 建構。
type MemoryKeyring struct {
	mu   sync.Mutex
	keys map[string]string
}

// NewMemoryKeyring 建構空的記憶體金鑰儲存。
func NewMemoryKeyring() *MemoryKeyring {
	return &MemoryKeyring{keys: map[string]string{}}
}

func (m *MemoryKeyring) Get(service, user string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok := m.keys[service+"\x00"+user]; ok {
		return v, nil
	}
	return "", ErrKeyNotFound
}

func (m *MemoryKeyring) Set(service, user, password string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[service+"\x00"+user] = password
	return nil
}

func (m *MemoryKeyring) Delete(service, user string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.keys[service+"\x00"+user]; !ok {
		return ErrKeyNotFound
	}
	delete(m.keys, service+"\x00"+user)
	return nil
}