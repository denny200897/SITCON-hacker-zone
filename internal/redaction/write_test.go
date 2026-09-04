package redaction

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileRejectsSecretBeforePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact.json")
	secret := []byte(`{"token":"AKIAIOSFODNN7EXAMPLE"}`)
	if err := WriteFile(path, secret, 0o600); err == nil {
		t.Fatal("secret was persisted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("secret path exists: %v", err)
	}
	if err := WriteFile(path, []byte(`{"ok":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
}
