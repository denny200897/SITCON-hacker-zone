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

func TestWriteFileAtomicallyReplacesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.json")
	if err := WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, []byte("new"), 0o640); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new" {
		t.Fatalf("content = %q", data)
	}
	leftovers, err := filepath.Glob(filepath.Join(dir, ".aegis-write-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("temporary files leaked: %v (%v)", leftovers, err)
	}
}
