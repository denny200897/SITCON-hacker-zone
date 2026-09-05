package redaction

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFile is the single default-deny persistence boundary for generated
// artifacts. Pattern matches are never written; callers may explicitly redact
// registered exact secrets before calling it.
func WriteFile(path string, data []byte, mode os.FileMode) error {
	if hits := Scan(string(data)); len(hits) > 0 {
		return fmt.Errorf("redaction: refused to persist secret patterns: %v", hits)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".aegis-write-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}
