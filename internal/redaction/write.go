package redaction

import (
	"fmt"
	"os"
)

// WriteFile is the single default-deny persistence boundary for generated
// artifacts. Pattern matches are never written; callers may explicitly redact
// registered exact secrets before calling it.
func WriteFile(path string, data []byte, mode os.FileMode) error {
	if hits := Scan(string(data)); len(hits) > 0 {
		return fmt.Errorf("redaction: refused to persist secret patterns: %v", hits)
	}
	return os.WriteFile(path, data, mode)
}
