// Package aegisassets exposes the schemas and bundled python-web pack carried
// inside the static Aegis binary. Runtime consumers materialize them into a
// content-addressed user cache only when an external tool needs a real path.
package aegisassets

import (
	"crypto/sha256"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// FS is the immutable distribution payload. These files remain the source
// tree's canonical schemas/pack; go:embed does not create a second copy.
//
//go:embed schemas/*.json packs/python-web
var FS embed.FS

// Materialize writes the embedded payload beneath cacheRoot/assets/<hash> and
// returns concrete paths for libraries and external tools that require them.
func Materialize(cacheRoot string) (schemasDir, packDir string, err error) {
	if cacheRoot == "" {
		return "", "", fmt.Errorf("assets: cache root is empty")
	}
	paths := []string{}
	if err := fs.WalkDir(FS, ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !d.IsDir() {
			paths = append(paths, path)
		}
		return nil
	}); err != nil {
		return "", "", err
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, path := range paths {
		data, readErr := FS.ReadFile(path)
		if readErr != nil {
			return "", "", readErr
		}
		_, _ = h.Write([]byte(path))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(data)
	}
	root := filepath.Join(cacheRoot, "assets", fmt.Sprintf("%x", h.Sum(nil))[:16])
	for _, path := range paths {
		data, readErr := FS.ReadFile(path)
		if readErr != nil {
			return "", "", readErr
		}
		destination := filepath.Join(root, filepath.FromSlash(path))
		if err := materializeFile(destination, data); err != nil {
			return "", "", err
		}
	}
	return filepath.Join(root, "schemas"), filepath.Join(root, "packs", "python-web"), nil
}

func materializeFile(path string, data []byte) error {
	if existing, err := os.ReadFile(path); err == nil {
		if string(existing) == string(data) {
			return nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("assets: mkdir %s: %w", filepath.Dir(path), err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".aegis-asset-*")
	if err != nil {
		return fmt.Errorf("assets: create temp: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
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
		return fmt.Errorf("assets: install %s: %w", path, err)
	}
	committed = true
	return nil
}
