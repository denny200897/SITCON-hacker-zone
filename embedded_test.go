package aegisassets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMaterializeIsContentAddressedAndRepairsModifiedFile(t *testing.T) {
	cache := t.TempDir()
	schemas1, pack1, err := Materialize(cache)
	if err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(pack1, "manifest.json")
	original, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	schemas2, pack2, err := Materialize(cache)
	if err != nil {
		t.Fatal(err)
	}
	if schemas1 != schemas2 || pack1 != pack2 {
		t.Fatal("same embedded payload must use the same content-addressed path")
	}
	repaired, err := os.ReadFile(filepath.Join(pack2, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(repaired) != string(original) {
		t.Fatal("modified cached asset was not repaired from embedded bytes")
	}
	if _, err := os.Stat(filepath.Join(schemas2, "finding.schema.json")); err != nil {
		t.Fatal(err)
	}
}
