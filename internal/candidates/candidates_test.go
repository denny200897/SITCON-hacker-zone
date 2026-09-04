package candidates

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRunParsesOnlyQualifiedSemgrepHits(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fake executable")
	}
	d := t.TempDir()
	script := filepath.Join(d, "semgrep")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s' '{\"results\":[{\"path\":\"app.py\",\"start\":{\"line\":7},\"extra\":{\"match\":\"db.execute(x)\",\"message\":\"SQL\",\"metadata\":{\"aegis_family\":\"sqli\",\"aegis_sink_type\":\"sql.concat\"}}},{\"path\":\"x.py\",\"start\":{\"line\":0},\"extra\":{}}]}'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := Run(context.Background(), d, "rule.yml", "r1", script)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "C-0001" || got[0].Sink.File != "app.py" {
		t.Fatalf("unexpected candidates: %#v", got)
	}
}
