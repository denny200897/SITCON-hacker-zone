package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aegis-dev/aegis/internal/schemav"
)

// TestAllSchemasHaveValidFixtures keeps the eleven M0a contracts exercised by
// a single registry-level test.  The fixtures intentionally use the smallest
// valid documents so a schema change fails close to its contract boundary.
func TestAllSchemasHaveValidFixtures(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	schemasDir := filepath.Join(root, "schemas")
	reg := schemav.New()
	if err := reg.LoadDir(schemasDir); err != nil {
		t.Fatal(err)
	}
	fixtures := map[string]map[string]any{
		"inventory":     {"snapshot_id": "SN-aaaaaaaaaaaa", "files": []any{}, "frameworks": []any{}, "routes": []any{}, "entrypoints": []any{}, "dependencies": []any{}},
		"candidate":     {"id": "C-0001", "sink": map[string]any{"file": "app.py", "line": int64(1), "symbol": "x", "type": "sql.concat"}, "sources": []any{map[string]any{"origin": "semgrep"}}},
		"finding":       {"id": "F-0001", "sink": map[string]any{"file": "app.py", "line": int64(1), "symbol": "x", "type": "sql.concat"}, "sources": []any{}, "reachability": "UNKNOWN", "verification": "NOT_RUN", "disposition": "OPEN", "snapshot_id": "SN-aaaaaaaaaaaa"},
		"witness_spec":  {"template_id": "py/http-endpoint/v3", "target_symbol": "app.x", "oracle_id": "sqli.error/v1", "payload": "{{NONCE}}'", "generated_files": map[string]any{}, "run_mode": "witness"},
		"run_request":   {"run_id": "R-0001", "kind": "negative", "oracle_id": "sqli.error/v1", "image": "alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "files": map[string]any{}, "mounts": []any{}, "cmd": []any{"true"}, "network": "none", "nonce": "abc", "timeout_sec": int64(60), "caps": map[string]any{"cpus": "1", "mem": "512m", "pids": int64(128), "cap_drop": "ALL", "no_new_privileges": true, "rootfs": "ro"}},
		"run_result":    {"exit": int64(0), "stdout": "", "stderr": "", "artifacts": []any{}, "fs_diff": map[string]any{"added": []any{}, "modified": []any{}}},
		"triage":        {"candidate_id": "C-0001", "verdict": "PROCEED", "rationale": "reachable"},
		"journal_event": {"seq": int64(1), "type": "finding_created", "ts": "2026-09-04T00:00:00Z", "schema_version": "1.0"},
		"settings":      map[string]any{},
		"tools":         map[string]any{},
	}
	for name, fixture := range fixtures {
		b, err := json.Marshal(fixture)
		if err != nil {
			t.Fatal(err)
		}
		if err := reg.Validate(name, b); err != nil {
			t.Errorf("%s valid fixture rejected: %v", name, err)
		}
	}
	// pack_manifest is validated against the shipped, hash-pinned pack itself.
	manifest, err := os.ReadFile(filepath.Join(root, "packs", "python-web", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Validate("pack_manifest", manifest); err != nil {
		t.Fatalf("pack_manifest shipped fixture rejected: %v", err)
	}
	// evidence exercises the nested run_result $ref and oracle contract.
	evidence := map[string]any{"id": "EV-0001", "kind": "exploit", "snapshot_id": "SN-aaaaaaaaaaaa", "repo_tree_hash": "sha256:" + string(make([]byte, 0)), "image": "alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "pack": map[string]any{"id": "python-web", "version": "1.0.0", "abi": int64(1)}, "runner_version": "aegis/1", "prompt_version": "v1", "schemas_version": "1.0", "run_request_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "run_result": fixtures["run_result"], "oracle": map[string]any{"oracle_id": "sqli.error/v1", "nonce": "abc", "result": true}, "created_by": "prover", "verified_by": "checker"}
	evidence["repo_tree_hash"] = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	b, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Validate("evidence", b); err != nil {
		t.Fatalf("evidence/$ref fixture rejected: %v", err)
	}
}
