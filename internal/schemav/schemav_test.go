package schemav

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// §22 M0a：schemas/ 11 個檔案存在且相互驗證通過（contracts tests 另在 tests/，
// 此處驗 registry 行為本身）。

func TestLoadDirAndValidate(t *testing.T) {
	dir := filepath.Join("..", "..", "schemas")
	r := New()
	if err := r.LoadDir(dir); err != nil {
		t.Fatal(err)
	}

	// 11 個 schema 齊備（§21.1）
	want := []string{
		"inventory", "candidate", "finding", "witness_spec", "run_request",
		"run_result", "evidence", "triage", "journal_event", "pack_manifest", "settings",
	}
	for _, n := range want {
		if _, err := os.Stat(filepath.Join(dir, n+".schema.json")); err != nil {
			t.Errorf("missing schema %s", n)
		}
	}

	// finding：合法樣本過
	ok := `{"id":"F-0007","sink":{"file":"app/db.py","line":88,"symbol":"u.find_by_name","type":"sql.concat"},
	  "sources":[{"origin":"semgrep"}],"reachability":"D2","verification":"PROVEN","disposition":"OPEN","snapshot_id":"SN-aaaaaaaaaaaa"}`
	if err := r.Validate("finding", []byte(ok)); err != nil {
		t.Fatalf("valid finding rejected: %v", err)
	}

	// 非法 verification 拒絕（閉集，§23-4）
	bad := strings.Replace(ok, `"PROVEN"`, `"NOT_EXPLOITABLE"`, 1)
	if err := r.Validate("finding", []byte(bad)); err == nil {
		t.Fatal("invented verification state accepted")
	}

	// 可變 tag 映像拒絕（run_request.image 只收 digest）
	img := `{"run_id":"R-0001","kind":"exploit","image":"aegis-python-web:3.12","files":{},
	  "mounts":[],"cmd":["/aegis/entrypoint.py"],"network":"none","nonce":"n","timeout_sec":60,
	  "caps":{"cpus":"1","mem":"512m","pids":128,"cap_drop":"ALL","no_new_privileges":true,"rootfs":"ro"}}`
	if err := r.Validate("run_request", []byte(img)); err == nil {
		t.Fatal("mutable tag image accepted")
	}
	digest := strings.Replace(img, `"aegis-python-web:3.12"`, `"aegis-python-web@sha256:`+strings.Repeat("ab", 32)+`"`, 1)
	if err := r.Validate("run_request", []byte(digest)); err != nil {
		t.Fatalf("digest image rejected: %v", err)
	}

	// evidence 引用 run_result schema（$ref）可解析
	ev := `{"id":"EV-0001","kind":"exploit","snapshot_id":"SN-aaaaaaaaaaaa","repo_tree_hash":"sha256:` +
		strings.Repeat("0", 64) + `","image":"i@sha256:` + strings.Repeat("0", 64) + `",
		"pack":{"id":"python-web","version":"1.0.0","abi":1},"runner_version":"0.1.0","prompt_version":"prover/v5",
		"schemas_version":"1.0","run_request_hash":"sha256:` + strings.Repeat("0", 64) + `",
		"run_result":{"exit":0,"stdout":"","stderr":"","artifacts":[],"fs_diff":{"added":[],"modified":[]}},
		"oracle":{"oracle_id":"sqli.error/v1","nonce":"aa","result":true},
		"prev_evidence_hash":null,"created_by":"prover","verified_by":"checker"}`
	if err := r.Validate("evidence", []byte(ev)); err != nil {
		t.Fatalf("valid evidence rejected: %v", err)
	}
}

func TestValidateUnknownSchema(t *testing.T) {
	r := New()
	if err := r.LoadDir(filepath.Join("..", "..", "schemas")); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate("nonexistent", []byte(`{}`)); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateBadJSON(t *testing.T) {
	r := New()
	_ = r.LoadDir(filepath.Join("..", "..", "schemas"))
	if err := r.Validate("finding", []byte("nope")); err == nil {
		t.Fatal("expected decode error")
	}
}