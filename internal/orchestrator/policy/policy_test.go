package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aegis-dev/aegis/internal/evidence"
	"github.com/aegis-dev/aegis/internal/schemav"
)

// ---- stub PackView / ASTCheck / SecretScan（不 import internal/packs，見整合 notes） ----

type stubPack struct {
	templates map[string]*Template
	oracles   map[string]*Oracle
}

func (p *stubPack) Template(id string) (*Template, error) {
	if t, ok := p.templates[id]; ok {
		return t, nil
	}
	return nil, fmt.Errorf("pack: template %q 不存在", id)
}

func (p *stubPack) Oracle(id string) (*Oracle, error) {
	if o, ok := p.oracles[id]; ok {
		return o, nil
	}
	return nil, fmt.Errorf("pack: oracle %q 不存在", id)
}

func testPack() *stubPack {
	return &stubPack{
		templates: map[string]*Template{
			"py/http-endpoint/v3": {
				TemplateID:   "py/http-endpoint/v3",
				Family:       "sqli",
				RunMode:      "witness",
				AllowedFiles: []string{".py"},
				ServiceCmd:   "python /aegis/witness/app.py",
				ServicePort:  8000,
				WaitFor:      "GET /healthz",
				Image:        "aegis-python-web@sha256:" + strings.Repeat("ab", 32),
			},
			"py/direct-sqlite/v1": {
				TemplateID:   "py/direct-sqlite/v1",
				Family:       "sqli",
				RunMode:      "direct",
				AllowedFiles: []string{".py"},
				ServiceCmd:   "python /target/app/main.py",
				ServicePort:  8000,
				WaitFor:      "GET /healthz",
				Image:        "aegis-python-web@sha256:" + strings.Repeat("ab", 32),
			},
		},
		oracles: map[string]*Oracle{
			"sqli.error/v1": {OracleID: "sqli.error/v1", Family: "sqli"},
		},
	}
}

type astSpy struct {
	dir, symbol string
	err         error
}

func (a *astSpy) check(dir, symbol string) error {
	a.dir, a.symbol = dir, symbol
	return a.err
}

type secretSpy struct {
	hits   bool
	texts  []string
	called bool
}

func (s *secretSpy) scan(text string) bool {
	s.called = true
	s.texts = append(s.texts, text)
	return s.hits
}

// nonce 固定測試值（模擬 runner 產生、prover 未知）。
const testNonce = "feedfacefeedfacefeedfacefeedface"

func baseSpec() map[string]any {
	return map[string]any{
		"template_id":   "py/http-endpoint/v3",
		"target_symbol": "app.db.UserRepo.find_by_name",
		"oracle_id":     "sqli.error/v1",
		"payload":       "{{NONCE}}'",
		"generated_files": map[string]any{
			"witness/app.py":     "app = {{NONCE}}",
			"witness/exploit.py": "exploit({{NONCE_HEX}})",
		},
		"assumptions":    []any{"產品將新增依名稱查詢使用者的 HTTP endpoint"},
		"run_mode":       "witness",
		"learning_notes": []any{"上輪 X", "這輪 Y", "預期 Z"},
	}
}

func compileInput(spec map[string]any, mutate func(*Input)) Input {
	ast := &astSpy{}
	sec := &secretSpy{}
	in := Input{
		Spec:                spec,
		FindingReachability: "D2",
		SnapshotDir:         "/tmp/snap",
		PrevSpecHashes:      map[string]bool{},
		SecretScan:          sec.scan,
		ASTCheck:            ast.check,
		NonceCount:          1,
		RunID:               "R-0001",
		SnapshotID:          "SN-0001",
		Kind:                "exploit",
		PackView:            testPack(),
	}
	if mutate != nil {
		mutate(&in)
	}
	return in
}

// expectReject 斷言 Compile 回傳 *SpecError 且 Reason 為 want；並檢查訊息不含 nonce。
func expectReject(t *testing.T, in Input, want string) {
	t.Helper()
	rr, err := Compile(in, testNonce)
	if err == nil {
		t.Fatalf("應遭拒收（%s），卻成功組出 RunRequest", want)
	}
	if rr != nil {
		t.Fatalf("拒收時 RunRequest 應為 nil")
	}
	var se *SpecError
	if !errors.As(err, &se) {
		t.Fatalf("錯誤應為 *SpecError，得到 %T: %v", err, err)
	}
	if se.Reason != want {
		t.Fatalf("拒收原因 = %q，期待 %q", se.Reason, want)
	}
	if reasons[se.Reason] == false {
		t.Fatalf("Reason %q 不在閉集", se.Reason)
	}
	// §18.2：拒收訊息絕不含 nonce
	if strings.Contains(err.Error(), testNonce) {
		t.Fatalf("SpecError 訊息不得含 nonce：%s", err.Error())
	}
}

// ---- 合法 spec 全走完 ----

func TestCompileHappyPath(t *testing.T) {
	spec := baseSpec()
	in := compileInput(spec, nil)
	rr, err := Compile(in, testNonce)
	if err != nil {
		t.Fatalf("合法 spec 不應被拒：%v", err)
	}

	// §5.2：欄位閉集與政策值
	if rr["run_id"] != "R-0001" || rr["kind"] != "exploit" {
		t.Fatalf("run_id/kind 錯誤：%v %v", rr["run_id"], rr["kind"])
	}
	wantImage := "aegis-python-web@sha256:" + strings.Repeat("ab", 32)
	if rr["image"] != wantImage {
		t.Fatalf("image = %v，期待 pack digest", rr["image"])
	}
	if rr["network"] != Network {
		t.Fatalf("network 應為 %q", Network)
	}
	if rr["timeout_sec"] != int64(TimeoutSec) {
		t.Fatalf("timeout_sec = %v", rr["timeout_sec"])
	}
	if rr["nonce"] != testNonce {
		t.Fatalf("nonce 應原樣進 RunRequest")
	}

	// caps 閉集（§5.2／§17.1）
	caps, ok := rr["caps"].(map[string]any)
	if !ok {
		t.Fatalf("caps 型別錯誤：%T", rr["caps"])
	}
	wantCaps := map[string]any{
		"cpus": CPUs, "mem": Mem, "pids": int64(PIDsLimit),
		"cap_drop": CapDrop, "no_new_privileges": true, "rootfs": "ro",
		"ulimit_nofile": int64(ULimitNF), "user": User,
	}
	for k, v := range wantCaps {
		if caps[k] != v {
			t.Fatalf("caps[%s] = %v，期待 %v", k, caps[k], v)
		}
	}
	if len(caps) != len(wantCaps) {
		t.Fatalf("caps 應為閉集 %v，得到 %v", wantCaps, caps)
	}

	// mounts 閉集
	mounts, ok := rr["mounts"].([]any)
	if !ok || len(mounts) != 1 {
		t.Fatalf("mounts 應為單一 TARGET_SNAPSHOT 唯讀掛載")
	}
	m0, ok := mounts[0].(map[string]any)
	if !ok || m0["src"] != "TARGET_SNAPSHOT" || m0["dst"] != "/target" || m0["readonly"] != true {
		t.Fatalf("mounts[0] 錯誤：%v", mounts[0])
	}

	// cmd 固定 entrypoint
	cmd, ok := rr["cmd"].([]any)
	if !ok || len(cmd) != 3 || cmd[0] != "/aegis/entrypoint.py" || cmd[1] != "--template" || cmd[2] != "py/http-endpoint/v3" {
		t.Fatalf("cmd 錯誤：%v", rr["cmd"])
	}

	// service 由 template metadata 決定
	svc, ok := rr["service"].(map[string]any)
	if !ok || svc["cmd"] != "python /aegis/witness/app.py" || svc["port"] != int64(8000) || svc["wait_for"] != "GET /healthz" {
		t.Fatalf("service 錯誤：%v", rr["service"])
	}

	// labels
	labels, ok := rr["labels"].(map[string]any)
	if !ok || labels["aegis.run_id"] != "R-0001" || labels["aegis.snapshot_id"] != "SN-0001" {
		t.Fatalf("labels 錯誤：%v", rr["labels"])
	}

	// §17.2：payload 與 files 內 nonce 已替換、無殘留 placeholder
	if rr["payload"] != testNonce+"'" {
		t.Fatalf("payload nonce 替換錯誤：%q", rr["payload"])
	}
	files, ok := rr["files"].(map[string]any)
	if !ok {
		t.Fatalf("files 型別錯誤：%T", rr["files"])
	}
	if files["witness/app.py"] != "app = "+testNonce {
		t.Fatalf("witness/app.py nonce 替換錯誤：%q", files["witness/app.py"])
	}
	if files["witness/exploit.py"] != "exploit("+testNonce+")" {
		t.Fatalf("witness/exploit.py nonce 替換錯誤：%q", files["witness/exploit.py"])
	}
	for k, v := range files {
		s, _ := v.(string)
		if strings.Contains(s, noncePlaceholder) || strings.Contains(s, noncePlaceholderHex) {
			t.Fatalf("%s 仍殘留 placeholder：%q", k, s)
		}
		if strings.Contains(k, noncePlaceholder) {
			t.Fatalf("檔名不得含 placeholder：%q", k)
		}
	}

	// 原 spec 不得被改動（PrevSpecHashes 以原始 spec 計 hash）
	if spec["payload"] != "{{NONCE}}'" {
		t.Fatalf("Compile 不得改動輸入 spec")
	}

	// RunRequest 符合機讀 schema（schemas/ 為唯一真源）
	validateRunRequest(t, rr)
}

// validateRunRequest 以 internal/schemav 對 schemas/run_request.schema.json 驗證。
func validateRunRequest(t *testing.T, rr map[string]any) {
	t.Helper()
	reg := schemav.New()
	if err := reg.LoadDir("../../../schemas"); err != nil {
		t.Fatalf("載入 schemas 失敗：%v", err)
	}
	data, err := json.Marshal(rr)
	if err != nil {
		t.Fatalf("marshal RunRequest：%v", err)
	}
	if err := reg.Validate("run_request", data); err != nil {
		t.Fatalf("RunRequest 不符 run_request.schema.json：%v", err)
	}
}

// ---- §17.9-1：template／oracle 解析 ----

func TestRejectUnknownTemplate(t *testing.T) {
	spec := baseSpec()
	spec["template_id"] = "py/nonexistent/v9"
	expectReject(t, compileInput(spec, nil), ReasonUnknownTemplate)
}

func TestRejectUnknownOracle(t *testing.T) {
	spec := baseSpec()
	spec["oracle_id"] = "rce.exec/v1"
	expectReject(t, compileInput(spec, nil), ReasonUnknownOracle)
}

func TestRejectFamilyMismatch(t *testing.T) {
	pack := testPack()
	pack.oracles["rce.exec/v1"] = &Oracle{OracleID: "rce.exec/v1", Family: "rce"}
	spec := baseSpec()
	spec["oracle_id"] = "rce.exec/v1"
	in := compileInput(spec, nil)
	in.PackView = pack
	expectReject(t, in, ReasonFamilyMismatch)
}

func TestRejectModeNotSupported(t *testing.T) {
	spec := baseSpec() // witness 模板
	spec["run_mode"] = "direct"
	expectReject(t, compileInput(spec, nil), ReasonModeNotSupported)
}

// ---- §17.9-2：target_symbol ----

func TestRejectTargetSymbolMissing(t *testing.T) {
	ast := &astSpy{err: fmt.Errorf("exit 1：未命中")}
	in := compileInput(baseSpec(), func(in *Input) { in.ASTCheck = ast.check })
	expectReject(t, in, ReasonTargetSymbolMissing)
}

func TestASTCheckReceivesSnapshotAndSymbol(t *testing.T) {
	ast := &astSpy{}
	in := compileInput(baseSpec(), func(in *Input) { in.ASTCheck = ast.check })
	if _, err := Compile(in, testNonce); err != nil {
		t.Fatalf("不應被拒：%v", err)
	}
	if ast.dir != "/tmp/snap" || ast.symbol != "app.db.UserRepo.find_by_name" {
		t.Fatalf("ASTCheck 參數錯誤：dir=%q symbol=%q", ast.dir, ast.symbol)
	}
}

// ---- §17.9-3：generated_files 子情況 ----

func TestRejectBadGeneratedFiles(t *testing.T) {
	cases := map[string]map[string]any{
		"非 witness 前綴":   {"app.py": "x"},
		"絕對路徑":           {"/abs/witness/app.py": "x"},
		" witness 後絕對路徑": {"witness//abs.py": "x"},
		"含 ..":           {"witness/../etc/app.py": "x"},
		"點段":             {"witness/./app.py": "x"},
		"空名稱":            {"witness/": "x"},
		"壞副檔名":           {"witness/app.sh": "x"},
		"內容非字串":          {"witness/app.py": 42},
	}
	for name, files := range cases {
		spec := baseSpec()
		spec["generated_files"] = files
		expectReject(t, compileInput(spec, nil), ReasonBadGeneratedFiles)
		_ = name
	}
}

func TestRejectTooManyFiles(t *testing.T) {
	files := map[string]any{}
	for i := 0; i < FilesMax+1; i++ {
		files[fmt.Sprintf("witness/f%d.py", i)] = "x"
	}
	spec := baseSpec()
	spec["generated_files"] = files
	expectReject(t, compileInput(spec, nil), ReasonBadGeneratedFiles)
}

func TestRejectOversizeFiles(t *testing.T) {
	spec := baseSpec()
	spec["generated_files"] = map[string]any{
		"witness/app.py": strings.Repeat("a", FilesBytesMax+1),
	}
	expectReject(t, compileInput(spec, nil), ReasonOversizeFiles)
}

func TestDirectModeOnlyExploitScript(t *testing.T) {
	// direct 模板 + 僅 exploit 腳本 → 通過（§17.8：兩模式同一介面）
	spec := baseSpec()
	spec["template_id"] = "py/direct-sqlite/v1"
	spec["run_mode"] = "direct"
	spec["generated_files"] = map[string]any{"witness/exploit.py": "exploit({{NONCE}})"}
	in := compileInput(spec, func(in *Input) { in.FindingReachability = "D0" })
	rr, err := Compile(in, testNonce)
	if err != nil {
		t.Fatalf("direct 模式合法 spec 不應被拒：%v", err)
	}
	files := rr["files"].(map[string]any)
	if len(files) != 1 || files["witness/exploit.py"] != "exploit("+testNonce+")" {
		t.Fatalf("direct 模式 files 錯誤：%v", files)
	}
	validateRunRequest(t, rr)

	// direct 模式夾帶其他檔案 → 拒收
	spec["generated_files"] = map[string]any{
		"witness/exploit.py": "exploit({{NONCE}})",
		"witness/app.py":     "app",
	}
	expectReject(t, compileInput(spec, nil), ReasonBadGeneratedFiles)
}

// ---- §17.9-4：payload ----

func TestRejectEmptyPayload(t *testing.T) {
	spec := baseSpec()
	delete(spec, "payload")
	expectReject(t, compileInput(spec, nil), ReasonEmptyPayload)
	spec = baseSpec()
	spec["payload"] = ""
	expectReject(t, compileInput(spec, nil), ReasonEmptyPayload)
}

func TestRejectPayloadTooLarge(t *testing.T) {
	spec := baseSpec()
	spec["payload"] = strings.Repeat("{{NONCE}}", 300) // 2400 bytes > 2KiB
	expectReject(t, compileInput(spec, nil), ReasonPayloadTooLarge)
}

func TestRejectMissingNoncePlaceholder(t *testing.T) {
	spec := baseSpec()
	spec["payload"] = "no placeholder here"
	expectReject(t, compileInput(spec, nil), ReasonMissingNoncePlaceholder)
}

// ---- §17.9-5：金鑰掃描 ----

func TestRejectSecretInSpec(t *testing.T) {
	spec := baseSpec()
	in := compileInput(spec, func(in *Input) { in.SecretScan = func(string) bool { return true } })
	expectReject(t, in, ReasonSecretInSpec)
}

func TestSecretScanCoversPayloadAndFiles(t *testing.T) {
	sec := &secretSpy{}
	in := compileInput(baseSpec(), func(in *Input) { in.SecretScan = sec.scan })
	if _, err := Compile(in, testNonce); err != nil {
		t.Fatalf("不應被拒：%v", err)
	}
	if !sec.called {
		t.Fatalf("SecretScan 未被呼叫")
	}
	joined := strings.Join(sec.texts, "\n")
	for _, want := range []string{"{{NONCE}}'", "app = {{NONCE}}", "exploit({{NONCE_HEX}})", "app.db.UserRepo.find_by_name"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("SecretScan 未掃到模型可控字串：%q", want)
		}
	}
}

// ---- §17.9-6：assumptions ----

func TestRejectMissingAssumptions(t *testing.T) {
	for _, reach := range []string{"D2", "D3"} {
		spec := baseSpec()
		delete(spec, "assumptions")
		in := compileInput(spec, func(in *Input) { in.FindingReachability = reach })
		expectReject(t, in, ReasonMissingAssumptions)
	}
	// D0/D1 不要求 assumptions
	for _, reach := range []string{"D0", "D1"} {
		spec := baseSpec()
		delete(spec, "assumptions")
		in := compileInput(spec, func(in *Input) { in.FindingReachability = reach })
		if _, err := Compile(in, testNonce); err != nil {
			t.Fatalf("%s 不應要求 assumptions：%v", reach, err)
		}
	}
}

// ---- §17.9-7：duplicate_spec ----

func TestRejectDuplicateSpec(t *testing.T) {
	spec := baseSpec()
	h, err := evidence.Hash(spec)
	if err != nil {
		t.Fatalf("hash spec：%v", err)
	}
	in := compileInput(spec, func(in *Input) { in.PrevSpecHashes = map[string]bool{h: true} })
	expectReject(t, in, ReasonDuplicateSpec)

	// 內容不同（payload 改一字）即非重複
	spec2 := baseSpec()
	spec2["payload"] = "{{NONCE}}\""
	in = compileInput(spec2, func(in *Input) { in.PrevSpecHashes = map[string]bool{h: true} })
	if _, err := Compile(in, testNonce); err != nil {
		t.Fatalf("內容不同的 spec 不應判 duplicate：%v", err)
	}
}

// ---- 注入項缺失 → fail-closed（整合錯誤，非 SpecError） ----

func TestMissingInjectionsFailClosed(t *testing.T) {
	in := compileInput(baseSpec(), nil)
	in.SecretScan = nil
	if _, err := Compile(in, testNonce); err == nil || errors.As(err, new(*SpecError)) {
		t.Fatalf("SecretScan 缺失應回非 SpecError 錯誤，得到：%v", err)
	}
	in = compileInput(baseSpec(), nil)
	in.ASTCheck = nil
	if _, err := Compile(in, testNonce); err == nil || errors.As(err, new(*SpecError)) {
		t.Fatalf("ASTCheck 缺失應回非 SpecError 錯誤，得到：%v", err)
	}
	in = compileInput(baseSpec(), nil)
	in.PackView = nil
	if _, err := Compile(in, testNonce); err == nil || errors.As(err, new(*SpecError)) {
		t.Fatalf("PackView 缺失應回非 SpecError 錯誤，得到：%v", err)
	}
	if _, err := Compile(in, ""); err == nil || errors.As(err, new(*SpecError)) {
		t.Fatalf("空 nonce 應回非 SpecError 錯誤，得到：%v", err)
	}
}

// ---- 拒收原因閉集 ----

func TestSpecErrorClosedSet(t *testing.T) {
	for _, r := range []string{
		ReasonMissingNoncePlaceholder, ReasonPayloadTooLarge, ReasonBadGeneratedFiles,
		ReasonTargetSymbolMissing, ReasonUnknownTemplate, ReasonUnknownOracle,
		ReasonFamilyMismatch, ReasonModeNotSupported, ReasonSecretInSpec,
		ReasonMissingAssumptions, ReasonDuplicateSpec, ReasonEmptyPayload, ReasonOversizeFiles,
	} {
		e := specErr(r)
		if !strings.HasPrefix(e.Error(), "policy: witness spec 遭拒（") {
			t.Fatalf("SpecError 訊息格式錯誤：%s", e.Error())
		}
	}
	unknown := &SpecError{Reason: "made_up_reason"}
	if !strings.Contains(unknown.Error(), "made_up_reason") {
		t.Fatalf("未知原因應現形於訊息")
	}
}
