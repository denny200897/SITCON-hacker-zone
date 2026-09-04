package orchestrator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aegis-dev/aegis/internal/packs"
)

// testPack 載入 bundled pack（含 schemas 驗證）；回傳 (pack, packDir, schemasDir)。
func testPack(t *testing.T) (*packs.Pack, string) {
	t.Helper()
	// 本測試檔位於 internal/orchestrator；pack 與 schemas 在 repo 根目錄。
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	packDir := filepath.Join(repoRoot, "packs", "python-web")
	schemasDir := filepath.Join(repoRoot, "schemas")
	pack, err := packs.LoadWithSchemas(packDir, schemasDir, false)
	if err != nil {
		t.Fatalf("載入 bundled pack: %v", err)
	}
	return pack, packDir
}

// TestPackAdapterResolvesDigest：bundled pack 的 template.image 已記 digest（§17.10 第 1 階）。
func TestPackAdapterResolvesDigest(t *testing.T) {
	pack, _ := testPack(t)
	pv := NewPackView(pack, "")
	tmpl, err := pv.Template("py/http-endpoint/v3")
	if err != nil {
		t.Fatal(err)
	}
	if !isDigestImage(tmpl.Image) {
		t.Fatalf("template image 非 digest 形式：%q", tmpl.Image)
	}
	if tmpl.Family != "sqli" || tmpl.RunMode != "witness" {
		t.Fatalf("template 元資料不符：%+v", tmpl)
	}
	o, err := pv.Oracle("sqli.error/v1")
	if err != nil {
		t.Fatal(err)
	}
	if o.Family != "sqli" || o.Touch == nil || *o.Touch != "sink.touch.sql/v1" {
		t.Fatalf("oracle 元資料不符：%+v", o)
	}
}

// TestPackAdapterImagesJSONFallback：manifest 未記 digest 時走 images.json（§17.10 第 3 階）。
func TestPackAdapterImagesJSONFallback(t *testing.T) {
	pack, _ := testPack(t)
	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "images.json")
	if err := RecordImage(cachePath, "aegis-python-web", "aegis-python-web@sha256:" + strings64); err != nil {
		t.Fatal(err)
	}
	// 模擬 manifest 未記 digest：清空 template image 再經 adapter 解析。
	pack.Manifest.Templates[0].Image = "aegis-python-web"
	pv := NewPackView(pack, cachePath)
	tmpl, err := pv.Template(pack.Manifest.Templates[0].TemplateID)
	if err != nil {
		t.Fatalf("images.json 後備解析失敗: %v", err)
	}
	if !isDigestImage(tmpl.Image) {
		t.Fatalf("解析結果非 digest：%q", tmpl.Image)
	}

	// 無任何記錄 → 解析序用盡 → error（§17.10 第 4 步：不自動構建）。
	pv2 := NewPackView(pack, "")
	if _, err := pv2.Template(pack.Manifest.Templates[0].TemplateID); err == nil {
		t.Fatal("映像解析序用盡應回 error（不自動構建）")
	}
}

const strings64 = "d7f6ad846cdf4f51b96731be926b947f45425e8a8327f62f62c8c7f5bd389b15"

// TestRecordImageRoundTrip：images.json 寫入後可讀回（canonical JSON 落檔）。
func TestRecordImageRoundTrip(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "images.json")
	d1 := "x@sha256:" + strings64
	d2 := "y@sha256:" + strings64
	if err := RecordImage(cachePath, "x", d1); err != nil {
		t.Fatal(err)
	}
	if err := RecordImage(cachePath, "y", d2); err != nil {
		t.Fatal(err)
	}
	if v, ok := lookupImagesJSON(cachePath, "x"); !ok || v != d1 {
		t.Fatalf("x 讀回不符：%q %v", v, ok)
	}
	if v, ok := lookupImagesJSON(cachePath, "y"); !ok || v != d2 {
		t.Fatalf("y 讀回不符：%q %v", v, ok)
	}
	if _, ok := lookupImagesJSON(cachePath, "zzz"); ok {
		t.Fatal("未記錄的參照不應命中")
	}
	// 檔案不存在 → miss 不炸。
	if _, ok := lookupImagesJSON(filepath.Join(t.TempDir(), "none.json"), "x"); ok {
		t.Fatal("缺檔應 miss")
	}
}

// TestNewNonce：32 hex、兩次呼叫不同（§17.2 runner 產生）。
func TestNewNonce(t *testing.T) {
	n1, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	n2, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	if len(n1) != 32 || n1 == n2 {
		t.Fatalf("nonce 長度或唯一性不符：%q %q", n1, n2)
	}
}

// TestASTCheck：module/class/method 的靜態解析（§17.9-2）。
func TestASTCheck(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("class UserRepo:\n    def find_by_name(self, name):\n        pass\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ASTCheck(dir, "app.UserRepo.find_by_name"); err != nil {
		t.Fatalf("合法符號應通過: %v", err)
	}
	for _, sym := range []string{
		"app.UserRepo.no_such_method",
		"app.NoClass",
		"nomodule.Foo",
		"app.",
	} {
		if err := ASTCheck(dir, sym); err == nil {
			t.Errorf("符號 %q 應解析失敗", sym)
		}
	}
	if err := ASTCheck("", "app.Foo"); err == nil {
		t.Error("空 snapshotDir 應回錯")
	}
}

// TestRunRequestToRunSpec：policy assemble 輸出 → sandbox.RunSpec 的翻譯。
func TestRunRequestToRunSpec(t *testing.T) {
	rr := map[string]any{
		"run_id":  "R-0001",
		"kind":    "exploit",
		"image":   "aegis-python-web@sha256:" + strings64,
		"cmd":     []any{"/aegis/entrypoint.py", "--template", "py/http-endpoint/v3"},
		"network": "none",
		"service": map[string]any{
			"cmd": "python /aegis/witness/app.py", "port": int64(8000), "wait_for": "GET /healthz",
		},
		"timeout_sec": int64(60),
	}
	spec, err := RunRequestToRunSpec(rr, "SN-abc", "/pack/sandbox/seccomp.json", "/snap/dir")
	if err != nil {
		t.Fatal(err)
	}
	if spec.RunID != "R-0001" || spec.SnapshotID != "SN-abc" || spec.TimeoutSec != 60 {
		t.Fatalf("基本欄位翻譯不符：%+v", spec)
	}
	if spec.Seccomp != "/pack/sandbox/seccomp.json" {
		t.Fatalf("seccomp 翻譯不符：%+v", spec)
	}
	wantEnv := []string{
		"AEGIS_SERVICE_CMD=python /aegis/witness/app.py",
		"AEGIS_SERVICE_PORT=8000",
		"AEGIS_HEALTH_PATH=/healthz",
	}
	if len(spec.Env) != len(wantEnv) {
		t.Fatalf("service env 不符：%v", spec.Env)
	}
	for i := range wantEnv {
		if spec.Env[i] != wantEnv[i] {
			t.Fatalf("env[%d] = %q，預期 %q", i, spec.Env[i], wantEnv[i])
		}
	}

	// 缺 cmd → 錯；缺 image → 錯。
	for _, broken := range []string{"cmd", "image", "run_id", "network", "timeout_sec"} {
		cp := map[string]any{}
		for k, v := range rr {
			cp[k] = v
		}
		delete(cp, broken)
		if _, err := RunRequestToRunSpec(cp, "SN-abc", "/s.json", "/snap"); err == nil {
			t.Errorf("缺 %s 應回錯", broken)
		}
	}
}

// TestOracleRuleConversion：pack oracle 條目 → checker Rule 的純資料轉換。
func TestOracleRuleConversion(t *testing.T) {
	pack, _ := testPack(t)
	vuln, err := pack.Oracle("sqli.error/v1")
	if err != nil {
		t.Fatal(err)
	}
	r, err := OracleRule(vuln)
	if err != nil {
		t.Fatal(err)
	}
	if r.OracleID != "sqli.error/v1" || r.Family != "sqli" || r.Touch != "sink.touch.sql/v1" {
		t.Fatalf("rule 元資料不符：%+v", r)
	}
	touchEntry, err := pack.Oracle("sink.touch.sql/v1")
	if err != nil {
		t.Fatal(err)
	}
	tr, err := OracleRule(touchEntry)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Touch != "" || tr.Rule.Field != "sql" {
		t.Fatalf("touch rule 轉換不符：%+v", tr)
	}
}

// TestSeccompPath：bundled pack 的 seccomp profile 存在；不存在的 pack 目錄回錯（§23-8）。
func TestSeccompPath(t *testing.T) {
	_, packDir := testPack(t)
	p, err := SeccompPath(packDir)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(p) != "seccomp.json" {
		t.Fatalf("seccomp 路徑不符：%q", p)
	}
	if _, err := SeccompPath(t.TempDir()); err == nil {
		t.Fatal("缺 profile 應回錯")
	}
}