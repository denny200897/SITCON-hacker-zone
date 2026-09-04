package packs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sha256Hex 計算位元組的 sha256 hex（測試 fixture 現算用）。
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// writePack 建立一個最小合法 fixture pack（§6.4 全欄位）到 t.TempDir()，
// 套用 mutate 後寫入 manifest；回傳 pack 目錄。mutate 為 nil 表示不改。
func writePack(t *testing.T, mutate func(*Manifest)) string {
	t.Helper()
	dir := t.TempDir()

	detector := []byte("rules:\n  - id: sqli-str-concat\n    patterns:\n      - pattern: \"$Q + $X\"\n")
	template := []byte("# witness 模板（fixture）\ndef exploit():\n    pass\n")

	oracleVuln := map[string]any{
		"oracle_id": "sqli.error/v1",
		"family":    "sqli",
		"touch":     "sink.touch.sql/v1",
		"rule":      map[string]any{"artifact": "sql_trace.jsonl", "kind": "nonce_statement_errored"},
	}
	oracleTouch := map[string]any{
		"oracle_id": "sink.touch.sql/v1",
		"family":    "sqli",
		"touch":     nil,
		"rule":      map[string]any{"artifact": "sql_trace.jsonl", "kind": "nonce_in_field", "field": "sql"},
	}
	oracleVulnBytes, oracleTouchBytes := mustJSON(t, oracleVuln), mustJSON(t, oracleTouch)

	payloadContent := "alice-{{NONCE}}"
	image := "aegis-python-web@sha256:" + strings.Repeat("ab", 32)

	m := &Manifest{
		PackID:        "python-web",
		Version:       "0.1.0",
		SchemaVersion: CorePackABI,
		Capabilities:  []string{},
		Detectors: []DetectorEntry{{
			ID: "sqli-str-concat", Path: "detectors/sqli.yml", SHA256: sha256Hex(detector),
		}},
		Templates: []TemplateEntry{{
			TemplateID:   "sqli.witness/v1",
			Family:       "sqli",
			RunMode:      "both",
			Path:         "templates/sqli_witness.py",
			SHA256:       sha256Hex(template),
			AllowedFiles: []string{".py"},
			ServiceCmd:   "python3 app.py",
			ServicePort:  5000,
			WaitFor:      "5000",
			Image:        image,
		}},
		Oracles: []OracleEntry{
			{OracleID: "sqli.error/v1", Family: "sqli", Touch: strPtr("sink.touch.sql/v1"),
				Rule: RuleEntry{Artifact: "sql_trace.jsonl", Kind: "nonce_statement_errored"},
				SHA256: sha256Hex(oracleVulnBytes)},
			{OracleID: "sink.touch.sql/v1", Family: "sqli",
				Rule: RuleEntry{Artifact: "sql_trace.jsonl", Kind: "nonce_in_field", Field: "sql"},
				SHA256: sha256Hex(oracleTouchBytes)},
		},
		Payloads: []PayloadEntry{{
			ID: "benign.sqli/v1", Family: "sqli", Kind: "benign",
			Content: payloadContent, SHA256: sha256Hex([]byte(payloadContent)),
		}},
		Images: map[string]string{"deps_helper": "aegis-deps-helper@sha256:" + strings.Repeat("cd", 32)},
		SinkTypes: []SinkTypeEntry{
			{Type: "sqli", Family: "sqli", Impact: "high"},
			{Type: "cmdi", Family: "cmdi", Impact: "high"},
		},
		TrustLevel: "bundled",
		Tests:      []TestEntry{{Name: "replay-sqli", Kind: "replay"}},
	}

	if mutate != nil {
		mutate(m)
	}

	// 檔案寫入（manifest 內容以 mutate 後的結構為準；檔案本身照原始內容寫）。
	if err := os.MkdirAll(filepath.Join(dir, "detectors"), 0o755); err != nil {
		t.Fatalf("packs: 建立 detectors 目錄: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "templates"), 0o755); err != nil {
		t.Fatalf("packs: 建立 templates 目錄: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "oracles"), 0o755); err != nil {
		t.Fatalf("packs: 建立 oracles 目錄: %v", err)
	}
	write := func(rel string, data []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, rel), data, 0o644); err != nil {
			t.Fatalf("packs: 寫入 %s: %v", rel, err)
		}
	}
	write("detectors/sqli.yml", detector)
	write("templates/sqli_witness.py", template)
	write(OraclePath("sqli.error/v1"), oracleVulnBytes)
	write(OraclePath("sink.touch.sql/v1"), oracleTouchBytes)
	manifestBytes, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatalf("packs: 序列化 manifest: %v", err)
	}
	write("manifest.json", manifestBytes)
	return dir
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("packs: 序列化 fixture: %v", err)
	}
	return b
}

func strPtr(s string) *string { return &s }

// TestLoadValid：合法 fixture pack 載入成功，查表與唯讀映射正確。
func TestLoadValid(t *testing.T) {
	dir := writePack(t, nil)

	p, err := Load(dir, false) // 走 findSchemasDir 自動搜尋路徑
	if err != nil {
		t.Fatalf("Load 合法 pack 失敗: %v", err)
	}
	if p.Dir != dir {
		t.Fatalf("Pack.Dir = %q, 期望 %q", p.Dir, dir)
	}
	if p.Manifest.PackID != "python-web" {
		t.Fatalf("PackID = %q", p.Manifest.PackID)
	}

	tpl, err := p.Template("sqli.witness/v1")
	if err != nil {
		t.Fatalf("Template 查表失敗: %v", err)
	}
	if tpl.RunMode != "both" || tpl.Family != "sqli" {
		t.Fatalf("Template 欄位不符: %+v", tpl)
	}
	if _, err := p.Template("nope/v1"); err == nil {
		t.Fatal("查詢不存在的 template 應回傳錯誤")
	}

	orc, err := p.Oracle("sqli.error/v1")
	if err != nil {
		t.Fatalf("Oracle 查表失敗: %v", err)
	}
	if orc.Rule.Kind != "nonce_statement_errored" {
		t.Fatalf("Oracle rule 不符: %+v", orc.Rule)
	}
	if orc.Touch == nil || *orc.Touch != "sink.touch.sql/v1" {
		t.Fatalf("Oracle touch 不符: %v", orc.Touch)
	}

	if got, ok := p.Impact("sqli"); !ok || got != "high" {
		t.Fatalf("Impact(sqli) = (%q, %v), 期望 (high, true)", got, ok)
	}
	if _, ok := p.Impact("xss"); ok {
		t.Fatal("Impact(xss) 應查無")
	}

	paths := p.DetectorPaths()
	if len(paths) != 1 || paths[0] != "detectors/sqli.yml" {
		t.Fatalf("DetectorPaths() = %v", paths)
	}
}

// TestLoadWithSchemasExplicit：明示 schemas 路徑的入口同樣可用。
func TestLoadWithSchemasExplicit(t *testing.T) {
	dir := writePack(t, nil)
	if _, err := Load(dir, false); err != nil {
		t.Fatalf("Load 失敗: %v", err)
	}
	schemas, err := findSchemasDir()
	if err != nil {
		t.Fatalf("findSchemasDir: %v", err)
	}
	p, err := LoadWithSchemas(dir, schemas, false)
	if err != nil {
		t.Fatalf("LoadWithSchemas 失敗: %v", err)
	}
	if p.Manifest.PackID != "python-web" {
		t.Fatalf("PackID = %q", p.Manifest.PackID)
	}
}

// TestRejectHashMismatch：檔案內容或 manifest 記載 hash 不符即拒載（§6.4）。
func TestRejectHashMismatch(t *testing.T) {
	// 1. manifest 記載的 template hash 與檔案不符。
	dir := writePack(t, func(m *Manifest) {
		m.Templates[0].SHA256 = strings.Repeat("ee", 32)
	})
	_, err := Load(dir, false)
	if !errors.Is(err, ErrHash) {
		t.Fatalf("template hash 不符應拒載 ErrHash, 得: %v", err)
	}

	// 2. 檔案被改動（hash 以現算值記載，檔案事後被竄改）。
	dir2 := writePack(t, nil)
	if err := os.WriteFile(filepath.Join(dir2, "templates", "sqli_witness.py"),
		[]byte("被竄改的內容\n"), 0o644); err != nil {
		t.Fatalf("竄改 template: %v", err)
	}
	_, err = Load(dir2, false)
	if !errors.Is(err, ErrHash) {
		t.Fatalf("檔案竄改應拒載 ErrHash, 得: %v", err)
	}

	// 3. payload 內容 hash 不符。
	dir3 := writePack(t, func(m *Manifest) {
		m.Payloads[0].SHA256 = strings.Repeat("ff", 32)
	})
	_, err = Load(dir3, false)
	if !errors.Is(err, ErrHash) {
		t.Fatalf("payload hash 不符應拒載 ErrHash, 得: %v", err)
	}

	// 4. oracle 檔 hash 不符。
	dir4 := writePack(t, func(m *Manifest) {
		m.Oracles[0].SHA256 = strings.Repeat("01", 32)
	})
	_, err = Load(dir4, false)
	if !errors.Is(err, ErrHash) {
		t.Fatalf("oracle hash 不符應拒載 ErrHash, 得: %v", err)
	}
}

// TestRejectSchemaVersionMismatch：ABI 版本不匹配即拒載（§6.4）。
func TestRejectSchemaVersionMismatch(t *testing.T) {
	dir := writePack(t, func(m *Manifest) { m.SchemaVersion = CorePackABI + 1 })
	_, err := Load(dir, false)
	if !errors.Is(err, ErrABI) {
		t.Fatalf("schema_version 不匹配應拒載 ErrABI, 得: %v", err)
	}
}

// TestRejectTouchMissing：oracle 家族 touch 缺漏即拒載（§17.3）。
func TestRejectTouchMissing(t *testing.T) {
	// 1. 主 rule 的 touch 指向同 family 不存在的 oracle_id。
	dir := writePack(t, func(m *Manifest) {
		m.Oracles[0].Touch = strPtr("sink.touch.nope/v1")
	})
	_, err := Load(dir, false)
	if !errors.Is(err, ErrTouch) {
		t.Fatalf("touch 指向不存在 id 應拒載 ErrTouch, 得: %v", err)
	}

	// 2. family 內無 touch==null 的 base rule（全被引用，base 缺漏）。
	dir2 := writePack(t, func(m *Manifest) {
		m.Oracles[1].Touch = strPtr("sqli.error/v1")
	})
	_, err = Load(dir2, false)
	if !errors.Is(err, ErrTouch) {
		t.Fatalf("缺 touch base 應拒載 ErrTouch, 得: %v", err)
	}

	// 3. 主 rule 的 touch 被移除（family 兩條皆 touch==null、無被引用 rule）。
	dir3 := writePack(t, func(m *Manifest) {
		m.Oracles[0].Touch = nil
	})
	_, err = Load(dir3, false)
	if !errors.Is(err, ErrTouch) {
		t.Fatalf("touch 缺漏應拒載 ErrTouch, 得: %v", err)
	}

	// 4. touch 指向別的 family 的 oracle_id 同樣拒載（必須同 family）。
	dir4 := writePack(t, func(m *Manifest) {
		m.Oracles = append(m.Oracles, OracleEntry{
			OracleID: "xss.dom/v1", Family: "xss",
			Rule: RuleEntry{Artifact: "dom_events.jsonl", Kind: "dom_event_with_nonce"},
			SHA256: sha256Hex([]byte("{}")),
		})
	})
	// xss 家族只有一條且 touch==null → base=1、refs=0 → ErrTouch
	if err := os.WriteFile(filepath.Join(dir4, OraclePath("xss.dom/v1")), []byte("{}"), 0o644); err != nil {
		t.Fatalf("寫入 xss oracle 檔: %v", err)
	}
	_, err = Load(dir4, false)
	if !errors.Is(err, ErrTouch) {
		t.Fatalf("家族缺被引用 rule 應拒載 ErrTouch, 得: %v", err)
	}
}

// TestRejectCommunity：community pack 未明示啟用即拒載（§6.4）。
func TestRejectCommunity(t *testing.T) {
	dir := writePack(t, func(m *Manifest) { m.TrustLevel = "community" })
	if _, err := Load(dir, false); !errors.Is(err, ErrTrust) {
		t.Fatalf("community 未啟用應拒載 ErrTrust, 得: %v", err)
	}
	// 明示啟用後可載入。
	if _, err := Load(dir, true); err != nil {
		t.Fatalf("community 明示啟用應可載入: %v", err)
	}
}

// TestRejectUnsupportedCapability：pack 要求 core 沒有的能力即拒載（§6.4）。
func TestRejectUnsupportedCapability(t *testing.T) {
	dir := writePack(t, func(m *Manifest) { m.Capabilities = []string{"headless_browser"} })
	_, err := Load(dir, false)
	if !errors.Is(err, ErrCapability) {
		t.Fatalf("不支援能力應拒載 ErrCapability, 得: %v", err)
	}
}

// TestRejectManifestSchemaViolation：manifest 不符 schema 即拒載（§5）。
func TestRejectManifestSchemaViolation(t *testing.T) {
	// 缺必填欄位 sink_types。
	dir := writePack(t, func(m *Manifest) { m.SinkTypes = nil })
	_, err := Load(dir, false)
	if !errors.Is(err, ErrManifest) {
		t.Fatalf("缺必填欄位應拒載 ErrManifest, 得: %v", err)
	}

	// trust_level 非閉集值。
	dir2 := writePack(t, func(m *Manifest) { m.TrustLevel = "unknown" })
	_, err = Load(dir2, false)
	if !errors.Is(err, ErrManifest) {
		t.Fatalf("trust_level 非閉集值應拒載 ErrManifest, 得: %v", err)
	}

	// oracle rule.kind 非封閉 enum。
	dir3 := writePack(t, func(m *Manifest) { m.Oracles[0].Rule.Kind = "arbitrary_code" })
	_, err = Load(dir3, false)
	if !errors.Is(err, ErrManifest) {
		t.Fatalf("rule.kind 非閉集值應拒載 ErrManifest, 得: %v", err)
	}
}

// TestRejectMutableTag：映像用可變 tag 即拒載（§6.3、§7.1）。
func TestRejectMutableTag(t *testing.T) {
	// 1. template.image 用人類可讀 tag（無 digest）→ schema pattern 拒載。
	dir := writePack(t, func(m *Manifest) { m.Templates[0].Image = "aegis-python-web:3.12" })
	_, err := Load(dir, false)
	if !errors.Is(err, ErrManifest) {
		t.Fatalf("可變 tag 應拒載 ErrManifest, 得: %v", err)
	}

	// 2. images 表用 tag:digest 混合形式。
	dir2 := writePack(t, func(m *Manifest) {
		m.Images["listener"] = "aegis-listener:1.2@sha256:" + strings.Repeat("ab", 32)
	})
	_, err = Load(dir2, false)
	if !errors.Is(err, ErrManifest) {
		t.Fatalf("images 表含 tag 應拒載 ErrManifest, 得: %v", err)
	}
}

// TestCheckDigest：digest 形式檢查的直接單元測試（含 ErrImage 分類）。
func TestCheckDigest(t *testing.T) {
	digest := "aegis-python-web@sha256:" + strings.Repeat("ab", 32)
	if err := checkDigest(digest); err != nil {
		t.Fatalf("合法 digest 不應報錯: %v", err)
	}
	cases := []struct {
		name  string
		image string
	}{
		{"僅 tag", "aegis-python-web:3.12"},
		{"名稱含 tag 的 digest", "aegis-python-web:3.12@sha256:" + strings.Repeat("ab", 32)},
		{"digest 非 hex", "aegis-python-web@sha256:zz"},
		{"digest 長度不足", "aegis-python-web@sha256:abcd"},
		{"缺名稱", "@sha256:" + strings.Repeat("ab", 32)},
	}
	for _, c := range cases {
		err := checkDigest(c.image)
		if !errors.Is(err, ErrImage) {
			t.Fatalf("%s 應拒載 ErrImage, 得: %v", c.name, err)
		}
	}
}

// TestRejectPathEscape：pack 內路徑不得越出 pack 目錄。
func TestRejectPathEscape(t *testing.T) {
	dir := writePack(t, func(m *Manifest) { m.Templates[0].Path = "../outside.py" })
	_, err := Load(dir, false)
	if err == nil || errors.Is(err, ErrHash) {
		t.Fatalf("路徑越出 pack 目錄應以路徑錯誤拒載, 得: %v", err)
	}
}

// TestMissingManifest：缺 manifest.json 回傳錯誤。
func TestMissingManifest(t *testing.T) {
	if _, err := Load(t.TempDir(), false); err == nil {
		t.Fatal("缺 manifest.json 應回傳錯誤")
	}
}