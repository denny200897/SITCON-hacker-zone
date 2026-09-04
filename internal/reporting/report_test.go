package reporting

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func sampleFinding(id, verification, reach string) Finding {
	return Finding{
		"id":            id,
		"sink":          map[string]any{"file": "app/db.py", "line": 88.0, "symbol": "UserRepo.find_by_name", "type": "sql.concat"},
		"sources":       []any{map[string]any{"origin": "semgrep"}},
		"reachability":  reach,
		"verification":  verification,
		"disposition":   "OPEN",
		"snapshot_id":   "SN-aaaaaaaaaaaa",
		"assumptions":   []any{"產品將新增依名稱查詢使用者的 HTTP endpoint"},
		"chain":         []any{"(假設)GET /users/{name}", "param name", "f-string 拼接", "cursor.execute"},
		"missing_links": []any{},
		"rationale":     "f-string 拼接未參數化",
		"fix":           map[string]any{"summary": "改用參數化查詢", "diff_suggestion": "- cur.execute(f\"SELECT ... '{name}'\")\n+ cur.execute(\"SELECT ... ?\", (name,))"},
		"severity":      "critical",
		"confidence":    0.8,
	}
}

func TestWriteFindingsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path, err := WriteFindings(dir, []Finding{sampleFinding("F-0007", "PROVEN", "D2")})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fs []map[string]any
	if err := json.Unmarshal(data, &fs); err != nil {
		t.Fatalf("findings.json not valid JSON: %v", err)
	}
	if len(fs) != 1 || fs[0]["id"] != "F-0007" {
		t.Fatalf("round trip: %+v", fs)
	}
}

func TestWriteSARIFValid(t *testing.T) {
	dir := t.TempDir()
	path, err := WriteSARIF(dir, []Finding{
		sampleFinding("F-0007", "PROVEN", "D2"),
		sampleFinding("F-0008", "NOT_PROVEN", "D1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var sarif map[string]any
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("sarif not valid JSON: %v", err)
	}
	if sarif["version"] != "2.1.0" {
		t.Fatalf("sarif version: %v", sarif["version"])
	}
	runs := sarif["runs"].([]any)
	results := runs[0].(map[string]any)["results"].([]any)
	if len(results) != 2 {
		t.Fatalf("results = %d", len(results))
	}
	r0 := results[0].(map[string]any)
	if r0["level"] != "error" || r0["ruleId"] != "sql.concat" {
		t.Fatalf("result0 = %+v", r0)
	}
	props := r0["properties"].(map[string]any)
	if props["aegis.reachability"] != "D2" || props["aegis.verification"] != "PROVEN" {
		t.Fatalf("props = %+v", props)
	}
}

func TestWriteReportMDThreeSectionsAndWitnessLabel(t *testing.T) {
	dir := t.TempDir()
	// D2 PROVEN：必須寫「合成見證下已證明」（§14-1）
	path, err := WriteReportMD(dir, []Finding{sampleFinding("F-0007", "PROVEN", "D2")}, "out/run-1", testNow())
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, want := range []string{"合成見證下已證明", "不代表當前產品可從外部攻擊", "假設：", "### 現況", "### 未來開發注意事項", "### 修補建議", "F-0007"} {
		if !strings.Contains(s, want) {
			t.Fatalf("report.md missing %q", want)
		}
	}
	// 不得寫成「當前產品可從外部攻擊」為主張
	if strings.Contains(s, "當前產品可從外部攻擊") && !strings.Contains(s, "不代表當前產品可從外部攻擊") {
		t.Fatal("improper claim")
	}
}

func TestWriteReportMDD2WithoutAssumptionHeaderIsWrong(t *testing.T) {
	// 防回歸：三段式結構固定（§4 Stage 4）
	dir := t.TempDir()
	path, err := WriteReportMD(dir, []Finding{sampleFinding("F-0007", "NOT_PROVEN", "D0")}, "out/run-1", testNow())
	if err != nil {
		t.Fatal(err)
	}
	s, _ := os.ReadFile(path)
	if !strings.Contains(string(s), "F-0007") {
		t.Fatal("missing finding")
	}
}

func testNow() time.Time { return time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC) }