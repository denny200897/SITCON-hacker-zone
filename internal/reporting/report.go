// Package reporting 實作 Stage 4 產出物（SPEC §4、§10）：
// findings.json（機讀）、findings.sarif（IDE/CI）、report.md（人讀模板）。
// 未啟用 LLM 敘寫時走純確定性輸出（§8：不得因此失敗）。
package reporting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aegis-dev/aegis/internal/redaction"
)

// Finding 是機讀 finding（欄位對應 schemas/finding.schema.json）。
// 這裡用 map[string]any 保持與 schema 的一致性（hash 路徑也要求 map）。
type Finding = map[string]any

// WriteFindings 落 findings.json（pretty JSON、UTF-8）。
func WriteFindings(dir string, findings []Finding) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("reporting: mkdir: %w", err)
	}
	data, err := marshalFindings(findings)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "findings.json")
	if err := redaction.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("reporting: write findings.json: %w", err)
	}
	return path, nil
}

func marshalFindings(findings []Finding) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(findings); err != nil {
		return nil, fmt.Errorf("reporting: encode: %w", err)
	}
	return buf.Bytes(), nil
}

// WriteSARIF 產 SARIF v2.1.0（IDE / GitHub code scanning 整合，§4 Stage 4）。
// 機讀 enum 與欄位永遠使用英文（§14-5）。
func WriteSARIF(dir string, findings []Finding) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("reporting: mkdir: %w", err)
	}
	sarif := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{
			map[string]any{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":           "aegis",
						"informationUri": "https://aegis.dev",
						"version":        "0.1.0",
						"rules":          sarifRules(findings),
					},
				},
				"results": sarifResults(findings),
			},
		},
	}
	data, err := marshalPretty(sarif)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "findings.sarif")
	if err := redaction.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("reporting: write sarif: %w", err)
	}
	return path, nil
}

func marshalPretty(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func sarifRules(findings []Finding) []any {
	seen := map[string]bool{}
	var rules []any
	for _, f := range findings {
		sink := asMap(f["sink"])
		id := str(sink["type"])
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		rules = append(rules, map[string]any{
			"id":               id,
			"shortDescription": map[string]any{"text": "Aegis sink: " + id},
		})
	}
	return rules
}

func sarifResults(findings []Finding) []any {
	var out []any
	for _, f := range findings {
		sink := asMap(f["sink"])
		level := sarifLevel(str(f["severity"]))
		result := map[string]any{
			"ruleId":  str(sink["type"]),
			"level":   level,
			"message": map[string]any{"text": str(f["rationale"])},
		}
		if file := str(sink["file"]); file != "" {
			location := map[string]any{"artifactLocation": map[string]any{"uri": filepath.ToSlash(file)}}
			if line := intValue(sink["line"]); line > 0 {
				location["region"] = map[string]any{"startLine": line}
			}
			result["locations"] = []any{map[string]any{"physicalLocation": location}}
		}
		if reach, ok := f["reachability"].(string); ok {
			properties := map[string]any{
				"aegis.reachability": reach,
				"aegis.verification": str(f["verification"]),
				"aegis.severity":     str(f["severity"]),
			}
			if supported, exists := f["proof_supported"].(bool); exists {
				properties["aegis.proof_supported"] = supported
			}
			if cwe := str(f["cwe"]); cwe != "" {
				properties["aegis.cwe"] = cwe
			}
			result["properties"] = properties
		}
		out = append(out, result)
	}
	return out
}

func sarifLevel(sev string) string {
	switch sev {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// WriteReportMD 產 report.md（人讀主報告；每 finding 三段式：現況／未來開發注意／修補建議，§4 Stage 4）。
// deterministic=true 時為純模板輸出（標註「未啟用 LLM 敘寫」）。
func WriteReportMD(dir string, findings []Finding, runDir string, now time.Time) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("reporting: mkdir: %w", err)
	}
	var b strings.Builder
	b.WriteString("# Aegis 資安審查報告\n\n")
	b.WriteString(fmt.Sprintf("> 產出時間：%s　｜　run 目錄：`%s`\n\n", now.Format(time.RFC3339), runDir))

	proven, others := splitByVerification(findings)
	unsupported := 0
	for _, finding := range findings {
		if supported, exists := finding["proof_supported"].(bool); exists && !supported {
			unsupported++
		}
	}
	b.WriteString("## 執行摘要\n\n")
	fmt.Fprintf(&b, "- Finding 總數：%d（PROVEN %d；尚無機械 proof 支援 %d）\n\n", len(findings), len(proven), unsupported)
	writeCoverage(&b, runDir)
	writeEnvironment(&b, runDir)
	if len(findings) == 0 {
		b.WriteString("> 本次沒有候選 finding。這只表示已載入的 pack 與實際執行的 detector／reviewer 在其覆蓋範圍內未命中；不代表已完成全語言、全漏洞類別的 SAST、DAST、合規掃描，也不構成「系統安全」結論。\n\n")
	}

	if len(proven) > 0 {
		b.WriteString("## 已證明（PROVEN）\n\n")
		for _, f := range proven {
			writeFinding(&b, f)
		}
	}
	if len(others) > 0 {
		b.WriteString("## 其他（未證明／否證／環境錯誤）\n\n")
		for _, f := range others {
			writeFinding(&b, f)
		}
	}

	b.WriteString("\n---\n\n## 電子產物\n\n")
	if _, err := os.Stat(filepath.Join(dir, "coverage.json")); err == nil {
		b.WriteString("- `coverage.json`（實際 pack／detector／語言覆蓋範圍）\n")
	}
	if _, err := os.Stat(filepath.Join(dir, "environment.json")); err == nil {
		b.WriteString("- `environment.json`（proof runtime image 與 snapshot compile smoke check）\n")
	}
	b.WriteString("- `findings.json`（機讀全量）\n- `findings.sarif`（IDE/CI 整合）\n")
	if _, err := os.Stat(filepath.Join(dir, "ai-events.jsonl")); err == nil {
		b.WriteString("- `ai-events.jsonl`（AI 階段、可見回覆與工具活動）\n")
	}
	if _, err := os.Stat(filepath.Join(dir, "audit.jsonl")); err == nil {
		b.WriteString("- `audit.jsonl`（政策閘與工具呼叫稽核）\n")
	}
	if st, err := os.Stat(filepath.Join(dir, "guardrails")); err == nil && st.IsDir() {
		b.WriteString("- `guardrails/`（已驗證絆線）\n")
	}
	if st, err := os.Stat(filepath.Join(dir, "evidence")); err == nil && st.IsDir() {
		b.WriteString("- `evidence/`（可複查 bundle）\n")
	}

	path := filepath.Join(dir, "report.md")
	if err := redaction.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return "", fmt.Errorf("reporting: write report.md: %w", err)
	}
	return path, nil
}

func writeEnvironment(b *strings.Builder, runDir string) {
	data, err := os.ReadFile(filepath.Join(runDir, "environment.json"))
	if err != nil {
		return
	}
	var env map[string]any
	if json.Unmarshal(data, &env) != nil {
		return
	}
	b.WriteString("## 環境準備\n\n")
	fmt.Fprintf(b, "- 狀態：`%s`\n- Runtime：`%s`\n- Image：`%s`\n- 檢查：`%s`\n- Run 網路：`%s`\n\n", str(env["status"]), str(env["runtime"]), str(env["image"]), str(env["check"]), str(env["network"]))
	if detail := str(env["detail"]); detail != "" {
		fmt.Fprintf(b, "- 詳細：%s\n\n", detail)
	}
	b.WriteString("> `SOURCE_COMPILED` 只證明 immutable snapshot 在固定 runtime 通過 compile smoke check；不代表應用成功啟動，也不代表任何 finding 已可利用。\n\n")
}

func writeCoverage(b *strings.Builder, runDir string) {
	data, err := os.ReadFile(filepath.Join(runDir, "coverage.json"))
	if err != nil {
		b.WriteString("- 審查覆蓋資訊：未知（run 缺少 `coverage.json`）\n\n")
		return
	}
	var coverage struct {
		PackID                 string   `json:"pack_id"`
		PackVersion            string   `json:"pack_version"`
		VerifiableExtensions   []string `json:"verifiable_extensions"`
		ProofRuntimeExtensions []string `json:"proof_runtime_extensions"`
		TargetExtensions       []string `json:"target_extensions"`
		TargetLanguages        []string `json:"target_languages"`
		UncoveredExtensions    []string `json:"uncovered_extensions"`
		DetectorIDs            []string `json:"detector_ids"`
		DetectorLanguages      []string `json:"detector_languages"`
		ExecutedDetectorIDs    []string `json:"executed_detector_ids"`
		DetectorNotes          []string `json:"detector_notes"`
		SinkTypes              []string `json:"sink_types"`
		ProofFamilies          []string `json:"proof_families"`
		LLMReviewerConfigured  bool     `json:"llm_reviewer_configured"`
		DiscoveryMode          string   `json:"discovery_mode"`
	}
	if err := json.Unmarshal(data, &coverage); err != nil {
		b.WriteString("- 審查覆蓋資訊：無法解析 `coverage.json`\n\n")
		return
	}
	fmt.Fprintf(b, "- 實際載入 pack：`%s@%s`\n", coverage.PackID, coverage.PackVersion)
	fmt.Fprintf(b, "- 候選發現模式：`%s`\n", coverage.DiscoveryMode)
	fmt.Fprintf(b, "- LLM discovery 目標語言：%s（副檔名 %s）\n", displayList(coverage.TargetLanguages), displayList(coverage.TargetExtensions))
	fmt.Fprintf(b, "- Semgrep detector：%s；規則語言：%s；成功執行：%s\n", displayList(coverage.DetectorIDs), displayList(coverage.DetectorLanguages), displayList(coverage.ExecutedDetectorIDs))
	fmt.Fprintf(b, "- Proof runtime 可執行 witness 副檔名：%s；具可信 oracle 的漏洞家族：%s\n", displayList(coverage.ProofRuntimeExtensions), displayList(coverage.ProofFamilies))
	fmt.Fprintf(b, "- Pack 登錄候選 sink 類型：%s；LLM reviewer：%t\n", displayList(coverage.SinkTypes), coverage.LLMReviewerConfigured)
	for _, note := range coverage.DetectorNotes {
		fmt.Fprintf(b, "- Detector 降級：%s\n", note)
	}
	if len(coverage.UncoveredExtensions) > 0 {
		fmt.Fprintf(b, "- **Proof runtime 尚不能執行：%s**（LLM reviewer 仍會審查；這不是 Semgrep 的限制）\n", displayList(coverage.UncoveredExtensions))
	}
	b.WriteString("\n")
}

func displayList(values []string) string {
	if len(values) == 0 {
		return "（無）"
	}
	return strings.Join(values, ", ")
}

func splitByVerification(fs []Finding) (proven, others []Finding) {
	for _, f := range fs {
		if str(f["verification"]) == "PROVEN" {
			proven = append(proven, f)
		} else {
			others = append(others, f)
		}
	}
	sort.Slice(proven, func(i, j int) bool { return str(proven[i]["id"]) < str(proven[j]["id"]) })
	sort.Slice(others, func(i, j int) bool { return str(others[i]["id"]) < str(others[j]["id"]) })
	return
}

func writeFinding(b *strings.Builder, f Finding) {
	sink := asMap(f["sink"])
	fmt.Fprintf(b, "### %s — %s（%s / %s）\n\n",
		str(f["id"]), str(sink["symbol"]), str(f["reachability"]), str(f["verification"]))
	if supported, exists := f["proof_supported"].(bool); exists && !supported {
		b.WriteString("**驗證邊界：尚未機械實證。** " + str(f["proof_note"]) + "\n\n")
	}
	if cwe := str(f["cwe"]); cwe != "" {
		fmt.Fprintf(b, "分類：`%s`；CWE：`%s`\n\n", str(sink["type"]), cwe)
	}
	if str(f["verification"]) == "PROVEN" && str(f["evidence_id"]) != "" {
		b.WriteString("重現／重驗：`aegis replay --run-dir <run-dir>`\n\n")
	}

	// D2/D3 即使 PROVEN 也必須寫「合成見證下已證明」（§14-1）
	reach := str(f["reachability"])
	if reach == "D2" || reach == "D3" {
		b.WriteString("**合成見證下已證明**（synthetic witness）——以下為產品假設，請人類判斷 MVP 是否可信；\n")
		b.WriteString("**不代表當前產品可從外部攻擊**。\n\n")
		for _, a := range strList(f["assumptions"]) {
			fmt.Fprintf(b, "- 假設：%s\n", a)
		}
		b.WriteString("\n")
	}

	b.WriteString("### 現況\n\n")
	fmt.Fprintf(b, "%s\n\n", str(f["rationale"]))
	for _, evidence := range strList(f["review_evidence"]) {
		fmt.Fprintf(b, "- Code review 證據：`%s`\n", evidence)
	}
	if len(strList(f["review_evidence"])) > 0 {
		b.WriteString("\n")
	}
	chain := strList(f["chain"])
	if len(chain) > 0 {
		b.WriteString("攻擊鏈：" + strings.Join(chain, " → ") + "\n\n")
	}

	b.WriteString("### 未來開發注意事項\n\n")
	miss := strList(f["missing_links"])
	if len(miss) > 0 {
		tripwireState := "尚未建立絆線"
		if len(strList(f["guardrails"])) > 0 {
			tripwireState = "已有已驗證絆線"
		}
		for _, m := range miss {
			fmt.Fprintf(b, "- 缺環節（%s）：%s\n", tripwireState, m)
		}
	} else {
		b.WriteString("- 本 finding 已形成完整攻擊鏈；修復前請勿擴大相關輸入面。\n")
	}
	b.WriteString("\n### 修補建議\n\n")
	fix := asMap(f["fix"])
	fmt.Fprintf(b, "%s\n\n", str(fix["summary"]))
	if d := str(fix["diff_suggestion"]); d != "" {
		b.WriteString("```diff\n" + d + "\n```\n\n")
	}
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func intValue(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case json.Number:
		value, _ := n.Int64()
		return int(value)
	default:
		return 0
	}
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}

func strList(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
