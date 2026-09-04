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
		if reach, ok := f["reachability"].(string); ok {
			result["properties"] = map[string]any{
				"aegis.reachability": reach,
				"aegis.verification": str(f["verification"]),
				"aegis.severity":     str(f["severity"]),
			}
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
	b.WriteString("## 執行摘要\n\n")
	fmt.Fprintf(&b, "- Finding 總數：%d（PROVEN %d）\n\n", len(findings), len(proven))

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
	b.WriteString("- `findings.json`（機讀全量）\n- `findings.sarif`（IDE/CI 整合）\n")
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
	chain := strList(f["chain"])
	if len(chain) > 0 {
		b.WriteString("攻擊鏈：" + strings.Join(chain, " → ") + "\n\n")
	}

	b.WriteString("### 未來開發注意事項\n\n")
	miss := strList(f["missing_links"])
	if len(miss) > 0 {
		for _, m := range miss {
			fmt.Fprintf(b, "- 缺環節（絆線已備）：%s\n", m)
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
