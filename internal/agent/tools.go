// tools.go：工具閘與執行本體（§18.1）。
// read_code／search_code／semgrep 是唯讀觀測；submit_witness_spec 是 prover
// 專用的提交工具，真實驗證在閘 (b)（schema + §17.2 placeholder + 核可）。
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aegis-dev/aegis/internal/llm"
)

// 輸出頻寬上限（§18.2 回饋頻寬有界的工具面：防 context 爆炸）。
const (
	MaxReadBytes   = 200 * 1024 // read_code 單次輸出上限
	MaxSearchHits  = 50         // search_code 上限筆數（§18.1）
	MaxSearchLine  = 200        // 單行截斷
	MaxSemgrepHits = 200        // semgrep 上限筆數（§18.1）
)

// SubmitHandler 是 submit_witness_spec 的閘 (b) 與核可：由 prover 迴圈注入。
// assistantText 是本輪 assistant 訊息的文字部分（三行 preamble 驗證用，§18.2）。
// 回傳 (accepted, feedback)；拒收時 feedback 為拒收原因（回給模型）。
type SubmitHandler func(ctx context.Context, spec map[string]any, assistantText string) (bool, string)

// ToolRegistry 是工具集合與 per-turn 閘。
type ToolRegistry struct {
	// SnapshotDir 是唯讀 snapshot 根（read_code/search_code 的路徑邊界）。
	SnapshotDir string
	// Rules 是 pack manifest 登錄的 detector 規則 id → 規則檔路徑（semgrep 用）。
	Rules map[string]string
	// SemgrepBin 是 semgrep 執行檔名；空值視為 "semgrep"。
	SemgrepBin string
	// OnSubmit 是 submit_witness_spec 閘（prover 專用；nil 時任何提交都拒絕）。
	OnSubmit SubmitHandler
	// audit 記錄器；nil 時不記（僅測試）。
	audit *AuditLog
}

// SetAudit 綁定 audit log。
func (t *ToolRegistry) SetAudit(a *AuditLog) { t.audit = a }

// Result 是單一工具執行結果（回填為 tool_result）。
type Result struct {
	Content string
	IsError bool
}

// Execute 執行一次工具呼叫：白名單閘 → 工具本體；每次呼叫記 audit（§18.1 閘 a）。
// assistantText 為本輪 assistant 文字（submit 的三行 preamble 驗證用）。
func (t *ToolRegistry) Execute(ctx context.Context, role llm.Role, tool string, input json.RawMessage, assistantText string) Result {
	if !HasWhitelist(role, tool) {
		t.audit.Append(role, tool, input, AuditDenied, "not_in_whitelist")
		return Result{Content: "policy_denied: 工具不在角色白名單（§18.1）", IsError: true}
	}
	if tool == "submit_witness_spec" && t.OnSubmit == nil {
		t.audit.Append(role, tool, input, AuditDenied, "no_submit_handler")
		return Result{Content: "policy_denied: 本 session 未開放提交", IsError: true}
	}

	var res Result
	switch tool {
	case "read_code":
		res = t.readCode(input)
	case "search_code":
		res = t.searchCode(input)
	case "semgrep":
		res = t.semgrep(ctx, input)
	case "submit_witness_spec":
		res = t.submit(ctx, role, input, assistantText)
	default:
		res = Result{Content: "policy_denied: 未知工具", IsError: true}
	}

	decision := AuditAllowed
	if res.IsError {
		decision = AuditError
		if strings.HasPrefix(res.Content, "policy_denied") {
			decision = AuditDenied
		}
	}
	t.audit.Append(role, tool, input, decision, "")
	return res
}

// pathInSnapshot 解析 snapshot 內相對路徑：EvalSymlinks＋Abs 後必須仍以
// snapshot 根開頭（§18.1 路徑政策；symlink 逃逸在此擋下）。
func pathInSnapshot(snapshotDir, rel string) (string, error) {
	if rel == "" {
		return "", fmt.Errorf("path 為空")
	}
	clean := filepath.Clean("/" + rel) // 去前導 ".."（掛在虛擬根下規整）
	abs := filepath.Join(snapshotDir, clean)
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("path 不可讀（%s）", rel)
	}
	realAbs, err := filepath.Abs(real)
	if err != nil {
		return "", fmt.Errorf("path 解析失敗（%s）", rel)
	}
	rootAbs, err := filepath.Abs(snapshotDir)
	if err != nil {
		return "", fmt.Errorf("snapshot 根解失敗：%w", err)
	}
	rootReal, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return "", fmt.Errorf("snapshot 根不可讀：%w", err)
	}
	if realAbs != rootReal && !strings.HasPrefix(realAbs, rootReal+string(filepath.Separator)) {
		return "", fmt.Errorf("path 越出 snapshot 根（§18.1 路徑政策）")
	}
	return realAbs, nil
}

// readCode：回傳 1-based 行切片；start/end 可省（省 start=1、end=檔尾）。
func (t *ToolRegistry) readCode(input json.RawMessage) Result {
	var args struct {
		Path  string `json:"path"`
		Start int64  `json:"start"`
		End   int64  `json:"end"`
	}
	if err := json.Unmarshal(input, &args); err != nil {
		return Result{Content: "policy_denied: read_code 參數非法：" + err.Error(), IsError: true}
	}
	abs, err := pathInSnapshot(t.SnapshotDir, args.Path)
	if err != nil {
		return Result{Content: "policy_denied: " + err.Error(), IsError: true}
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return Result{Content: "read_code 失敗：" + err.Error(), IsError: true}
	}
	lines := bytes.Split(data, []byte("\n"))
	start, end := args.Start, args.End
	if start < 1 {
		start = 1
	}
	if end < 1 || end > int64(len(lines)) {
		end = int64(len(lines))
	}
	if start > end {
		return Result{Content: "read_code 失敗：start > end", IsError: true}
	}
	var buf bytes.Buffer
	total := 0
	for i := start; i <= end; i++ {
		line := append([]byte(fmt.Sprintf("%d: ", i)), lines[i-1]...)
		if total+len(line) > MaxReadBytes {
			fmt.Fprintf(&buf, "…（輸出達 %d 位元組上限，截斷；請縮小 range）\n", MaxReadBytes)
			break
		}
		buf.Write(line)
		buf.WriteByte('\n')
		total += len(line) + 1
	}
	return Result{Content: buf.String()}
}

// searchCode：純 Go regexp 逐檔掃描（不 shell out，§18.1）；query ≤256 字元、
// RE2 編譯失敗（含 lookahead／backreference）即政策拒絕。上限 50 筆、附 file:line。
func (t *ToolRegistry) searchCode(input json.RawMessage) Result {
	var args struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(input, &args); err != nil {
		return Result{Content: "policy_denied: search_code 參數非法：" + err.Error(), IsError: true}
	}
	if len(args.Query) > 256 {
		return Result{Content: "policy_denied: query 逾 256 字元（§18.1）", IsError: true}
	}
	re, err := regexp.Compile(args.Query)
	if err != nil {
		return Result{Content: "policy_denied: regexp 無法編譯（RE2 不支援 lookahead／backreference）：" + err.Error(), IsError: true}
	}
	type hit struct {
		Path string `json:"path"`
		Line int    `json:"line"`
		Text string `json:"text"`
	}
	hits := make([]hit, 0, MaxSearchHits)
	walkErr := filepath.WalkDir(t.SnapshotDir, func(path string, d os.DirEntry, werr error) error {
		if werr != nil || d.IsDir() || len(hits) >= MaxSearchHits {
			return nil
		}
		info, serr := d.Info()
		if serr != nil || info.Size() > 1024*1024 { // 跳過 >1MB 檔（二進位／產物）
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		for i, line := range bytes.Split(data, []byte("\n")) {
			if len(hits) >= MaxSearchHits {
				return filepath.SkipAll
			}
			if re.Match(line) {
				text := string(line)
				if len(text) > MaxSearchLine {
					text = text[:MaxSearchLine]
				}
				rel, rerr := filepath.Rel(t.SnapshotDir, path)
				if rerr != nil {
					rel = path
				}
				hits = append(hits, hit{Path: rel, Line: i + 1, Text: text})
			}
		}
		return nil
	})
	if walkErr != nil && walkErr != filepath.SkipAll {
		// filepath.SkipAll 是正常截斷；其他錯誤屬環境問題。
		return Result{Content: "search_code 失敗：" + walkErr.Error(), IsError: true}
	}
	out, merr := json.Marshal(hits)
	if merr != nil {
		return Result{Content: "search_code 序列化失敗：" + merr.Error(), IsError: true}
	}
	if len(hits) == 0 {
		return Result{Content: "[]", IsError: false}
	}
	return Result{Content: string(out)}
}

// semgrep：只接受 pack manifest 登錄的規則 id（§18.1）；模型自帶規則一律
// policy_denied。回傳 [{path, line, rule_id, matched_text}]，截 200 筆。
func (t *ToolRegistry) semgrep(ctx context.Context, input json.RawMessage) Result {
	var args struct {
		Rule string `json:"rule"`
	}
	if err := json.Unmarshal(input, &args); err != nil {
		return Result{Content: "policy_denied: semgrep 參數非法：" + err.Error(), IsError: true}
	}
	rulePath, ok := t.Rules[args.Rule]
	if !ok || args.Rule == "" {
		return Result{Content: "policy_denied: 規則 id 未登錄於 pack manifest（§18.1）", IsError: true}
	}
	bin := t.SemgrepBin
	if bin == "" {
		bin = "semgrep"
	}
	// semgrep 以 os/exec 呼叫（§16），snapshot 唯讀掃描，--json 機器可讀輸出。
	out, err := exec.CommandContext(ctx, bin, "--json", "--config", rulePath, t.SnapshotDir).Output()
	if err != nil {
		return Result{Content: "semgrep 失敗（未安裝或規則錯誤？）：" + err.Error(), IsError: true}
	}
	hits, err := parseSemgrepJSON(out, args.Rule)
	if err != nil {
		return Result{Content: "semgrep 輸出解析失敗：" + err.Error(), IsError: true}
	}
	if len(hits) > MaxSemgrepHits {
		hits = hits[:MaxSemgrepHits]
	}
	b, mErr := json.Marshal(hits)
	if mErr != nil {
		return Result{Content: "semgrep 序列化失敗：" + mErr.Error(), IsError: true}
	}
	return Result{Content: string(b)}
}

// semgrepHit 是 §18.1 固定回傳格式。
type semgrepHit struct {
	Path        string `json:"path"`
	Line        int64  `json:"line"`
	RuleID      string `json:"rule_id"`
	MatchedText string `json:"matched_text"`
}

// parseSemgrepJSON 抽 semgrep --json 的 results 欄位（最小欄位集）。
func parseSemgrepJSON(data []byte, ruleID string) ([]semgrepHit, error) {
	var parsed struct {
		Results []struct {
			Path   string `json:"path"`
			Start  struct {
				Line int64 `json:"line"`
			} `json:"start"`
			Extra struct {
				Match string `json:"match"`
			} `json:"extra"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, err
	}
	hits := make([]semgrepHit, 0, len(parsed.Results))
	for _, r := range parsed.Results {
		hits = append(hits, semgrepHit{Path: r.Path, Line: r.Start.Line, RuleID: ruleID, MatchedText: r.Extra.Match})
	}
	return hits, nil
}

// submit 呼叫閘 (b)：schema 驗證 + §17.2 placeholder + 核可全在 handler 內。
func (t *ToolRegistry) submit(ctx context.Context, role llm.Role, input json.RawMessage, assistantText string) Result {
	var spec map[string]any
	if err := json.Unmarshal(input, &spec); err != nil {
		t.audit.Append(role, "submit_witness_spec", input, AuditDenied, "invalid_json")
		return Result{Content: "policy_denied: WitnessSpec 非 JSON object：" + err.Error(), IsError: true}
	}
	accepted, feedback := t.OnSubmit(ctx, spec, assistantText)
	if !accepted {
		t.audit.Append(role, "submit_witness_spec", input, AuditDenied, feedback)
		return Result{Content: "spec_rejected: " + feedback, IsError: true}
	}
	return Result{Content: feedback}
}