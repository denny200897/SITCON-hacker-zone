// Package oracles 實作 SPEC §17.3 的 host 端 deterministic checker（checker 層）：
// 載入 pack manifest 的 oracle 規則（純資料）→ 讀 run 收回的 artifacts（JSONL）
// → 輸出 {"result": bool, "evidence_refs": [...]}。
//
// 鐵則：checker 永不在沙箱內判定、永不呼叫 LLM（§17.3）；條件種類是本套件內的
// 封閉 enum——不得為 rule 發明直譯器、不得讓 rule 帶可執行碼。本套件不含任何
// goroutine 並行（§23-1）。
package oracles

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/aegis-dev/aegis/internal/evidence"
)

// ConditionKind 是 oracle 條件種類的封閉 enum（§17.3）。v1 固定六種，
// 新增種類必須改 checker 原始碼並升版本——rule 只能引用，不能自創。
type ConditionKind string

const (
	// KindNonceInField：存在 entry 的指定 field 含 nonce 字串。
	// 對應 paired touch rule（如 "sql" 欄位含 nonce → 輸入確實流經 sink）。
	KindNonceInField ConditionKind = "nonce_in_field"
	// KindNonceStatementErrored：存在 entry 的 "sql" 含 nonce 且 "error" 非 null。
	// 只有引號真的改變 SQL 語法才會觸發 driver 例外（§17.3：良性輸入也會把
	// nonce 插進 SQL 字面值，「含 nonce」無法區分良性送達與真正跳脫）。
	KindNonceStatementErrored ConditionKind = "nonce_statement_errored"
	// KindRowCountAtLeast：存在 entry 的 "rows"（數值）>= Threshold
	//（boolean-based SQLi 證明：exploit 的 rows ≥ 種子列數而 negative 為 0）。
	KindRowCountAtLeast ConditionKind = "rowcount_at_least"
	// KindListenerRequestWithNonce：listener.jsonl 任一 entry 的任意字串欄位值含 nonce
	//（SSRF：請求 query/body/header 含 nonce 即 success，§17.5）。
	KindListenerRequestWithNonce ConditionKind = "listener_request_with_nonce"
	// KindDOMEventWithNonce：browser observer events 任一 entry 的任意字串欄位值含 nonce。
	KindDOMEventWithNonce ConditionKind = "dom_event_with_nonce"
	// KindCanaryFileMatch：canary 檔案／fs 事件觀察任一 entry 的任意字串欄位值含 nonce。
	KindCanaryFileMatch ConditionKind = "canary_file_match"
)

// conditionKinds 是封閉集成員表（§17.3：不發明新種類）。
var conditionKinds = map[ConditionKind]bool{
	KindNonceInField:             true,
	KindNonceStatementErrored:    true,
	KindRowCountAtLeast:          true,
	KindListenerRequestWithNonce: true,
	KindDOMEventWithNonce:        true,
	KindCanaryFileMatch:          true,
}

// Valid 檢查條件種類是否為封閉集成員。
func (k ConditionKind) Valid() bool { return conditionKinds[k] }

// ConditionKinds 回傳 v1 全部條件種類（§17.3 封閉集，順序固定）。
func ConditionKinds() []ConditionKind {
	return []ConditionKind{
		KindNonceInField,
		KindNonceStatementErrored,
		KindRowCountAtLeast,
		KindListenerRequestWithNonce,
		KindDOMEventWithNonce,
		KindCanaryFileMatch,
	}
}

// sqlTraceFields 是 SQL trace entry 的欄位閉集（§17.3：
// {"ts","sql","params","error","rows"}——execute 的完整語法、參數、例外訊息、回傳列數）。
var sqlTraceFields = map[string]bool{
	"ts":     true,
	"sql":    true,
	"params": true,
	"error":  true,
	"rows":   true,
}

// SQLTraceFields 回傳 SQL trace entry 欄位閉集（§17.3，順序固定）。
func SQLTraceFields() []string {
	return []string{"ts", "sql", "params", "error", "rows"}
}

// isSQLTraceKind 回傳該條件種類是否作用於 SQL trace artifact
//（這三種才受欄位閉集約束）。
func isSQLTraceKind(k ConditionKind) bool {
	return k == KindNonceInField || k == KindNonceStatementErrored || k == KindRowCountAtLeast
}

// Condition 是一條 oracle 判定條件（純資料，對應 pack manifest 的 rule 欄位）。
type Condition struct {
	// Artifact 是 artifactsDir 底下的檔名（如 "sql_trace.jsonl"）。
	// 不得含路徑分隔字元——checker 只讀收回的 artifacts 目錄。
	Artifact string
	// Kind 是條件種類（封閉 enum，§17.3）。
	Kind ConditionKind
	// Field 僅 KindNonceInField 使用（如 "sql"）；其餘種類忽略。
	Field string
	// Threshold 僅 KindRowCountAtLeast 使用；其餘種類忽略。
	Threshold int
}

// validate 檢查條件本身的完整性（未命中與條件不合法是兩回事，不得混淆）。
func (c Condition) validate() error {
	if c.Artifact == "" {
		return fmt.Errorf("oracles: 條件缺少 artifact")
	}
	if c.Artifact == "." || c.Artifact == ".." || filepath.Base(c.Artifact) != c.Artifact {
		return fmt.Errorf("oracles: artifact %q 不得含路徑分隔字元（只能取 artifactsDir 底下的檔名）", c.Artifact)
	}
	if !c.Kind.Valid() {
		return fmt.Errorf("oracles: 未知的條件種類 %q（v1 封閉集：%v，§17.3）", c.Kind, ConditionKinds())
	}
	if c.Kind == KindNonceInField && c.Field == "" {
		return fmt.Errorf("oracles: kind %q 需要 field", KindNonceInField)
	}
	return nil
}

// Rule 對應 pack manifest 的單一 oracle 條目（純資料）。
// Family 必附 paired touch rule（§17.3：Touch 缺漏由 pack ABI 驗證 §6.4 拒載，
// 本套件不重複做 ABI 驗證）。
type Rule struct {
	OracleID string
	Family   string
	Touch    string
	Rule     Condition
}

// Result 是 checker 的輸出（§17.3：{"result": bool, "evidence_refs": [...]}）。
// Result 為 false 時 EvidenceRefs 恆為空——證據引用只伴隨命中。
type Result struct {
	Result bool
	// EvidenceRefs 為 "artifact#行號" 形式（行號為 JSONL 的 1-based 行號）。
	EvidenceRefs []string
}

// Check 以單一條件判定 artifactsDir 內的 artifact。
//
// 讀 artifactsDir/<cond.Artifact>（JSONL，每行一個 JSON object，經 UseNumber 解碼，
// §21.4 規則 2）。回傳 (Result{Result:false}, nil) 表示「未命中」；artifact 檔案
// 不存在或內容不合法回傳 error——環境問題要與未命中嚴格區分（§19）。
func Check(cond Condition, nonce string, artifactsDir string) (Result, error) {
	if err := cond.validate(); err != nil {
		return Result{}, err
	}
	if nonce == "" {
		return Result{}, fmt.Errorf("oracles: nonce 不可為空（oracle 觀察的對象就是 nonce，§17.2）")
	}
	if artifactsDir == "" {
		return Result{}, fmt.Errorf("oracles: artifactsDir 不可為空")
	}

	path := filepath.Join(artifactsDir, cond.Artifact)
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Result{}, fmt.Errorf("oracles: artifact 檔案不存在 %s（環境問題，非未命中）: %w", path, err)
		}
		return Result{}, fmt.Errorf("oracles: 開啟 artifact 失敗 %s: %w", path, err)
	}
	defer f.Close()

	var refs []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024) // 單行上限 16MiB，防超長 trace 行
	line := 0
	for sc.Scan() {
		line++
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue // 空行不計命中，但行號仍遞增以對齊檔案實際行號
		}
		entry, err := evidence.Decode(raw)
		if err != nil {
			return Result{}, fmt.Errorf("oracles: %s 第 %d 行不是合法 JSON object: %w", cond.Artifact, line, err)
		}
		if isSQLTraceKind(cond.Kind) {
			if err := checkSQLTraceClosed(entry); err != nil {
				return Result{}, fmt.Errorf("oracles: %s 第 %d 行: %w", cond.Artifact, line, err)
			}
		}
		matched, err := match(cond, nonce, entry)
		if err != nil {
			return Result{}, fmt.Errorf("oracles: %s 第 %d 行: %w", cond.Artifact, line, err)
		}
		if matched {
			refs = append(refs, fmt.Sprintf("%s#%d", cond.Artifact, line))
		}
	}
	if err := sc.Err(); err != nil {
		return Result{}, fmt.Errorf("oracles: 讀取 artifact %s: %w", path, err)
	}
	return Result{Result: len(refs) > 0, EvidenceRefs: refs}, nil
}

// CheckRule 以 pack manifest 的 oracle 條目判定（包裝 Check）。
func CheckRule(r Rule, nonce string, artifactsDir string) (Result, error) {
	return Check(r.Rule, nonce, artifactsDir)
}

// checkSQLTraceClosed 驗證 entry 未超出 SQL trace 欄位閉集（§17.3）。
func checkSQLTraceClosed(entry map[string]any) error {
	for k := range entry {
		if !sqlTraceFields[k] {
			return fmt.Errorf("oracles: sql trace entry 含未知欄位 %q（欄位閉集 %v，§17.3）", k, SQLTraceFields())
		}
	}
	return nil
}

// match 對單一 entry 評估條件。存在量詞語意：任一 entry 命中即成立。
func match(cond Condition, nonce string, entry map[string]any) (bool, error) {
	switch cond.Kind {
	case KindNonceInField:
		v, ok := entry[cond.Field]
		if !ok {
			return false, nil // 欄位缺漏視為未命中，不是錯誤
		}
		return walkStringValues(v, func(s string) bool { return strings.Contains(s, nonce) }), nil
	case KindNonceStatementErrored:
		sv, ok := entry["sql"]
		if !ok {
			return false, nil
		}
		s, ok := sv.(string)
		if !ok || !strings.Contains(s, nonce) {
			return false, nil
		}
		// error 非 null 才成立（§17.3：良性輸入也會把 nonce 插進 SQL 字面值）
		ev, present := entry["error"]
		return present && ev != nil, nil
	case KindRowCountAtLeast:
		v, ok := entry["rows"]
		if !ok {
			return false, nil
		}
		return numGE(v, cond.Threshold), nil
	case KindListenerRequestWithNonce, KindDOMEventWithNonce, KindCanaryFileMatch:
		return walkStringValues(entry, func(s string) bool { return strings.Contains(s, nonce) }), nil
	default:
		// Condition.validate 已擋下未知種類；此分支僅防禦未來新增 enum 成員漏寫 case
		return false, fmt.Errorf("oracles: 條件種類 %q 尚無判定器（封閉集內缺 case，屬 checker 實作錯誤）", cond.Kind)
	}
}

// walkStringValues 對 v 內所有字串值（含 map／array 巢狀）依序套用 fn；
// fn 回 true 表示命中並提前終止。map 迭代順序不定，但只影響「哪個字串先被檢查」，
// 不影響存在量詞的判定結果。
func walkStringValues(v any, fn func(string) bool) bool {
	switch t := v.(type) {
	case string:
		return fn(t)
	case map[string]any:
		for _, sv := range t {
			if walkStringValues(sv, fn) {
				return true
			}
		}
	case []any:
		for _, ev := range t {
			if walkStringValues(ev, fn) {
				return true
			}
		}
	}
	return false
}

// numGE 判斷數值 v 是否 >= threshold。解碼一律經 UseNumber（§21.4），
// 數值以 json.Number 原字面比較：優先整數路徑，非整數退回浮點。
func numGE(v any, threshold int) bool {
	switch n := v.(type) {
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i >= int64(threshold)
		}
		f, err := n.Float64()
		if err != nil {
			return false // 非法數值字面不視為命中
		}
		return f >= float64(threshold)
	case float64:
		return n >= float64(threshold)
	case int64:
		return n >= int64(threshold)
	}
	return false
}