// Package policy 實作 policy compiler（SPEC §5.2、§17.1、§17.2、§17.9）——
// 模型不可繞過的信任邊界：prover 只輸出受限的 WitnessSpec，RunRequest 全由本套件
// 組裝；映像 digest、掛載、網路、上限一律由政策決定，不接受模型輸入（不變式 1）。
//
// 與 internal/packs 解耦：本套件定義最小介面 PackView，整合時由 packs.Pack 滿足。
// AST 檢查與金鑰掃描同樣以函式注入（internal/redaction 掃描、pack 的 AST helper）。
package policy

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/aegis-dev/aegis/internal/evidence"
)

// ---- SpecError（§17.9：驗證閉集，任一不符即 witness_spec_rejected） ----

// SpecError 的 Reason 閉集（§17.9＋§17.2；不得發明新值）。
const (
	ReasonMissingNoncePlaceholder = "missing_nonce_placeholder"
	ReasonPayloadTooLarge         = "payload_too_large"
	ReasonBadGeneratedFiles       = "bad_generated_files"
	ReasonTargetSymbolMissing     = "target_symbol_missing"
	ReasonUnknownTemplate         = "unknown_template"
	ReasonUnknownOracle           = "unknown_oracle"
	ReasonFamilyMismatch          = "family_mismatch"
	ReasonModeNotSupported        = "mode_not_supported"
	ReasonSecretInSpec            = "secret_in_spec"
	ReasonMissingAssumptions      = "missing_assumptions"
	ReasonDuplicateSpec           = "duplicate_spec"
	ReasonEmptyPayload            = "empty_payload"
	ReasonOversizeFiles           = "oversize_files"
)

// reasons 是 Reason 閉集（§21.2 精神：集合成員檢查，防止拼字錯誤流入訊息）。
var reasons = map[string]bool{
	ReasonMissingNoncePlaceholder: true,
	ReasonPayloadTooLarge:         true,
	ReasonBadGeneratedFiles:       true,
	ReasonTargetSymbolMissing:     true,
	ReasonUnknownTemplate:         true,
	ReasonUnknownOracle:           true,
	ReasonFamilyMismatch:          true,
	ReasonModeNotSupported:        true,
	ReasonSecretInSpec:            true,
	ReasonMissingAssumptions:      true,
	ReasonDuplicateSpec:           true,
	ReasonEmptyPayload:            true,
	ReasonOversizeFiles:           true,
}

// SpecError 是 prover 可收到的拒收原因（§18.2 回饋會引用）。
// 訊息只含原因與說明，絕不含 nonce（§18.2：nonce 不進回饋訊息）。
type SpecError struct {
	Reason string
}

// Error 實作 error；訊息為 zh-TW、不含任何機密值。
func (e *SpecError) Error() string {
	if !reasons[e.Reason] {
		return fmt.Sprintf("policy: witness spec 遭拒（未知原因 %q）", e.Reason)
	}
	return fmt.Sprintf("policy: witness spec 遭拒（%s）：%s", e.Reason, reasonText[e.Reason])
}

// reasonText 給出各拒收原因的 zh-TW 說明（給 prover 的重送指引；不含機密）。
var reasonText = map[string]string{
	ReasonMissingNoncePlaceholder: "payload 未含 {{NONCE}} 或 {{NONCE_HEX}} placeholder，請重送",
	ReasonPayloadTooLarge:         "payload 超過 2KiB 上限",
	ReasonBadGeneratedFiles:       "generated_files 鍵或副檔名不符規範（witness/<name>、相對路徑、允許清單、≤8 檔）",
	ReasonTargetSymbolMissing:     "target_symbol 無法在 snapshot 中以 AST 靜態解析",
	ReasonUnknownTemplate:         "template_id 不存在於 pack manifest",
	ReasonUnknownOracle:           "oracle_id 不存在於 pack manifest",
	ReasonFamilyMismatch:          "template 與 oracle 的 family 不一致",
	ReasonModeNotSupported:        "template 不支援該 run_mode",
	ReasonSecretInSpec:            "spec 內容命中金鑰樣式，請移除後重送",
	ReasonMissingAssumptions:      "D2/D3 finding 未附至少一條 assumption",
	ReasonDuplicateSpec:           "與先前已提交的 spec 內容 hash 相同",
	ReasonEmptyPayload:            "payload 必填且不得為空",
	ReasonOversizeFiles:           "generated_files 內容總大小超過 256KiB",
}

func specErr(reason string) *SpecError { return &SpecError{Reason: reason} }

// ---- PackView：與 internal/packs 解耦的最小介面 ----

// Template 是本套件所需的模板元資料（整合時由 packs.Manifest 的 TemplateEntry 滿足）。
type Template struct {
	TemplateID   string
	Family       string
	RunMode      string // "witness" | "direct"（template 支援的單一模式，§17.9-1）
	AllowedFiles []string
	ServiceCmd   string
	ServicePort  int
	WaitFor      string
	Image        string // 必為 digest 形式（§17.10：永不使用可變 tag）
}

// Oracle 是本套件所需的 oracle 元資料（整合時由 packs.Manifest 的 OracleEntry 滿足；
// 條件規則由 checker 套件持有，本套件只需要 oracle_id 與 family）。
type Oracle struct {
	OracleID string
	Family   string
	Touch    *string
}

// PackView 解析 template_id／oracle_id（整合時由 packs.Pack 滿足）。
type PackView interface {
	Template(id string) (*Template, error)
	Oracle(id string) (*Oracle, error)
}

// ---- 輸入與輸出 ----

// Input 是 Compile 的全部輸入；除 Spec 外均為 orchestrator／pack 注入的政策資料。
type Input struct {
	// Spec 是 prover 提交的 WitnessSpec（§5.2；已通過 schema 驗證為前提）。
	Spec map[string]any
	// FindingReachability 是該 finding 的 triage 結論（"D0".."D3"）。
	FindingReachability string
	// SnapshotDir 是目標 repo 的快照目錄（AST helper 唯讀掛載來源）。
	SnapshotDir string
	// PrevSpecHashes 是先前已提交 spec 的 canonical hash 集合（§17.9-7）。
	PrevSpecHashes map[string]bool
	// SecretScan 注入金鑰樣式掃描（§7.2／internal/redaction.Scan 包裝），命中回 true。
	SecretScan func(string) bool
	// ASTCheck 注入 AST helper 檢查（§17.9-2）；回非 nil 即 target_symbol_missing。
	ASTCheck func(snapshotDir, targetSymbol string) error
	// NonceCount 是 runner 本輪已產生的 nonce 個數（每次 run 重新產生；runner 記錄用）。
	NonceCount int
	// PackView 解析 template_id／oracle_id（整合時由 packs.Pack 滿足，§17.9-1）。
	PackView PackView
	// RunID／SnapshotID 進 RunRequest 與容器 labels（§17.1）。
	RunID      string
	SnapshotID string
	// Kind 是 run 種類（negative|positive|exploit，§5.2）；空值預設 "exploit"。
	Kind string
}

// RunRequest 的固定政策常數（§5.2／§17.1 canonical run flags 閉集）。
const (
	TimeoutSec = 60
	CPUs       = "1"
	Mem        = "512m"
	PIDsLimit  = 128
	ULimitNF   = 256
	CapDrop    = "ALL"
	User       = "65532:65532"
	Network    = "none" // ssrf-internal 由 M2 依 finding 型態決定
	// PayloadMax 是 payload 上限（§17.9-4：2KiB）。
	PayloadMax = 2048
	// FilesMax 與 FilesBytesMax 是 generated_files 的檔數與總大小上限（§17.9-3）。
	FilesMax       = 8
	FilesBytesMax  = 256 * 1024
	FilesPrefix    = "witness/"
	DirectFileName = "witness/exploit.py" // direct 模式僅允許 exploit 腳本（§17.8）
)

// nonce placeholders（§17.2；兩者語意相同）。
const (
	noncePlaceholder    = "{{NONCE}}"
	noncePlaceholderHex = "{{NONCE_HEX}}"
)

// runIDPattern 與 run_request.schema.json 的 run_id pattern 一致（政策自我檢查）。
var runIDPattern = regexp.MustCompile(`^R-[0-9]{4}$`)

// digestPattern 檢查映像參照為 digest 形式（§17.10：可變 tag 一律拒絕）。
var digestPattern = regexp.MustCompile(`^.+@sha256:[0-9a-f]{64}$`)

// Compile 驗證 WitnessSpec（§17.9 閉集）並組裝 RunRequest（§5.2）。
// nonce 由 runner 產生、prover 事前未知；本函式把它替換進 payload 與 generated_files，
// 但絕不將其放進任何 SpecError 訊息（§18.2）。
func Compile(in Input, nonce string) (map[string]any, error) {
	// 注入項檢查：政策元件缺失是整合錯誤，不是 prover 的拒收原因。
	if nonce == "" {
		return nil, fmt.Errorf("policy: nonce 不得為空（runner 必須先產生）")
	}
	if in.SecretScan == nil {
		return nil, fmt.Errorf("policy: SecretScan 未注入（§17.9-5 金鑰掃描不可略過）")
	}
	if in.ASTCheck == nil {
		return nil, fmt.Errorf("policy: ASTCheck 未注入（§17.9-2 AST 靜態解析不可略過）")
	}
	if in.PackView == nil {
		return nil, fmt.Errorf("policy: PackView 未注入（§17.9-1 manifest 解析不可略過）")
	}
	if !runIDPattern.MatchString(in.RunID) {
		return nil, fmt.Errorf("policy: run_id %q 不符 R-#### 格式", in.RunID)
	}
	if in.SnapshotID == "" {
		return nil, fmt.Errorf("policy: snapshot_id 不得為空")
	}
	if in.SnapshotDir == "" {
		return nil, fmt.Errorf("policy: snapshot 目錄不得為空")
	}

	kind := in.Kind
	if kind == "" {
		kind = "exploit"
	}

	// §17.9-1：template／oracle 解析與 family／mode 一致性
	tmplID, _ := in.Spec["template_id"].(string)
	if tmplID == "" {
		return nil, specErr(ReasonUnknownTemplate)
	}
	tmpl, err := in.PackView.Template(tmplID)
	if err != nil || tmpl == nil {
		return nil, specErr(ReasonUnknownTemplate)
	}
	if !digestPattern.MatchString(tmpl.Image) {
		// §17.10：映像參照必為 digest 形式；manifest 給出可變 tag 是整合錯誤，fail-closed。
		return nil, fmt.Errorf("policy: template %q 的 image 非 digest 形式，請先以 /doctor 本地構建", tmplID)
	}
	oracleID, _ := in.Spec["oracle_id"].(string)
	if oracleID == "" {
		return nil, specErr(ReasonUnknownOracle)
	}
	oracle, err := in.PackView.Oracle(oracleID)
	if err != nil || oracle == nil {
		return nil, specErr(ReasonUnknownOracle)
	}
	if tmpl.Family != oracle.Family {
		return nil, specErr(ReasonFamilyMismatch)
	}
	runMode, _ := in.Spec["run_mode"].(string)
	if runMode == "" || runMode != tmpl.RunMode {
		return nil, specErr(ReasonModeNotSupported)
	}

	// §17.9-2：target_symbol 以 AST 靜態解析存在於 snapshot
	targetSymbol, _ := in.Spec["target_symbol"].(string)
	if targetSymbol == "" {
		return nil, specErr(ReasonTargetSymbolMissing)
	}
	if err := in.ASTCheck(in.SnapshotDir, targetSymbol); err != nil {
		return nil, specErr(ReasonTargetSymbolMissing)
	}

	// §17.9-3：generated_files 鍵為 witness/<name>、相對、無 ..、副檔名允許、≤8 檔
	files, rerr := validateFiles(in.Spec, tmpl)
	if rerr != nil {
		return nil, rerr
	}

	// §17.9-4：payload 必填、≤2KiB、至少含一個 nonce placeholder
	payload, _ := in.Spec["payload"].(string)
	if payload == "" {
		return nil, specErr(ReasonEmptyPayload)
	}
	if len(payload) > PayloadMax {
		return nil, specErr(ReasonPayloadTooLarge)
	}
	if !strings.Contains(payload, noncePlaceholder) && !strings.Contains(payload, noncePlaceholderHex) {
		return nil, specErr(ReasonMissingNoncePlaceholder)
	}

	// §17.9-5：金鑰樣式掃描（payload、各檔內容、assumptions、target_symbol）
	if scanHits(in, payload, files, targetSymbol) {
		return nil, specErr(ReasonSecretInSpec)
	}

	// §17.9-6：D2/D3 finding 未附 ≥1 條 assumption
	assumptions := stringList(in.Spec["assumptions"])
	if isD2D3(in.FindingReachability) && len(assumptions) < 1 {
		return nil, specErr(ReasonMissingAssumptions)
	}

	// §17.9-7：與任一先前已提交 spec 內容 hash 相同（對原始 spec 計 hash；
	// spec 內一律是 placeholder，不會因 run 而異）
	h, err := evidence.Hash(in.Spec)
	if err != nil {
		return nil, fmt.Errorf("policy: spec canonical hash: %w", err)
	}
	if in.PrevSpecHashes[h] {
		return nil, specErr(ReasonDuplicateSpec)
	}

	// §17.2：nonce 統一替換（payload 與 generated_files 內容；鍵不含 placeholder）
	return assemble(in, tmpl, files, payload, kind, nonce), nil
}

// validateFiles 依 §17.9-3 檢查 generated_files，回傳通過的 (鍵, 內容) 集合。
func validateFiles(spec map[string]any, tmpl *Template) ([][2]string, error) {
	raw, ok := spec["generated_files"].(map[string]any)
	if !ok {
		return nil, specErr(ReasonBadGeneratedFiles)
	}
	if len(raw) > FilesMax {
		return nil, specErr(ReasonBadGeneratedFiles)
	}
	allowed := map[string]bool{}
	for _, ext := range tmpl.AllowedFiles {
		allowed[strings.ToLower(ext)] = true
	}

	keys := []string{}
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys) // 決定性輸出順序（同 spec 重組出同 RunRequest，利於 hash）

	out := make([][2]string, 0, len(keys))
	total := 0
	for _, k := range keys {
		if !validFileKey(k) {
			return nil, specErr(ReasonBadGeneratedFiles)
		}
		if runMode, _ := spec["run_mode"].(string); runMode == "direct" && k != DirectFileName {
			// §17.8：direct 模式只含 exploit 腳本，不得夾帶其他檔案
			return nil, specErr(ReasonBadGeneratedFiles)
		}
		if !allowed[strings.ToLower(path.Ext(k))] {
			return nil, specErr(ReasonBadGeneratedFiles)
		}
		content, ok := raw[k].(string)
		if !ok {
			return nil, specErr(ReasonBadGeneratedFiles)
		}
		total += len(content)
		out = append(out, [2]string{k, content})
	}
	if total > FilesBytesMax {
		return nil, specErr(ReasonOversizeFiles)
	}
	return out, nil
}

// validFileKey 檢查鍵為 witness/<name>：相對路徑、無 ".."、無絕對路徑、名稱非空。
func validFileKey(k string) bool {
	if !strings.HasPrefix(k, FilesPrefix) {
		return false
	}
	rest := k[len(FilesPrefix):]
	if rest == "" || strings.HasPrefix(rest, "/") {
		return false // 空名稱或以 "/" 開頭（絕對路徑）
	}
	for _, seg := range strings.Split(rest, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// scanHits 對 spec 內所有模型可控字串做金鑰掃描（§17.9-5）。
func scanHits(in Input, payload string, files [][2]string, targetSymbol string) bool {
	if in.SecretScan(payload) || in.SecretScan(targetSymbol) {
		return true
	}
	for _, kv := range files {
		if in.SecretScan(kv[1]) {
			return true
		}
	}
	for _, a := range stringList(in.Spec["assumptions"]) {
		if in.SecretScan(a) {
			return true
		}
	}
	for _, n := range stringList(in.Spec["learning_notes"]) {
		if in.SecretScan(n) {
			return true
		}
	}
	return false
}

// isD2D3 判斷 reachability 是否為 D2/D3（§17.9-6）。
func isD2D3(reachability string) bool {
	return reachability == "D2" || reachability == "D3"
}

// stringList 把 spec 欄位安全轉為 []string（缺欄或型別不符即空）。
func stringList(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// replaceNonce 依 §17.2 統一替換兩種 placeholder（HEX 先換，語意相同）。
func replaceNonce(s, nonce string) string {
	s = strings.ReplaceAll(s, noncePlaceholderHex, nonce)
	return strings.ReplaceAll(s, noncePlaceholder, nonce)
}

// assemble 組 RunRequest（§5.2／run_request.schema.json；全部欄位由政策決定，
// 欄位集閉合於 schema 的 additionalProperties:false）。
func assemble(in Input, tmpl *Template, files [][2]string, payload, kind, nonce string) map[string]any {
	fileMap := make(map[string]any, len(files))
	for _, kv := range files {
		fileMap[kv[0]] = replaceNonce(kv[1], nonce)
	}
	if len(fileMap) == 0 {
		fileMap = map[string]any{} // 空檔集維持 JSON object
	}
	return map[string]any{
		"run_id":  in.RunID,
		"kind":    kind,
		"image":   tmpl.Image, // digest 形式（assemble 前已檢查，見 compile 檢查）
		"files":   fileMap,
		"payload": replaceNonce(payload, nonce), // 以 docker cp 寫入 /aegis/payload.txt
		"mounts": []any{map[string]any{
			"src": "TARGET_SNAPSHOT", "dst": "/target", "readonly": true,
		}},
		"cmd": []any{"/aegis/entrypoint.py", "--template", tmpl.TemplateID},
		"service": map[string]any{
			"cmd": tmpl.ServiceCmd, "port": int64(tmpl.ServicePort), "wait_for": tmpl.WaitFor,
		},
		"network":     Network,
		"nonce":       nonce,
		"timeout_sec": int64(TimeoutSec),
		"caps": map[string]any{
			"cpus": CPUs, "mem": Mem, "pids": int64(PIDsLimit),
			"cap_drop": CapDrop, "no_new_privileges": true, "rootfs": "ro",
			"ulimit_nofile": int64(ULimitNF), "user": User,
		},
		"labels": map[string]any{
			"aegis.run_id": in.RunID, "aegis.snapshot_id": in.SnapshotID, "aegis.kind": kind,
		},
	}
}
