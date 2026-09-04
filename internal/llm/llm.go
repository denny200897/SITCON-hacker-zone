// Package llm 是供應商抽象層（SPEC §3.2）：所有 LLM 存取統一經 Adapter 介面。
// 使用者 BYOK——金鑰只在 host 端 adapter 內使用，永不進沙箱、報告、aegis.toml（§23-6）。
//
// 閉集原則（§23-4）：role、stop_reason、錯誤分類皆為閉集；供應商差異只體現在
// 各 adapter 內部，orchestrator 只看本包型別。
package llm

import "context"

// Role 是 §3.1 角色閉集；每角色的 effort／工具白名單由 orchestrator 決定（§18.1）。
type Role string

const (
	RoleRecon    Role = "recon"
	RoleReviewer Role = "reviewer"
	RoleTriager  Role = "triager"
	RoleProver   Role = "prover"
	RoleReporter Role = "reporter"
)

// StopReason 是回應終止原因閉集（§18.3 refusal 偵測、§18.1 tool loop 驅動）。
type StopReason string

const (
	StopEndTurn  StopReason = "end_turn"
	StopToolUse  StopReason = "tool_use"
	StopMaxTokens StopReason = "max_tokens"
	StopRefusal   StopReason = "refusal"
	StopOther     StopReason = "other"
)

// Message 是對話歷史中的一則訊息。Content 為內容塊序列
//（文字、tool_use、tool_result——見 ContentBlock）。
type Message struct {
	Role    string // "user" | "assistant"（閉集；operator 回饋以 user 訊息包 <operator> 標記，§18.3）
	Content []ContentBlock
}

// ContentBlock 是訊息內容塊（閉集：text / tool_use / tool_result）。
type ContentBlock struct {
	Type string // "text" | "tool_use" | "tool_result"
	// Text：type=text 的文字內容。
	Text string
	// ToolUse：type=tool_use 時的呼叫（ID／Name／Input 為模型提交的原始 JSON）。
	ToolUse *ToolUse
	// ToolResult：type=tool_result 時的結果（ID 對應被回填的 ToolUse.ID）。
	ToolResult *ToolResult
}

// ToolUse 是模型發起的工具呼叫。
type ToolUse struct {
	ID    string
	Name  string
	Input []byte // 原始 JSON（提交工具模式的 schema 驗證以 raw bytes 為準，§18.3）
}

// ToolResult 是 host 端工具執行結果（回填用）。
type ToolResult struct {
	ID      string
	Content string
	IsError bool
}

// ToolDef 是交給模型的工具定義；InputSchema 為 schemas/ 載入的原始 JSON schema
//（真源在 schemas/，不得 struct-tag 生成第二真源，§18.1、§23-11）。
type ToolDef struct {
	Name        string
	Description string
	InputSchema []byte // JSON schema 物件
}

// ChatRequest 是一次 chat 呼叫的輸入。
type ChatRequest struct {
	Role    Role
	Model   string // 不帶 provider 前綴的 model id（全域引用語法 <provider>/<model-id> 由 orchestrator 拆分，§3.2）
	System  string // system prompt（anthropic adapter 加 cache_control 打快取，§18.3）
	Messages []Message
	Tools   []ToolDef
	// MaxTokens：非串流 16000、串流 64000 起跳（§18.3）。
	MaxTokens int
	// Stream：prover 產 witness 檔案必串流（§17.10、§18.3）。
	Stream bool
	// Effort 是角色深度（§18.3：prover xhigh、reviewer/triager high、recon low、
	// reporter medium）。端點不支援時 adapter 顯式降級（能力缺失不影響正確性，§3.2）。
	Effort string
}

// Usage 是單次呼叫的計量（成本不預估，§23-7；僅記錄供報告）。
type Usage struct {
	InputTokens         int64
	OutputTokens        int64
	CacheReadTokens     int64
	CacheCreationTokens int64
}

// Response 是一次 chat 呼叫的輸出。
type Response struct {
	StopReason StopReason
	Content    []ContentBlock
	Usage      Usage
	// RefusalCategory：StopRefusal 時供應商給的類別（anthropic 為 StopDetails.Category，
	// 如 "cyber"；openai-compat 無訊號則為空）（§18.3、§3.2）。
	RefusalCategory string
	// Model：實際回應的模型（供 evidence 記錄）。
	Model string
}

// Adapter 是供應商介面（§3.2）。實作：anthropic（一級公民）、openai-compat（通用轉接）。
type Adapter interface {
	// Chat 執行一次 LLM 呼叫。錯誤分類只准 HTTP 狀態碼（§18.3）：
	// 回傳 *APIError 供 orchestrator 以 StatusCode 分類（429/5xx 重試耗盡記 env、
	// 4xx 不重試記 ENV_ERROR）。
	Chat(ctx context.Context, req ChatRequest) (Response, error)

	// Provider 回傳供應商名（config 全域引用語法的 <provider> 段，§3.2）。
	Provider() string
}

// Error 是供應商 API 錯誤（§18.3 錯誤分類：只准 HTTP 狀態碼）。
type Error struct {
	StatusCode int
	Body       string // 截尾的回應體（除錯用；不含金鑰）
}

func (e *Error) Error() string {
	return "llm: HTTP " + itoa(e.StatusCode) + "：" + e.Body
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [4]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}