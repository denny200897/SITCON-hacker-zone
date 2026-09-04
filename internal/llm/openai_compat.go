// OpenAICompatAdapter 是 openai-compat 供應商轉接器（SPEC §3.2 第二列）：
// 涵蓋 OpenAI / OpenRouter / vLLM / Ollama / Gemini 相容端點——使用者自訂名稱
// + base_url + 金鑰（BYOK，§3.3；金鑰由呼叫端經建構子注入，永不落盤、永不記錄，§23-6）。
//
// 依 §23-11：不引入第三方 openai 客戶端 library，以標準庫 net/http + encoding/json
// 手刻 §3.2 定義的最小介面；工具 schema 以 schemas/ 載入的原始 bytes 為真源，
// 原樣（verbatim）序列化，不用 struct-tag 生成第二真源。
//
// 能力降級（§3.2「能力缺失不影響正確性」）：
//   - refusal_signal：openai-compat 無訊號——空回應視同該次嘗試失敗，回
//     StopRefusal／RefusalCategory="empty_response"（§18.3 降級 note）。
//   - effort（reasoning_effort）：以 §18.3 的顯式降級——首次呼叫帶上欄位；若端點
//     回 400 且錯誤體提及 reasoning 欄位，重試一次（不帶欄位）並在本 adapter
//     實例上記住降級（capability probe），後續呼叫直接省略。
//   - stream：v1 openai-compat 一律非串流（stream: false）；ChatRequest.Stream
//     為真時以非串流降級，正確性不受影響（串流為 anthropic 一級能力，§3.2）。
//     【ASK 回報】spec §17.10 要求 prover 必串流，但未定義 openai-compat 的串流
//     行為；此處採「降級為非串流」而非報錯，如需嚴格報錯請改 Chat 內註解處。
//
// 錯誤分類（§18.3，只准 HTTP 狀態碼、不得寬泛 catch-all）：非 2xx 一律回
// *Error{StatusCode, Body}，由 orchestrator 依狀態碼分類（429/5xx 可重試、
// 4xx 不重試）；傳輸層錯誤（連線、context 取消、JSON 解析）原樣回傳，不做分類。
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// 錯誤體截尾上限（§18.2 回饋有界的精神：除錯輸出必須截尾；金鑰另外遮蔽）。
const openAIErrBodyMax = 4096

// 預設 client timeout：LLM 非串流呼叫（16000 tokens 起跳，§18.3）可能長達數分鐘，
// 取 300s 為上界；context 取消仍可更早中止（見 Chat）。
const openAITimeout = 300 * time.Second

// OpenAICompatAdapter 實作 Adapter（§3.2）。
type OpenAICompatAdapter struct {
	// provider 是使用者自訂供應商名（全域引用語法 <provider>/<model-id> 的
	// <provider> 段，如 "my-ollama"，§3.2）。
	provider string
	// endpoint = <base URL 去尾斜線>/chat/completions；base_url 由使用者提供
	//（含 /v1 等版本段與否由使用者決定，此處僅拼接路徑）。
	endpoint string
	// apiKey 由呼叫端注入（BYOK，§3.3）；只放進 Authorization header，
	// 永不寫入任何 log／evidence／錯誤訊息（§23-6）。
	apiKey string
	// defaultModel 是 req.Model 缺省時的 model id（不含 provider 前綴）。
	defaultModel string

	client *http.Client

	// effortUnsupported 是 capability probe 的降級記憶（§3.2 能力矩陣）：
	// 端點拒收 reasoning_effort 後，本實例後續呼叫一律省略該欄位。
	effortUnsupported atomic.Bool
}

// NewOpenAICompat 建立一個 openai-compat 轉接器。provider 為使用者自訂名稱
// （Provider() 回傳值）；baseURL 如 "https://api.openai.com/v1"；apiKey 為使用者
// 自帶金鑰；defaultModel 在 req.Model 為空時使用。
func NewOpenAICompat(provider, baseURL, apiKey, defaultModel string) *OpenAICompatAdapter {
	return &OpenAICompatAdapter{
		provider:     provider,
		endpoint:     strings.TrimRight(baseURL, "/") + "/chat/completions",
		apiKey:       apiKey,
		defaultModel: defaultModel,
		client:       &http.Client{Timeout: openAITimeout},
	}
}

// Provider 回傳使用者自訂供應商名（§3.2 模型引用語法）。
func (a *OpenAICompatAdapter) Provider() string { return a.provider }

// ---- 請求／回應的線格式（OpenAI chat completions 最小子集）----

type openAIMessage struct {
	Role       string           `json:"role"`
	Content    string           `json:"content,omitempty"`
	ToolCalls  []openAIToolCall `json:"tool_calls,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
}

type openAIToolCall struct {
	// ID 為端點給的 call id；Type 固定 "function"。
	ID   string         `json:"id"`
	Type string         `json:"type"`
	Func openAIFuncCall `json:"function"`
}

type openAIFuncCall struct {
	Name string `json:"name"`
	// Arguments 是 JSON 字串（OpenAI 格式）：llm.ToolUse.Input 的原始 bytes
	// 直接放進字串，不做重組，供 §18.3「raw bytes 為準」的 schema 驗證。
	Arguments string `json:"arguments"`
}

type openAITool struct {
	Type     string         `json:"type"`
	Function openAIToolFunc `json:"function"`
}

type openAIToolFunc struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Parameters 以 json.RawMessage 原樣內嵌 schemas/ 載入的 schema bytes
	//（verbatim，不重組不生成，§23-11）。
	Parameters json.RawMessage `json:"parameters,omitempty"`
}

type openAIRequest struct {
	Model    string          `json:"model"`
	Messages []openAIMessage `json:"messages"`
	Tools    []openAITool    `json:"tools,omitempty"`
	// MaxTokens：採 "max_tokens" 名稱（vLLM／Ollama／OpenRouter 等 compat 端點
	// 皆支援）；較新的 o 系列端點要 "max_completion_tokens"——v1 擇一取廣泛相容的
	// max_tokens，遇此類端點由使用者以 base_url／model 搭配解決（此決策已記錄）。
	MaxTokens int `json:"max_tokens,omitempty"`
	// ReasoningEffort 對應 §18.3 的 effort 深度；端點不支援時顯式降級省略。
	ReasoningEffort string `json:"reasoning_effort,omitempty"`
	// Stream：v1 一律非串流（見檔頭降級說明）。
	Stream bool `json:"stream"`
}

type openAIResponse struct {
	Model   string         `json:"model"`
	Choices []openAIChoice `json:"choices"`
	Usage   *openAIUsage   `json:"usage,omitempty"`
}

type openAIChoice struct {
	Message      openAIMessage `json:"message"`
	FinishReason string        `json:"finish_reason"`
}

type openAIUsage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	// PromptTokensDetails.CachedTokens → CacheReadTokens（prompt caching 視端點，
	// §3.2 能力矩陣）；CacheCreationTokens 無對應訊號，恆為 0。
	PromptTokensDetails *struct {
		CachedTokens int64 `json:"cached_tokens"`
	} `json:"prompt_tokens_details,omitempty"`
}

// ---- Adapter.Chat ----

// Chat 執行一次 POST {base}/chat/completions（§3.2）。
func (a *OpenAICompatAdapter) Chat(ctx context.Context, req ChatRequest) (Response, error) {
	model := req.Model
	if model == "" {
		model = a.defaultModel
	}

	msgs, err := a.buildMessages(req)
	if err != nil {
		return Response{}, err
	}

	body := openAIRequest{
		Model:    model,
		Messages: msgs,
		Stream:   false, // v1 非串流（檔頭降級說明）
	}
	if req.MaxTokens > 0 {
		body.MaxTokens = req.MaxTokens
	}
	tools := make([]openAITool, 0, len(req.Tools))
	for _, t := range req.Tools {
		tools = append(tools, openAITool{
			Type: "function",
			Function: openAIToolFunc{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  json.RawMessage(t.InputSchema), // verbatim
			},
		})
	}
	if len(tools) > 0 {
		body.Tools = tools
	}
	// effort 能力探測（§3.2 顯式降級）：先假設端點支援而帶上欄位；400 提及
	// reasoning 時重試一次並記住降級（見下方 400 分支）。
	if req.Effort != "" && !a.effortUnsupported.Load() {
		body.ReasoningEffort = req.Effort
	}

	payload, err := json.Marshal(&body)
	if err != nil {
		return Response{}, fmt.Errorf("llm: openai-compat 請求編碼失敗：%w", err)
	}

	status, raw, err := a.postWithRetry(ctx, payload)
	if err != nil {
		// 傳輸層錯誤／context 取消：非 HTTP 狀態碼，不做錯誤分類（§18.3），
		// 也不自動重試（簡單優先）。
		return Response{}, err
	}

	if status < 200 || status > 299 {
		errBody := a.redactBody(raw)
		// effort 顯式降級（§3.2、§18.3）：僅當 400 且錯誤體提及 reasoning 欄位時，
		// 重試「一次」（不帶 reasoning_effort），並在本實例記住降級。
		if status == http.StatusBadRequest && body.ReasoningEffort != "" &&
			!a.effortUnsupported.Load() && openAIMentionsEffort(errBody) {
			a.effortUnsupported.Store(true)
			body.ReasoningEffort = ""
			payload2, mErr := json.Marshal(&body)
			if mErr != nil {
				return Response{}, fmt.Errorf("llm: openai-compat 請求編碼失敗：%w", mErr)
			}
			status, raw, err = a.postWithRetry(ctx, payload2)
			if err != nil {
				return Response{}, err
			}
			if status < 200 || status > 299 {
				return Response{}, &Error{StatusCode: status, Body: a.redactBody(raw)}
			}
		} else {
			// 錯誤分類只看 HTTP 狀態碼（§18.3）：統一回 *Error。
			return Response{}, &Error{StatusCode: status, Body: errBody}
		}
	}

	var out openAIResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return Response{}, fmt.Errorf("llm: openai-compat 回應解析失敗：%w", err)
	}

	resp := Response{Model: out.Model}
	if out.Usage != nil {
		resp.Usage = Usage{
			InputTokens:  out.Usage.PromptTokens,
			OutputTokens: out.Usage.CompletionTokens,
		}
		// prompt caching 視端點（§3.2 能力矩陣）：訊號存在才取，缺省 0。
		if d := out.Usage.PromptTokensDetails; d != nil {
			resp.Usage.CacheReadTokens = d.CachedTokens
		}
	}

	// 空回應 → 該次嘗試失敗（§18.3 降級 note：openai-compat 無 refusal 訊號，
	// 以輸出內容判讀；RefusalCategory 無供應商訊號，給內部標記 "empty_response"）。
	if len(out.Choices) == 0 {
		resp.StopReason = StopRefusal
		resp.RefusalCategory = "empty_response"
		return resp, nil
	}

	choice := out.Choices[0]
	if choice.Message.Content != "" {
		resp.Content = append(resp.Content, ContentBlock{Type: "text", Text: choice.Message.Content})
	}
	for _, tc := range choice.Message.ToolCalls {
		resp.Content = append(resp.Content, ContentBlock{
			Type: "tool_use",
			ToolUse: &ToolUse{
				ID:    tc.ID,
				Name:  tc.Func.Name,
				Input: []byte(tc.Func.Arguments), // JSON 字串原樣保留為 raw bytes（§18.3）
			},
		})
	}

	if len(resp.Content) == 0 {
		resp.StopReason = StopRefusal
		resp.RefusalCategory = "empty_response"
		return resp, nil
	}
	resp.StopReason = mapFinishReason(choice.FinishReason)
	return resp, nil
}

// buildMessages 把 llm.ChatRequest 訊息序列映射成 OpenAI messages 陣列：
// system → 首則 role "system"；text／tool_use 併入所屬 role 的訊息；
// tool_result → 獨立 role "tool" 訊息（帶 tool_call_id），並保持 OpenAI 要求的
// 「tool 訊息緊接在帶 tool_calls 的 assistant 訊息之後」順序。
func (a *OpenAICompatAdapter) buildMessages(req ChatRequest) ([]openAIMessage, error) {
	msgs := make([]openAIMessage, 0, len(req.Messages)+1)
	if req.System != "" {
		msgs = append(msgs, openAIMessage{Role: "system", Content: req.System})
	}
	for _, m := range req.Messages {
		var texts []string
		var calls []openAIToolCall
		for _, b := range m.Content {
			switch b.Type {
			case "text":
				texts = append(texts, b.Text)
			case "tool_use":
				if b.ToolUse == nil {
					return nil, fmt.Errorf("llm: openai-compat tool_use 區塊缺 ToolUse（role=%s）", m.Role)
				}
				calls = append(calls, openAIToolCall{
					ID:   b.ToolUse.ID,
					Type: "function",
					Func: openAIFuncCall{
						Name:      b.ToolUse.Name,
						Arguments: string(b.ToolUse.Input), // 原始 JSON 字串
					},
				})
			case "tool_result":
				if b.ToolResult == nil {
					return nil, fmt.Errorf("llm: openai-compat tool_result 區塊缺 ToolResult（role=%s）", m.Role)
				}
				// 先沖出累積文字，讓 tool 訊息緊貼前一則 assistant tool_calls。
				if len(texts) > 0 {
					msgs = append(msgs, openAIMessage{Role: m.Role, Content: strings.Join(texts, "\n")})
					texts = nil
				}
				// IsError 在 OpenAI tool 訊息無原生欄位：內容原樣回填（不做加工），
				// 由模型自行判讀（閉集不擴充，§23-4）。
				msgs = append(msgs, openAIMessage{
					Role:       "tool",
					Content:    b.ToolResult.Content,
					ToolCallID: b.ToolResult.ID,
				})
			default:
				// 閉集外型別：防禦性拒收，不猜測。
				return nil, fmt.Errorf("llm: openai-compat 未知的內容塊型別 %q", b.Type)
			}
		}
		if len(texts) > 0 || len(calls) > 0 {
			am := openAIMessage{Role: m.Role, ToolCalls: calls}
			if len(texts) > 0 {
				am.Content = strings.Join(texts, "\n")
			}
			msgs = append(msgs, am)
		}
	}
	return msgs, nil
}

// post 送出一次 HTTP 請求，回傳（狀態碼, 原始回應體, error）。
// context 取消／逾時會中止請求（NewRequestWithContext）；client 層另有 300s 上界。
func (a *OpenAICompatAdapter) post(ctx context.Context, payload []byte) (int, []byte, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, fmt.Errorf("llm: openai-compat 建構請求失敗：%w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// 金鑰只進 header（BYOK，§23-6）；不設定任何會洩漏金鑰的 log hook。
	if a.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+a.apiKey)
	}
	httpResp, err := a.client.Do(httpReq)
	if err != nil {
		// 保留 ctx.Err() 的可判讀性（errors.Is(err, context.Canceled) 成立）。
		return 0, nil, err
	}
	defer httpResp.Body.Close()
	raw, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("llm: openai-compat 讀取回應失敗：%w", err)
	}
	return httpResp.StatusCode, raw, nil
}

// postWithRetry retries only transient HTTP failures. 4xx responses other than
// 429 are returned immediately, preserving the provider's deterministic error
// classification; context cancellation always wins over the backoff.
func (a *OpenAICompatAdapter) postWithRetry(ctx context.Context, payload []byte) (int, []byte, error) {
	for attempt := 0; attempt < 3; attempt++ {
		status, raw, err := a.post(ctx, payload)
		if err != nil {
			return status, raw, err
		}
		if status != http.StatusTooManyRequests && (status < 500 || status > 599) {
			return status, raw, nil
		}
		if attempt == 2 {
			return status, raw, nil
		}
		t := time.NewTimer(time.Duration(50*(attempt+1)) * time.Millisecond)
		select {
		case <-ctx.Done():
			t.Stop()
			return 0, nil, ctx.Err()
		case <-t.C:
		}
	}
	return 0, nil, fmt.Errorf("llm: openai-compat retry state invalid")
}

// redactBody 把非 2xx 回應體做成 *Error.Body：先遮蔽金鑰（防供應商把 header
// 原文 echo 回來，§23-6），再截尾至 openAIErrBodyMax。
func (a *OpenAICompatAdapter) redactBody(raw []byte) string {
	s := string(raw)
	if a.apiKey != "" {
		s = strings.ReplaceAll(s, a.apiKey, "[redacted]")
	}
	if len(s) > openAIErrBodyMax {
		s = s[:openAIErrBodyMax] + "…（截尾）"
	}
	return s
}

// openAIMentionsEffort 是 effort 能力探測的 heuristic：400 錯誤體提及 reasoning
// 欄位才視為「端點不支援」，避免把其他 400（schema／驗證錯誤）誤判成降級。
func openAIMentionsEffort(body string) bool {
	l := strings.ToLower(body)
	return strings.Contains(l, "reasoning_effort") || strings.Contains(l, "reasoning")
}

// mapFinishReason 把 finish_reason 映射進 StopReason 閉集（§23-4）：
// tool_calls→StopToolUse、stop→StopEndTurn、length→StopMaxTokens，
// 其他（含 content_filter 等 compat 端點自創值）一律 StopOther。
func mapFinishReason(s string) StopReason {
	switch s {
	case "tool_calls":
		return StopToolUse
	case "stop":
		return StopEndTurn
	case "length":
		return StopMaxTokens
	default:
		return StopOther
	}
}
