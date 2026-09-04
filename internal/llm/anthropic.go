package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/anthropics/anthropic-sdk-go/packages/param"
)

// AnthropicAdapter 是 anthropic 供應商的一級公民 adapter（SPEC §3.2、§18.3）。
// BYOK：金鑰由呼叫端在建構時傳入，adapter 只放進請求標頭，永不寫 log／報告（§23-6）。
type AnthropicAdapter struct {
	client anthropic.Client
}

// 確認 AnthropicAdapter 實作 Adapter 契約（§3.2）。
var _ Adapter = (*AnthropicAdapter)(nil)

// NewAnthropic 建構 anthropic adapter（§18.3 client）。
//
// apiKey：使用者自帶金鑰（BYOK，§3.2）；空字串時退回 SDK 的 ANTHROPIC_API_KEY
// 環境變數解析（§3.3 憑證解析優先序：環境變數 > keychain > 設定檔）。
// baseURL：測試／代理用注入點（option.WithBaseURL）；空字串表示官方端點。
// SDK 內建重試保留：WithMaxRetries(2)（429／5xx／連線錯誤指數退避，§18.3）。
// adapter 本身不加重試迴圈、不做任何 log（金鑰防洩，§23-6）。
func NewAnthropic(apiKey string, baseURL string) Adapter {
	opts := []option.RequestOption{option.WithMaxRetries(2)}
	if apiKey != "" {
		opts = append(opts, option.WithAPIKey(apiKey))
	}
	if baseURL != "" {
		opts = append(opts, option.WithBaseURL(baseURL))
	}
	return &AnthropicAdapter{client: anthropic.NewClient(opts...)}
}

// Provider 回傳供應商名（config 全域引用語法 <provider> 段，§3.2）。
func (a *AnthropicAdapter) Provider() string { return "anthropic" }

// Chat 執行一次 Messages API 呼叫（§18.3）。
//
// 錯誤分類只准 HTTP 狀態碼（§18.3、§23-4 閉集）：API 回應的錯誤以
// errors.As 取 *anthropic.Error.StatusCode 後包成 *Error；其餘錯誤
// （本地的參數錯誤、非 HTTP 的傳輸錯誤）原樣上拋、不做寬泛 catch-all。
func (a *AnthropicAdapter) Chat(ctx context.Context, req ChatRequest) (Response, error) {
	params, err := a.buildParams(req)
	if err != nil {
		// 本地參數錯誤（schema 不合法等）：尚未發出 HTTP 請求，不上 HTTP 狀態碼。
		return Response{}, err
	}

	if req.Stream {
		// 串流（prover 產 witness 檔案必串流，§17.10、§18.3）：逐事件消費，
		// 結束後以 message.Accumulate(stream.Current()) 累積出完整 Message
		//（Go SDK 無 GetFinalMessage()）；stream.Err() 必查（§18.3）。
		stream := a.client.Messages.NewStreaming(ctx, params)
		defer stream.Close()
		var msg anthropic.Message
		for stream.Next() {
			if err := msg.Accumulate(stream.Current()); err != nil {
				// 事件流本身解不動（非 HTTP 分類問題），原樣上拋。
				return Response{}, fmt.Errorf("llm: anthropic stream accumulate: %w", err)
			}
		}
		if err := stream.Err(); err != nil {
			return Response{}, classifyAnthropicError(err)
		}
		return mapMessage(msg), nil
	}

	resp, err := a.client.Messages.New(ctx, params)
	if err != nil {
		return Response{}, classifyAnthropicError(err)
	}
	return mapMessage(*resp), nil
}

// buildParams 把 ChatRequest 轉成 MessageNewParams（§18.3 各項細節）。
func (a *AnthropicAdapter) buildParams(req ChatRequest) (anthropic.MessageNewParams, error) {
	params := anthropic.MessageNewParams{
		Model: anthropic.Model(req.Model),
		// max_tokens：非串流 16000、串流 64000 起跳；呼叫端設更高則從高（§18.3）。
		MaxTokens: maxTokensFor(req),
		Messages:  toMessageParams(req.Messages),
	}

	// prompt caching：system prompt（靜態＋sink pack 知識）以 cache_control 打快取
	//（§18.3）。文字原樣送出，不塞時間戳／run id（整個 run 逐 byte 穩定）。
	if req.System != "" {
		params.System = []anthropic.TextBlockParam{{
			Text:         req.System,
			CacheControl: anthropic.NewCacheControlEphemeralParam(),
		}}
	}

	// thinking：5 系列一律 adaptive 形式（§18.3）。絕不傳 ThinkingConfigParamOfEnabled
	//（budget_tokens 形式，5 系列回 400，§23-5）。閘門以 model id 樣式判定，
	// 見 isFiveSeriesModel 的註解。
	if isFiveSeriesModel(req.Model) {
		params.Thinking = anthropic.ThinkingConfigParamUnion{
			OfAdaptive: &anthropic.ThinkingConfigAdaptiveParam{},
		}
	}

	// effort 深度：API output_config.effort（§18.3；欄位名已對官方 SDK
	// MessageNewParams.OutputConfig.Effort 驗證，無出入）。非空值原樣映射
	//（呼叫端契約：prover xhigh、reviewer/triager high、recon low、reporter medium）。
	if req.Effort != "" {
		params.OutputConfig = anthropic.OutputConfigParam{
			Effort: anthropic.OutputConfigEffort(req.Effort),
		}
	}

	tools, err := buildToolParams(req.Tools)
	if err != nil {
		return anthropic.MessageNewParams{}, err
	}
	params.Tools = tools

	return params, nil
}

// maxTokensFor 計算 max_tokens：非串流 16000、串流 64000 起跳（§18.3），
// 呼叫端設更高則取呼叫端的值。
func maxTokensFor(req ChatRequest) int64 {
	floor := 16000
	if req.Stream {
		floor = 64000
	}
	if req.MaxTokens > floor {
		return int64(req.MaxTokens)
	}
	return int64(floor)
}

// isFiveSeriesModel 判定是否 5 系列（決定要不要開 adaptive thinking，§18.3「5 系列一律」）。
//
// 閘門（heuristic，僅供 thinking 開關之用）：在 model id（小寫）中找版本主號——
//   - 優先看「claude」後一段（新式命名 claude-5-sonnet）；
//   - 其次看 family（sonnet／opus／haiku）後一段（claude-sonnet-5、
//     claude-sonnet-5-20260101）。
//
// 例："claude-sonnet-5"、"claude-opus-5-20260101"、"claude-5-sonnet" → true；
// "claude-sonnet-4-5"、"claude-opus-4-8"、"claude-3-5-sonnet"（3.5 老命名，family 後無版本段）→ false。
// 非 5 系列不設 thinking：§23-5 禁止 budget 形式，故 v1 對 4 系列一律不打 thinking 參數。
func isFiveSeriesModel(model string) bool {
	parts := strings.Split(strings.ToLower(model), "-")
	for i, p := range parts {
		isClaude := p == "claude"
		isFamily := p == "sonnet" || p == "opus" || p == "haiku"
		if (!isClaude && !isFamily) || i+1 >= len(parts) {
			continue
		}
		if majorVersion(parts[i+1]) == 5 {
			return true
		}
	}
	return false
}

// majorVersion 取段落的前導數字（"5"→5、"5x"→5、"20260101"→20260101；無數字→0）。
func majorVersion(seg string) int {
	n := 0
	for i := 0; i < len(seg) && seg[i] >= '0' && seg[i] <= '9'; i++ {
		n = n*10 + int(seg[i]-'0')
	}
	return n
}

// buildToolParams 把 ToolDef（InputSchema 為 schemas/ 載入的原始 JSON schema bytes）
// 轉成 ToolParam。以 param.SetJSON 把 schema bytes 原樣（verbatim）作為
// input_schema 送出——不 parse 成 struct、不做 struct-tag 生成，schemas/ 是唯一真源
// （§18.3、§23-11）；這也保證工具定義逐 byte 穩定（prompt caching 前提，§18.3）。
func buildToolParams(defs []ToolDef) ([]anthropic.ToolUnionParam, error) {
	if len(defs) == 0 {
		return nil, nil
	}
	out := make([]anthropic.ToolUnionParam, 0, len(defs))
	for _, d := range defs {
		trimmed := bytes.TrimSpace(d.InputSchema)
		if !json.Valid(trimmed) || !bytes.HasPrefix(trimmed, []byte("{")) {
			return nil, fmt.Errorf("llm: tool %q 的 InputSchema 不是合法的 JSON schema 物件（真源為 schemas/，§23-11）", d.Name)
		}
		var schema anthropic.ToolInputSchemaParam
		param.SetJSON(trimmed, &schema)
		tp := anthropic.ToolParam{Name: d.Name, InputSchema: schema}
		if d.Description != "" {
			tp.Description = anthropic.String(d.Description)
		}
		out = append(out, anthropic.ToolUnionParam{OfTool: &tp})
	}
	return out, nil
}

// toMessageParams 把對話歷史映射成 MessageParam（§18.1 工具迴圈回填）：
// text → NewTextBlock、tool_use → NewToolUseBlock（raw input JSON 原樣回傳）、
// tool_result → NewToolResultBlock。角色只有 user／assistant（閉集）；
// operator 回饋由呼叫端包成 user 訊息（§18.3）。不做 assistant prefill（§23-5）。
func toMessageParams(msgs []Message) []anthropic.MessageParam {
	out := make([]anthropic.MessageParam, 0, len(msgs))
	for _, m := range msgs {
		blocks := make([]anthropic.ContentBlockParamUnion, 0, len(m.Content))
		for _, b := range m.Content {
			switch b.Type {
			case "text":
				blocks = append(blocks, anthropic.NewTextBlock(b.Text))
			case "tool_use":
				input := b.ToolUse.Input
				if len(bytes.TrimSpace(input)) == 0 {
					input = []byte("{}")
				}
				blocks = append(blocks, anthropic.NewToolUseBlock(b.ToolUse.ID, json.RawMessage(input), b.ToolUse.Name))
			case "tool_result":
				blocks = append(blocks, anthropic.NewToolResultBlock(b.ToolResult.ID, b.ToolResult.Content, b.ToolResult.IsError))
			}
		}
		if m.Role == "assistant" {
			out = append(out, anthropic.NewAssistantMessage(blocks...))
		} else {
			out = append(out, anthropic.NewUserMessage(blocks...))
		}
	}
	return out
}

// mapMessage 把 SDK 的 Message 映射回閉集 Response（§3.2、§18.3）。
// stop_reason 映射到閉集：end_turn／tool_use／max_tokens／refusal，
// 其餘（stop_sequence、pause_turn、model_context_window_exceeded）→ other（§23-4）。
// 內容塊只保留閉集（text／tool_use）；thinking 等閉集外塊略過——Adapter 契約
// 的 ContentBlock 無此型別（§3.2 閉集原則）。
func mapMessage(m anthropic.Message) Response {
	resp := Response{Model: string(m.Model)}
	switch m.StopReason {
	case anthropic.StopReasonEndTurn:
		resp.StopReason = StopEndTurn
	case anthropic.StopReasonToolUse:
		resp.StopReason = StopToolUse
	case anthropic.StopReasonMaxTokens:
		resp.StopReason = StopMaxTokens
	case anthropic.StopReasonRefusal:
		resp.StopReason = StopRefusal
		// refusal 訊號：StopDetails.Category（如 "cyber"）供 §3.1 處理鏈使用（§18.3）。
		resp.RefusalCategory = string(m.StopDetails.Category)
	default:
		resp.StopReason = StopOther
	}

	resp.Usage = Usage{
		InputTokens:         m.Usage.InputTokens,
		OutputTokens:        m.Usage.OutputTokens,
		CacheReadTokens:     m.Usage.CacheReadInputTokens,
		CacheCreationTokens: m.Usage.CacheCreationInputTokens,
	}

	for _, b := range m.Content {
		switch b.Type {
		case "text":
			resp.Content = append(resp.Content, ContentBlock{Type: "text", Text: b.Text})
		case "tool_use":
			// 提交工具模式：以 raw JSON 反序列化後綁 schema 驗證（§18.3）。
			// v1.70.1 的 ContentBlockUnion.Input 即為 json.RawMessage
			//（規格書寫的 ToolUseBlock.JSON.Input.Raw() 等價；空值退回 JSON raw，再退 "{}"）。
			input := []byte(b.Input)
			if len(bytes.TrimSpace(input)) == 0 && b.JSON.Input.Valid() {
				input = []byte(b.JSON.Input.Raw())
			}
			if len(bytes.TrimSpace(input)) == 0 {
				input = []byte("{}")
			}
			resp.Content = append(resp.Content, ContentBlock{
				Type: "tool_use",
				ToolUse: &ToolUse{
					ID:    b.ID,
					Name:  b.Name,
					Input: input,
				},
			})
		}
	}
	return resp
}

// classifyAnthropicError 只用 HTTP 狀態碼分類（§18.3，不得寬泛 catch-all）：
// *anthropic.Error → *Error{StatusCode, Body(截尾)}，交由 orchestrator 以
// StatusCode 分流（429／5xx 已由 SDK 內建退避重試耗盡後至此，記 env；4xx 不重試，
// 記 ENV_ERROR）。非 API 錯誤（連線錯誤、context 取消等）原樣上拋，不偽裝成狀態碼。
// Body 只含 API 回應體（截尾 2KiB），不含金鑰（§23-6）。
func classifyAnthropicError(err error) error {
	var apiErr *anthropic.Error
	if errors.As(err, &apiErr) {
		return &Error{
			StatusCode: apiErr.StatusCode,
			Body:       truncateBody(apiErr.RawJSON()),
		}
	}
	return err
}

// truncateBody 把錯誤回應體截到 2KiB（rune 邊界安全），供 *Error.Body 除錯用（§18.3）。
func truncateBody(s string) string {
	const max = 2048
	if len(s) <= max {
		return s
	}
	cut := s[:max]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut
}
