// runtime.go：AgentRuntime tool loop（§18.1）。
// 手寫迴圈（不用 SDK toolrunner）：StopReason == tool_use 時逐塊過閘、執行、
// 以 tool_result 回填 user 訊息後續呼叫；非 tool_use 即回傳終態回應。
// 迴圈上限 MaxTurns 由呼叫端設定，防無界循環（harness 側邊界，非模型控制）。
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aegis-dev/aegis/internal/llm"
)

// unmarshalStrictJSON 解 JSON（欄位不嚴格，但需合法）。
func unmarshalStrictJSON(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	return dec.Decode(v)
}

// jsonMarshal 序列化（縮排不必要；schema 傳輸用原樣）。
func jsonMarshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("agent: 序列化 schema: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// MaxTurns 預設迴圈上限（單一 session 內 tool round 數；超出歸 harness 錯誤）。
const MaxTurns = 32

// MaxTurnsExceededError 是迴圈逾限（呼叫端歸 harness 失敗）。
var MaxTurnsExceededError = errors.New("agent: tool loop 超過回合上限")

// Runtime 是單一 session 的 tool loop。
type Runtime struct {
	Adapter  llm.Adapter
	Tools    *ToolRegistry
	MaxTurns int
}

// Run 執行 tool loop 至終態（非 tool_use 回應或 submit 被核可）。
// 回傳最終回應與完整對話歷史（含本輪所有 assistant／tool_result 往返——呼叫端
// 據此維持跨輪 session 連續性）；回合數耗盡回 MaxTurnsExceededError。
func (rt *Runtime) Run(ctx context.Context, req llm.ChatRequest) (llm.Response, []llm.Message, error) {
	if rt.MaxTurns < 1 {
		return llm.Response{}, nil, MaxTurnsExceededError
	}
	history := make([]llm.Message, len(req.Messages))
	copy(history, req.Messages)
	req.Messages = history

	for turn := 0; turn < rt.MaxTurns; turn++ {
		resp, err := rt.Adapter.Chat(ctx, req)
		if err != nil {
			return llm.Response{}, history, err
		}
		if resp.StopReason != llm.StopToolUse {
			return resp, history, nil
		}

		// 本輪 assistant 文字（submit 的三行 preamble 驗證用）。
		text := ""
		for _, b := range resp.Content {
			if b.Type == "text" {
				text += b.Text
			}
		}

		// 逐 tool_use 過閘執行，包成 tool_result 回填（§18.1）。
		var results []llm.ContentBlock
		for _, block := range resp.Content {
			if block.Type != "tool_use" || block.ToolUse == nil {
				continue
			}
			out := rt.Tools.Execute(ctx, req.Role, block.ToolUse.Name, block.ToolUse.Input, text)
			results = append(results, llm.ContentBlock{
				Type:       "tool_result",
				ToolResult: &llm.ToolResult{ID: block.ToolUse.ID, Content: out.Content, IsError: out.IsError},
			})
		}
		history = append(history,
			llm.Message{Role: "assistant", Content: resp.Content},
			llm.Message{Role: "user", Content: results})
		req.Messages = history // append 可能重新配置；每次都同步回 req
	}
	return llm.Response{}, history, MaxTurnsExceededError
}

// NewToolDefs 由 schemas/tools.schema.json 的 definitions 組 ToolDef 集合
//（真源在 schemas/；僅取該 role 白名單內的工具，§18.1）。
// toolsSchemaBytes 是 tools.schema.json 的原始內容；由呼叫端載入（不得
// struct-tag 生成，§23-11）。
func NewToolDefs(role llm.Role, toolsSchema []byte, witnessSpecSchema []byte, descriptions map[string]string) ([]llm.ToolDef, error) {
	var defs struct {
		Definitions map[string]any `json:"definitions"`
	}
	if err := unmarshalStrictJSON(toolsSchema, &defs); err != nil {
		return nil, fmt.Errorf("agent: 解析 tools schema: %w", err)
	}
	var spec any
	if err := unmarshalStrictJSON(witnessSpecSchema, &spec); err != nil {
		return nil, fmt.Errorf("agent: 解析 witness_spec schema: %w", err)
	}

	var out []llm.ToolDef
	for _, name := range Whitelist[role] {
		desc := descriptions[name]
		switch {
		case name == "submit_witness_spec":
			// 提交工具的輸入即 WitnessSpec；schema 真源是 witness_spec.schema.json。
			raw, err := jsonMarshal(spec)
			if err != nil {
				return nil, err
			}
			out = append(out, llm.ToolDef{Name: name, Description: desc, InputSchema: raw})
		default:
			schema, ok := defs.Definitions[name]
			if !ok {
				return nil, fmt.Errorf("agent: tools schema 缺 definition %q", name)
			}
			raw, err := jsonMarshal(schema)
			if err != nil {
				return nil, err
			}
			out = append(out, llm.ToolDef{Name: name, Description: desc, InputSchema: raw})
		}
	}
	return out, nil
}