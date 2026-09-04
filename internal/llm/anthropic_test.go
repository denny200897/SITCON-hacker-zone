package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// 本檔所有測試僅以 httptest server 搭配 adapter 的 baseURL 注入點（§18.3
// option.WithBaseURL）運作：零網路、零真實 API 呼叫。斷言聚焦：
//
//   - 請求形狀（§18.3）：adaptive thinking（絕無 budget_tokens 形式，§23-5）、
//     output_config.effort、system cache_control、工具 schema 以 schemas/ 原始 bytes
//     逐 byte 送出（§23-11）、max_tokens 起跳值（非串流 16000／串流 64000）。
//   - 回應映射（閉集，§23-4）：stop_reason 五值、refusal category、tool_use raw input。
//   - 錯誤分類（只准 HTTP 狀態碼，§18.3）：429／400 → *Error{StatusCode, Body}；
//     400 不重試、429 走 SDK 內建重試（WithMaxRetries(2)）。
//   - 串流（§18.3）：SSE 事件 → message.Accumulate → 完整 Message。

// capture 記錄測試伺服器收到的每筆請求（body／路徑／標頭）。
// 依 §23-1 harness 序列執行，但 httptest 的 handler 跑在自己的 goroutine，
// 故以 mutex 保護。
type capture struct {
	mu     sync.Mutex
	bodies []string
	paths  []string
	keys   []string
}

func (c *capture) record(r *http.Request) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bodies = append(c.bodies, string(body))
	c.paths = append(c.paths, r.URL.Path)
	c.keys = append(c.keys, r.Header.Get("x-api-key"))
}

func (c *capture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.bodies)
}

func (c *capture) last() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bodies[len(c.bodies)-1]
}

// jsonBody 把請求 body 解成 map；以 json.RawMessage 取原樣片段。
func jsonBody(t *testing.T, body string) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("請求 body 不是合法 JSON: %v\n%s", err, body)
	}
	return m
}

// newTestAdapter 起一個 httptest server，以 NewAnthropic 的 baseURL 注入點指過去。
// respond 依序（循環）回傳預備好的回應。
func newTestAdapter(t *testing.T, respond ...http.HandlerFunc) (Adapter, *capture) {
	t.Helper()
	cap := &capture{}
	i := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.record(r)
		// SDK 內建重試對 429／5xx 生效（§18.3）；給極短 Retry-After-Ms 讓測試不等退避。
		w.Header().Set("Retry-After-Ms", "1")
		j := i % len(respond)
		i++
		respond[j](w, r)
	}))
	t.Cleanup(srv.Close)
	return NewAnthropic("test-key-0123456789", srv.URL), cap
}

func respondJSON(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

// jsonDeltaEvent 以 json.Marshal 產生 input_json_delta 事件的 wire JSON，
// 避免手寫 partial_json 轉義出錯（partial 內含 {{NONCE}} 佔位符）。
func jsonDeltaEvent(index int, partial string) string {
	b, err := json.Marshal(map[string]any{
		"type":  "content_block_delta",
		"index": index,
		"delta": map[string]any{"type": "input_json_delta", "partial_json": partial},
	})
	if err != nil {
		return ""
	}
	return string(b)
}

// sse 回傳一個把 events 依序以 text/event-stream 寫出的 handler。
func sse(events ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for _, e := range events {
			var head struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal([]byte(e), &head); err != nil {
				continue
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", head.Type, e)
		}
	}
}

// ---- 測資 ----

// candidateSchema 帶 $defs／additionalProperties／title 等「SDK struct 欄位裝不下」的鍵，
// 用來驗證 schema 以原始 bytes 逐 byte 送出（§23-11：schemas/ 是唯一真源）。
const candidateSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","title":"Candidate","type":"object","required":["id","sink"],"additionalProperties":false,"$defs":{"loc":{"type":"integer","minimum":1}},"properties":{"id":{"type":"string","pattern":"^C-[0-9]{4}$"},"sink":{"type":"object","required":["file","line"],"properties":{"file":{"type":"string"},"line":{"$ref":"#/$defs/loc"}}}}}`

// messageJSON 是非串流回應骨架；content／stop_reason／stop_details 由呼叫端帶入。
func messageJSON(stopReason, stopDetails, content string) string {
	sd := stopDetails
	if sd == "" {
		sd = "null"
	}
	return fmt.Sprintf(`{"id":"msg_01","type":"message","role":"assistant","model":"claude-sonnet-5","content":%s,"stop_reason":%q,"stop_sequence":null,"stop_details":%s,"usage":{"input_tokens":120,"output_tokens":45,"cache_read_input_tokens":88,"cache_creation_input_tokens":7}}`,
		content, stopReason, sd)
}

// ---- 請求形狀 ----

// TestAnthropicRequestShape 驗證 §18.3 的 client／thinking／effort／cache／schema 各項。
func TestAnthropicRequestShape(t *testing.T) {
	adapter, cap := newTestAdapter(t, respondJSON(200, messageJSON("end_turn", "", `[{"type":"text","text":"ok"}]`)))
	resp, err := adapter.Chat(context.Background(), ChatRequest{
		Role:   RoleProver,
		Model:  "claude-sonnet-5",
		System: "你是 Aegis prover（靜態 system prompt）。",
		Messages: []Message{
			{Role: "user", Content: []ContentBlock{{Type: "text", Text: "分析此 sink"}}},
			// 歷史中的 assistant tool_use 以 raw input 原樣回填（§18.1 迴圈）。
			{Role: "assistant", Content: []ContentBlock{{
				Type:    "tool_use",
				ToolUse: &ToolUse{ID: "toolu_01", Name: "submit_witness_spec", Input: []byte(`{"payload":"x=1"}`)},
			}}},
			{Role: "user", Content: []ContentBlock{{
				Type:       "tool_result",
				ToolResult: &ToolResult{ID: "toolu_01", Content: "rejected", IsError: true},
			}}},
		},
		Tools: []ToolDef{{
			Name:        "submit_witness_spec",
			Description: "提交 WitnessSpec",
			InputSchema: []byte(candidateSchema),
		}},
		Effort: "xhigh",
	})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if cap.count() != 1 {
		t.Fatalf("請求次數 = %d, want 1", cap.count())
	}
	m := jsonBody(t, cap.last())

	// 路徑與標頭（測試內檢查金鑰已送出，但 adapter 本身永不記 log，§23-6）。
	if got := cap.paths[0]; got != "/v1/messages" {
		t.Errorf("路徑 = %q, want /v1/messages", got)
	}
	if got := cap.keys[0]; got != "test-key-0123456789" {
		t.Errorf("x-api-key 未依呼叫端金鑰送出")
	}

	// thinking：adaptive 形式，絕非 budget 形式（§18.3、§23-5）。
	var think struct {
		Type         string `json:"type"`
		BudgetTokens int    `json:"budget_tokens"`
	}
	if err := json.Unmarshal(m["thinking"], &think); err != nil {
		t.Fatalf("thinking 解析: %v (%s)", err, m["thinking"])
	}
	if think.Type != "adaptive" {
		t.Errorf("thinking.type = %q, want \"adaptive\"", think.Type)
	}
	if think.BudgetTokens != 0 || strings.Contains(cap.last(), "budget_tokens") {
		t.Errorf("請求出現 budget_tokens 形式（§23-5 禁止）: %s", cap.last())
	}

	// effort 落在 output_config（§18.3）。
	var oc struct {
		Effort string `json:"effort"`
	}
	if err := json.Unmarshal(m["output_config"], &oc); err != nil {
		t.Fatalf("output_config 解析: %v (%s)", err, m["output_config"])
	}
	if oc.Effort != "xhigh" {
		t.Errorf("output_config.effort = %q, want \"xhigh\"", oc.Effort)
	}

	// system cache_control 打快取（§18.3）。
	var sys []struct {
		Text         string          `json:"text"`
		CacheControl json.RawMessage `json:"cache_control"`
	}
	if err := json.Unmarshal(m["system"], &sys); err != nil {
		t.Fatalf("system 解析: %v (%s)", err, m["system"])
	}
	if len(sys) != 1 || sys[0].Text != "你是 Aegis prover（靜態 system prompt）。" {
		t.Errorf("system 內容不符: %s", m["system"])
	}
	if !strings.Contains(string(sys[0].CacheControl), `"ephemeral"`) {
		t.Errorf("system 缺 cache_control ephemeral: %s", sys[0].CacheControl)
	}

	// 工具 schema：以原始 bytes 逐 byte 送出（§23-11）。
	var tools []struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		InputSchema json.RawMessage `json:"input_schema"`
	}
	if err := json.Unmarshal(m["tools"], &tools); err != nil {
		t.Fatalf("tools 解析: %v (%s)", err, m["tools"])
	}
	if len(tools) != 1 {
		t.Fatalf("tools 數 = %d, want 1", len(tools))
	}
	if tools[0].Name != "submit_witness_spec" || tools[0].Description != "提交 WitnessSpec" {
		t.Errorf("工具名／描述不符: %s", m["tools"])
	}
	if string(tools[0].InputSchema) != candidateSchema {
		t.Errorf("input_schema 未逐 byte 保留（§23-11）:\n got  %s\n want %s", tools[0].InputSchema, candidateSchema)
	}

	// max_tokens：非串流 16000 起跳（§18.3）。
	if got := strings.TrimSpace(string(m["max_tokens"])); got != "16000" {
		t.Errorf("max_tokens = %s, want 16000", got)
	}

	// 歷史映射：user／assistant、tool_result 回填、raw input 原樣。
	var msgs []struct {
		Role    string `json:"role"`
		Content []struct {
			Type      string          `json:"type"`
			Text      string          `json:"text"`
			ID        string          `json:"id"`
			Name      string          `json:"name"`
			Input     json.RawMessage `json:"input"`
			ToolUseID string          `json:"tool_use_id"`
			ToolR     json.RawMessage `json:"content"`
			IsError   bool            `json:"is_error"`
		} `json:"content"`
	}
	if err := json.Unmarshal(m["messages"], &msgs); err != nil {
		t.Fatalf("messages 解析: %v", err)
	}
	if len(msgs) != 3 || msgs[0].Role != "user" || msgs[1].Role != "assistant" || msgs[2].Role != "user" {
		t.Fatalf("messages 角色序不符: %s", m["messages"])
	}
	if msgs[1].Content[0].Type != "tool_use" || msgs[1].Content[0].Input != nil && string(msgs[1].Content[0].Input) != `{"payload":"x=1"}` {
		t.Errorf("tool_use raw input 未逐 byte 回填: %s", m["messages"])
	}
	if msgs[2].Content[0].ToolUseID != "toolu_01" || msgs[2].Content[0].IsError != true ||
		!strings.Contains(string(msgs[2].Content[0].ToolR), "rejected") {
		t.Errorf("tool_result 回填不符: %s", m["messages"])
	}

	// 回應映射：end_turn。
	if resp.StopReason != StopEndTurn {
		t.Errorf("StopReason = %q, want end_turn", resp.StopReason)
	}
	if len(resp.Content) != 1 || resp.Content[0].Type != "text" || resp.Content[0].Text != "ok" {
		t.Errorf("Content 映射不符: %+v", resp.Content)
	}
	if resp.Model != "claude-sonnet-5" {
		t.Errorf("Model = %q", resp.Model)
	}
	if resp.Usage.InputTokens != 120 || resp.Usage.OutputTokens != 45 ||
		resp.Usage.CacheReadTokens != 88 || resp.Usage.CacheCreationTokens != 7 {
		t.Errorf("Usage 映射不符: %+v", resp.Usage)
	}
}

// TestAnthropicThinkingGate 驗證 5 系列閘門：5 系列才送 adaptive thinking；
// 非 5 系列（含 claude-3-5-sonnet 的「3.5」老命名）一律不打 thinking 參數
// （§23-5 禁止 budget 形式，故非 5 系列 v1 不開 thinking）。
func TestAnthropicThinkingGate(t *testing.T) {
	cases := []struct {
		model    string
		hasThink bool
	}{
		{"claude-sonnet-5", true},
		{"claude-opus-5-20260101", true},
		{"claude-5-sonnet", true},
		{"claude-sonnet-4-5", false},
		{"claude-opus-4-8", false},
		{"claude-3-5-sonnet", false},
	}
	for _, tc := range cases {
		adapter, cap := newTestAdapter(t, respondJSON(200, messageJSON("end_turn", "", `[]`)))
		if _, err := adapter.Chat(context.Background(), ChatRequest{
			Model:    tc.model,
			Messages: []Message{{Role: "user", Content: []ContentBlock{{Type: "text", Text: "hi"}}}},
		}); err != nil {
			t.Fatalf("%s: Chat: %v", tc.model, err)
		}
		m := jsonBody(t, cap.last())
		_, ok := m["thinking"]
		if ok != tc.hasThink {
			t.Errorf("%s: thinking 存在 = %v, want %v（body: %s）", tc.model, ok, tc.hasThink, cap.last())
		}
	}
}

// TestAnthropicEffortOmitted 驗證未給 effort 時不送 output_config（顯式降級原則，
// 能力缺失不影響正確性，§3.2）。
func TestAnthropicEffortOmitted(t *testing.T) {
	adapter, cap := newTestAdapter(t, respondJSON(200, messageJSON("end_turn", "", `[]`)))
	if _, err := adapter.Chat(context.Background(), ChatRequest{
		Model:    "claude-sonnet-5",
		Messages: []Message{{Role: "user", Content: []ContentBlock{{Type: "text", Text: "hi"}}}},
	}); err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if _, ok := jsonBody(t, cap.last())["output_config"]; ok {
		t.Errorf("未給 effort 卻送出 output_config: %s", cap.last())
	}
}

// TestAnthropicMaxTokensFloor 驗證 max_tokens：非串流 16000、串流 64000 起跳，
// 呼叫端更高則從高（§18.3）。
func TestAnthropicMaxTokensFloor(t *testing.T) {
	cases := []struct {
		name      string
		stream    bool
		maxTokens int
		want      string
	}{
		{"非串流未設", false, 0, "16000"},
		{"非串流更高", false, 20000, "20000"},
		{"串流未設", true, 0, "64000"},
		{"串流更高", true, 100000, "100000"},
		{"非串流低於起跳", false, 5000, "16000"},
	}
	for _, tc := range cases {
		adapter, cap := newTestAdapter(t, respondJSON(200, messageJSON("end_turn", "", `[]`)))
		if _, err := adapter.Chat(context.Background(), ChatRequest{
			Model:     "claude-sonnet-5",
			Stream:    tc.stream,
			MaxTokens: tc.maxTokens,
			Messages:  []Message{{Role: "user", Content: []ContentBlock{{Type: "text", Text: "hi"}}}},
		}); err != nil {
			t.Fatalf("%s: Chat: %v", tc.name, err)
		}
		if got := strings.TrimSpace(string(jsonBody(t, cap.last())["max_tokens"])); got != tc.want {
			t.Errorf("%s: max_tokens = %s, want %s", tc.name, got, tc.want)
		}
	}
}

// ---- 回應映射（閉集 §23-4）----

func TestAnthropicStopReasonMapping(t *testing.T) {
	cases := []struct {
		name       string
		stopReason string
		stopDetail string
		content    string
		want       StopReason
		category   string
	}{
		{"end_turn", "end_turn", "", `[{"type":"text","text":"done"}]`, StopEndTurn, ""},
		{"tool_use", "tool_use", "", `[{"type":"tool_use","id":"toolu_9","name":"submit_witness_spec","input":{"witness":{"payload":"{{NONCE}}"}}}]`, StopToolUse, ""},
		{"max_tokens", "max_tokens", "", `[]`, StopMaxTokens, ""},
		{"refusal", "refusal", `{"type":"refusal","category":"cyber","explanation":null}`, `[]`, StopRefusal, "cyber"},
		{"stop_sequence→other", "stop_sequence", "", `[]`, StopOther, ""},
		{"pause_turn→other", "pause_turn", "", `[]`, StopOther, ""},
	}
	for _, tc := range cases {
		adapter, _ := newTestAdapter(t, respondJSON(200, messageJSON(tc.stopReason, tc.stopDetail, tc.content)))
		resp, err := adapter.Chat(context.Background(), ChatRequest{
			Model:    "claude-sonnet-5",
			Messages: []Message{{Role: "user", Content: []ContentBlock{{Type: "text", Text: "hi"}}}},
		})
		if err != nil {
			t.Fatalf("%s: Chat: %v", tc.name, err)
		}
		if resp.StopReason != tc.want {
			t.Errorf("%s: StopReason = %q, want %q", tc.name, resp.StopReason, tc.want)
		}
		if resp.RefusalCategory != tc.category {
			t.Errorf("%s: RefusalCategory = %q, want %q（§18.3 StopDetails.Category）", tc.name, resp.RefusalCategory, tc.category)
		}
	}
}

func TestAnthropicToolUseResponse(t *testing.T) {
	adapter, _ := newTestAdapter(t, respondJSON(200, messageJSON("tool_use", "",
		`[{"type":"tool_use","id":"toolu_42","name":"submit_witness_spec","input":{"payload":"GET /?x={{NONCE}}","files":["witness/app.py"]}}]`)))
	resp, err := adapter.Chat(context.Background(), ChatRequest{
		Model:    "claude-sonnet-5",
		Messages: []Message{{Role: "user", Content: []ContentBlock{{Type: "text", Text: "hi"}}}},
		Tools:    []ToolDef{{Name: "submit_witness_spec", InputSchema: []byte(candidateSchema)}},
	})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if len(resp.Content) != 1 || resp.Content[0].ToolUse == nil {
		t.Fatalf("tool_use 塊映射不符: %+v", resp.Content)
	}
	tu := resp.Content[0].ToolUse
	if tu.ID != "toolu_42" || tu.Name != "submit_witness_spec" {
		t.Errorf("ToolUse ID／Name 不符: %+v", tu)
	}
	// raw input 逐 byte（提交工具模式以 raw bytes 綁 schema 驗證，§18.3）。
	if string(tu.Input) != `{"payload":"GET /?x={{NONCE}}","files":["witness/app.py"]}` {
		t.Errorf("ToolUse.Input 非原始 bytes: %s", tu.Input)
	}
}

// ---- 串流（§18.3：NewStreaming → 逐事件 → Accumulate → stream.Err() 必查）----

func TestAnthropicStreamingToolUse(t *testing.T) {
	events := []string{
		`{"type":"message_start","message":{"id":"msg_s1","type":"message","role":"assistant","model":"claude-sonnet-5","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":10,"output_tokens":1,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}}}`,
		`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
		`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"先寫計畫："}}`,
		`{"type":"content_block_stop","index":0}`,
		`{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_s1","name":"submit_witness_spec","input":{}}}`,
		jsonDeltaEvent(1, `{"payload":"GET /?q={{NON`),
		jsonDeltaEvent(1, `CE}}"}`),
		`{"type":"content_block_stop","index":1}`,
		`{"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null,"stop_details":null},"usage":{"output_tokens":42}}`,
		`{"type":"message_stop"}`,
	}
	adapter, cap := newTestAdapter(t, sse(events...))
	resp, err := adapter.Chat(context.Background(), ChatRequest{
		Role:     RoleProver,
		Model:    "claude-sonnet-5",
		Stream:   true,
		Effort:   "xhigh",
		Messages: []Message{{Role: "user", Content: []ContentBlock{{Type: "text", Text: "產出 witness"}}}},
		Tools:    []ToolDef{{Name: "submit_witness_spec", InputSchema: []byte(candidateSchema)}},
	})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}

	// 請求形狀：stream=true、串流 max_tokens 64000 起跳、thinking adaptive。
	m := jsonBody(t, cap.last())
	if got := strings.TrimSpace(string(m["stream"])); got != "true" {
		t.Errorf("stream = %s, want true", got)
	}
	if got := strings.TrimSpace(string(m["max_tokens"])); got != "64000" {
		t.Errorf("串流 max_tokens = %s, want 64000（§18.3）", got)
	}
	if !strings.Contains(cap.last(), `"thinking":{"type":"adaptive"}`) {
		t.Errorf("串流請求缺 adaptive thinking: %s", cap.last())
	}
	if !strings.Contains(cap.last(), `"effort":"xhigh"`) {
		t.Errorf("串流請求缺 output_config.effort: %s", cap.last())
	}

	// Accumulate 出的完整訊息：文字塊＋工具塊（input_json_delta 逐段拼接）。
	if resp.StopReason != StopToolUse {
		t.Errorf("StopReason = %q, want tool_use", resp.StopReason)
	}
	if len(resp.Content) != 2 || resp.Content[0].Type != "text" || resp.Content[0].Text != "先寫計畫：" {
		t.Errorf("串流文字塊不符: %+v", resp.Content)
	}
	if len(resp.Content) != 2 || resp.Content[1].ToolUse == nil {
		t.Fatalf("串流工具塊不符: %+v", resp.Content)
	}
	tu := resp.Content[1].ToolUse
	if tu.ID != "toolu_s1" || tu.Name != "submit_witness_spec" {
		t.Errorf("串流 ToolUse ID／Name 不符: %+v", tu)
	}
	if string(tu.Input) != `{"payload":"GET /?q={{NONCE}}"}` {
		t.Errorf("串流 input_json_delta 未正確累積: %s", tu.Input)
	}
	if resp.Usage.OutputTokens != 42 {
		t.Errorf("串流 Usage.OutputTokens = %d, want 42", resp.Usage.OutputTokens)
	}
}

// ---- 錯誤分類（只准 HTTP 狀態碼，§18.3；不寬泛 catch-all）----

// TestAnthropicError400NoRetry：4xx 不重試（§18.3），單一請求即回 *llm.Error。
func TestAnthropicError400NoRetry(t *testing.T) {
	adapter, cap := newTestAdapter(t, respondJSON(400,
		`{"type":"error","error":{"type":"invalid_request_error","message":"thinking 違規"}}`))
	_, err := adapter.Chat(context.Background(), ChatRequest{
		Model:    "claude-sonnet-5",
		Messages: []Message{{Role: "user", Content: []ContentBlock{{Type: "text", Text: "hi"}}}},
	})
	var e *Error
	if !asAPIError(err, &e) {
		t.Fatalf("錯誤型別 = %T, want *llm.Error", err)
	}
	if e.StatusCode != 400 {
		t.Errorf("StatusCode = %d, want 400", e.StatusCode)
	}
	if !strings.Contains(e.Body, "invalid_request_error") {
		t.Errorf("Body 未含回應體: %q", e.Body)
	}
	// 金鑰永不見於錯誤訊息（§23-6）。
	if strings.Contains(e.Error(), "test-key-0123456789") {
		t.Errorf("錯誤訊息洩漏金鑰: %q", e.Error())
	}
	if cap.count() != 1 {
		t.Errorf("4xx 不應重試，請求次數 = %d, want 1（§18.3）", cap.count())
	}
}

// TestAnthropicError429Retries：429 交給 SDK 內建退避重試（WithMaxRetries(2)，§18.3），
// 耗盡後回 *llm.Error{429}，分類仍只看 HTTP 狀態碼。
func TestAnthropicError429Retries(t *testing.T) {
	adapter, cap := newTestAdapter(t, respondJSON(429,
		`{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}`))
	_, err := adapter.Chat(context.Background(), ChatRequest{
		Model:    "claude-sonnet-5",
		Messages: []Message{{Role: "user", Content: []ContentBlock{{Type: "text", Text: "hi"}}}},
	})
	var e *Error
	if !asAPIError(err, &e) {
		t.Fatalf("錯誤型別 = %T, want *llm.Error", err)
	}
	if e.StatusCode != 429 {
		t.Errorf("StatusCode = %d, want 429", e.StatusCode)
	}
	// WithMaxRetries(2)：初次＋2 次重試；不 over-assert 之下的下限檢查。
	if cap.count() < 2 {
		t.Errorf("429 應觸發 SDK 內建重試，請求次數 = %d, want >=2", cap.count())
	}
}

// TestAnthropicInvalidToolSchema：schema 真源是 schemas/（§23-11）——不合法的
// schema 在本地即拒絕，請求不出門。
func TestAnthropicInvalidToolSchema(t *testing.T) {
	adapter, cap := newTestAdapter(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("不應發出請求")
	})
	_, err := adapter.Chat(context.Background(), ChatRequest{
		Model:    "claude-sonnet-5",
		Messages: []Message{{Role: "user", Content: []ContentBlock{{Type: "text", Text: "hi"}}}},
		Tools:    []ToolDef{{Name: "bad", InputSchema: []byte(`{"type":`)}},
	})
	if err == nil {
		t.Fatal("不合法 schema 應在本地報錯")
	}
	if cap.count() != 0 {
		t.Errorf("不應發出請求，請求次數 = %d", cap.count())
	}
}

func TestAnthropicProvider(t *testing.T) {
	if got := NewAnthropic("k", "").Provider(); got != "anthropic" {
		t.Errorf("Provider() = %q, want \"anthropic\"（§3.2）", got)
	}
}

// asAPIError 包 errors.As，供測試斷言 *llm.Error（§18.3 分類結果）。
func asAPIError(err error, target **Error) bool {
	if err == nil || target == nil {
		return false
	}
	e, ok := err.(*Error)
	if !ok {
		return false
	}
	*target = e
	return true
}
