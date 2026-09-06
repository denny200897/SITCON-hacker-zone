package llm

// openai_compat_test.go：以 httptest.Server 走 adapter 的 base_url 注入點，
// 全程無網路、無真實 API 呼叫。涵蓋 §3.2／§18.3 對 openai-compat 的要求：
// 請求映射、回應映射、finish_reason 閉集、空回應視同嘗試失敗、
// HTTP 狀態碼錯誤分類、effort 顯式降級、context 取消。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// capturedReq 記錄 server 收到的原始請求（含原始 body bytes，供 verbatim 驗證）。
type capturedReq struct {
	Authorization string
	ContentType   string
	Body          []byte
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "operation timed out" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return true }

var _ net.Error = timeoutNetError{}

// wireRequest 是對 capture body 的解碼視圖（Parameters 用 RawMessage 驗 verbatim）。
type wireRequest struct {
	Model           string          `json:"model"`
	Messages        []openAIMessage `json:"messages"`
	Tools           []openAITool    `json:"tools"`
	MaxTokens       int             `json:"max_tokens"`
	ReasoningEffort string          `json:"reasoning_effort"`
	Stream          bool            `json:"stream"`
}

// newCaptureServer 起一個 httptest server：每次請求記錄後，依序回覆 replies。
// 依 sync.Mutex 保護（adapter 的降級記憶會造成多次請求）。
func newCaptureServer(t *testing.T, replies []openAIResponse, statuses ...int) (*httptest.Server, *[]capturedReq) {
	t.Helper()
	var mu sync.Mutex
	captured := &[]capturedReq{}
	i := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(replies[min(i, len(replies)-1)])
		mu.Lock()
		*captured = append(*captured, capturedReq{
			Authorization: r.Header.Get("Authorization"),
			ContentType:   r.Header.Get("Content-Type"),
			Body:          readAllBody(r),
		})
		n := i
		i++
		mu.Unlock()
		status := http.StatusOK
		if n < len(statuses) {
			status = statuses[n]
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == http.StatusOK {
			fmt.Fprint(w, string(b))
		} else {
			// 非 2xx：回一個提及 reasoning 欄位的錯誤體（供降級探測測試）；
			// 一般錯誤測試只看狀態碼與 Body 非空。
			fmt.Fprint(w, `{"error":{"message":"bad request: reasoning_effort unsupported"}}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, captured
}

// readAllBody 讀光請求體（測試專用）。
func readAllBody(r *http.Request) []byte {
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := r.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return []byte(sb.String())
}

func decoded(t *testing.T, raw []byte) wireRequest {
	t.Helper()
	var w wireRequest
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatalf("解碼請求體失敗：%v", err)
	}
	return w
}

func newCompat(t *testing.T, srv *httptest.Server) *OpenAICompatAdapter {
	t.Helper()
	return NewOpenAICompat("my-ollama", srv.URL, "test-key", "qwen3:32b")
}

func simpleContentReply(finish string) openAIResponse {
	return openAIResponse{
		Model: "qwen3:32b",
		Choices: []openAIChoice{{
			Message:      openAIMessage{Role: "assistant", Content: "hello there"},
			FinishReason: finish,
		}},
		Usage: &openAIUsage{PromptTokens: 12, CompletionTokens: 34},
	}
}

// TestOpenAICompatProvider 驗證 Provider() 回傳使用者自訂名稱（§3.2）。
func TestOpenAICompatProvider(t *testing.T) {
	srv, _ := newCaptureServer(t, []openAIResponse{simpleContentReply("stop")})
	a := NewOpenAICompat("my-ollama", srv.URL, "k", "m")
	if got := a.Provider(); got != "my-ollama" {
		t.Fatalf("Provider() = %q, 欲得 %q", got, "my-ollama")
	}
}

// TestOpenAICompatRequestMapping 驗證請求體映射：system／user／assistant＋
// tool_calls／tool role、tools schema verbatim、max_tokens、model、Authorization。
func TestOpenAICompatRequestMapping(t *testing.T) {
	srv, captured := newCaptureServer(t, []openAIResponse{simpleContentReply("stop")})
	a := newCompat(t, srv)

	schema := `{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}`
	req := ChatRequest{
		Role:   RoleRecon,
		Model:  "m1",
		System: "sys prompt",
		Messages: []Message{
			{Role: "user", Content: []ContentBlock{{Type: "text", Text: "hello"}}},
			{Role: "assistant", Content: []ContentBlock{
				{Type: "text", Text: "calling tool"},
				{Type: "tool_use", ToolUse: &ToolUse{ID: "call_1", Name: "read_file", Input: []byte(`{"path":"a.go"}`)}},
			}},
			{Role: "user", Content: []ContentBlock{
				{Type: "tool_result", ToolResult: &ToolResult{ID: "call_1", Content: "file contents", IsError: true}},
			}},
		},
		Tools: []ToolDef{{
			Name:        "read_file",
			Description: "read a file",
			InputSchema: []byte(schema),
		}},
		MaxTokens: 16000,
		Effort:    "high",
	}
	if _, err := a.Chat(context.Background(), req); err != nil {
		t.Fatalf("Chat 失敗：%v", err)
	}
	if len(*captured) != 1 {
		t.Fatalf("請求數 = %d, 欲得 1", len(*captured))
	}
	c := (*captured)[0]
	if c.Authorization != "Bearer test-key" {
		t.Errorf("Authorization = %q, 欲得 Bearer test-key", c.Authorization)
	}
	if c.ContentType != "application/json" {
		t.Errorf("Content-Type = %q", c.ContentType)
	}
	w := decoded(t, c.Body)

	if w.Model != "m1" {
		t.Errorf("model = %q, 欲得 m1", w.Model)
	}
	if w.MaxTokens != 16000 {
		t.Errorf("max_tokens = %d, 欲得 16000", w.MaxTokens)
	}
	if w.ReasoningEffort != "high" {
		t.Errorf("reasoning_effort = %q, 欲得 high", w.ReasoningEffort)
	}
	if w.Stream {
		t.Errorf("stream 應為 false（v1 非串流）")
	}
	if len(w.Messages) != 4 {
		t.Fatalf("messages 數 = %d, 欲得 4：%s", len(w.Messages), c.Body)
	}
	if w.Messages[0].Role != "system" || w.Messages[0].Content != "sys prompt" {
		t.Errorf("messages[0] = %+v, 欲得 system/sys prompt", w.Messages[0])
	}
	if w.Messages[1].Role != "user" || w.Messages[1].Content != "hello" {
		t.Errorf("messages[1] = %+v", w.Messages[1])
	}
	asst := w.Messages[2]
	if asst.Role != "assistant" || asst.Content != "calling tool" {
		t.Errorf("messages[2] role/content = %+v", asst)
	}
	if len(asst.ToolCalls) != 1 {
		t.Fatalf("tool_calls 數 = %d", len(asst.ToolCalls))
	}
	tc := asst.ToolCalls[0]
	if tc.ID != "call_1" || tc.Type != "function" || tc.Func.Name != "read_file" {
		t.Errorf("tool_calls[0] = %+v", tc)
	}
	// arguments 必須是原始 JSON 字串（raw bytes 原樣，§18.3）。
	if tc.Func.Arguments != `{"path":"a.go"}` {
		t.Errorf("arguments = %q, 欲得原始 JSON 字串", tc.Func.Arguments)
	}
	toolMsg := w.Messages[3]
	if toolMsg.Role != "tool" || toolMsg.ToolCallID != "call_1" || toolMsg.Content != "file contents" {
		t.Errorf("tool 訊息 = %+v", toolMsg)
	}
	// tools：schema 以 raw bytes 原樣內嵌（verbatim，§23-11）。
	if len(w.Tools) != 1 {
		t.Fatalf("tools 數 = %d", len(w.Tools))
	}
	if w.Tools[0].Type != "function" || w.Tools[0].Function.Name != "read_file" ||
		w.Tools[0].Function.Description != "read a file" {
		t.Errorf("tools[0] = %+v", w.Tools[0])
	}
	if string(w.Tools[0].Function.Parameters) != schema {
		t.Errorf("parameters 非原樣：got %q, want %q", w.Tools[0].Function.Parameters, schema)
	}
}

// TestOpenAICompatDefaultModel 驗證 req.Model 為空時用 defaultModel。
func TestOpenAICompatDefaultModel(t *testing.T) {
	srv, captured := newCaptureServer(t, []openAIResponse{simpleContentReply("stop")})
	a := newCompat(t, srv)
	if _, err := a.Chat(context.Background(), ChatRequest{Messages: []Message{
		{Role: "user", Content: []ContentBlock{{Type: "text", Text: "hi"}}},
	}}); err != nil {
		t.Fatalf("Chat 失敗：%v", err)
	}
	if got := decoded(t, (*captured)[0].Body).Model; got != "qwen3:32b" {
		t.Errorf("model = %q, 欲得 default qwen3:32b", got)
	}
}

// TestOpenAICompatResponseContent 驗證純文字回應映射與 usage。
func TestOpenAICompatResponseContent(t *testing.T) {
	srv, _ := newCaptureServer(t, []openAIResponse{simpleContentReply("stop")})
	a := newCompat(t, srv)
	resp, err := a.Chat(context.Background(), ChatRequest{
		Model: "m", MaxTokens: 100,
		Messages: []Message{{Role: "user", Content: []ContentBlock{{Type: "text", Text: "hi"}}}},
	})
	if err != nil {
		t.Fatalf("Chat 失敗：%v", err)
	}
	if resp.StopReason != StopEndTurn {
		t.Errorf("StopReason = %q, 欲得 end_turn", resp.StopReason)
	}
	if resp.Model != "qwen3:32b" {
		t.Errorf("Model = %q", resp.Model)
	}
	if len(resp.Content) != 1 || resp.Content[0].Type != "text" || resp.Content[0].Text != "hello there" {
		t.Errorf("Content = %+v", resp.Content)
	}
	if resp.Usage.InputTokens != 12 || resp.Usage.OutputTokens != 34 {
		t.Errorf("Usage = %+v, 欲得 12/34", resp.Usage)
	}
}

// TestOpenAICompatResponseToolCalls 驗證 tool_calls 回應映射（arguments 保留 raw bytes）。
func TestOpenAICompatResponseToolCalls(t *testing.T) {
	srv, _ := newCaptureServer(t, []openAIResponse{{
		Model: "m",
		Choices: []openAIChoice{{
			Message: openAIMessage{Role: "assistant", ToolCalls: []openAIToolCall{{
				ID:   "call_9",
				Type: "function",
				Func: openAIFuncCall{Name: "list_files", Arguments: `{"path":"internal"}`},
			}}},
			FinishReason: "tool_calls",
		}},
		Usage: &openAIUsage{PromptTokens: 5, CompletionTokens: 7},
	}})
	a := newCompat(t, srv)
	resp, err := a.Chat(context.Background(), ChatRequest{Model: "m"})
	if err != nil {
		t.Fatalf("Chat 失敗：%v", err)
	}
	if resp.StopReason != StopToolUse {
		t.Errorf("StopReason = %q, 欲得 tool_use", resp.StopReason)
	}
	if len(resp.Content) != 1 || resp.Content[0].Type != "tool_use" {
		t.Fatalf("Content = %+v", resp.Content)
	}
	tu := resp.Content[0].ToolUse
	if tu.ID != "call_9" || tu.Name != "list_files" {
		t.Errorf("ToolUse = %+v", tu)
	}
	if string(tu.Input) != `{"path":"internal"}` {
		t.Errorf("Input = %q, 欲得 raw bytes 原樣", tu.Input)
	}
}

// TestOpenAICompatFinishReasons 驗證 finish_reason → StopReason 閉集映射（§23-4）。
func TestOpenAICompatFinishReasons(t *testing.T) {
	cases := []struct {
		finish string
		want   StopReason
	}{
		{"tool_calls", StopToolUse},
		{"stop", StopEndTurn},
		{"length", StopMaxTokens},
		{"content_filter", StopOther}, // compat 端點自創值 → 閉集 other
		{"", StopOther},
	}
	for _, c := range cases {
		srv, _ := newCaptureServer(t, []openAIResponse{simpleContentReply(c.finish)})
		a := newCompat(t, srv)
		resp, err := a.Chat(context.Background(), ChatRequest{Model: "m"})
		if err != nil {
			t.Fatalf("Chat(%q) 失敗：%v", c.finish, err)
		}
		if resp.StopReason != c.want {
			t.Errorf("finish_reason %q → StopReason %q, 欲得 %q", c.finish, resp.StopReason, c.want)
		}
	}
}

// TestOpenAICompatEmptyResponseRefusal 驗證 §18.3 降級 note：openai-compat 無
// refusal 訊號，空回應（無文字、無 tool_calls）視同該次嘗試失敗。
func TestOpenAICompatEmptyResponseRefusal(t *testing.T) {
	srv, _ := newCaptureServer(t, []openAIResponse{{
		Model:   "m",
		Choices: []openAIChoice{{Message: openAIMessage{Role: "assistant"}, FinishReason: "stop"}},
	}})
	a := newCompat(t, srv)
	resp, err := a.Chat(context.Background(), ChatRequest{Model: "m"})
	if err != nil {
		t.Fatalf("Chat 失敗：%v", err)
	}
	if resp.StopReason != StopRefusal {
		t.Errorf("StopReason = %q, 欲得 refusal", resp.StopReason)
	}
	if resp.RefusalCategory != "empty_response" {
		t.Errorf("RefusalCategory = %q, 欲得 empty_response", resp.RefusalCategory)
	}
	if len(resp.Content) != 0 {
		t.Errorf("Content 應為空，got %+v", resp.Content)
	}
}

// TestOpenAICompatHTTPErrorClassification 驗證 §18.3 錯誤分類：非 2xx 一律
// *Error{StatusCode, Body}，只看 HTTP 狀態碼。
func TestOpenAICompatHTTPErrorClassification(t *testing.T) {
	restore := setOpenAIRetryDelayForTest(t, 0)
	defer restore()
	for _, status := range []int{400, 401, 429, 500, 503} {
		// Transient statuses are retried; keep returning the same error so this
		// test verifies exhaustion rather than accidental recovery.
		srv, _ := newCaptureServer(t, []openAIResponse{simpleContentReply("stop")}, status, status, status)
		a := newCompat(t, srv)
		resp, err := a.Chat(context.Background(), ChatRequest{Model: "m"})
		if err == nil {
			t.Fatalf("HTTP %d：應回錯誤，got %+v", status, resp)
		}
		var e *Error
		if !errors.As(err, &e) {
			t.Fatalf("HTTP %d：錯誤型別 = %T, 欲得 *llm.Error", status, err)
		}
		if e.StatusCode != status {
			t.Errorf("HTTP %d：StatusCode = %d", status, e.StatusCode)
		}
		if e.Body == "" {
			t.Errorf("HTTP %d：Body 不應為空", status)
		}
	}
}

func TestOpenAICompatRetriesTransientTransportError(t *testing.T) {
	restore := setOpenAIRetryDelayForTest(t, 0)
	defer restore()
	calls := 0
	a := NewOpenAICompat("openrouter", "https://openrouter.ai/api/v1", "test-key", "test-model")
	a.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return nil, timeoutNetError{}
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(
				`{"model":"test-model","choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`,
			)),
			Request: r,
		}, nil
	})}

	resp, err := a.Chat(context.Background(), ChatRequest{Model: "test-model", Messages: []Message{
		{Role: "user", Content: []ContentBlock{{Type: "text", Text: "hi"}}},
	}})
	if err != nil {
		t.Fatalf("Chat should retry transient transport errors: %v", err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
	if len(resp.Content) != 1 || resp.Content[0].Text != "ok" {
		t.Fatalf("response = %+v", resp)
	}
}

// TestOpenAICompatErrorBodyTruncated 驗證錯誤體截尾（有界除錯輸出，§18.2 精神）。
func TestOpenAICompatErrorBodyTruncated(t *testing.T) {
	big := make([]byte, 10*1024)
	for i := range big {
		big[i] = 'x'
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(big)
	}))
	t.Cleanup(srv.Close)
	a := newCompat(t, srv)
	_, err := a.Chat(context.Background(), ChatRequest{Model: "m"})
	var e *Error
	if !errors.As(err, &e) || e.StatusCode != 500 {
		t.Fatalf("欲得 500 的 *Error，got %v", err)
	}
	if len(e.Body) > openAIErrBodyMax+len("…（截尾）") {
		t.Errorf("Body 長度 = %d, 應截尾至 ≤ %d", len(e.Body), openAIErrBodyMax)
	}
}

// TestOpenAICompatEffortProbe 顯式降級（§3.2／§18.3）：首次帶 reasoning_effort；
// 400 提及 reasoning → 重試一次（不帶欄位）並記住降級，後續呼叫直接省略。
func TestOpenAICompatEffortProbe(t *testing.T) {
	ok := simpleContentReply("stop")
	srv, captured := newCaptureServer(t, []openAIResponse{ok, ok},
		http.StatusBadRequest, http.StatusOK)
	a := newCompat(t, srv)

	resp, err := a.Chat(context.Background(), ChatRequest{Model: "m", Effort: "xhigh"})
	if err != nil {
		t.Fatalf("Chat 應在降級後成功：%v", err)
	}
	if resp.StopReason != StopEndTurn {
		t.Errorf("StopReason = %q", resp.StopReason)
	}
	if len(*captured) != 2 {
		t.Fatalf("請求數 = %d, 欲得 2（一次 400＋一次降級重試）", len(*captured))
	}
	first := decoded(t, (*captured)[0].Body)
	if first.ReasoningEffort != "xhigh" {
		t.Errorf("首次請求應帶 reasoning_effort=xhigh, got %q", first.ReasoningEffort)
	}
	second := decoded(t, (*captured)[1].Body)
	if second.ReasoningEffort != "" {
		t.Errorf("降級重試不應帶 reasoning_effort, got %q", second.ReasoningEffort)
	}

	// 本實例已記住降級：第三次呼叫直接省略欄位（capability probe 記憶）。
	if _, err := a.Chat(context.Background(), ChatRequest{Model: "m", Effort: "low"}); err != nil {
		t.Fatalf("第三次 Chat 失敗：%v", err)
	}
	if len(*captured) != 3 {
		t.Fatalf("請求數 = %d, 欲得 3（不再重試）", len(*captured))
	}
	third := decoded(t, (*captured)[2].Body)
	if third.ReasoningEffort != "" {
		t.Errorf("降級後 reasoning_effort 應省略, got %q", third.ReasoningEffort)
	}
}

// TestOpenAICompatEffortOmittedWhenEmpty 驗證 Effort 為空時不送 reasoning_effort。
func TestOpenAICompatEffortOmittedWhenEmpty(t *testing.T) {
	srv, captured := newCaptureServer(t, []openAIResponse{simpleContentReply("stop")})
	a := newCompat(t, srv)
	if _, err := a.Chat(context.Background(), ChatRequest{Model: "m"}); err != nil {
		t.Fatalf("Chat 失敗：%v", err)
	}
	if got := decoded(t, (*captured)[0].Body).ReasoningEffort; got != "" {
		t.Errorf("reasoning_effort = %q, 應省略", got)
	}
}

// TestOpenAICompatEffortNotDowngradedOnOther400 驗證探測 heuristic：不提及
// reasoning 的 400 不觸發降級（避免把 schema／驗證錯誤誤判成能力缺失）。
func TestOpenAICompatEffortNotDowngradedOnOther400(t *testing.T) {
	var mu sync.Mutex
	i := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		i++
		mu.Unlock()
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":{"message":"invalid model id"}}`)
	}))
	t.Cleanup(srv.Close)
	a := newCompat(t, srv)
	_, err := a.Chat(context.Background(), ChatRequest{Model: "m", Effort: "high"})
	var e *Error
	if !errors.As(err, &e) || e.StatusCode != 400 {
		t.Fatalf("欲得 400 *Error, got %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if i != 1 {
		t.Errorf("請求數 = %d, 欲得 1（非 reasoning 400 不重試）", i)
	}
	if a.effortUnsupported.Load() {
		t.Errorf("不應記住降級")
	}
}

// TestOpenAICompatContextCancel 驗證 context 取消會中止 HTTP 請求。
func TestOpenAICompatContextCancel(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-release:
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"choices":[]}`)
		}
	}))
	t.Cleanup(srv.Close)
	a := newCompat(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := a.Chat(ctx, ChatRequest{Model: "m"})
	close(release)
	srv.CloseClientConnections()
	if err == nil {
		t.Fatal("context 取消應回錯誤")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("錯誤應包 context.DeadlineExceeded, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Chat 未被 context 中止，耗時 %v", elapsed)
	}
}

func setOpenAIRetryDelayForTest(t *testing.T, delay time.Duration) func() {
	t.Helper()
	old := openAIRetryDelay
	openAIRetryDelay = func(int) time.Duration { return delay }
	return func() { openAIRetryDelay = old }
}
