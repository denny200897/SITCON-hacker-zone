package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aegis-dev/aegis/internal/redaction"
)

type aiTraceKey struct{}

type aiTrace struct {
	mu    sync.Mutex
	file  *os.File
	out   io.Writer
	watch bool
}

type aiTraceContext struct {
	trace *aiTrace
	phase string
}

type aiTraceEvent struct {
	TS      string `json:"ts"`
	Role    string `json:"role"`
	Phase   string `json:"phase"`
	Kind    string `json:"kind"`
	Content string `json:"content"`
}

func openAITrace(runDir string, out io.Writer, watch bool) (*aiTrace, error) {
	f, err := os.OpenFile(filepath.Join(runDir, "ai-events.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("開啟 AI event stream：%w", err)
	}
	return &aiTrace{file: f, out: out, watch: watch}, nil
}

func (t *aiTrace) Close() error {
	if t == nil || t.file == nil {
		return nil
	}
	return t.file.Close()
}

func withAITrace(ctx context.Context, trace *aiTrace, phase string) context.Context {
	if trace == nil {
		return ctx
	}
	return context.WithValue(ctx, aiTraceKey{}, aiTraceContext{trace: trace, phase: phase})
}

func withAIPhase(ctx context.Context, phase string) context.Context {
	current, _ := ctx.Value(aiTraceKey{}).(aiTraceContext)
	if current.trace == nil {
		return ctx
	}
	current.phase = phase
	return context.WithValue(ctx, aiTraceKey{}, current)
}

func emitAITrace(ctx context.Context, role, kind, content string) {
	traceContext, _ := ctx.Value(aiTraceKey{}).(aiTraceContext)
	trace := traceContext.trace
	if trace == nil || trace.file == nil {
		return
	}
	masked, _ := redaction.Mask(content)
	event := aiTraceEvent{TS: time.Now().UTC().Format(time.RFC3339Nano), Role: role, Phase: traceContext.phase, Kind: kind, Content: masked}
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	_, _ = trace.file.Write(append(data, '\n'))
	_ = trace.file.Sync()
	if trace.watch && trace.out != nil {
		fmt.Fprintln(trace.out, formatWatchEvent(event))
	}
}

// formatWatchEvent intentionally never renders full prompts, source bundles, or
// tool results. ai-events.jsonl retains the complete redacted audit stream; the
// terminal is an operator dashboard, not a second artifact dump.
func formatWatchEvent(event aiTraceEvent) string {
	label := event.Role + " · " + event.Phase
	switch event.Kind {
	case "workflow":
		return "◆ " + label + " — " + oneLine(event.Content, 500)
	case "commentary":
		return "💭 " + label + "\n  " + oneLine(event.Content, 600)
	case "request":
		metadata, payload, _ := strings.Cut(event.Content, "\n")
		if payload == "" {
			payload = metadata
			metadata = "request"
		}
		return fmt.Sprintf("▶ %s — request sent (%s; payload %s)", label, oneLine(metadata, 180), humanBytes(len(payload)))
	case "response":
		if summary, count, ok := structuredResponseSummary(event.Content); ok {
			return fmt.Sprintf("✓ %s — response received; %d candidate(s)\n  %s", label, count, oneLine(summary, 600))
		}
		if strings.HasPrefix(event.Phase, "prove-") || event.Phase == "report" {
			return fmt.Sprintf("✓ %s — response received (%s)", label, humanBytes(len(event.Content)))
		}
		return fmt.Sprintf("✓ %s — response received (%s)\n  %s", label, humanBytes(len(event.Content)), oneLine(event.Content, 500))
	case "usage":
		return "  " + label + " — " + oneLine(event.Content, 240)
	case "tool_call":
		tool, args, _ := strings.Cut(event.Content, " ")
		return fmt.Sprintf("  → %s · %s — call (%s)", label, tool, summarizeToolCall(tool, args))
	case "tool_result":
		if strings.HasPrefix(event.Content, "ERROR ") {
			return fmt.Sprintf("  ✗ %s — tool error: %s", label, oneLine(strings.TrimPrefix(event.Content, "ERROR "), 300))
		}
		tool, result, _ := strings.Cut(event.Content, " ")
		return fmt.Sprintf("  ← %s · %s — %s", label, tool, summarizeToolResult(tool, result))
	default:
		if strings.HasPrefix(event.Kind, "tool_") {
			return fmt.Sprintf("  ↳ %s — %s (%s)", label, event.Kind, humanBytes(len(event.Content)))
		}
		return "• " + label + " · " + event.Kind + " — " + oneLine(event.Content, 400)
	}
}

func structuredResponseSummary(content string) (string, int, bool) {
	var envelope struct {
		AnalysisSummary string            `json:"analysis_summary"`
		Candidates      []json.RawMessage `json:"candidates"`
	}
	payload := strings.TrimSpace(content)
	if strings.HasPrefix(payload, "```") {
		if newline := strings.IndexByte(payload, '\n'); newline >= 0 {
			payload = payload[newline+1:]
		}
		payload = strings.TrimSuffix(strings.TrimSpace(payload), "```")
	}
	if json.Unmarshal([]byte(payload), &envelope) == nil && envelope.AnalysisSummary != "" {
		return envelope.AnalysisSummary, len(envelope.Candidates), true
	}
	var candidates []json.RawMessage
	if json.Unmarshal([]byte(payload), &candidates) == nil {
		return "Structured candidate list received", len(candidates), true
	}
	return "", 0, false
}

func summarizeToolCall(tool, args string) string {
	if tool == "read_code" {
		var input struct {
			Path  string `json:"path"`
			Start int    `json:"start"`
			End   int    `json:"end"`
		}
		if json.Unmarshal([]byte(args), &input) == nil && input.Path != "" {
			lineRange := ""
			if input.Start > 0 || input.End > 0 {
				lineRange = fmt.Sprintf(" lines %d-%d", input.Start, input.End)
			}
			return oneLine(input.Path+lineRange, 180)
		}
	}
	if tool == "search_code" {
		var input struct {
			Query string `json:"query"`
		}
		if json.Unmarshal([]byte(args), &input) == nil {
			return "query=" + oneLine(input.Query, 160)
		}
	}
	if tool == "semgrep" {
		var input struct {
			Rule string `json:"rule"`
		}
		if json.Unmarshal([]byte(args), &input) == nil {
			return "rule=" + oneLine(input.Rule, 160)
		}
	}
	return humanBytes(len(args)) + " args"
}

func summarizeToolResult(tool, result string) string {
	if tool == "search_code" || tool == "semgrep" {
		var entries []json.RawMessage
		if json.Unmarshal([]byte(result), &entries) == nil {
			return fmt.Sprintf("%d hit(s)", len(entries))
		}
	}
	return "result received (" + humanBytes(len(result)) + ")"
}

func oneLine(value string, limit int) string {
	value = strings.Join(strings.Fields(value), " ")
	runes := []rune(value)
	if len(runes) > limit {
		return string(runes[:limit]) + "…"
	}
	return value
}

func humanBytes(size int) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	}
	return fmt.Sprintf("%.1f KiB", float64(size)/1024)
}
