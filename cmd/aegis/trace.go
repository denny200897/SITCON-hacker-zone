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

	"github.com/charmbracelet/lipgloss"

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
		return nil, fmt.Errorf("opening AI event stream: %w", err)
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
		if line := formatWatchEvent(event); line != "" {
			fmt.Fprintln(trace.out, line)
		}
	}
}

// Watch-stream styling. The rendered output is meant to read like an agent
// conversation (thinking → actions → results) rather than a raw event dump.
// lipgloss emits ANSI only when the destination is a real terminal (the TUI or
// an interactive --watch); piped/redirected output and `go test` degrade to
// plain text, so substring assertions and log redirection stay clean.
var (
	stThink    = lipgloss.NewStyle().Foreground(lipgloss.Color("#A78BFA")).Bold(true)
	stThinkTxt = lipgloss.NewStyle().Foreground(lipgloss.Color("#B9A7F0")).Italic(true)
	stTool     = lipgloss.NewStyle().Foreground(lipgloss.Color("#4FD1C5")).Bold(true)
	stPhase    = lipgloss.NewStyle().Foreground(lipgloss.Color("#48BB78")).Bold(true)
	stAnswer   = lipgloss.NewStyle().Foreground(lipgloss.Color("#E6EDEB"))
	stDim      = lipgloss.NewStyle().Foreground(lipgloss.Color("#6B7A77"))
	stErr      = lipgloss.NewStyle().Foreground(lipgloss.Color("#F87171"))
)

// formatWatchEvent renders one audit event as a single conversational block for
// the live watch stream. It intentionally never prints full prompts, source
// bundles, or raw tool results — ai-events.jsonl keeps the complete redacted
// record; the terminal shows the agent's reasoning and actions, not a data dump.
//
// Returning "" drops an event from the visible stream (kept in the audit log):
// outbound-payload sizes and token accounting are log detail, not operator
// signal, and would otherwise bury the thinking-and-tools narrative in noise.
func formatWatchEvent(event aiTraceEvent) string {
	label := event.Role
	if event.Phase != "" {
		label += " · " + event.Phase
	}
	switch event.Kind {
	case "request", "usage":
		return ""
	case "workflow":
		// A phase boundary: a blank line then a bright header, so the transcript
		// reads in scannable sections rather than one unbroken wall.
		return "\n" + stPhase.Render("● "+oneLine(event.Content, 400)) + "  " + stDim.Render("("+label+")")
	case "commentary":
		// The agent's public progress note before a group of tool calls — the
		// visible "thinking" the operator wants to follow. Drop the "turn N:"
		// bookkeeping prefix and show it as a readable, indented block.
		text := event.Content
		if strings.HasPrefix(text, "turn ") {
			if _, rest, ok := strings.Cut(text, ": "); ok {
				text = rest
			}
		}
		return stThink.Render("💭 "+label) + "\n" + indentLines(stThinkTxt.Render(oneLine(text, 1000)), "   ")
	case "response":
		if summary, count, ok := structuredResponseSummary(event.Content); ok {
			return stTool.Render("⏺") + " " + stAnswer.Render(oneLine(summary, 600)) +
				" " + stDim.Render(fmt.Sprintf("(%d candidate(s))", count))
		}
		if strings.HasPrefix(event.Phase, "prove-") || event.Phase == "report" {
			// Long structured artifacts (proofs, reports) land in files; a
			// byte-count line here is noise.
			return ""
		}
		return stTool.Render("⏺") + " " + stAnswer.Render(oneLine(event.Content, 800))
	case "tool_call":
		tool, args, _ := strings.Cut(event.Content, " ")
		return stTool.Render("⏺ "+tool) + " " + stDim.Render(summarizeToolCall(tool, args))
	case "tool_result":
		if strings.HasPrefix(event.Content, "ERROR ") {
			return "  " + stErr.Render("⎿ error: "+oneLine(strings.TrimPrefix(event.Content, "ERROR "), 300))
		}
		tool, result, _ := strings.Cut(event.Content, " ")
		return "  " + stDim.Render("⎿ "+summarizeToolResult(tool, result))
	default:
		if strings.HasPrefix(event.Kind, "tool_") {
			return "  " + stDim.Render("⎿ "+event.Kind+" ("+humanBytes(len(event.Content))+")")
		}
		return stDim.Render("• " + label + " · " + event.Kind + " — " + oneLine(event.Content, 400))
	}
}

// indentLines prefixes every line of s so wrapped blocks stay visually nested
// under their header.
func indentLines(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = prefix + lines[i]
	}
	return strings.Join(lines, "\n")
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
