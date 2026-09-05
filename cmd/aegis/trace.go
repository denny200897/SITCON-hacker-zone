package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
		fmt.Fprintf(trace.out, "\n[AI %s · %s · %s]\n%s\n", role, traceContext.phase, kind, masked)
	}
}
