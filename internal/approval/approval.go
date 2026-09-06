// Package approval defines the operator approval boundary for host-side
// environment mutations such as building a proof image.
package approval

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

type Decision int

const (
	Deny Decision = iota
	AllowOnce
	AllowRun
)

type BuildRequest struct {
	Pack       string
	Image      string
	Action     string
	BuildDir   string
	Network    string
	RunNetwork string
	// Recipe, when set, is the agent-authored Dockerfile shown to the operator
	// before an agent-built proof environment is built.
	Recipe string
}

type Approver func(BuildRequest) (Decision, error)

type contextKey struct{}

func WithApprover(ctx context.Context, approver Approver) context.Context {
	return context.WithValue(ctx, contextKey{}, approver)
}

func FromContext(ctx context.Context) Approver {
	if ctx == nil {
		return nil
	}
	approver, _ := ctx.Value(contextKey{}).(Approver)
	return approver
}

// indentBlock indents each line of a recipe by four spaces for display,
// capping length so a huge Dockerfile cannot flood the prompt.
func indentBlock(s string) string {
	if len(s) > 4000 {
		s = s[:4000] + "\n    …(truncated)"
	}
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = "    " + l
	}
	return strings.Join(lines, "\n")
}

// Prompt is deliberately line-oriented so the same menu works in the
// full-screen console and a plain terminal. Bare Enter selects AllowOnce.
func Prompt(in io.Reader, out io.Writer, req BuildRequest) (Decision, error) {
	fmt.Fprintf(out, "\nAegis 需要建立驗證環境\n\n  Pack：%s\n  映像：%s\n  來源：%s\n  動作：%s\n  Build 網路：%s\n  Run 網路：%s\n", req.Pack, req.Image, req.BuildDir, req.Action, req.Network, req.RunNetwork)
	if req.Recipe != "" {
		fmt.Fprintf(out, "\n  Agent 提供的 Dockerfile：\n%s\n", indentBlock(req.Recipe))
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "› 1. 允許這一次（預設）")
	fmt.Fprintln(out, "  2. 本次 review 全部允許")
	fmt.Fprintln(out, "  3. 拒絕")
	fmt.Fprint(out, "\n按 Enter 確認 [1]：")
	var answer string
	if _, err := fmt.Fscanln(in, &answer); err != nil {
		if strings.Contains(err.Error(), "unexpected newline") {
			return AllowOnce, nil
		}
		if err == io.EOF {
			return Deny, errors.New("核准輸入已結束")
		}
		return Deny, err
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "", "1", "y", "yes":
		return AllowOnce, nil
	case "2", "a", "all":
		return AllowRun, nil
	case "3", "n", "no", "q", "quit":
		return Deny, nil
	default:
		return Deny, fmt.Errorf("無效的核准選項 %q（請選 1、2 或 3）", answer)
	}
}
