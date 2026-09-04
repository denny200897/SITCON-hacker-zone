// Package triage contains the deterministic Stage 2 policy. It deliberately
// does not infer vulnerability truth from model prose: it only classifies the
// reachable surface and records the evidence used for that classification.
package triage

import (
	"fmt"
	"github.com/aegis-dev/aegis/internal/candidates"
	"github.com/aegis-dev/aegis/internal/inventory"
)

type Result struct {
	CandidateID  string              `json:"candidate_id"`
	Verdict      string              `json:"verdict"`
	Reachability string              `json:"reachability,omitempty"`
	Mode         string              `json:"mode,omitempty"`
	MissingLinks []map[string]string `json:"missing_links,omitempty"`
	Priority     string              `json:"priority,omitempty"`
	Rationale    string              `json:"rationale"`
}

func Evaluate(c candidates.Candidate, inv *inventory.Inventory) Result {
	r := Result{CandidateID: c.ID, Priority: c.PriorityHint}
	if c.SuspectedVulnClass == "" || c.Sink.File == "" {
		r.Verdict = "FALSE_POSITIVE"
		r.Rationale = "candidate 缺少可辨識的 sink/family"
		return r
	}
	for _, route := range inv.Routes {
		if route.HandlerFile == c.Sink.File {
			r.Verdict = "PROCEED"
			r.Reachability = "D2"
			r.Mode = "witness"
			r.Rationale = fmt.Sprintf("HTTP route %s %s 可達（%s:%d）", route.Method, route.Path, c.Sink.File, c.Sink.Line)
			return r
		}
	}
	for _, ep := range inv.Entrypoints {
		if ep.File == c.Sink.File {
			r.Verdict = "PROCEED"
			r.Reachability = "D1"
			r.Mode = "direct"
			r.Rationale = fmt.Sprintf("本地入口 %s 可達（%s:%d）", ep.Kind, c.Sink.File, c.Sink.Line)
			return r
		}
	}
	r.Verdict = "FALSE_POSITIVE"
	r.Reachability = "UNKNOWN"
	r.MissingLinks = []map[string]string{{"link": "entrypoint", "evidence": "inventory 未找到同檔案入口"}}
	r.Rationale = "未找到可驗證的輸入入口"
	return r
}
