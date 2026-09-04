// Package triage contains deterministic reachability and scoring policy.
package triage

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

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
	FPReason     string              `json:"fp_reason,omitempty"`
}

// RubricEvidence is the four-question SPEC §20.1 decision record. A positive
// answer is usable only when it carries file:line evidence.
type RubricEvidence struct {
	DefaultFlow, NonDefaultFlow, ThinWiring, Uncalled bool
	DefaultAt, NonDefaultAt, ThinWiringAt, UncalledAt string
}

// Assess applies the ordered ACD rubric without model judgement.
func Assess(candidateID, priority string, e RubricEvidence) Result {
	r := Result{CandidateID: candidateID, Verdict: "PROCEED", Priority: priority}
	if e.DefaultFlow && validLocation(e.DefaultAt) {
		r.Reachability, r.Mode = "D0", "direct"
		r.Rationale = "default input flows to sink at " + e.DefaultAt
		return r
	}
	if e.NonDefaultFlow && validLocation(e.NonDefaultAt) {
		r.Reachability, r.Mode = "D1", "direct"
		r.Rationale = "non-default input path reaches sink at " + e.NonDefaultAt
		return r
	}
	if e.ThinWiring && validLocation(e.ThinWiringAt) {
		r.Reachability, r.Mode = "D2", "witness"
		r.MissingLinks = []map[string]string{{"link": "input wiring", "evidence": e.ThinWiringAt}}
		r.Rationale = "callable sink exists and needs one input adapter at " + e.ThinWiringAt
		return r
	}
	if e.Uncalled && validLocation(e.UncalledAt) {
		r.Reachability, r.Mode = "D3", "witness"
		r.MissingLinks = []map[string]string{{"link": "feature caller", "evidence": e.UncalledAt}}
		r.Rationale = "sink has no evidenced caller at " + e.UncalledAt
		return r
	}
	r.Reachability = "UNKNOWN"
	r.Priority = "low"
	r.MissingLinks = []map[string]string{{"link": "input-to-sink flow", "evidence": "missing file:line evidence"}}
	r.Rationale = "insufficient file:line evidence for an ACD classification"
	return r
}

func Evaluate(c candidates.Candidate, inv *inventory.Inventory) Result {
	return EvaluateAt(c, inv, "")
}

// EvaluateAt derives only relationships that can be proven from snapshot
// source. It intentionally returns UNKNOWN instead of inventing false positives.
func EvaluateAt(c candidates.Candidate, inv *inventory.Inventory, snapshotDir string) Result {
	if c.SuspectedVulnClass == "" || c.Sink.File == "" {
		reason := "candidate lacks a sink or vulnerability family"
		return Result{CandidateID: c.ID, Verdict: "FALSE_POSITIVE", Priority: c.PriorityHint, FPReason: reason, Rationale: reason}
	}
	if inv == nil || snapshotDir == "" {
		return Assess(c.ID, c.PriorityHint, RubricEvidence{})
	}
	data, err := os.ReadFile(filepath.Join(snapshotDir, filepath.FromSlash(c.Sink.File)))
	if err != nil {
		return Assess(c.ID, c.PriorityHint, RubricEvidence{})
	}
	sinkFn := functionAt(pythonFunctions(string(data)), c.Sink.Line)
	location := fmt.Sprintf("%s:%d", c.Sink.File, c.Sink.Line)
	if sinkFn != "" {
		for _, route := range inv.Routes {
			if route.HandlerFile == c.Sink.File && route.HandlerSymbol == sinkFn {
				return Assess(c.ID, c.PriorityHint, RubricEvidence{DefaultFlow: true, DefaultAt: location})
			}
		}
		return Assess(c.ID, c.PriorityHint, RubricEvidence{ThinWiring: true, ThinWiringAt: location})
	}
	return Assess(c.ID, c.PriorityHint, RubricEvidence{Uncalled: true, UncalledAt: location})
}

type functionRange struct {
	name        string
	first, last int
}

var defRE = regexp.MustCompile(`^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(`)

func pythonFunctions(src string) []functionRange {
	lines := strings.Split(src, "\n")
	var out []functionRange
	for i, line := range lines {
		match := defRE.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		last := len(lines)
		for j := i + 1; j < len(lines); j++ {
			trimmed := strings.TrimSpace(lines[j])
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			current := len(lines[j]) - len(strings.TrimLeft(lines[j], " \t"))
			if current <= indent {
				last = j
				break
			}
		}
		out = append(out, functionRange{name: match[1], first: i + 1, last: last})
	}
	return out
}

func functionAt(functions []functionRange, line int) string {
	for _, function := range functions {
		if line >= function.first && line <= function.last {
			return function.name
		}
	}
	return ""
}

var locationRE = regexp.MustCompile(`^.+:[1-9][0-9]*$`)

func validLocation(location string) bool { return locationRE.MatchString(location) }

// Severity implements the SPEC §20.2 matrix. UNKNOWN uses the D3 column.
func Severity(impact, reachability string) string {
	if reachability == "UNKNOWN" {
		reachability = "D3"
	}
	if impact == "high" {
		switch reachability {
		case "D0", "D1":
			return "critical"
		case "D2":
			return "high"
		default:
			return "medium"
		}
	}
	switch reachability {
	case "D0", "D1":
		return "high"
	case "D2":
		return "medium"
	default:
		return "low"
	}
}

// Confidence implements SPEC §20.3. NOT_RUN has no evidence and scores zero.
func Confidence(verification, mode string, assumptions, successfulVariants int) float64 {
	if verification == "HYPOTHESIS_REJECTED" || verification == "NOT_RUN" {
		return 0
	}
	if verification == "NOT_PROVEN" {
		return 0.20
	}
	base := 0.60
	if mode == "direct" {
		base = 0.90
	}
	base -= float64(assumptions) * 0.05
	if successfulVariants > 1 {
		base += 0.05
	}
	if base < 0.10 {
		base = 0.10
	}
	if base > 0.95 {
		base = 0.95
	}
	return float64(int(base*100+0.5)) / 100
}
