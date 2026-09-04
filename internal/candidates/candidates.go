// Package candidates implements the deterministic Stage 1 detector adapter.
// Semgrep is treated as an untrusted candidate source: its output never
// becomes a finding without the local shape and schema checks below.
package candidates

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
)

type Candidate struct {
	ID                 string   `json:"id"`
	Sink               Sink     `json:"sink"`
	Sources            []Source `json:"sources"`
	MatchedText        string   `json:"matched_text,omitempty"`
	SuspectedVulnClass string   `json:"suspected_vuln_class,omitempty"`
	Rationale          string   `json:"rationale,omitempty"`
	PriorityHint       string   `json:"priority_hint,omitempty"`
}
type Sink struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Symbol string `json:"symbol"`
	Type   string `json:"type"`
}
type Source struct {
	Origin string `json:"origin"`
	Rule   string `json:"rule,omitempty"`
}

// Run executes exactly one trusted, repository-provided semgrep rule. Rules
// and the binary are selected by the caller; model output is never accepted.
func Run(ctx context.Context, root, rulePath, ruleID, bin string) ([]Candidate, error) {
	if bin == "" {
		bin = "semgrep"
	}
	if root == "" || rulePath == "" || ruleID == "" {
		return nil, fmt.Errorf("candidates: root/rule/ruleID 不可為空")
	}
	cmd := exec.CommandContext(ctx, bin, "--json", "--config", rulePath, root)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("candidates: semgrep 失敗：%s: %w", stderr.String(), err)
	}
	var doc struct {
		Results []struct {
			Path  string `json:"path"`
			Start struct {
				Line int `json:"line"`
			} `json:"start"`
			Extra struct {
				Message  string         `json:"message"`
				Match    string         `json:"match"`
				Metadata map[string]any `json:"metadata"`
			} `json:"extra"`
		} `json:"results"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("candidates: semgrep JSON 無效：%w", err)
	}
	result := make([]Candidate, 0, len(doc.Results))
	for i, hit := range doc.Results {
		if hit.Path == "" || hit.Start.Line < 1 {
			continue
		}
		path := filepath.ToSlash(hit.Path)
		if filepath.IsAbs(path) {
			if rel, rerr := filepath.Rel(root, path); rerr == nil {
				path = filepath.ToSlash(rel)
			}
		}
		family, _ := hit.Extra.Metadata["aegis_family"].(string)
		sinkType, _ := hit.Extra.Metadata["aegis_sink_type"].(string)
		if family == "" || sinkType == "" {
			continue
		}
		result = append(result, Candidate{ID: fmt.Sprintf("C-%04d", i+1), Sink: Sink{File: path, Line: hit.Start.Line, Symbol: symbolFor(path), Type: sinkType}, Sources: []Source{{Origin: "semgrep", Rule: ruleID}}, MatchedText: hit.Extra.Match, SuspectedVulnClass: family, Rationale: hit.Extra.Message, PriorityHint: "high"})
	}
	return result, nil
}

func symbolFor(path string) string {
	base := filepath.Base(path)
	if ext := filepath.Ext(base); ext != "" {
		base = base[:len(base)-len(ext)]
	}
	return base
}
