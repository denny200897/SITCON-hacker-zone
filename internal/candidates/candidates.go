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
	"sort"
)

type Candidate struct {
	ID                 string   `json:"id"`
	Sink               Sink     `json:"sink"`
	Sources            []Source `json:"sources"`
	MatchedText        string   `json:"matched_text,omitempty"`
	SuspectedVulnClass string   `json:"suspected_vuln_class,omitempty"`
	CWE                string   `json:"cwe,omitempty"`
	Impact             string   `json:"impact,omitempty"`
	Evidence           []string `json:"evidence,omitempty"`
	Chain              []string `json:"chain,omitempty"`
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

// Merge combines candidates produced by every configured detector. Hits for
// the same sink type within five lines are one finding; provenance is retained
// and IDs are reassigned deterministically.
func Merge(groups ...[]Candidate) []Candidate {
	all := make([]Candidate, 0)
	for _, group := range groups {
		all = append(all, group...)
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Sink.File != all[j].Sink.File {
			return all[i].Sink.File < all[j].Sink.File
		}
		if all[i].Sink.Type != all[j].Sink.Type {
			return all[i].Sink.Type < all[j].Sink.Type
		}
		return all[i].Sink.Line < all[j].Sink.Line
	})
	merged := make([]Candidate, 0, len(all))
	for _, hit := range all {
		if len(merged) > 0 {
			last := &merged[len(merged)-1]
			if last.Sink.File == hit.Sink.File && last.Sink.Type == hit.Sink.Type && hit.Sink.Line-last.Sink.Line <= 5 {
				for _, source := range hit.Sources {
					if !hasSource(last.Sources, source) {
						last.Sources = append(last.Sources, source)
					}
				}
				if last.CWE == "" {
					last.CWE = hit.CWE
				}
				if impactRank(hit.Impact) > impactRank(last.Impact) {
					last.Impact = hit.Impact
				}
				last.Evidence = appendUnique(last.Evidence, hit.Evidence...)
				last.Chain = appendUnique(last.Chain, hit.Chain...)
				if last.Rationale == "" || len(hit.Rationale) > len(last.Rationale) {
					last.Rationale = hit.Rationale
				}
				if last.SuspectedVulnClass == "" {
					last.SuspectedVulnClass = hit.SuspectedVulnClass
				}
				continue
			}
		}
		merged = append(merged, hit)
	}
	for i := range merged {
		merged[i].ID = fmt.Sprintf("C-%04d", i+1)
	}
	return merged
}

func appendUnique(values []string, additions ...string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		seen[value] = true
	}
	for _, value := range additions {
		if value != "" && !seen[value] {
			values = append(values, value)
			seen[value] = true
		}
	}
	return values
}

func impactRank(impact string) int {
	switch impact {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func hasSource(sources []Source, want Source) bool {
	for _, source := range sources {
		if source == want {
			return true
		}
	}
	return false
}
