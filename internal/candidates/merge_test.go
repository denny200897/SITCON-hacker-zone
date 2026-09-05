package candidates

import "testing"

func TestMergeDeduplicatesNearbyHitsAndRetainsSources(t *testing.T) {
	a := Candidate{Sink: Sink{File: "app.py", Line: 10, Type: "sql.concat"}, Sources: []Source{{Origin: "semgrep", Rule: "a"}}}
	b := Candidate{Sink: Sink{File: "app.py", Line: 14, Type: "sql.concat"}, Sources: []Source{{Origin: "semgrep", Rule: "b"}}}
	c := Candidate{Sink: Sink{File: "app.py", Line: 30, Type: "sql.concat"}, Sources: []Source{{Origin: "semgrep", Rule: "a"}}}
	got := Merge([]Candidate{c, a}, []Candidate{b})
	if len(got) != 2 || got[0].ID != "C-0001" || got[1].ID != "C-0002" {
		t.Fatalf("unexpected merge: %#v", got)
	}
	if len(got[0].Sources) != 2 {
		t.Fatalf("provenance lost: %#v", got[0].Sources)
	}
}

func TestMergeRetainsLLMGlobalEvidenceWhenSemgrepAlsoMatches(t *testing.T) {
	semgrep := Candidate{Sink: Sink{File: "app.py", Line: 10, Type: "sql.concat"}, Sources: []Source{{Origin: "semgrep"}}}
	llm := Candidate{Sink: Sink{File: "app.py", Line: 12, Type: "sql.concat"}, Sources: []Source{{Origin: "llm"}},
		CWE: "CWE-89", Impact: "high", Evidence: []string{"routes.py:8", "app.py:12"},
		Chain: []string{"HTTP parameter", "query builder", "SQL execute"}, Rationale: "cross-file tainted SQL flow"}
	got := Merge([]Candidate{semgrep}, []Candidate{llm})
	if len(got) != 1 || got[0].CWE != "CWE-89" || got[0].Impact != "high" || len(got[0].Evidence) != 2 || len(got[0].Chain) != 3 {
		t.Fatalf("LLM evidence lost during merge: %#v", got)
	}
}
