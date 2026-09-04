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
