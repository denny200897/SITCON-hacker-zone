package triage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aegis-dev/aegis/internal/candidates"
	"github.com/aegis-dev/aegis/internal/inventory"
)

func TestAssessRubricAllDistancesAndUnknown(t *testing.T) {
	tests := []struct {
		name, want string
		evidence   RubricEvidence
	}{
		{"D0", "D0", RubricEvidence{DefaultFlow: true, DefaultAt: "app.py:10"}},
		{"D1", "D1", RubricEvidence{NonDefaultFlow: true, NonDefaultAt: "app.py:11"}},
		{"D2", "D2", RubricEvidence{ThinWiring: true, ThinWiringAt: "app.py:12"}},
		{"D3", "D3", RubricEvidence{Uncalled: true, UncalledAt: "app.py:13"}},
		{"unsupported", "UNKNOWN", RubricEvidence{DefaultFlow: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Assess("C-0001", "high", test.evidence)
			if got.Reachability != test.want {
				t.Fatalf("got %#v", got)
			}
			if test.want == "UNKNOWN" && got.Priority != "low" {
				t.Fatalf("UNKNOWN must be low priority: %#v", got)
			}
		})
	}
}

func TestEvaluateAtDistinguishesRouteFlowFromUnrelatedRoute(t *testing.T) {
	dir := t.TempDir()
	source := "@app.get('/users')\ndef users():\n    query = 'select ' + input()\n    return query\n\ndef helper():\n    query = 'select ' + input()\n    return query\n"
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	inv := &inventory.Inventory{Routes: []inventory.Route{{HandlerFile: "app.py", HandlerSymbol: "users", HandlerLine: 1}}}
	c := candidates.Candidate{ID: "C-0001", SuspectedVulnClass: "sqli", Sink: candidates.Sink{File: "app.py", Line: 3, Type: "sql.concat"}, PriorityHint: "high"}
	if got := EvaluateAt(c, inv, dir); got.Reachability != "D0" {
		t.Fatalf("route flow: %#v", got)
	}
	c.Sink.Line = 7
	if got := EvaluateAt(c, inv, dir); got.Reachability != "D2" {
		t.Fatalf("unrelated route: %#v", got)
	}
}

func TestSeverityMatrixAndConfidence(t *testing.T) {
	tests := []struct{ impact, distance, want string }{
		{"high", "D0", "critical"}, {"high", "D1", "critical"}, {"high", "D2", "high"}, {"high", "D3", "medium"}, {"high", "UNKNOWN", "medium"},
		{"medium", "D0", "high"}, {"medium", "D1", "high"}, {"medium", "D2", "medium"}, {"medium", "D3", "low"},
	}
	for _, test := range tests {
		if got := Severity(test.impact, test.distance); got != test.want {
			t.Errorf("%s/%s: %s", test.impact, test.distance, got)
		}
	}
	if got := Confidence("PROVEN", "direct", 2, 2); got != 0.85 {
		t.Fatalf("direct confidence %v", got)
	}
	if got := Confidence("PROVEN", "witness", 0, 2); got != 0.65 {
		t.Fatalf("witness confidence %v", got)
	}
	if got := Confidence("NOT_PROVEN", "witness", 0, 0); got != 0.20 {
		t.Fatalf("not proven %v", got)
	}
}
