package triage

import (
	"github.com/aegis-dev/aegis/internal/candidates"
	"github.com/aegis-dev/aegis/internal/inventory"
	"testing"
)

func TestEvaluateRouteAndMissingLink(t *testing.T) {
	c := candidates.Candidate{ID: "C-0001", SuspectedVulnClass: "sqli", Sink: candidates.Sink{File: "app.py", Line: 4, Type: "sql.concat"}, PriorityHint: "high"}
	got := Evaluate(c, &inventory.Inventory{Routes: []inventory.Route{{HandlerFile: "app.py", Method: "GET", Path: "/users"}}})
	if got.Verdict != "PROCEED" || got.Reachability != "D2" || got.Mode != "witness" {
		t.Fatalf("route result: %#v", got)
	}
	got = Evaluate(c, &inventory.Inventory{})
	if got.Verdict != "FALSE_POSITIVE" || len(got.MissingLinks) != 1 {
		t.Fatalf("missing result: %#v", got)
	}
}
