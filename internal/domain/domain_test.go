package domain

import "testing"

func TestFormatIDZeroPad4(t *testing.T) {
	if got := FormatID("F", 7); got != "F-0007" {
		t.Fatalf("got %s", got)
	}
	if got := FormatID("EV", 1234); got != "EV-1234" {
		t.Fatalf("got %s", got)
	}
}

func TestParseIDRoundTrip(t *testing.T) {
	for _, id := range []string{"F-0007", "EV-0031", "R-0042", "GR-0012"} {
		p, n, err := ParseID(id)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if FormatID(p, n) != id {
			t.Fatalf("%s round trip failed: %s-%04d", id, p, n)
		}
	}
}

func TestParseIDRejectsBad(t *testing.T) {
	for _, id := range []string{"", "F", "F007", "F-", "XX-0007", "F-abc", "F-7"} {
		if _, _, err := ParseID(id); err == nil {
			t.Fatalf("expected error for %q", id)
		}
	}
}

func TestExitClassifies(t *testing.T) {
	cases := map[int]FailureClass{
		0:   "",
		2:   FailureHarness,
		3:   FailureHarness,
		124: FailureEnv,
		125: FailureEnv,
		126: FailureEnv,
		127: FailureEnv,
		9:   FailureEnv, // 非閉集碼守門歸 env
	}
	for code, want := range cases {
		if got := ExitClassifies(code); got != want {
			t.Fatalf("ExitClassifies(%d) = %q want %q", code, got, want)
		}
	}
}

func TestJournalEventTypesClosed(t *testing.T) {
	// §21.3 閉集：恰好 17 個
	if len(JournalEventTypes) != 17 {
		t.Fatalf("event types count changed: %d", len(JournalEventTypes))
	}
	if !IsJournalEventType("witness_spec_rejected") {
		t.Fatal("missing known type")
	}
	if IsJournalEventType("made_up_event") {
		t.Fatal("invented event type accepted")
	}
}