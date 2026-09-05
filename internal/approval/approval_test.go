package approval

import (
	"bytes"
	"strings"
	"testing"
)

func TestPromptDefaultsToAllowOnceOnEnter(t *testing.T) {
	var out bytes.Buffer
	got, err := Prompt(strings.NewReader("\n"), &out, BuildRequest{Pack: "go-web", Image: "go@sha256:abc", Action: "build", Network: "pinned", RunNetwork: "none"})
	if err != nil || got != AllowOnce {
		t.Fatalf("decision=%v err=%v", got, err)
	}
	for _, want := range []string{"go-web", "go@sha256:abc", "允許這一次", "按 Enter"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("menu missing %q:\n%s", want, out.String())
		}
	}
}

func TestPromptChoices(t *testing.T) {
	for input, want := range map[string]Decision{"1\n": AllowOnce, "2\n": AllowRun, "3\n": Deny} {
		got, err := Prompt(strings.NewReader(input), &bytes.Buffer{}, BuildRequest{})
		if err != nil || got != want {
			t.Fatalf("input=%q decision=%v err=%v", input, got, err)
		}
	}
}
