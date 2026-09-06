package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aegis-dev/aegis/internal/agent"
	"github.com/aegis-dev/aegis/internal/agentenv"
	"github.com/aegis-dev/aegis/internal/approval"
	"github.com/aegis-dev/aegis/internal/llm"
	"github.com/aegis-dev/aegis/internal/reporting"
	"github.com/aegis-dev/aegis/internal/schemav"
)

// TestAgentEnvProveFullPathEndToEnd exercises the whole agent-built-environment
// prove path a review takes — the tool gate (submit_environment_spec), operator
// approval, the real Docker build/run/exploit, and the trusted oracle — with the
// LLM's move scripted (a stub adapter returns the environment spec). Requires
// Docker; set AEGIS_DOCKER_TEST=1 to run.
func TestAgentEnvProveFullPathEndToEnd(t *testing.T) {
	if os.Getenv("AEGIS_DOCKER_TEST") != "1" {
		t.Skip("set AEGIS_DOCKER_TEST=1 to run the Docker end-to-end prove path")
	}
	runner := &agentenv.Runner{HelperImage: "curlimages/curl:latest"}
	if err := runner.Available(); err != nil {
		t.Skipf("docker unavailable: %v", err)
	}

	schemasDir, err := projectSchemasDir()
	if err != nil {
		t.Fatal(err)
	}
	registry := schemav.New()
	if err := registry.LoadDir(schemasDir); err != nil {
		t.Fatal(err)
	}
	toolsSchema, err := os.ReadFile(filepath.Join(schemasDir, "tools.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	envSchema, err := os.ReadFile(filepath.Join(schemasDir, "environment_spec.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	toolDefs, err := agent.NewEnvToolDefs(toolsSchema, envSchema, map[string]string{
		"read_code": "read", "search_code": "search", "submit_environment_spec": "submit",
	})
	if err != nil {
		t.Fatal(err)
	}
	audit, err := agent.OpenAuditLog(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()

	// A snapshot whose app reflects the q parameter — a stand-in for a reflected
	// input vulnerability.
	snap := t.TempDir()
	app := `import http.server, urllib.parse
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("q", [""])[0]
        self.send_response(200); self.end_headers()
        self.wfile.write(("reflected: " + q).encode())
    def log_message(self, *a): pass
http.server.HTTPServer(("0.0.0.0", 8000), H).serve_forever()
`
	if err := os.WriteFile(filepath.Join(snap, "app.py"), []byte(app), 0o644); err != nil {
		t.Fatal(err)
	}

	// The scripted "LLM": first it submits the environment spec, then it ends.
	spec := `{"dockerfile":"FROM python:3.12-slim\nWORKDIR /app\nCOPY app.py .\nCMD [\"python\",\"app.py\"]\n","app_port":8000,"ready_path":"/","exploit":{"method":"GET","path":"/?q={{NONCE}}"},"oracle":{"kind":"reflected_nonce"}}`
	adapter := &sequenceRoleAdapter{responses: []llm.Response{
		{StopReason: llm.StopToolUse, Content: []llm.ContentBlock{
			{Type: "tool_use", ToolUse: &llm.ToolUse{ID: "t1", Name: "submit_environment_spec", Input: []byte(spec)}},
		}},
		{StopReason: llm.StopEndTurn, Content: []llm.ContentBlock{{Type: "text", Text: "done"}}},
	}}

	// Operator auto-approves the build.
	ctx := approval.WithApprover(context.Background(), func(approval.BuildRequest) (approval.Decision, error) {
		return approval.AllowOnce, nil
	})
	ctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()

	finding := reporting.Finding{
		"id": "F-0001", "snapshot_id": "snap",
		"sink": map[string]any{"type": "reflected_input", "file": "app.py", "line": float64(5)},
	}

	res, reason := proveOneWithAgentEnv(ctx, io.Discard, runner, adapter, "test-model",
		registry, toolDefs, audit, t.TempDir(), snap, "F-0001", finding, "code context", false)
	if res == nil || !res.Proven {
		t.Fatalf("expected PROVEN through the full path; reason=%q res=%+v", reason, res)
	}
	if res.OracleKind != agentenv.OracleReflectedNonce || len(res.EvidenceRefs) == 0 {
		t.Fatalf("weak proof: %+v", res)
	}
}
