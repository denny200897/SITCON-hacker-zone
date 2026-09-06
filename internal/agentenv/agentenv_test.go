package agentenv

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseRequiresNonceAndRejectsUnknownFields(t *testing.T) {
	// Missing {{NONCE}} in the exploit → rejected (oracle could never fire).
	noNonce := `{"dockerfile":"FROM scratch\nCMD [\"x\"]","app_port":8000,
		"exploit":{"method":"GET","path":"/search?q=hello"},
		"oracle":{"kind":"reflected_nonce"}}`
	if _, err := Parse([]byte(noNonce)); err == nil {
		t.Fatal("expected error when exploit carries no {{NONCE}}")
	}

	// Unknown field → rejected.
	unknown := `{"dockerfile":"FROM scratch\nCMD [\"x\"]","app_port":8000,"wat":1,
		"exploit":{"method":"GET","path":"/?q={{NONCE}}"},"oracle":{"kind":"reflected_nonce"}}`
	if _, err := Parse([]byte(unknown)); err == nil {
		t.Fatal("expected error on unknown field")
	}

	ok := `{"dockerfile":"FROM python:3.12-slim\nCMD [\"python\",\"-V\"]","app_port":8000,
		"exploit":{"method":"POST","path":"/login","body":"user=a&note={{NONCE}}"},
		"oracle":{"kind":"log_nonce"}}`
	s, err := Parse([]byte(ok))
	if err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}
	if s.readyPath() != "/" {
		t.Fatalf("default ready path = %q, want /", s.readyPath())
	}
}

func TestWithNonceSubstitutes(t *testing.T) {
	e := Exploit{Method: "POST", Path: "/x?q={{NONCE}}", Body: "b={{NONCE}}",
		Headers: map[string]string{"X-Test": "v-{{NONCE}}"}}
	got := e.withNonce("N123")
	if got.Path != "/x?q=N123" || got.Body != "b=N123" || got.Headers["X-Test"] != "v-N123" {
		t.Fatalf("substitution wrong: %+v", got)
	}
}

// End-to-end: build a tiny app that reflects ?q= into its response, run it on
// an isolated network, exploit it, and require the trusted oracle to observe
// the nonce. Skipped unless AEGIS_DOCKER_TEST=1 and Docker is available, since
// it pulls base images and runs containers.
func TestProveReflectedNonceEndToEnd(t *testing.T) {
	if os.Getenv("AEGIS_DOCKER_TEST") != "1" {
		t.Skip("set AEGIS_DOCKER_TEST=1 to run the Docker end-to-end proof")
	}
	r := &Runner{HelperImage: "curlimages/curl:latest"}
	if err := r.Available(); err != nil {
		t.Skipf("docker unavailable: %v", err)
	}

	ctxDir := t.TempDir()
	// A stdlib-only HTTP server that reflects the q parameter — no pip needed.
	app := `import http.server, urllib.parse
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("q", [""])[0]
        self.send_response(200); self.end_headers()
        self.wfile.write(("reflected: " + q).encode())
    def log_message(self, *a): pass
http.server.HTTPServer(("0.0.0.0", 8000), H).serve_forever()
`
	if err := os.WriteFile(filepath.Join(ctxDir, "app.py"), []byte(app), 0o644); err != nil {
		t.Fatal(err)
	}

	spec := Spec{
		Dockerfile: "FROM python:3.12-slim\nWORKDIR /app\nCOPY app.py .\nCMD [\"python\",\"app.py\"]\n",
		AppPort:    8000,
		ReadyPath:  "/",
		Exploit:    Exploit{Method: "GET", Path: "/?q={{NONCE}}"},
		Oracle:     Oracle{Kind: OracleReflectedNonce},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	nonce := "AEGIS_NONCE_7f3c2a"
	res, err := r.Prove(ctx, "test-run-1", ctxDir, spec, nonce, t.TempDir())
	if err != nil {
		t.Fatalf("Prove error: %v", err)
	}
	if !res.Proven {
		t.Fatalf("expected PROVEN; reason=%q buildTail=%q logTail=%q respTail=%q",
			res.Reason, res.BuildLogTail, res.LogTail, res.ResponseTail)
	}
	if len(res.EvidenceRefs) == 0 || !strings.Contains(res.ResponseTail, nonce) {
		t.Fatalf("weak proof: refs=%v respTail=%q", res.EvidenceRefs, res.ResponseTail)
	}
}
