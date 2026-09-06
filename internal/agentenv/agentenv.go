package agentenv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/aegis-dev/aegis/internal/oracles"
)

// Runner builds and exploits agent-authored target environments with Docker.
type Runner struct {
	// Bin is the docker executable ("docker" when empty).
	Bin string
	// HelperImage is a pinned image whose `curl` drives the exploit and
	// readiness probe. It must have curl on PATH (e.g. curlimages/curl@sha256…).
	HelperImage string
	// BuildNetwork is the docker network mode for `docker build` ("default"
	// allows dependency downloads; "none" forbids all build-time network).
	BuildNetwork string

	BuildTimeout   time.Duration
	ReadyTimeout   time.Duration
	ExploitTimeout time.Duration
	Memory         string // e.g. "512m"
	CPUs           string // e.g. "1.0"
	Pids           int    // pids-limit
}

// Result is the outcome of a proof attempt. Proven is true only when the
// trusted nonce oracle observed the run nonce.
type Result struct {
	Proven       bool
	OracleKind   string
	EvidenceRefs []string
	ResponseTail string
	LogTail      string
	BuildLogTail string
	// Reason explains a non-proof (build failed, app never came up, oracle miss).
	Reason string
}

func (r *Runner) bin() string {
	if r.Bin != "" {
		return r.Bin
	}
	return "docker"
}

func (r *Runner) buildNet() string {
	if r.BuildNetwork != "" {
		return r.BuildNetwork
	}
	return "default"
}

func (r *Runner) defaults() {
	if r.BuildTimeout == 0 {
		r.BuildTimeout = 6 * time.Minute
	}
	if r.ReadyTimeout == 0 {
		r.ReadyTimeout = 60 * time.Second
	}
	if r.ExploitTimeout == 0 {
		r.ExploitTimeout = 20 * time.Second
	}
	if r.Memory == "" {
		r.Memory = "512m"
	}
	if r.CPUs == "" {
		r.CPUs = "1.0"
	}
	if r.Pids == 0 {
		r.Pids = 256
	}
}

// Available reports whether docker is usable (daemon reachable).
func (r *Runner) Available() error {
	_, _, err := r.docker(context.Background(), 15*time.Second, nil, "info", "--format", "{{.ServerVersion}}")
	if err != nil {
		return fmt.Errorf("agentenv: docker not available: %w", err)
	}
	return nil
}

// Prove builds the agent's environment, runs it isolated, sends one exploit
// carrying the nonce, and returns PROVEN only if the trusted oracle observes
// that nonce. contextDir is the docker build context (the immutable snapshot);
// artifactsDir is where the captured response/log JSONL is written for the
// oracle. All Docker objects created here are labelled with runID and removed
// before returning.
func (r *Runner) Prove(ctx context.Context, runID, contextDir string, spec Spec, nonce, artifactsDir string) (Result, error) {
	r.defaults()
	if r.HelperImage == "" {
		return Result{}, fmt.Errorf("agentenv: HelperImage (a curl-capable pinned image) is required")
	}
	if nonce == "" {
		return Result{}, fmt.Errorf("agentenv: nonce must not be empty")
	}
	if err := os.MkdirAll(artifactsDir, 0o700); err != nil {
		return Result{}, fmt.Errorf("agentenv: artifacts dir: %w", err)
	}

	image := "aegis-agentenv-" + sanitize(runID)
	network := "aegis-net-" + sanitize(runID)
	appName := "aegis-app-" + sanitize(runID)
	label := "aegis-run=" + runID

	// Everything created below is torn down here, success or failure.
	defer r.cleanup(image, network, appName, label)

	// 1) Build the agent's image (network allowed, approval is upstream).
	buildOut, _, err := r.docker(ctx, r.BuildTimeout, []byte(spec.Dockerfile),
		"build", "--network", r.buildNet(), "--memory", r.Memory,
		"--label", label, "-t", image, "-f", "-", contextDir)
	buildTail := tail(buildOut, 2000)
	if err != nil {
		return Result{BuildLogTail: buildTail, Reason: "image build failed"}, nil
	}

	// 2) Private, egress-less network for run + exploit.
	if _, stderr, err := r.docker(ctx, 30*time.Second, nil,
		"network", "create", "--internal", "--label", label, network); err != nil {
		return Result{BuildLogTail: buildTail, Reason: "could not create isolated network: " + tail(stderr, 400)}, nil
	}

	// 3) Start the app, capabilities dropped and resource-limited.
	cidOut, stderr, err := r.docker(ctx, 60*time.Second, nil,
		"run", "-d", "--name", appName, "--hostname", "app",
		"--network", network, "--label", label,
		"--memory", r.Memory, "--cpus", r.CPUs, "--pids-limit", fmt.Sprint(r.Pids),
		"--security-opt", "no-new-privileges", "--cap-drop", "ALL",
		image)
	if err != nil {
		return Result{BuildLogTail: buildTail, Reason: "app container failed to start: " + tail(stderr, 400)}, nil
	}
	cid := strings.TrimSpace(string(cidOut))

	// 4) Wait until the app answers on its port (or give up with its logs).
	if !r.waitReady(ctx, network, spec.AppPort, spec.readyPath()) {
		logTail := r.appLogs(ctx, cid)
		return Result{BuildLogTail: buildTail, LogTail: logTail,
			Reason: "app did not become ready on port " + fmt.Sprint(spec.AppPort)}, nil
	}

	// 5) Fire the single exploit request from the pinned helper.
	exploit := spec.Exploit.withNonce(nonce)
	body, xErr := r.sendExploit(ctx, network, spec.AppPort, exploit)
	logTail := r.appLogs(ctx, cid)
	if xErr != nil {
		return Result{BuildLogTail: buildTail, LogTail: logTail,
			Reason: "exploit request failed: " + xErr.Error()}, nil
	}

	// 6) Capture artifacts and let the trusted oracle decide.
	cond, artifact, content := r.oracleInputs(spec.Oracle.Kind, body, logTail)
	if err := os.WriteFile(filepath.Join(artifactsDir, artifact), content, 0o600); err != nil {
		return Result{}, fmt.Errorf("agentenv: write artifact: %w", err)
	}
	oracleRes, err := oracles.Check(cond, nonce, artifactsDir)
	if err != nil {
		return Result{}, fmt.Errorf("agentenv: oracle check: %w", err)
	}

	res := Result{
		Proven:       oracleRes.Result,
		OracleKind:   spec.Oracle.Kind,
		EvidenceRefs: oracleRes.EvidenceRefs,
		ResponseTail: tail([]byte(body), 1000),
		LogTail:      logTail,
		BuildLogTail: buildTail,
	}
	if !res.Proven {
		res.Reason = "nonce not observed by the " + spec.Oracle.Kind + " oracle"
	}
	return res, nil
}

// oracleInputs maps the spec's oracle kind onto a trusted oracles.Condition and
// the JSONL artifact the exploit produced.
// oracleInputs maps the spec's oracle kind onto a trusted oracles.Condition and
// the captured JSONL artifact. Both kinds use canary_file_match, which fires
// when the run nonce appears in any string field of the captured output — the
// SQL-specific nonce_in_field kind is intentionally not reused here.
func (r *Runner) oracleInputs(kind, body, logs string) (cond oracles.Condition, artifact string, content []byte) {
	switch kind {
	case OracleLogNonce:
		line, _ := json.Marshal(map[string]string{"log": logs})
		return oracles.Condition{Kind: oracles.KindCanaryFileMatch, Artifact: "applog.jsonl"},
			"applog.jsonl", append(line, '\n')
	default: // reflected_nonce
		line, _ := json.Marshal(map[string]string{"body": body})
		return oracles.Condition{Kind: oracles.KindCanaryFileMatch, Artifact: "response.jsonl"},
			"response.jsonl", append(line, '\n')
	}
}

func (r *Runner) waitReady(ctx context.Context, network string, port int, path string) bool {
	deadline := time.Now().Add(r.ReadyTimeout)
	url := fmt.Sprintf("http://app:%d%s", port, path)
	for time.Now().Before(deadline) {
		if _, _, err := r.docker(ctx, 8*time.Second, nil,
			"run", "--rm", "--network", network, "--entrypoint", "curl",
			r.HelperImage, "-sS", "-m", "4", "-o", "/dev/null", url); err == nil {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Second):
		}
	}
	return false
}

func (r *Runner) sendExploit(ctx context.Context, network string, port int, e Exploit) (string, error) {
	url := fmt.Sprintf("http://app:%d%s", port, e.Path)
	args := []string{"run", "--rm", "--network", network, "--entrypoint", "curl",
		r.HelperImage, "-sS", "-m", fmt.Sprint(int(r.ExploitTimeout.Seconds()))}
	if e.Method == "POST" {
		args = append(args, "-X", "POST")
		if e.Body != "" {
			args = append(args, "--data-raw", e.Body)
		}
	}
	for k, v := range e.Headers {
		args = append(args, "-H", k+": "+v)
	}
	args = append(args, url)
	stdout, stderr, err := r.docker(ctx, r.ExploitTimeout+10*time.Second, nil, args...)
	if err != nil {
		return string(stdout), fmt.Errorf("%v: %s", err, tail(stderr, 300))
	}
	return string(stdout), nil
}

func (r *Runner) appLogs(ctx context.Context, cid string) string {
	if cid == "" {
		return ""
	}
	stdout, stderr, _ := r.docker(ctx, 15*time.Second, nil, "logs", "--tail", "200", cid)
	return tail(append(append([]byte{}, stdout...), stderr...), 4000)
}

func (r *Runner) cleanup(image, network, appName, label string) {
	ctx := context.Background()
	_, _, _ = r.docker(ctx, 30*time.Second, nil, "rm", "-f", appName)
	// Sweep anything else that carried our label, then the network and image.
	if out, _, err := r.docker(ctx, 15*time.Second, nil, "ps", "-aq", "--filter", "label="+label); err == nil {
		for _, id := range strings.Fields(string(out)) {
			_, _, _ = r.docker(ctx, 20*time.Second, nil, "rm", "-f", id)
		}
	}
	_, _, _ = r.docker(ctx, 20*time.Second, nil, "network", "rm", network)
	_, _, _ = r.docker(ctx, 30*time.Second, nil, "image", "rm", "-f", image)
}

// docker runs one docker subcommand with a timeout, returning stdout/stderr.
func (r *Runner) docker(ctx context.Context, timeout time.Duration, stdin []byte, args ...string) (stdout, stderr []byte, err error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, r.bin(), args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return outBuf.Bytes(), errBuf.Bytes(), err
}

// sanitize keeps a run id safe for docker object names.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := b.String()
	if len(out) > 48 {
		out = out[:48]
	}
	return out
}

func tail(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
