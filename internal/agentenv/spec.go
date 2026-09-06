// Package agentenv builds and exploits an agent-authored target environment to
// prove a vulnerability.
//
// The safety model (why this is allowed to run agent-written build recipes):
//   - The BUILD step may reach the network (to install dependencies) but runs
//     only after explicit operator approval, under a memory and time cap.
//   - The RUN and EXPLOIT steps happen on a Docker `--internal` network with no
//     route off the host: the app talks only to our pinned helper, which drives
//     one request and captures the response. Nothing the agent authored can
//     reach the internet during exploitation.
//   - The app container drops all capabilities, gets no-new-privileges, and has
//     memory/CPU/pid limits.
//   - A verdict is never the agent's word: a trusted nonce oracle
//     (internal/oracles) must observe the run's random nonce in the captured
//     response or logs. No nonce, no proof.
package agentenv

import (
	"encoding/json"
	"fmt"
	"strings"
)

// NoncePlaceholder is substituted with the run's random nonce before the
// exploit is sent; the oracle then looks for that exact nonce.
const NoncePlaceholder = "{{NONCE}}"

// Spec is the agent-authored recipe (mirrors schemas/environment_spec.schema.json).
type Spec struct {
	Dockerfile string  `json:"dockerfile"`
	AppPort    int     `json:"app_port"`
	ReadyPath  string  `json:"ready_path,omitempty"`
	Exploit    Exploit `json:"exploit"`
	Oracle     Oracle  `json:"oracle"`
	Rationale  string  `json:"rationale,omitempty"`
}

type Exploit struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

type Oracle struct {
	Kind string `json:"kind"`
}

// Oracle kinds understood by this package.
const (
	OracleReflectedNonce = "reflected_nonce"
	OracleLogNonce       = "log_nonce"
)

// Parse decodes and structurally validates a spec. Schema validation
// (schemas/environment_spec.schema.json) is applied separately by the caller;
// this adds the semantic rule the schema cannot express: the exploit must
// actually carry the nonce, otherwise the oracle can never fire.
func Parse(data []byte) (Spec, error) {
	var s Spec
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Spec{}, fmt.Errorf("agentenv: decode spec: %w", err)
	}
	if err := s.validate(); err != nil {
		return Spec{}, err
	}
	return s, nil
}

func (s Spec) validate() error {
	if len(strings.TrimSpace(s.Dockerfile)) < 20 {
		return fmt.Errorf("agentenv: dockerfile is empty or too short")
	}
	if s.AppPort < 1 || s.AppPort > 65535 {
		return fmt.Errorf("agentenv: app_port %d out of range", s.AppPort)
	}
	switch s.Exploit.Method {
	case "GET", "POST":
	default:
		return fmt.Errorf("agentenv: exploit.method %q must be GET or POST", s.Exploit.Method)
	}
	if s.Exploit.Path == "" {
		return fmt.Errorf("agentenv: exploit.path is required")
	}
	if !strings.HasPrefix(s.Exploit.Path, "/") {
		return fmt.Errorf("agentenv: exploit.path must start with /")
	}
	switch s.Oracle.Kind {
	case OracleReflectedNonce, OracleLogNonce:
	default:
		return fmt.Errorf("agentenv: oracle.kind %q unsupported (want reflected_nonce or log_nonce)", s.Oracle.Kind)
	}
	if !s.carriesNonce() {
		return fmt.Errorf("agentenv: exploit path or body must contain the %s placeholder", NoncePlaceholder)
	}
	return nil
}

// carriesNonce reports whether the placeholder appears anywhere the exploit
// sends data (path, body, or a header value).
func (s Spec) carriesNonce() bool {
	if strings.Contains(s.Exploit.Path, NoncePlaceholder) || strings.Contains(s.Exploit.Body, NoncePlaceholder) {
		return true
	}
	for _, v := range s.Exploit.Headers {
		if strings.Contains(v, NoncePlaceholder) {
			return true
		}
	}
	return false
}

// withNonce returns a copy of the exploit with the placeholder replaced by the
// concrete nonce in the path, body, and header values.
func (e Exploit) withNonce(nonce string) Exploit {
	out := Exploit{
		Method: e.Method,
		Path:   strings.ReplaceAll(e.Path, NoncePlaceholder, nonce),
		Body:   strings.ReplaceAll(e.Body, NoncePlaceholder, nonce),
	}
	if len(e.Headers) > 0 {
		out.Headers = make(map[string]string, len(e.Headers))
		for k, v := range e.Headers {
			out.Headers[k] = strings.ReplaceAll(v, NoncePlaceholder, nonce)
		}
	}
	return out
}

func (s Spec) readyPath() string {
	if s.ReadyPath == "" {
		return "/"
	}
	if !strings.HasPrefix(s.ReadyPath, "/") {
		return "/" + s.ReadyPath
	}
	return s.ReadyPath
}
