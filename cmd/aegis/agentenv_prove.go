package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aegis-dev/aegis/internal/agent"
	"github.com/aegis-dev/aegis/internal/agentenv"
	"github.com/aegis-dev/aegis/internal/approval"
	"github.com/aegis-dev/aegis/internal/llm"
	"github.com/aegis-dev/aegis/internal/reporting"
	"github.com/aegis-dev/aegis/internal/schemav"
)

// agentEnvHelperImage is the pinned, curl-capable image that drives the
// readiness probe and the single exploit request from inside the isolated
// network. Override with AEGIS_AGENTENV_HELPER (prefer a @sha256 digest).
const agentEnvHelperImage = "curlimages/curl:8.11.0"

// agentEnvMaxAttempts caps how many build+exploit cycles one finding may use;
// each cycle is an expensive Docker build, so the budget is small.
const agentEnvMaxAttempts = 3

func helperImage() string {
	if v := os.Getenv("AEGIS_AGENTENV_HELPER"); v != "" {
		return v
	}
	return agentEnvHelperImage
}

func newNonce() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return "AEGIS-" + hex.EncodeToString(b[:])
}

const envProverSystem = `You are a security prover. A candidate vulnerability was reported in a code snapshot. Your job is to PROVE it is real by standing the target up in Docker and exploiting it — never by asserting it.

Use read_code and search_code to understand how the vulnerable code is reached (routes, handlers, how input flows to the sink). Then call submit_environment_spec exactly once with:
- dockerfile: a complete Dockerfile that builds the app FROM the snapshot (the build context is the repo root; COPY the source in, install deps, and start the app listening on app_port). Keep it minimal and correct.
- app_port + ready_path: where the app listens and a path that returns once it is up.
- exploit: a single HTTP request whose path or body contains the literal {{NONCE}} placeholder, sent to the vulnerable endpoint so the nonce reaches the sink.
- oracle: reflected_nonce if the nonce comes back in the response, or log_nonce if it appears in the app's logs.

The harness will build the image (after operator approval), run it on an isolated network with no internet access, send your exploit, and let a trusted oracle look for the nonce. If it is not PROVEN you will get feedback; revise the Dockerfile/exploit and submit again. Do not claim success yourself — only the oracle decides.`

// runAgentEnvProve attempts to prove each not-yet-PROVEN finding by having the
// prover model author a Docker build+exploit recipe (agent-built environment),
// gated by operator approval. It updates findings in place and reports how many
// it proved. Findings already PROVEN by the pinned pack flow are left untouched.
func runAgentEnvProve(ctx context.Context, out io.Writer, runDir, scanRoot string, findings []reporting.Finding, watch bool) (int, error) {
	// Which findings still need proving?
	var pending []int
	for i, f := range findings {
		if strings.ToUpper(stringValue(f["verification"])) != "PROVEN" {
			pending = append(pending, i)
		}
	}
	if len(pending) == 0 {
		return 0, nil
	}

	runner := &agentenv.Runner{HelperImage: helperImage()}
	if err := runner.Available(); err != nil {
		fmt.Fprintf(out, "○ agent-built proof skipped — %v\n", err)
		return 0, nil
	}

	adapter, model, err := proverAdapter(scanRoot)
	if err != nil {
		fmt.Fprintf(out, "○ agent-built proof skipped — %v\n", err)
		return 0, nil
	}
	schemasDir, err := projectSchemasDir()
	if err != nil {
		return 0, err
	}
	toolsSchema, err := os.ReadFile(filepath.Join(schemasDir, "tools.schema.json"))
	if err != nil {
		return 0, err
	}
	envSchema, err := os.ReadFile(filepath.Join(schemasDir, "environment_spec.schema.json"))
	if err != nil {
		return 0, err
	}
	toolDefs, err := agent.NewEnvToolDefs(toolsSchema, envSchema, map[string]string{
		"read_code":               "read a file and line range inside the snapshot (read-only)",
		"search_code":             "search the snapshot with RE2 (read-only)",
		"submit_environment_spec": "submit a Dockerfile + exploit that proves the vulnerability by building and running the target",
	})
	if err != nil {
		return 0, err
	}
	registry := schemav.New()
	if err := registry.LoadDir(schemasDir); err != nil {
		return 0, err
	}
	cacheDir, err := snapshotCacheDir()
	if err != nil {
		return 0, err
	}
	audit, err := agent.OpenAuditLog(runDir)
	if err != nil {
		return 0, err
	}
	defer audit.Close()

	fmt.Fprintf(out, "\n→ agent-built environment: attempting %d finding(s) that lack a pinned oracle\n", len(pending))
	proven := 0
	for _, idx := range pending {
		finding := findings[idx]
		findingID := stringValue(finding["id"])
		snapshotID := stringValue(finding["snapshot_id"])
		snapshotDir := filepath.Join(cacheDir, "snapshots", snapshotID)
		if stat, statErr := os.Stat(snapshotDir); statErr != nil || !stat.IsDir() {
			fmt.Fprintf(out, "  ○ %s — snapshot missing, skipped\n", findingID)
			continue
		}
		sink := mapValue(finding["sink"])
		contextText, _ := sinkContext(snapshotDir, stringValue(sink["file"]), intValue(sink["line"]), 200)

		result, reason := proveOneWithAgentEnv(ctx, out, runner, adapter, model, registry, toolDefs, audit,
			runDir, snapshotDir, findingID, finding, contextText, watch)
		if result != nil && result.Proven {
			finding["verification"] = "PROVEN"
			finding["proof_note"] = "proven by agent-built environment (" + result.OracleKind + " oracle)"
			if len(result.EvidenceRefs) > 0 {
				setEvidenceID(finding, result.EvidenceRefs[0])
			}
			proven++
			fmt.Fprintf(out, "  ✓ %s — PROVEN (agent-built env, %s)\n", findingID, result.OracleKind)
		} else {
			fmt.Fprintf(out, "  ○ %s — not proven (%s)\n", findingID, reason)
		}
	}
	return proven, nil
}

// proveOneWithAgentEnv runs one bounded prover session for a single finding.
func proveOneWithAgentEnv(ctx context.Context, out io.Writer, runner *agentenv.Runner, adapter llm.Adapter, model string,
	registry *schemav.Registry, toolDefs []llm.ToolDef, audit *agent.AuditLog,
	runDir, snapshotDir, findingID string, finding reporting.Finding, contextText string, watch bool) (*agentenv.Result, string) {

	var last *agentenv.Result
	attempts := 0

	tools := &agent.ToolRegistry{SnapshotDir: snapshotDir}
	tools.SetAudit(audit)
	tools.OnSubmitEnv = func(ctx context.Context, spec map[string]any, _ string) (bool, string) {
		attempts++
		data, err := json.Marshal(spec)
		if err != nil {
			return false, "could not serialize spec: " + err.Error()
		}
		if err := registry.Validate("environment_spec", data); err != nil {
			return false, "spec failed schema validation: " + err.Error()
		}
		s, err := agentenv.Parse(data)
		if err != nil {
			return false, err.Error()
		}
		// Operator approval before building anything.
		approver := approval.FromContext(ctx)
		if approver == nil {
			return false, "no operator approval channel; cannot build the environment"
		}
		dec, err := approver(approval.BuildRequest{
			Pack: "(agent-built)", Action: "build+run agent-authored environment",
			Image: firstLine(s.Dockerfile), BuildDir: snapshotDir,
			Network: "build:default", RunNetwork: "none", Recipe: s.Dockerfile,
		})
		if err != nil || dec == approval.Deny {
			return false, "operator declined to build this environment"
		}
		nonce := newNonce()
		artifactsDir := filepath.Join(runDir, "evidence", "agentenv", findingID, fmt.Sprint(attempts))
		if watch {
			fmt.Fprintf(out, "    ⏺ building & exploiting (attempt %d) …\n", attempts)
		}
		res, perr := runner.Prove(ctx, findingID+"-"+fmt.Sprint(attempts), snapshotDir, s, nonce, artifactsDir)
		if perr != nil {
			return false, "sandbox error: " + perr.Error()
		}
		last = &res
		if res.Proven {
			return true, "accepted"
		}
		if attempts >= agentEnvMaxAttempts {
			return false, "budget exhausted after " + fmt.Sprint(attempts) + " attempts; last: " + res.Reason
		}
		return false, "not proven: " + res.Reason + ". Revise the Dockerfile/exploit so the app starts and the nonce reaches the vulnerable sink, then resubmit."
	}

	prompt := fmt.Sprintf("Finding %s. Sink type: %s. Location: %s:%v.\nCode context:\n%s\n\nProve this by building and exploiting the target.",
		findingID, stringValue(mapValue(finding["sink"])["type"]),
		stringValue(mapValue(finding["sink"])["file"]), mapValue(finding["sink"])["line"], contextText)

	rt := &agent.Runtime{Adapter: adapter, Tools: tools, MaxTurns: 12}
	_, _, runErr := rt.Run(ctx, llm.ChatRequest{
		Role: llm.RoleProver, Model: model, Effort: "high", Tools: toolDefs,
		System:   envProverSystem,
		Messages: []llm.Message{{Role: "user", Content: []llm.ContentBlock{{Type: "text", Text: prompt}}}},
	})
	if last != nil {
		if last.Proven {
			return last, ""
		}
		return last, last.Reason
	}
	if runErr != nil {
		return nil, "prover error: " + runErr.Error()
	}
	return nil, "agent submitted no environment"
}

// writeFindings persists findings.json after the agent-built proof pass so the
// report reflects any newly PROVEN findings.
func writeFindings(runDir string, findings []reporting.Finding) error {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(runDir, "findings.json"), append(data, '\n'), 0o644)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
