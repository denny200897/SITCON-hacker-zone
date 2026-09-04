// Package agent 實作 AgentRuntime 與工具閘（SPEC §18.1）。
//
// 兩條 per-turn 閘（§18.1：拿掉即違反不變式 1）：
//  (a) 每個 tool call 前做路徑政策與白名單檢查並記 audit log；
//  (b) submit_witness_spec 前做 schema 驗證 + §17.2 placeholder 檢查 + 核可。
//
// audit log 為獨立 JSONL 串流（<runDir>/audit.jsonl），不佔用 §21.3 journal
// 事件閉集；每筆記 role／tool／args／decision（allowed|denied|error）。
package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/aegis-dev/aegis/internal/llm"
	"github.com/aegis-dev/aegis/internal/redaction"
)

// ---- 角色工具白名單（§18.1 閉集） ----

// Whitelist 依角色閉集：recon/reviewer/triager 三個讀取工具；prover 加
// submit_witness_spec；reporter 只有 read_code。所有角色都沒有 shell／寫檔工具。
var Whitelist = map[llm.Role][]string{
	llm.RoleRecon:    {"read_code", "search_code", "semgrep"},
	llm.RoleReviewer: {"read_code", "search_code", "semgrep"},
	llm.RoleTriager:  {"read_code", "search_code", "semgrep"},
	llm.RoleProver:   {"read_code", "search_code", "semgrep", "submit_witness_spec"},
	llm.RoleReporter: {"read_code"},
}

// HasWhitelist 檢查白名單成員（未知角色一律 false）。
func HasWhitelist(role llm.Role, tool string) bool {
	for _, t := range Whitelist[role] {
		if t == tool {
			return true
		}
	}
	return false
}

// ---- audit log ----

// AuditDecision 是審查決定閉集。
type AuditDecision string

const (
	AuditAllowed AuditDecision = "allowed"
	AuditDenied  AuditDecision = "denied"
	AuditError   AuditDecision = "error"
)

// AuditEntry 是一筆 tool call 稽核記錄（JSONL 逐行）。
type AuditEntry struct {
	Ts       string          `json:"ts"`
	Role     string          `json:"role"`
	Tool     string          `json:"tool"`
	Args     json.RawMessage `json:"args"`
	Decision AuditDecision   `json:"decision"`
	Reason   string          `json:"reason,omitempty"`
}

// AuditLog 是 append-only 的 audit.jsonl。
type AuditLog struct {
	f *os.File
}

// OpenAuditLog 開啟（或建立）<runDir>/audit.jsonl 以附加寫入。
func OpenAuditLog(runDir string) (*AuditLog, error) {
	f, err := os.OpenFile(runDir+"/audit.jsonl", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("agent: 開啟 audit log: %w", err)
	}
	return &AuditLog{f: f}, nil
}

// Append records and flushes one entry. Audit is a security boundary: callers
// must fail closed when this method returns an error.
func (a *AuditLog) Append(role llm.Role, tool string, args json.RawMessage, d AuditDecision, reason string) error {
	if a == nil || a.f == nil {
		return fmt.Errorf("agent: audit log unavailable")
	}
	if args == nil {
		args = json.RawMessage("null")
	}
	if redaction.HasSecret(string(args)) || redaction.HasSecret(reason) {
		return fmt.Errorf("agent: audit persistence denied by secret gate")
	}
	e := AuditEntry{Ts: time.Now().UTC().Format(time.RFC3339Nano), Role: string(role),
		Tool: tool, Args: args, Decision: d, Reason: reason}
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("agent: encode audit entry: %w", err)
	}
	if _, err := a.f.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("agent: write audit entry: %w", err)
	}
	if err := a.f.Sync(); err != nil {
		return fmt.Errorf("agent: sync audit entry: %w", err)
	}
	return nil
}

// Close 關閉檔案。
func (a *AuditLog) Close() error {
	if a == nil || a.f == nil {
		return nil
	}
	return a.f.Close()
}
