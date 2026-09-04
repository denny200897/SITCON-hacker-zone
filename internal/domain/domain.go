// Package domain 定義 Aegis 的核心型別與閉集 enum（SPEC §2.5、§5、§21.2）。
// 不發明新狀態值——reachability／verification／disposition／exit code 全是閉集（§23-4）。
package domain

import (
	"fmt"
	"strconv"
)

// ---- ID 規則（§21.2：journal 統一分配，monotonic、zero-pad 4） ----

// FormatID 以 zero-pad 4 格式化序號（"F-0007"）。
func FormatID(prefix string, n int) string {
	return fmt.Sprintf("%s-%04d", prefix, n)
}

// ParseID 解析 "F-0007" → ("F", 7)、"EV-0031" → ("EV", 31)。
// 前綴限 F／EV／R／GR（§21.2 閉集）。
func ParseID(id string) (prefix string, n int, err error) {
	for i := 0; i < len(id); i++ {
		if id[i] == '-' {
			prefix, rest := id[:i], id[i+1:]
			switch prefix {
			case "F", "EV", "R", "GR":
			default:
				return "", 0, fmt.Errorf("domain: bad id prefix %q", id)
			}
			if len(rest) != 4 { // §21.2：zero-pad 4
				return "", 0, fmt.Errorf("domain: bad id %q", id)
			}
			n, err = strconv.Atoi(rest)
			if err != nil {
				return "", 0, fmt.Errorf("domain: bad id %q", id)
			}
			return prefix, n, nil
		}
	}
	return "", 0, fmt.Errorf("domain: bad id %q", id)
}

// ---- 三維狀態模型（§2.5：三個獨立維度，合法狀態組合不做交叉限制） ----

// Reachability 是 triage 的結論，與證明結果無關。
type Reachability string

const (
	ReachabilityUnknown Reachability = "UNKNOWN"
	ReachabilityD0      Reachability = "D0"
	ReachabilityD1      Reachability = "D1"
	ReachabilityD2      Reachability = "D2"
	ReachabilityD3      Reachability = "D3"
)

// Verification 是驗證結果。
type Verification string

const (
	VerificationNotRun           Verification = "NOT_RUN"
	VerificationProven           Verification = "PROVEN"
	VerificationHypothesisRej    Verification = "HYPOTHESIS_REJECTED"
	VerificationNotProven        Verification = "NOT_PROVEN"
	VerificationEnvError         Verification = "ENV_ERROR"
)

// Disposition 是人類處置——唯一寫入點是 `aegis report --set-disposition`（§8）。
type Disposition string

const (
	DispositionOpen          Disposition = "OPEN"
	DispositionFalsePositive Disposition = "FALSE_POSITIVE"
	DispositionAcceptedRisk  Disposition = "ACCEPTED_RISK"
	DispositionFixed         Disposition = "FIXED"
)

// Mode：直攻（D0/D1）或見證（D2/D3）。
type Mode string

const (
	ModeDirect  Mode = "direct"
	ModeWitness Mode = "witness"
)

// Severity 由確定性規則綜合 ACD／impact／confidence 計算（§20.2）。
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityNone     Severity = "none"
)

// ---- 失敗分類（§9.1：預算是「試幾種」不是「試幾次」） ----

type FailureClass string

const (
	FailureEnv             FailureClass = "env"
	FailureHarness         FailureClass = "harness"
	FailureUncontrolled    FailureClass = "uncontrolled" // v1 不出現（§9.1）
	FailureControlledMiss  FailureClass = "controlled_miss"
)

// ---- NOT_PROVEN 原因（§9.3 閉集） ----

type NotProvenReason string

const (
	NotProvenHarnessBudget NotProvenReason = "harness_budget"
	NotProvenSandboxBudget NotProvenReason = "sandbox_budget"
	NotProvenOscillation   NotProvenReason = "oscillation"
	NotProvenUserCancelled NotProvenReason = "user_cancelled"
)

// ---- Exit code 契約（§17.1 閉集，orchestrator 依此分類，不得發明新碼） ----

const (
	ExitOK              = 0   // 流程跑完；成功只由 oracle 判定
	ExitServiceNotReady = 2   // harness
	ExitExploitCrashed  = 3   // harness
	ExitTimeout         = 124 // env（host 端強制逾時）
	ExitDockerErr       = 125 // env
	ExitDockerNotFound  = 126 // env
	ExitDockerCmdErr    = 127 // env
)

// ExitClassifies 依 §17.1 把 exit code 映射到失敗分類傾向。
// 回傳 "" 表示非閉集碼（呼叫端視為 env：docker 本身錯誤的守門）。
func ExitClassifies(code int) FailureClass {
	switch code {
	case ExitOK:
		return "" // 進 oracle 判定，不是失敗分類
	case ExitServiceNotReady, ExitExploitCrashed:
		return FailureHarness
	case ExitTimeout, ExitDockerErr, ExitDockerNotFound, ExitDockerCmdErr:
		return FailureEnv
	default:
		return FailureEnv
	}
}

// ---- Run kinds（§17.7：三種 control run 分離執行、固定順序） ----

type RunKind string

const (
	RunNegative RunKind = "negative"
	RunPositive RunKind = "positive"
	RunExploit  RunKind = "exploit"
)

// ---- Journal event types（§21.3 閉集；加新事件必須升 schema_version） ----

var JournalEventTypes = []string{
	"run_started", "snapshot_created", "stage_completed",
	"candidate_created", "candidate_merged", "finding_created", "triage_updated",
	"witness_spec_submitted", "witness_spec_rejected",
	"run_requested", "run_completed", "evidence_written",
	"verification_updated", "budget_updated", "disposition_updated",
	"report_written", "cancelled",
}

// IsJournalEventType 檢查閉集成員。
func IsJournalEventType(t string) bool {
	for _, e := range JournalEventTypes {
		if e == t {
			return true
		}
	}
	return false
}

// ---- Schema 版本 ----

// SchemasVersion 隨 schemas/ 目錄綁定，記入 evidence 與 journal。
const SchemasVersion = "1.0"