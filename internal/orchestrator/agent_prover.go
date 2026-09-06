// agent_prover.go：M0c prover 迴圈（§9.3 停止條件、§18.2 回饋協定）。
//
// 職責切分：每次「假設的驗證」仍走決定性三控制 run（ProveFunc；ADR 0002 單次
// 預算語意），本檔在其外層做多假設迭代——§9.3 的計數器、停止條件、振盪偵測、
// fresh-eyes 最後一輪全部由本迴圈持有；模型無權放棄（分類權在程式）。
//
// 回饋協定（§18.2）：run 結束後以 user 訊息內 <operator>…</operator> 送出
// 結構化 run_outcome（固定欄位、tails 有界、nonce 紅線後不出現）；模型下一輪
// 提交新 spec 前會要求模型輸出三行 preamble（學到／改／預期），作為可觀測
// 修正紀錄；閘只拒收會影響安全/正確性的 schema、nonce、duplicate 問題。
//
// v1 序列、無 goroutine（§23-1）。
package orchestrator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/aegis-dev/aegis/internal/agent"
	"github.com/aegis-dev/aegis/internal/domain"
	"github.com/aegis-dev/aegis/internal/journal"
	"github.com/aegis-dev/aegis/internal/llm"
	"github.com/aegis-dev/aegis/internal/orchestrator/budget"
	"github.com/aegis-dev/aegis/internal/orchestrator/policy"
	"github.com/aegis-dev/aegis/internal/redaction"
)

// ProveFunc 是決定性三控制 run 執行器的注入點：正式接線用 (*Prover).Prove
// （單次預算，預算管理上移到本迴圈）；單元測試注入假實作即可驅動整個迴圈，
// 不必起 docker。
type ProveFunc func(context.Context, ProveInput) (*ProveResult, error)

// §18.3 各角色的 effort 配置（v1 閉集；prover xhigh、reviewer/triager high、
// recon low、reporter medium）。
const (
	EffortProver   = "xhigh"
	EffortReviewer = "high"
	EffortTriager  = "high"
	EffortRecon    = "low"
	EffortReporter = "medium"
)

// FindingContext 是 prover session 的注入資料（§18.4：每 finding 一個 session，
// 只注入 sink 鄰域，不帶全 repo）。
type FindingContext struct {
	FindingID    string
	Reachability string // D0..D3
	TargetSymbol string
	OracleID     string
	SnapshotID   string
	Context      string // sink 鄰域（±200 行與同 module 呼叫者；呼叫端組裝）
}

// AttemptRecord 是一次完整三控制 run 嘗試的日誌：NOT_PROVEN 附完整嘗試日誌、
// HYPOTHESIS_REJECTED 的 rationale 逐條由此而來（§9.3）。
type AttemptRecord struct {
	Seq          int         `json:"seq"`
	SpecHash     string      `json:"spec_hash"`
	Payload      string      `json:"payload"`
	Preamble     string      `json:"preamble,omitempty"` // assistant 文字截尾版
	FailureClass string      `json:"failure_class,omitempty"`
	Verification string      `json:"verification"`
	Runs         []RunRecord `json:"runs,omitempty"`
	Note         string      `json:"note,omitempty"` // 非 run 失敗（未提交 spec 等）說明
}

// AgentProveResult 是 prover 迴圈的終態。
type AgentProveResult struct {
	Verification    domain.Verification
	NotProvenReason domain.NotProvenReason // 僅 NOT_PROVEN 時非空
	FailureClass    domain.FailureClass    // 非 PROVEN 時的最終 §19 分類
	Attempts        []AttemptRecord        // 完整嘗試日誌（終態一律附）
	Scope           map[string]string      // HYPOTHESIS_REJECTED 的 scope（§9.3）
	Rationale       []string               // HYPOTHESIS_REJECTED 的逐條否證理由
	OracleID        string
}

// 無後續假設的文字標記：§9.3「以結構化輸出明示『無後續假設』」——v1 工具面為
// submit-only，以此固定標記在 session 終態文字偵測（決策記於 ADR 0003）。
const NoMoreHypothesesMarker = "無後續假設"

// preamble 偵測：三行各以 學到／改／預期 開頭（允許全半形冒號）。
var preambleRe = regexp.MustCompile(`(?m)^\s*(學到|改|預期)\s*[:：]`)

// AgentProver 是 M0c 的 prover 迴圈（§9.3/§18.2）。
type AgentProver struct {
	Prove   ProveFunc // 決定性三控制 run（必填）
	Journal *journal.Journal
	Adapter llm.Adapter // prover role（必填）
	Tools   *agent.ToolRegistry
	// ToolDefs 由 schemas/ 組裝（agent.NewToolDefs；呼叫端載入 schema 檔）。
	ToolDefs []llm.ToolDef
	// ValidateSpec 是閘 (b) 的 schema 驗證（呼叫端以 schemav 綁
	// witness_spec.schema.json；nil 視為跳過——正式接線不得為 nil）。
	ValidateSpec func(map[string]any) error

	Model  string
	System string // system prompt（prompt 版本化 §18.4：第一行 version:）

	Finding    FindingContext
	Budget     budget.Budget // 迴圈級預算（§9.3 計數器在此扣抵）
	RunDir     string        // artifacts 根（<RunDir>/evidence/runs/<runID>/）
	MaxTurns   int           // 單一 session 的 tool loop 上限（agent.MaxTurns 預設）
	OnResponse func(turn int, response llm.Response)
}

// Run 執行 prover 迴圈至 §9.3 終態。
func (ap *AgentProver) Run(ctx context.Context) (*AgentProveResult, error) {
	if ap.Prove == nil || ap.Adapter == nil || ap.Tools == nil || ap.Journal == nil || ap.ValidateSpec == nil {
		return nil, fmt.Errorf("orchestrator: AgentProver 缺 Prove／Adapter／Tools")
	}

	counters := ap.Budget.NewCounters()
	seenHashes := map[string]bool{} // 同款重試不計也不收（§9.3）
	feedbackSeen := false           // 曾送出 operator 回饋 → prompt 會要求三行 preamble
	freshEyesUsed := false
	freshRound := false // fresh-eyes 進行中：任何非 PROVEN 結果即進終態、不扣預算
	var pendingTerminal *budget.Stop
	lastFailSig := "" // 最近一次 harness 分類的失敗簽名（振盪偵測 §9.3）
	awaitingNoMoreConfirmation := false

	// pendingSpec 由閘 (b) 核可後填入；session 結束後由迴圈取出。
	var pendingSpec map[string]any
	var fatalJournalErr error
	ap.Tools.OnSubmit = func(_ context.Context, spec map[string]any, assistantText string) (bool, string) {
		if err := ap.checkSpec(spec, assistantText, feedbackSeen, seenHashes); err != nil {
			if appendErr := ap.journalSpecRejected(err.reason); appendErr != nil {
				fatalJournalErr = appendErr
				return false, "journal write failed (fail-closed)"
			}
			return false, err.feedback
		}
		seenHashes[specHash(spec)] = true
		pendingSpec = spec
		return true, "accepted"
	}

	msgs := []llm.Message{userText(ap.findingPrompt(false))}
	attempts := []AttemptRecord{}
	var learned []string // 各輪 preamble 的「學到」行（rationale 素材）

	for {
		ap.Tools.ResetSession()
		runtime := &agent.Runtime{Adapter: ap.Adapter, Tools: ap.Tools, MaxTurns: ap.sessionTurns(), StopOnAccepted: true, OnResponse: ap.OnResponse}
		resp, history, err := runtime.Run(ctx, ap.chatRequest(msgs))
		if fatalJournalErr != nil {
			return nil, fmt.Errorf("orchestrator: rejected-spec journal: %w", fatalJournalErr)
		}
		if err != nil {
			if errors.Is(err, context.Canceled) {
				rec := AttemptRecord{Seq: len(attempts) + 1, Verification: string(domain.VerificationNotProven), Note: "user_cancelled"}
				return ap.terminal(domain.VerificationNotProven, domain.NotProvenUserCancelled, "", append(attempts, rec), learned, "")
			}
			if errors.Is(err, agent.MaxTurnsExceededError) {
				rec := AttemptRecord{Seq: len(attempts) + 1, Verification: string(domain.VerificationNotRun),
					FailureClass: string(domain.FailureHarness), Note: "tool_loop_max_turns"}
				attempts = append(attempts, rec)
				if freshRound {
					return ap.terminal(domain.Verification(pendingTerminal.Terminal), pendingTerminal.Reason,
						domain.FailureHarness, attempts, learned, "")
				}
				stop := ap.Budget.OnFailure(budget.Verdict{Class: domain.FailureHarness}, &counters, 0)
				if stop != nil {
					return ap.stopResult(stop, attempts, learned, "")
				}
				msgs = append(msgs, userText(ap.operatorError("tool loop 回合用盡；請縮短調查並提交一個 WitnessSpec")))
				feedbackSeen = true
				continue
			}
			// LLM／transport 失敗（§19 第 0 點）→ env；fresh 輪直接進終態。
			rec := AttemptRecord{Seq: len(attempts) + 1, Verification: string(domain.VerificationNotRun),
				FailureClass: string(domain.FailureEnv), Note: "llm_transport: " + bounded(err.Error(), 512)}
			attempts = append(attempts, rec)
			if freshRound {
				return ap.terminal(domain.Verification(pendingTerminal.Terminal), pendingTerminal.Reason,
					domain.FailureEnv, attempts, learned, "")
			}
			v := budget.Verdict{Class: domain.FailureEnv}
			stop := ap.Budget.OnFailure(v, &counters, 0)
			if stop != nil {
				return ap.stopResult(stop, attempts, learned, "")
			}
			msgs = append(msgs, userText(ap.operatorError(err.Error())))
			feedbackSeen = true
			continue
		}

		// refusal／截斷是 provider/environment failure，不可誤標成「模型沒有假設」。
		if resp.StopReason == llm.StopRefusal || resp.StopReason == llm.StopMaxTokens {
			rec := AttemptRecord{Seq: len(attempts) + 1, Verification: string(domain.VerificationNotRun),
				FailureClass: string(domain.FailureEnv), Note: "llm_stop: " + string(resp.StopReason)}
			attempts = append(attempts, rec)
			if freshRound {
				return ap.terminal(domain.Verification(pendingTerminal.Terminal), pendingTerminal.Reason, domain.FailureEnv, attempts, learned, "")
			}
			stop := ap.Budget.OnFailure(budget.Verdict{Class: domain.FailureEnv}, &counters, 0)
			if stop != nil {
				return ap.stopResult(stop, attempts, learned, "")
			}
			msgs = history
			msgs = append(msgs, userText(ap.operatorError("provider 回應被拒絕或截斷；請縮短調查並重試")))
			feedbackSeen = true
			continue
		}

		// session 終態文字（無 submit 時為標記偵測與嘗試日誌素材）。
		finalText := responseText(resp)
		if pendingSpec == nil {
			rec := AttemptRecord{Seq: len(attempts) + 1, Verification: string(domain.VerificationNotRun),
				Preamble: bounded(finalText, 512)}
			switch {
			case awaitingNoMoreConfirmation && exactNoMoreHypotheses(finalText):
				// 只有在一次 controlled miss 後，並經獨立回合精確確認，才接受
				// 「無後續假設」。避免否定句、引用 repo 文字或 prompt injection
				// 以 substring 提前終止證明流程。
				rec.Verification = string(domain.VerificationHypothesisRej)
				rec.FailureClass = string(domain.FailureControlledMiss)
				rec.Note = NoMoreHypothesesMarker
				return ap.terminal(domain.VerificationHypothesisRej, "", domain.FailureControlledMiss,
					append(attempts, rec), learned, "")
			case feedbackSeen && hasControlledMiss(attempts) && exactNoMoreHypotheses(finalText):
				awaitingNoMoreConfirmation = true
				msgs = history
				msgs = append(msgs, userText(ap.operatorError("若確實已無其他攻擊鏈假設，請在下一回合只輸出唯一一行："+NoMoreHypothesesMarker)))
				continue
			case freshRound:
				// fresh 輪未提交 → 進 pendingTerminal（假設用盡的終態）。
				rec.Verification = string(domain.VerificationNotRun)
				rec.Note = "fresh_eyes_no_spec"
				return ap.terminal(domain.Verification(pendingTerminal.Terminal), pendingTerminal.Reason,
					domain.FailureControlledMiss, append(attempts, rec), learned, "")
			default:
				// session 結束但未提交 spec：模型未完成其職責 → harness 分類
				//（§19 決策樹無此形狀；決策記於 ADR 0003）。
				rec.Verification = string(domain.VerificationNotRun)
				rec.FailureClass = string(domain.FailureHarness)
				rec.Note = "no_spec_submitted"
			}
			attempts = append(attempts, rec)
			learned = append(learned, learnedLines(finalText)...)
			stop := ap.Budget.OnFailure(budget.Verdict{Class: domain.FailureHarness}, &counters, 0)
			if stop != nil {
				return ap.stopResult(stop, attempts, learned, "")
			}
			msgs = history
			msgs = append(msgs, userText(ap.operatorError("session 結束但未提交 WitnessSpec；請以 read_code／search_code 調查後以 submit_witness_spec 提交假設（payload 必含 {{NONCE}}）")))
			feedbackSeen = true
			continue
		}

		// 有核可的 spec → 執行決定性三控制 run（單次預算；預算由本迴圈管）。
		spec := pendingSpec
		pendingSpec = nil
		hash := specHash(spec)
		rec := AttemptRecord{Seq: len(attempts) + 1, SpecHash: hash,
			Payload: bounded(strField(spec, "payload"), 512), Preamble: bounded(finalText, 512)}

		sandboxRunStart := time.Now()
		res, perr := ap.Prove(ctx, ProveInput{
			FindingID:    ap.Finding.FindingID,
			Reachability: ap.Finding.Reachability,
			Spec:         spec,
		})
		sandboxElapsed := time.Since(sandboxRunStart)
		// 只累計實際 deterministic prover/sandbox 所用時間；LLM 等待不屬於
		// sandbox budget。向上取整，避免大量不足一秒的執行永遠不計入。
		counters.SandboxSecUsed += int((sandboxElapsed + time.Second - 1) / time.Second)
		if perr != nil {
			if errors.Is(perr, context.Canceled) {
				rec.Verification = string(domain.VerificationNotProven)
				rec.Note = "user_cancelled"
				return ap.terminal(domain.VerificationNotProven, domain.NotProvenUserCancelled, "", append(attempts, rec), learned, "")
			}
			var specErr *policy.SpecError
			if errors.As(perr, &specErr) {
				// policy compiler 拒收表示模型提交的 spec 不合規，不是環境故障；
				// 不扣 env 預算，落 journal 後要求模型修正並重送。
				if err := ap.journalSpecRejected(specErr.Reason); err != nil {
					return nil, fmt.Errorf("orchestrator: rejected-spec journal: %w", err)
				}
				rec.Verification = string(domain.VerificationNotRun)
				rec.Note = "spec_rejected: " + specErr.Reason
				attempts = append(attempts, rec)
				msgs = history
				msgs = append(msgs, userText(ap.operatorError(specErr.Error())))
				feedbackSeen = true
				continue
			}
			// 決定性 harness 例外（docker 不可用等）→ env（§19 第 1 點）。
			// 環境修正後必須能原樣重跑同一 spec；duplicate_spec 只阻擋模型
			// 重複假設，不應阻擋「不改程式、修環境後重跑」。
			delete(seenHashes, hash)
			rec.Verification = string(domain.VerificationNotRun)
			rec.FailureClass = string(domain.FailureEnv)
			rec.Note = "prove_error: " + bounded(perr.Error(), 512)
			attempts = append(attempts, rec)
			if freshRound {
				return ap.terminal(domain.Verification(pendingTerminal.Terminal), pendingTerminal.Reason,
					domain.FailureEnv, attempts, learned, "")
			}
			stop := ap.Budget.OnFailure(budget.Verdict{Class: domain.FailureEnv}, &counters, 0)
			if stop != nil {
				return ap.stopResult(stop, attempts, learned, strField(spec, "oracle_id"))
			}
			msgs = history
			msgs = append(msgs, userText(ap.operatorError(perr.Error())))
			feedbackSeen = true
			continue
		}
		if ap.Budget.SandboxExceeded(counters) {
			rec.Verification = string(domain.VerificationNotProven)
			rec.FailureClass = string(domain.FailureHarness)
			rec.Note = "sandbox_budget"
			return ap.terminal(domain.VerificationNotProven, domain.NotProvenSandboxBudget,
				domain.FailureHarness, append(attempts, rec), learned, res.OracleID)
		}

		rec.Runs = res.Runs
		rec.Verification = string(res.Verification)
		rec.FailureClass = string(res.FailureClass)
		attempts = append(attempts, rec)
		learned = append(learned, learnedLines(finalText)...)

		if res.Verification == domain.VerificationProven {
			return ap.terminal(domain.VerificationProven, "", "", attempts, learned, res.OracleID)
		}
		if res.FailureClass == "" {
			return nil, fmt.Errorf("orchestrator: 非 PROVEN 且無失敗分類（內部不一致）")
		}

		if freshRound {
			// fresh-eyes 輪：不論結果進終態（§9.3；不扣計數器）。
			return ap.terminal(domain.Verification(pendingTerminal.Terminal), pendingTerminal.Reason,
				res.FailureClass, attempts, learned, res.OracleID)
		}

		// 迴圈級預算扣抵與停止判定（§9.3；分類來自決策樹，非模型宣稱）。
		v := budget.Verdict{Class: res.FailureClass, OracleMisfired: res.OracleMisfired}
		sig := ap.failureSig(res)
		same := 0
		if res.FailureClass == domain.FailureHarness && sig == lastFailSig {
			same = 2 // 與上一次 harness 失敗同簽名 → 振盪線
		}
		if res.FailureClass == domain.FailureHarness {
			lastFailSig = sig
		}
		stop := ap.Budget.OnFailure(v, &counters, same)
		if res.FailureClass == domain.FailureEnv {
			delete(seenHashes, hash)
		}

		if stop != nil {
			// fresh-eyes 最後一輪（§9.3）：假設用盡時開全新 session（不帶先前
			// 失敗敘事），最多 1 個新假設、不計入 hypotheses；之後不論結果進終態。
			if stop.Terminal == string(domain.VerificationHypothesisRej) && !freshEyesUsed {
				freshEyesUsed = true
				freshRound = true
				pendingTerminal = stop
				msgs = []llm.Message{userText(ap.findingPrompt(true))}
				// duplicate_spec 的範圍是整個 finding；fresh-eyes 只重置對話，
				// 不得忘記先前已提交過的內容 hash。
				feedbackSeen = false
				continue
			}
			return ap.stopResult(stop, attempts, learned, res.OracleID)
		}

		// 續跑：operator 回饋（§18.2 有界 tails；nonce 不出現）。
		msgs = history
		msgs = append(msgs, userText(ap.operatorRunOutcome(res, counters)))
		feedbackSeen = true
	}
}

func exactNoMoreHypotheses(text string) bool {
	return strings.TrimSpace(text) == NoMoreHypothesesMarker
}

func hasControlledMiss(attempts []AttemptRecord) bool {
	for _, attempt := range attempts {
		if attempt.FailureClass == string(domain.FailureControlledMiss) {
			return true
		}
	}
	return false
}

// ---- 終態組裝與落檔 ----

// terminal 組終態、寫 verification_updated journal 事件後回傳。
func (ap *AgentProver) terminal(v domain.Verification, reason domain.NotProvenReason,
	class domain.FailureClass, attempts []AttemptRecord, learned []string, oracleID string) (*AgentProveResult, error) {

	res := &AgentProveResult{
		Verification:    v,
		NotProvenReason: reason,
		FailureClass:    class,
		Attempts:        attempts,
		OracleID:        oracleID,
	}
	if v == domain.VerificationHypothesisRej {
		res.Scope = ap.scope()
		res.Rationale = rationaleLines(learned, attempts)
	}
	if err := ap.journalVerification(res); err != nil {
		return nil, fmt.Errorf("orchestrator: terminal journal: %w", err)
	}
	return res, nil
}

// stopResult 把 budget.Stop 轉成終態（scope/rationale 僅 HYPOTHESIS_REJECTED）。
func (ap *AgentProver) stopResult(stop *budget.Stop, attempts []AttemptRecord,
	learned []string, oracleID string) (*AgentProveResult, error) {
	v := domain.Verification(stop.Terminal)
	var class domain.FailureClass
	if len(attempts) > 0 {
		class = domain.FailureClass(attempts[len(attempts)-1].FailureClass)
	}
	return ap.terminal(v, stop.Reason, class, attempts, learned, oracleID)
}

// journalVerification 落 verification_updated（NOT_PROVEN 附嘗試日誌；
// HYPOTHESIS_REJECTED 附 scope 與逐條 rationale，§9.3）。
func (ap *AgentProver) journalVerification(res *AgentProveResult) error {
	if ap.Journal == nil {
		return fmt.Errorf("journal unavailable")
	}
	doc := map[string]any{
		"verification":  string(res.Verification),
		"failure_class": string(res.FailureClass),
		"attempts":      attemptsDocs(res.Attempts),
	}
	if res.NotProvenReason != "" {
		doc["reason"] = string(res.NotProvenReason)
	}
	if res.Scope != nil {
		doc["scope"] = res.Scope
		doc["rationale"] = res.Rationale
	}
	if res.OracleID != "" {
		doc["oracle_id"] = res.OracleID
	}
	doc["budget"] = map[string]any{"max_env": ap.Budget.MaxEnv, "max_harness": ap.Budget.MaxHarness,
		"max_hypotheses": ap.Budget.MaxHypotheses}
	_, err := ap.Journal.Append("verification_updated", ap.Finding.FindingID, doc)
	return err
}

// ---- 閘 (b)：submit_witness_spec 的迴圈級檢查（§18.1；schema 驗證由呼叫端注入） ----

type gateErr struct {
	feedback string
	reason   string // journal witness_spec_rejected 的 reason
}

// checkSpec 順序：schema → §17.2 placeholder → duplicate hash。
func (ap *AgentProver) checkSpec(spec map[string]any, assistantText string,
	feedbackSeen bool, seenHashes map[string]bool) *gateErr {
	if ap.ValidateSpec != nil {
		if err := ap.ValidateSpec(spec); err != nil {
			return &gateErr{"invalid_spec: " + bounded(err.Error(), 512), "invalid_spec"}
		}
	}
	payload := strField(spec, "payload")
	if !strings.Contains(payload, "{{NONCE}}") && !strings.Contains(payload, "{{NONCE_HEX}}") {
		return &gateErr{"missing_nonce_placeholder: payload 必含 {{NONCE}} 或 {{NONCE_HEX}}（§17.2）", "missing_nonce_placeholder"}
	}
	hash := specHash(spec)
	if seenHashes[hash] {
		return &gateErr{"duplicate_spec: 同內容 spec 已提交過（同款重試不計也不收，§9.3）", "duplicate_spec"}
	}
	return nil
}

// journalSpecRejected 落 witness_spec_rejected 事件。
func (ap *AgentProver) journalSpecRejected(reason string) error {
	if ap.Journal == nil {
		return fmt.Errorf("journal unavailable")
	}
	_, err := ap.Journal.Append("witness_spec_rejected", ap.Finding.FindingID, map[string]any{"reason": reason})
	return err
}

// ---- prompt 組裝（§18.4） ----

// findingPrompt 組 session 的第一則 user 訊息；fresh=true 時不帶任何先前失敗敘事
// （fresh-eyes §9.3——只有原始資料與一句 dry 說明）。
func (ap *AgentProver) findingPrompt(fresh bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "finding_id: %s\nreachability: %s\ntarget_symbol: %s\noracle_id: %s\nsnapshot_id: %s\n\n",
		ap.Finding.FindingID, ap.Finding.Reachability, ap.Finding.TargetSymbol,
		ap.Finding.OracleID, ap.Finding.SnapshotID)
	contextText := ap.Finding.Context
	if redaction.HasSecret(contextText) {
		contextText = "[redacted: sink context 命中 secret pattern；需人工確認後再繼續]"
	}
	b.WriteString("sink 鄰域（§18.4，非全 repo）：\n```\n" + contextText + "\n```\n\n")
	b.WriteString("請以 read_code／search_code 調查後，以 submit_witness_spec 提交 WitnessSpec" +
		"（payload 必含 {{NONCE}} 或 {{NONCE_HEX}}）。提交後由 harness 執行 negative → positive → exploit 三控制 run。\n")
	if fresh {
		b.WriteString("（fresh-eyes 最後一輪：僅此一輪，最多 1 個新假設；不論結果之後進終態。）\n")
	}
	return b.String()
}

// chatRequest 組 prover 的 ChatRequest（工具定義順序整個 run 逐 byte 穩定，§18.3）。
func (ap *AgentProver) chatRequest(msgs []llm.Message) llm.ChatRequest {
	return llm.ChatRequest{
		Role:     llm.RoleProver,
		Model:    ap.Model,
		System:   ap.System,
		Messages: msgs,
		Tools:    ap.ToolDefs,
		Effort:   EffortProver,
		Stream:   true,
	}
}

// ---- operator 回饋訊息（§18.2） ----

// operatorRunOutcome 組 §18.2 固定欄位的 run_outcome；完整輸出只在 evidence，
// 模型看到的永遠是截尾版。
func (ap *AgentProver) operatorRunOutcome(res *ProveResult, counters budget.Counters) string {
	last := RunRecord{}
	if n := len(res.Runs); n > 0 {
		last = res.Runs[n-1]
	}
	doc := map[string]any{
		"type": "run_outcome",
		// run_id／kind 為最後一個 run（miss／控制點失敗都發生在最後一個 run）。
		"run_id": last.RunID, "kind": last.Kind, "exit": last.Exit,
		"oracle": map[string]any{
			"result": last.VulnOracle,
			"observed_summary": bounded(fmt.Sprintf("exit=%d vuln_oracle=%v touch_oracle=%v misfired=%v",
				last.Exit, last.VulnOracle, last.TouchOracle, res.OracleMisfired), 2048),
		},
		"failure_class": string(res.FailureClass),
		"budget": map[string]any{
			"env_left": counters.EnvLeft, "harness_left": counters.HarnessLeft,
			"hypotheses_left": counters.HypothesesLeft,
		},
		"hints": ap.hints(res),
	}
	out, _ := json.MarshalIndent(doc, "", "  ")
	// 三行 preamble 規則提醒；缺少時不中止有效 spec，避免格式問題阻塞 PoC。
	return "<operator>\n" + string(out) + "\n</operator>\n" +
		"（提交新 WitnessSpec 前，請先輸出三行：學到：／改：／預期：。payload 繼續以 {{NONCE}} 撰寫。）\n"
}

// operatorError 是非 run 失敗（transport／prove 例外／未提交）的回饋；格式同 §18.2。
func (ap *AgentProver) operatorError(errMsg string) string {
	if redaction.HasSecret(errMsg) {
		errMsg = "[redacted: error 命中 secret pattern]"
	}
	doc := map[string]any{
		"type": "run_outcome", "run_id": "", "kind": "", "exit": -1,
		"oracle":        map[string]any{"result": false, "observed_summary": ""},
		"failure_class": string(domain.FailureEnv),
		"budget":        map[string]any{},
		"hints":         map[string]any{"error": bounded(errMsg, 2048)},
	}
	out, _ := json.MarshalIndent(doc, "", "  ")
	return "<operator>\n" + string(out) + "\n</operator>\n"
}

// hints 讀最後一個 run 的 artifacts tails（§18.2 有界；nonce 以 @@NONCE@@ 紅線）。
func (ap *AgentProver) hints(res *ProveResult) map[string]any {
	h := map[string]any{}
	if len(res.Runs) == 0 {
		return h
	}
	last := res.Runs[len(res.Runs)-1]
	art := artifactsDirFor(ap.RunDir, last.RunID)
	for _, spec := range []struct {
		key, file string
		max       int
	}{
		{"run_log_tail", "run.log", 4096},
		{"service_log_tail", "service.log", 4096},
		{"sql_trace_tail", "sql_trace.jsonl", 2048},
	} {
		if data, err := readTail(art, spec.file, spec.max); err == nil && len(data) > 0 {
			v := redactNonces(string(data), res.Runs)
			if redaction.HasSecret(v) {
				v = "[redacted: secret pattern detected]"
			}
			h[spec.key] = v
		}
	}
	return h
}

// failureSig 組 §9.3 失敗簽名（exit code ＋ run.log sha256；nonce 紅線後計算，
// 否則不同 nonce 的同型失敗永遠不同簽名、振盪偵測失效）。
func (ap *AgentProver) failureSig(res *ProveResult) string {
	if len(res.Runs) == 0 {
		return budget.FailureSig(-1, "")
	}
	last := res.Runs[len(res.Runs)-1]
	sha := ""
	if data, err := os.ReadFile(filepath.Join(artifactsDirFor(ap.RunDir, last.RunID), "run.log")); err == nil {
		sha = fmt.Sprintf("%x", sha256.Sum256(redactNoncesBytes(data, res.Runs)))
	}
	return budget.FailureSig(last.Exit, sha)
}

// redactNonces 把所有 run 的 nonce 換成 @@NONCE@@（§18.2：nonce 不進回饋）。
func redactNonces(s string, runs []RunRecord) string {
	for _, r := range runs {
		if r.Nonce != "" {
			s = strings.ReplaceAll(s, r.Nonce, "@@NONCE@@")
		}
	}
	return s
}

func redactNoncesBytes(b []byte, runs []RunRecord) []byte {
	return []byte(redactNonces(string(b), runs))
}

// ---- 小工具 ----

func userText(s string) llm.Message {
	return llm.Message{Role: "user", Content: []llm.ContentBlock{{Type: "text", Text: s}}}
}

func responseText(resp llm.Response) string {
	var b strings.Builder
	for _, blk := range resp.Content {
		if blk.Type == "text" {
			b.WriteString(blk.Text)
		}
	}
	return b.String()
}

// countPreambleLines 數三行 preamble 的命中類別數（學到／改／預期）。
func countPreambleLines(text string) int {
	seen := map[string]bool{}
	for _, m := range preambleRe.FindAllStringSubmatch(text, -1) {
		seen[m[1]] = true
	}
	return len(seen)
}

// learnedLines 抽 assistant 文字中的「學到」行（rationale 素材）。
func learnedLines(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimLeft(line, " \t"), "學到") {
			out = append(out, bounded(strings.TrimSpace(line), 512))
		}
	}
	return out
}

// rationaleLines 逐條列出否證與其 control run（§9.3；HYPOTHESIS_REJECTED 落檔）。
func rationaleLines(learned []string, attempts []AttemptRecord) []string {
	out := []string{}
	for _, a := range attempts {
		line := fmt.Sprintf("attempt %d: verification=%s failure_class=%s runs=%s",
			a.Seq, a.Verification, a.FailureClass, runSummary(a.Runs))
		out = append(out, line)
		if a.Note != "" {
			out = append(out, "  note: "+a.Note)
		}
	}
	out = append(out, learned...)
	return out
}

func runSummary(runs []RunRecord) string {
	parts := []string{}
	for _, r := range runs {
		parts = append(parts, fmt.Sprintf("%s(exit=%d,vuln=%v,touch=%v)", r.Kind, r.Exit, r.VulnOracle, r.TouchOracle))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " ")
}

func attemptsDocs(attempts []AttemptRecord) []map[string]any {
	out := make([]map[string]any, 0, len(attempts))
	for _, a := range attempts {
		doc := map[string]any{
			"seq": a.Seq, "spec_hash": a.SpecHash, "payload": a.Payload,
			"verification": a.Verification, "failure_class": a.FailureClass,
		}
		if a.Preamble != "" {
			doc["preamble"] = a.Preamble
		}
		if a.Note != "" {
			doc["note"] = a.Note
		}
		if len(a.Runs) > 0 {
			rd := make([]map[string]any, 0, len(a.Runs))
			for _, r := range a.Runs {
				rd = append(rd, map[string]any{"run_id": r.RunID, "kind": r.Kind, "exit": r.Exit,
					"vuln_oracle": r.VulnOracle, "touch_oracle": r.TouchOracle, "evidence_id": r.EvidenceID})
			}
			doc["runs"] = rd
		}
		out = append(out, doc)
	}
	return out
}

// scope 組 HYPOTHESIS_REJECTED 的 scope（被測 sink／context／版本，§9.3）。
func (ap *AgentProver) scope() map[string]string {
	return map[string]string{
		"finding_id":    ap.Finding.FindingID,
		"target_symbol": ap.Finding.TargetSymbol,
		"snapshot_id":   ap.Finding.SnapshotID,
	}
}

// specHash 以 canonical JSON 的 sha256 為 spec 內容 hash（encoding/json 對
// map 的 key 逐層排序，序列輸出穩定）。
func specHash(spec map[string]any) string {
	b, err := json.Marshal(spec)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

// bounded 截尾（以 rune 計，中文安全）。
func bounded(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

// artifactsDirFor 找 run 的 artifacts 目錄（不存在回原路徑，讀檔時自然失敗）。
func artifactsDirFor(runDir, runID string) string {
	return filepath.Join(runDir, "evidence", "runs", runID)
}

// readTail 讀檔尾 ≤max bytes（對齊行首；檔案不存在回空）。
func readTail(dir, name string, max int) (string, error) {
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return "", err
	}
	if len(data) > max {
		data = data[len(data)-max:]
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		}
	}
	return string(data), nil
}

// sessionTurns 回傳單一 session 的 tool loop 上限。
func (ap *AgentProver) sessionTurns() int {
	if ap.MaxTurns > 0 {
		return ap.MaxTurns
	}
	return agent.MaxTurns
}
