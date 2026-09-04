// Package budget 實作 Aegis 的證明預算、失敗分類決策樹與停止條件
// （SPEC §5.4、§9、§19）。分類與停止全部由純程式判定（確定性），
// 模型宣稱的分類僅為 hint，不進本套件——分類權最終在程式。
//
// v1 禁止 goroutine 並行（§23-1）：本套件全部為同步純函式。
package budget

import (
	"fmt"

	"github.com/aegis-dev/aegis/internal/domain"
)

// Budget 是單一 finding 的證明預算上限（§5.4 [budget]；§9.1 各分類各走各的計數器）。
type Budget struct {
	MaxEnv           int // env 修正上限（build／映像／provider／transport）
	MaxHarness       int // harness 修正上限（witness 接線、exploit 腳本 bug）
	MaxHypotheses    int // 不同攻擊鏈假設數上限
	MaxSandboxMinutes int // 沙箱時數上限（防 hang，非防花費；§9.4）
}

// Default 回傳 §5.4 的預設預算：env 5／harness 8／hypotheses 3／sandbox 10 分鐘。
func Default() Budget {
	return Budget{
		MaxEnv:           5,
		MaxHarness:       8,
		MaxHypotheses:    3,
		MaxSandboxMinutes: 10,
	}
}

// Counters 是進行中的計數器狀態；欄位為「剩餘次數」。
// 由 orchestrator 持有，傳指標給 OnFailure 扣抵。
type Counters struct {
	EnvLeft        int
	HarnessLeft    int
	HypothesesLeft int
	SandboxSecUsed int // 沙箱已用秒數（呼叫端累計；本套件只讀，見 SandboxExceeded）
}

// NewCounters 以預算上限初始化計數器。
func (b Budget) NewCounters() Counters {
	return Counters{
		EnvLeft:        b.MaxEnv,
		HarnessLeft:    b.MaxHarness,
		HypothesesLeft: b.MaxHypotheses,
	}
}

// RunOutcome 是呼叫端（orchestrator）對單次 run 觀察到的事實旗標。
// 呼叫端契約：
//   - 每個需要分類的 run 結束時呼叫 Classify 一次，只填與該 run 相關的旗組；
//     正常通過的 negative／positive run 不需分類（不呼叫）；
//   - negative run：僅在漏洞 oracle 誤觸發時設 NegativeOracleTrue（第 4 點）；
//   - positive run：touch rule 未通過時設 PositivePassed=false、其餘旗組歸零
//     （ExploitExitZero 留 false，第 5 點據此與 exploit run 區辨）；
//   - exploit run：必設 ExploitExitZero／ExploitOracleResult，並帶入
//     PositivePassed=「本迭代 positive 是否已通過」（第 7 點前置條件）；
//   - 順序違規（guardrail 偵測到固定順序被破壞，如 positive 未通過卻執行 exploit）
//     設 OrderViolation=true，第 5 點為其讓位（否則第 8 點永不命中、guardrail 失效）。
type RunOutcome struct {
	LLMTransportFailure bool   // 第 0 點：refusal 鏈／連線重試／schema 驗證重試用盡
	Exit                int    // run 的 exit code（§17.1 閉集；依 domain.ExitClassifies 分類）
	DockerUnavailable   bool   // 第 1 點：docker daemon 不可用／image 拉取或構建失敗
	NegativeOracleTrue  bool   // 第 4 點：negative run 漏洞 oracle = true（oracle 誤觸發）
	PositivePassed      bool   // positive control 狀態：本迭代 touch rule 是否通過
	ExploitExitZero     bool   // exploit run exit 0
	ExploitOracleResult bool   // exploit run 漏洞 oracle 判定結果
	OrderViolation      bool   // 第 8 點：固定順序被破壞
	StderrHash          string // 失敗簽名：exit code 與 stderr sha256 之簽名（§9.3 振盪偵測；見 FailureSig）
}

// FailureSig 組出 §9.3 的失敗簽名（exit code ＋ stderr sha256）。
// 呼叫端以簽名是否連續相同計算 sameSigCount 傳給 OnFailure。
func FailureSig(exit int, stderrSha256 string) string {
	return fmt.Sprintf("%d|%s", exit, stderrSha256)
}

// Verdict 是決策樹的輸出。
type Verdict struct {
	Class          domain.FailureClass // env|harness|controlled_miss|""（僅 PROVEN 時為空）
	Proven         bool                // 第 6 點：機械證明成立
	Guardrail      string              // 第 8 點回 "order_violation"，否則 ""
	OracleMisfired bool                // 第 4 點：oracle_id 由呼叫端帶，此處只給旗標
}

// Classify 依 §19 決策樹分類——依序第一個命中者生效。
// prevFailureSig 是上一個失敗 run 的簽名；分類樹本身不依賴它
//（振盪判定由呼叫端比較簽名得 sameSigCount 後交給 OnFailure），
// 保留於簽名是為了讓呼叫端能在單一呼叫點完成「分類＋簽名鏈維護」。
func (b Budget) Classify(o RunOutcome, prevFailureSig string) (Verdict, error) {
	_ = prevFailureSig // 見函式註解：分類為純函式，簽名鏈由呼叫端維護

	// 0. LLM／transport 失敗 → env
	if o.LLMTransportFailure {
		return Verdict{Class: domain.FailureEnv}, nil
	}
	// 1. docker daemon 不可用／image 拉取或構建失敗 → env（不改程式，修環境重跑）
	if o.DockerUnavailable {
		return Verdict{Class: domain.FailureEnv}, nil
	}
	// exit code 分類（§17.1）：2/3 → harness（第 2/3 點）、124/125/126/127 及
	// 其他非零碼（含 build 非零）→ env（第 1 點）、0 → 進 oracle 判定。
	switch domain.ExitClassifies(o.Exit) {
	case domain.FailureEnv:
		return Verdict{Class: domain.FailureEnv}, nil // 第 1 點
	case domain.FailureHarness:
		return Verdict{Class: domain.FailureHarness}, nil // 第 2/3 點
	}

	// 4. negative run 漏洞 oracle 誤觸發 → harness（標記 oracle_id 待檢修）
	if o.NegativeOracleTrue {
		return Verdict{Class: domain.FailureHarness, OracleMisfired: true}, nil
	}
	// 8. 順序違規先於第 5 點讓位判定（見 RunOutcome 契約）：第 8 點 → 防禦性 harness。
	if o.OrderViolation {
		return Verdict{Class: domain.FailureHarness, Guardrail: "order_violation"}, nil
	}
	// 5. positive run touch rule = false → harness（輸入未流經 sink；本迭代不執行 exploit）。
	// 閘門：exploit run 必帶 ExploitExitZero=true，不會落入此點——否則第 7 點的
	// uncontrolled 形狀（exploit exit 0、oracle=false、positive 未通過）會在此被
	// 誤判成第 5 點，下面的 uncontrolled 防線變成死碼。
	if !o.ExploitExitZero && !o.PositivePassed {
		return Verdict{Class: domain.FailureHarness}, nil
	}
	// 6. exploit exit 0 且漏洞 oracle = true → PROVEN
	if o.ExploitExitZero && o.ExploitOracleResult {
		return Verdict{Proven: true}, nil
	}
	// 7. exploit exit 0 且漏洞 oracle = false，且最近一次 positive 已通過
	//    → controlled_miss（「controlled_miss 只在 positive 已通過時成立」）
	if o.ExploitExitZero && !o.ExploitOracleResult && o.PositivePassed {
		return Verdict{Class: domain.FailureControlledMiss}, nil
	}

	// 殘差：exploit 已送出但 positive 未通過且未標記順序違規——即 §9.1 的
	// uncontrolled 形狀。v1 每個 oracle 家族必附 paired touch rule，此分類
	// 不出現；呼叫端應改報 OrderViolation（第 8 點）。收到即回 error。
	if o.ExploitExitZero {
		return Verdict{}, fmt.Errorf("budget: classify: uncontrolled 分類在 v1 不允許（§9.1）：exploit exit 0 且 oracle=false 但 positive 未通過；請以 OrderViolation 回報順序違規")
	}
	return Verdict{}, fmt.Errorf("budget: classify: 決策樹無節點命中（呼叫端旗組不構成可分類的 run 結果）")
}

// Stop 是 §9.3 的停止判定結果。Stop 為 nil 表示繼續 prover 迴圈。
type Stop struct {
	Terminal           string               // PROVEN|HYPOTHESIS_REJECTED|NOT_PROVEN|ENV_ERROR（domain.Verification）
	Reason             domain.NotProvenReason // 僅 NOT_PROVEN 時為閉集原因，其餘為 ""
	HypothesisRejected bool                 // 該假設（或全部假設）被否證
}

// OnFailure 依 §9.3 扣抵計數器並判定停止條件（全部由 orchestrator 判定，模型無權放棄）。
// sameSigCount 是呼叫端以失敗簽名（FailureSig）比較得出的「連續相同簽名次數」。
// 預算用盡的判定先於振盪（§9.3 條列順序）；兩者皆命中時以用盡的原因為準。
// 呼叫端只應傳入 Classify 的輸出；其他分類採防禦性停止（不應發生）。
func (b Budget) OnFailure(v Verdict, c *Counters, sameSigCount int) *Stop {
	if v.Proven {
		return nil // PROVEN 無 stop、不動計數器
	}

	switch v.Class {
	case domain.FailureControlledMiss:
		// 對「漏洞假設」的真正反證：扣假設、歸零即否證終態。
		c.HypothesesLeft--
		if c.HypothesesLeft <= 0 {
			return &Stop{
				Terminal:           string(domain.VerificationHypothesisRej),
				HypothesisRejected: true,
			}
		}
		return nil

	case domain.FailureHarness:
		c.HarnessLeft--
		if c.HarnessLeft <= 0 {
			return &Stop{Terminal: string(domain.VerificationNotProven), Reason: domain.NotProvenHarnessBudget}
		}
		// 振盪：連續 2 次 harness 分類的失敗簽名相同 → 停（非否證）。
		if sameSigCount >= 2 {
			return &Stop{Terminal: string(domain.VerificationNotProven), Reason: domain.NotProvenOscillation}
		}
		return nil

	case domain.FailureEnv:
		c.EnvLeft--
		if c.EnvLeft <= 0 {
			return &Stop{Terminal: string(domain.VerificationEnvError)}
		}
		return nil

	default:
		// 防禦性分支：Classify 不會產出其他分類（uncontrolled 已在 Classify 回 error）。
		// 不停在這裡會讓 orchestrator 無限迴圈，故以 NOT_PROVEN 收斂。
		return &Stop{Terminal: string(domain.VerificationNotProven), Reason: domain.NotProvenHarnessBudget}
	}
}

// SandboxExceeded 回報沙箱時數是否超過預算（§9.3：防 hang；預設每 finding 10 分鐘）。
// 命中時 orchestrator 應以 NOT_PROVEN（原因 sandbox_budget）收斂。
func (b Budget) SandboxExceeded(c Counters) bool {
	if b.MaxSandboxMinutes <= 0 {
		return false // 未設上限（≤0 視為關閉）
	}
	return c.SandboxSecUsed >= b.MaxSandboxMinutes*60
}