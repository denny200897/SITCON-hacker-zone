package budget

import (
	"strings"
	"testing"

	"github.com/aegis-dev/aegis/internal/domain"
)

// ---- §5.4 預設值與計數器初始化 ----

func TestDefaultBudget(t *testing.T) {
	b := Default()
	if b.MaxEnv != 5 || b.MaxHarness != 8 || b.MaxHypotheses != 3 || b.MaxSandboxMinutes != 10 {
		t.Fatalf("Default() = %+v，期望 5/8/3/10（§5.4）", b)
	}
}

func TestNewCountersInitFromBudget(t *testing.T) {
	b := Budget{MaxEnv: 2, MaxHarness: 4, MaxHypotheses: 1, MaxSandboxMinutes: 7}
	c := b.NewCounters()
	if c.EnvLeft != 2 || c.HarnessLeft != 4 || c.HypothesesLeft != 1 {
		t.Fatalf("NewCounters() = %+v，應以預算上限初始化", c)
	}
}

func TestFailureSigFormat(t *testing.T) {
	// §9.3：簽名 = exit code 與 stderr sha256 之組合
	if got := FailureSig(2, "abc"); got != "2|abc" {
		t.Fatalf("FailureSig = %q", got)
	}
}

// ---- §19 決策樹：各節點 ----

// 第 0 點：refusal 鏈／連線重試／schema 驗證重試用盡 → env。
func TestClassifyPoint0LLMTransport(t *testing.T) {
	v, err := Default().Classify(RunOutcome{LLMTransportFailure: true}, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v.Class != domain.FailureEnv || v.Proven {
		t.Fatalf("verdict = %+v，期望 env", v)
	}
}

// 第 1 點：docker 不可用／image 拉取或構建失敗／build 非零／exit 124-127 → env。
func TestClassifyPoint1Env(t *testing.T) {
	b := Default()
	if v, err := b.Classify(RunOutcome{DockerUnavailable: true}, ""); err != nil || v.Class != domain.FailureEnv {
		t.Fatalf("docker 不可用：verdict=%+v err=%v", v, err)
	}
	// build 非零（非閉集碼，如 exit 1）→ env（ExitClassifies 守門）
	if v, err := b.Classify(RunOutcome{Exit: 1}, ""); err != nil || v.Class != domain.FailureEnv {
		t.Fatalf("build 非零：verdict=%+v err=%v", v, err)
	}
	for _, code := range []int{124, 125, 126, 127} {
		v, err := b.Classify(RunOutcome{Exit: code}, "")
		if err != nil || v.Class != domain.FailureEnv {
			t.Fatalf("exit %d：verdict=%+v err=%v", code, v, err)
		}
	}
}

// 第 2/3 點：exit 2（service 未就緒）、exit 3（exploit 例外崩潰）→ harness。
func TestClassifyPoint2And3Harness(t *testing.T) {
	b := Default()
	for _, code := range []int{2, 3} {
		v, err := b.Classify(RunOutcome{Exit: code}, "")
		if err != nil || v.Class != domain.FailureHarness || v.Proven {
			t.Fatalf("exit %d：verdict=%+v err=%v", code, v, err)
		}
	}
}

// 第 4 點：negative run 漏洞 oracle = true → harness，且標記 oracle 誤觸發。
func TestClassifyPoint4NegativeOracleMisfire(t *testing.T) {
	v, err := Default().Classify(RunOutcome{NegativeOracleTrue: true}, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v.Class != domain.FailureHarness {
		t.Fatalf("class = %q，期望 harness", v.Class)
	}
	if !v.OracleMisfired {
		t.Fatal("oracle 誤觸發旗標未設（oracle_id 待檢修）")
	}
}

// 第 5 點：positive run touch rule = false → harness（本迭代不執行 exploit）。
func TestClassifyPoint5PositiveFailed(t *testing.T) {
	v, err := Default().Classify(RunOutcome{PositivePassed: false}, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v.Class != domain.FailureHarness || v.OracleMisfired || v.Guardrail != "" {
		t.Fatalf("verdict = %+v，期望 harness 無附帶旗標", v)
	}
}

// 第 6 點：exploit exit 0 且漏洞 oracle = true → PROVEN（Class 為空）。
func TestClassifyPoint6Proven(t *testing.T) {
	v, err := Default().Classify(RunOutcome{
		PositivePassed:      true,
		ExploitExitZero:     true,
		ExploitOracleResult: true,
	}, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !v.Proven || v.Class != "" {
		t.Fatalf("verdict = %+v，期望 PROVEN", v)
	}
}

// 第 7 點：exploit exit 0 且 oracle = false，且 positive 已通過 → controlled_miss。
func TestClassifyPoint7ControlledMiss(t *testing.T) {
	v, err := Default().Classify(RunOutcome{
		PositivePassed:  true,
		ExploitExitZero: true,
		// ExploitOracleResult = false
	}, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v.Class != domain.FailureControlledMiss || v.Proven {
		t.Fatalf("verdict = %+v，期望 controlled_miss", v)
	}
}

// 第 8 點：順序錯誤 → 防禦性 harness，記 guardrail。
func TestClassifyPoint8OrderViolation(t *testing.T) {
	// 如：positive 未通過卻執行了 exploit
	v, err := Default().Classify(RunOutcome{OrderViolation: true, ExploitExitZero: true}, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v.Class != domain.FailureHarness {
		t.Fatalf("class = %q，期望防禦性 harness", v.Class)
	}
	if v.Guardrail != "order_violation" {
		t.Fatalf("guardrail = %q，期望 order_violation", v.Guardrail)
	}
}

// ---- §19：依序第一個命中者生效（多條件同時真時驗證優先序） ----

func TestClassifyPrecedence(t *testing.T) {
	b := Default()
	cases := []struct {
		name string
		in   RunOutcome
		want Verdict
	}{
		{
			// 第 0 點先於第 1 點
			name: "p0_over_p1",
			in:   RunOutcome{LLMTransportFailure: true, DockerUnavailable: true},
			want: Verdict{Class: domain.FailureEnv},
		},
		{
			// 第 1 點先於第 2 點：docker 不可用壓過 exit 2
			name: "p1_over_p2",
			in:   RunOutcome{DockerUnavailable: true, Exit: 2},
			want: Verdict{Class: domain.FailureEnv},
		},
		{
			// exit 分類（§17.1）先於第 4 點
			name: "exit_over_p4",
			in:   RunOutcome{Exit: 3, NegativeOracleTrue: true},
			want: Verdict{Class: domain.FailureHarness},
		},
		{
			// 第 4 點先於第 8 點：oracle 誤觸發帶走分類，不記 guardrail
			name: "p4_over_p8",
			in:   RunOutcome{NegativeOracleTrue: true, OrderViolation: true},
			want: Verdict{Class: domain.FailureHarness, OracleMisfired: true},
		},
		{
			// 第 8 點讓位說明：OrderViolation 壓過第 5 點（否則 guardrail 永不命中）
			name: "p8_over_p5",
			in:   RunOutcome{OrderViolation: true, PositivePassed: false},
			want: Verdict{Class: domain.FailureHarness, Guardrail: "order_violation"},
		},
		{
			// 第 6 點先於第 7 點：exit 0 且 oracle=true 即 PROVEN
			name: "p6_over_p7",
			in:   RunOutcome{PositivePassed: true, ExploitExitZero: true, ExploitOracleResult: true},
			want: Verdict{Proven: true},
		},
		{
			// exploit run（ExploitExitZero=true）不落入第 5 點
			name: "exploit_not_p5",
			in:   RunOutcome{PositivePassed: true, ExploitExitZero: true, ExploitOracleResult: false},
			want: Verdict{Class: domain.FailureControlledMiss},
		},
	}
	for _, c := range cases {
		v, err := b.Classify(c.in, "")
		if err != nil {
			t.Fatalf("%s: err: %v", c.name, err)
		}
		if v != c.want {
			t.Fatalf("%s: verdict = %+v，期望 %+v", c.name, v, c.want)
		}
	}
}

// §9.1：uncontrolled 在 v1 不出現——exploit exit 0、oracle=false、positive 未通過、
// 且呼叫端未標記順序違規時，Classify 必須回 error（不得靜默歸類）。
func TestClassifyRejectsUncontrolled(t *testing.T) {
	_, err := Default().Classify(RunOutcome{
		PositivePassed:  false,
		ExploitExitZero: true,
		// ExploitOracleResult = false
	}, "")
	if err == nil {
		t.Fatal("uncontrolled 形狀應回 error（§9.1）")
	}
	if !strings.Contains(err.Error(), "uncontrolled") {
		t.Fatalf("error 應提及 uncontrolled：%v", err)
	}
}

// 呼叫端誤把「不需分類的通過 run」（如已通過的 positive）餵進決策樹 → 防禦性 error。
func TestClassifyRejectsUnclassifiable(t *testing.T) {
	if _, err := Default().Classify(RunOutcome{PositivePassed: true}, ""); err == nil {
		t.Fatal("無節點命中應回 error")
	}
}

// ---- §9.3 停止條件 ----

func TestOnFailureProvenNoStop(t *testing.T) {
	b := Default()
	c := b.NewCounters()
	if stop := b.OnFailure(Verdict{Proven: true}, &c, 0); stop != nil {
		t.Fatalf("PROVEN 不應停止：%+v", stop)
	}
	if c.EnvLeft != b.MaxEnv || c.HarnessLeft != b.MaxHarness || c.HypothesesLeft != b.MaxHypotheses {
		t.Fatalf("PROVEN 不得動計數器：%+v", c)
	}
}

// controlled_miss：扣假設；3 個假設全數否證 → HYPOTHESIS_REJECTED。
func TestOnFailureHypothesesExhausted(t *testing.T) {
	b := Default()
	c := b.NewCounters()
	v := Verdict{Class: domain.FailureControlledMiss}

	for want := 2; want >= 1; want-- {
		if stop := b.OnFailure(v, &c, 0); stop != nil {
			t.Fatalf("第 %d 次否證不應停止：%+v", 4-want, stop)
		}
		if c.HypothesesLeft != want {
			t.Fatalf("HypothesesLeft = %d，期望 %d", c.HypothesesLeft, want)
		}
	}
	stop := b.OnFailure(v, &c, 0)
	if stop == nil {
		t.Fatal("假設歸零應停止")
	}
	if stop.Terminal != string(domain.VerificationHypothesisRej) || !stop.HypothesisRejected {
		t.Fatalf("stop = %+v，期望 HYPOTHESIS_REJECTED（否證）", stop)
	}
}

// harness 修正用盡 → NOT_PROVEN（harness_budget）。
func TestOnFailureHarnessBudgetExhausted(t *testing.T) {
	b := Default()
	c := b.NewCounters()
	v := Verdict{Class: domain.FailureHarness}
	for i := 0; i < b.MaxHarness-1; i++ {
		if stop := b.OnFailure(v, &c, 1); stop != nil {
			t.Fatalf("第 %d 次 harness 失敗不應停止：%+v", i+1, stop)
		}
	}
	stop := b.OnFailure(v, &c, 1)
	if stop == nil {
		t.Fatal("harness 用盡應停止")
	}
	if stop.Terminal != string(domain.VerificationNotProven) || stop.Reason != domain.NotProvenHarnessBudget {
		t.Fatalf("stop = %+v，期望 NOT_PROVEN/harness_budget", stop)
	}
	if stop.HypothesisRejected {
		t.Fatal("harness 用盡不是否證")
	}
}

// env 修正用盡 → ENV_ERROR。
func TestOnFailureEnvBudgetExhausted(t *testing.T) {
	b := Default()
	c := b.NewCounters()
	v := Verdict{Class: domain.FailureEnv}
	for i := 0; i < b.MaxEnv-1; i++ {
		if stop := b.OnFailure(v, &c, 0); stop != nil {
			t.Fatalf("第 %d 次 env 失敗不應停止：%+v", i+1, stop)
		}
	}
	stop := b.OnFailure(v, &c, 0)
	if stop == nil {
		t.Fatal("env 用盡應停止")
	}
	if stop.Terminal != string(domain.VerificationEnvError) || stop.Reason != "" {
		t.Fatalf("stop = %+v，期望 ENV_ERROR", stop)
	}
}

// 振盪：harness 分類且連續 2 次失敗簽名相同 → NOT_PROVEN（oscillation，非否證）。
func TestOnFailureOscillation(t *testing.T) {
	b := Default()

	// 第一次（sameSigCount=1）：不停
	c := b.NewCounters()
	if stop := b.OnFailure(Verdict{Class: domain.FailureHarness}, &c, 1); stop != nil {
		t.Fatalf("單次簽名不應停止：%+v", stop)
	}
	// 第二次同簽名（sameSigCount=2）：停，oscillation
	stop := b.OnFailure(Verdict{Class: domain.FailureHarness}, &c, 2)
	if stop == nil {
		t.Fatal("連續 2 次相同簽名應停止")
	}
	if stop.Terminal != string(domain.VerificationNotProven) || stop.Reason != domain.NotProvenOscillation {
		t.Fatalf("stop = %+v，期望 NOT_PROVEN/oscillation", stop)
	}
	if stop.HypothesisRejected {
		t.Fatal("振盪非否證")
	}
}

// 用盡先於振盪：兩者同時命中時以用盡的原因收斂（避免計數器歸零後仍續跑）。
func TestOnFailureExhaustionBeforeOscillation(t *testing.T) {
	b := Default()
	c := b.NewCounters()
	c.HarnessLeft = 1
	stop := b.OnFailure(Verdict{Class: domain.FailureHarness}, &c, 2)
	if stop == nil || stop.Reason != domain.NotProvenHarnessBudget {
		t.Fatalf("stop = %+v，期望 harness_budget 先於 oscillation", stop)
	}
}

// 振盪僅適用 harness 分類：controlled_miss／env 不因同簽名停。
func TestOnFailureOscillationOnlyForHarness(t *testing.T) {
	b := Default()
	c := b.NewCounters()
	if stop := b.OnFailure(Verdict{Class: domain.FailureControlledMiss}, &c, 5); stop != nil {
		t.Fatalf("controlled_miss 同簽名不應觸發振盪停：%+v", stop)
	}
	if c.HypothesesLeft != b.MaxHypotheses-1 {
		t.Fatalf("HypothesesLeft = %d", c.HypothesesLeft)
	}
	c2 := b.NewCounters()
	if stop := b.OnFailure(Verdict{Class: domain.FailureEnv}, &c2, 5); stop != nil {
		t.Fatalf("env 同簽名不應觸發振盪停：%+v", stop)
	}
	if c2.EnvLeft != b.MaxEnv-1 {
		t.Fatalf("EnvLeft = %d", c2.EnvLeft)
	}
}

// §9.3 沙箱時數上限（防 hang）：超過即應收斂；上限 ≤0 視為關閉。
func TestSandboxExceeded(t *testing.T) {
	b := Default() // 10 分鐘
	if b.SandboxExceeded(Counters{SandboxSecUsed: 9 * 60}) {
		t.Fatal("9 分鐘不應超限")
	}
	if !b.SandboxExceeded(Counters{SandboxSecUsed: 10 * 60}) {
		t.Fatal("10 分鐘應超限")
	}
	off := Budget{MaxSandboxMinutes: 0}
	if off.SandboxExceeded(Counters{SandboxSecUsed: 1 << 30}) {
		t.Fatal("上限關閉時不應超限")
	}
}

// OnFailure 只接受 Classify 的輸出；異常分類採防禦性收斂（不應無限迴圈）。
func TestOnFailureDefensiveUnknownClass(t *testing.T) {
	b := Default()
	c := b.NewCounters()
	stop := b.OnFailure(Verdict{Class: domain.FailureUncontrolled}, &c, 0)
	if stop == nil || stop.Terminal != string(domain.VerificationNotProven) {
		t.Fatalf("stop = %+v，期望防禦性 NOT_PROVEN", stop)
	}
}