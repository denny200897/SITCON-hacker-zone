// prove.go：決定性三控制 run 流水線（negative → positive → exploit；§5.2 固定順序）。
// v1 序列、無 goroutine（§23-1）；每個 run 獨立容器、獨立 nonce、獨立 evidence。
// 失敗分類全走 budget.Classify（§19 決策樹），停止權在 orchestrator（§9.3）。
//
// 誠實邊界（ADR 0002）：M0b 決定性 harness 無自我修正能力，呼叫端以單次預算
//（MaxEnv=MaxHarness=MaxHypotheses=1）驅動——任一失敗即終態：
// env → ENV_ERROR、harness → NOT_PROVEN(harness_budget)、controlled_miss →
// HYPOTHESIS_REJECTED。重試與假設迭代由 M0c agent 迴圈承接（多假設預算）。
package orchestrator

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/aegis-dev/aegis/internal/domain"
	"github.com/aegis-dev/aegis/internal/evidence"
	"github.com/aegis-dev/aegis/internal/journal"
	"github.com/aegis-dev/aegis/internal/orchestrator/budget"
	"github.com/aegis-dev/aegis/internal/orchestrator/policy"
	"github.com/aegis-dev/aegis/internal/oracles"
	"github.com/aegis-dev/aegis/internal/packs"
	"github.com/aegis-dev/aegis/internal/redaction"
	"github.com/aegis-dev/aegis/internal/sandbox"
)

// Prover 是一次證明工作的執行器（三控制 run；§5.2）。
type Prover struct {
	Runner  *sandbox.Runner
	Journal *journal.Journal
	Store   *evidence.Store
	Pack    *packs.Pack
	PackDir string // seccomp profile 來源（pack/sandbox/seccomp.json）

	SnapshotID  string
	SnapshotDir string
	RunDir      string // <runDir>；evidence/ 與 evidence/runs/ 於其下

	CachePath string // ~/.cache/aegis/images.json（映像解析 §17.10；可空）

	Budget         budget.Budget
	PrevSpecHashes map[string]bool
}

// ProveInput 是一次證明的輸入（M0b 由呼叫端手寫；M0c 由 agent 迴圈產生）。
type ProveInput struct {
	FindingID    string         // F-####；journal finding_id
	Reachability string         // D0..D3
	Spec         map[string]any // WitnessSpec（payload 為 exploit 假設，含 {{NONCE}}）
}

// RunRecord 是單一 run 的結果摘要（evidence 的宿主側視圖）。
type RunRecord struct {
	RunID       string
	Kind        string
	Exit        int
	VulnOracle  bool
	TouchOracle bool
	EvidenceID  string
	Nonce       string // §17.2：run 結束後才記錄（供離線 replay 重驗 oracle）
	Err         string // 非空 = 執行環境錯誤
}

// ProveResult 是三控制 run 的終態。
type ProveResult struct {
	Verification    domain.Verification
	NotProvenReason domain.NotProvenReason // 僅 NOT_PROVEN 時非空
	Runs            []RunRecord
	FailureClass    domain.FailureClass // 非 PROVEN 時的 §19 分類
	OracleMisfired  bool
	OracleID        string // 本輪使用的 vuln oracle（replay 驗證用）
}

// Prove 執行三控制 run（固定順序 negative → positive → exploit；§5.2）。
// exploit 只在 negative（vuln oracle 未誤觸發）與 positive（touch rule 命中）都通過後執行；
// 順序由本函式強制，呼叫端無法破壞（guardrail，§5.2-3）。
func (p *Prover) Prove(ctx context.Context, in ProveInput) (*ProveResult, error) {
	if err := p.Runner.Available(); err != nil {
		return nil, fmt.Errorf("orchestrator: docker 不可用: %w", err)
	}
	seccomp, err := SeccompPath(p.PackDir)
	if err != nil {
		return nil, err
	}

	res := &ProveResult{Verification: domain.VerificationNotRun, OracleID: strField(in.Spec, "oracle_id")}
	counters := p.Budget.NewCounters()

	// 各 kind 的 payload 來源：
	//   negative／positive：pack manifest 的 benign payload（pack 資料，非模型輸入）
	//   exploit：spec.payload（prover 假設；policy 驗證 placeholder 與大小）
	benign, err := p.benignPayload()
	if err != nil {
		return nil, err
	}
	plan := []struct {
		kind    domain.RunKind
		payload string
	}{
		{domain.RunNegative, benign},
		{domain.RunPositive, benign},
		{domain.RunExploit, strField(in.Spec, "payload")},
	}

	positivePassed := false
	for _, step := range plan {
		if step.kind == domain.RunExploit && !positivePassed {
			// 順序 guardrail：positive 未通過不得執行 exploit（§5.2-3）。
			res.Verification = domain.VerificationNotProven
			res.NotProvenReason = domain.NotProvenHarnessBudget
			res.FailureClass = domain.FailureHarness
			return res, nil
		}
		rec, verdict, stop, err := p.runOne(ctx, seccomp, in, string(step.kind), step.payload, positivePassed, &counters)
		if err != nil {
			return nil, err
		}
		res.Runs = append(res.Runs, *rec)

		switch {
		case stop != nil:
			res.Verification = domain.Verification(stop.Terminal)
			res.NotProvenReason = stop.Reason
			res.FailureClass = verdict.Class
			res.OracleMisfired = verdict.OracleMisfired
			return res, nil
		case verdict.Proven:
			res.Verification = domain.VerificationProven
			return res, nil
		case verdict.Class != "":
			// 預算未到停止線（M0c 可重試），決定性 harness 無下一個修正動作：
			// 以分類直接終態（ADR 0002）。
			res.FailureClass = verdict.Class
			res.OracleMisfired = verdict.OracleMisfired
			switch verdict.Class {
			case domain.FailureEnv:
				res.Verification = domain.VerificationEnvError
			case domain.FailureHarness:
				res.Verification = domain.VerificationNotProven
				res.NotProvenReason = domain.NotProvenHarnessBudget
			case domain.FailureControlledMiss:
				res.Verification = domain.VerificationHypothesisRej
			}
			return res, nil
		}
		if step.kind == domain.RunPositive {
			positivePassed = true // runOne 正常返回即 positive 控制點成立
		}
	}
	// 三 run 皆過但無 PROVEN——不應發生（exploit 的 Classify 必回 Proven 或錯誤）。
	return nil, fmt.Errorf("orchestrator: 三控制 run 完成但無終態（內部不一致）")
}

// runOne 執行單一 run：compile → 容器 → 收回 → oracle → 分類。
// verdict.Class 為空表示該 run 正常通過其控制點（negative 無誤觸發／positive 通過）。
func (p *Prover) runOne(ctx context.Context, seccomp string, in ProveInput, kind, payload string, positivePassed bool, counters *budget.Counters) (*RunRecord, budget.Verdict, *budget.Stop, error) {
	runID, err := p.Journal.NextID("R")
	if err != nil {
		return nil, budget.Verdict{}, nil, fmt.Errorf("orchestrator: 分配 run id: %w", err)
	}
	nonce, err := NewNonce()
	if err != nil {
		return nil, budget.Verdict{}, nil, err
	}

	// spec 組裝：以 kind 的 payload 覆寫 spec.payload（negative/positive 用 pack 良性載荷）。
	spec := cloneSpec(in.Spec)
	spec["payload"] = payload

	rr, cerr := policy.Compile(policy.Input{
		Spec:                spec,
		FindingReachability: in.Reachability,
		SnapshotDir:         p.SnapshotDir,
		PrevSpecHashes:      p.PrevSpecHashes,
		SecretScan:          func(s string) bool { return redaction.HasSecret(s) },
		ASTCheck:            ASTCheck,
		PackView:            NewPackView(p.Pack, p.CachePath),
		RunID:               runID,
		SnapshotID:          p.SnapshotID,
		Kind:                kind,
	}, nonce)
	if cerr != nil {
		return nil, budget.Verdict{}, nil, fmt.Errorf("orchestrator: policy compile: %w", cerr)
	}
	for _, evt := range []struct {
		typ string
		doc map[string]any
	}{
		{"witness_spec_submitted", map[string]any{
			"run_id": runID, "kind": kind,
			"template_id": strField(spec, "template_id"), "oracle_id": strField(spec, "oracle_id"),
		}},
		{"run_requested", map[string]any{
			"run_id": runID, "kind": kind, "image": strField(rr, "image"), "nonce": nonce,
		}},
	} {
		if _, err := p.Journal.Append(evt.typ, in.FindingID, evt.doc); err != nil {
			return nil, budget.Verdict{}, nil, err
		}
	}

	_, evID, exit, rerr := p.executeRun(ctx, seccomp, rr, nonce, in.FindingID, string(kind))
	rec := &RunRecord{RunID: runID, Kind: kind, Exit: exit, Nonce: nonce, EvidenceID: evID}

	// 執行層錯誤（docker/reclaim 等）：歸 env，扣預算（§19 第 1 點）。
	if rerr != nil {
		v := budget.Verdict{Class: domain.FailureEnv}
		p.journalBudget(in.FindingID, v)
		stop := p.Budget.OnFailure(v, counters, 0)
		rec.Err = rerr.Error()
		return rec, v, stop, nil
	}

	// oracle 判定（§17.3：host 端 checker；stdout 永不為證據）。
	vulnOracle, vulnErr := p.checkOracle(in, string(kind), runID, nonce, "vuln")
	touchOracle, touchErr := p.checkOracle(in, string(kind), runID, nonce, "touch")
	rec.VulnOracle = vulnOracle
	rec.TouchOracle = touchOracle

	var outcome budget.RunOutcome
	outcome.Exit = exit
	switch domain.RunKind(kind) {
	case domain.RunNegative:
		// negative 只在其控制點上分類：vuln oracle 誤觸發 → harness（§19 第 4 點）。
		if vulnErr != nil || vulnOracle {
			outcome.NegativeOracleTrue = true
		} else {
			return rec, budget.Verdict{}, nil, nil
		}
	case domain.RunPositive:
		// positive 控制點：exit 0 且 touch rule 命中；否則 harness（§19 第 5 點）。
		if exit == 0 && touchErr == nil && touchOracle {
			return rec, budget.Verdict{}, nil, nil
		}
		outcome.PositivePassed = false
	case domain.RunExploit:
		outcome.ExploitExitZero = exit == 0
		outcome.ExploitOracleResult = vulnErr == nil && vulnOracle
		outcome.PositivePassed = positivePassed
	}
	v, cerr := p.Budget.Classify(outcome, "")
	if cerr != nil {
		return nil, budget.Verdict{}, nil, fmt.Errorf("orchestrator: classify %s %s: %w", kind, runID, cerr)
	}
	p.journalBudget(in.FindingID, v)
	stop := p.Budget.OnFailure(v, counters, 0)
	return rec, v, stop, nil
}

// executeRun 執行容器生命週期：StageWitness（注入 staging）→ docker create →
// start → reclaim。注入走 per-run witness volume（ADR 0002；docker 29 對
// --read-only rootfs 的 docker cp 限制）。產物落 <RunDir>/evidence/runs/<runID>/，
// 並寫 run_result EV。回傳 (artifacts 目錄, evidence id, exit code, 執行層錯誤)。
func (p *Prover) executeRun(ctx context.Context, seccomp string, rr map[string]any, nonce, findingID, kind string) (artDir, evID string, exit int, retErr error) {
	runID, err := reqStr(rr, "run_id")
	if err != nil {
		return "", "", 0, err
	}
	// 注入失敗／後續任一步失敗時，best-effort 清收 staging 殘留（staging 容器
	// 由 Reaper 以 label 反查、witness volume 直接刪）；Reclaim 成功路徑會再清一次。
	defer func() {
		if retErr != nil {
			_ = p.Runner.Reaper(runID)
			_ = p.Runner.RemoveWitnessVolume(runID)
		}
	}()

	// 注入：witness 檔案與 payload 一律以檔案給入（§17.4-4；機制 ADR 0002）。
	files := sandbox.StageFiles{}
	if rawFiles, ok := rr["files"].(map[string]any); ok {
		for name, content := range rawFiles {
			s, ok := content.(string)
			if !ok {
				return "", "", 0, fmt.Errorf("orchestrator: RunRequest.files[%q] 非字串", name)
			}
			rel := strings.TrimPrefix(name, policy.FilesPrefix)
			if rel == name {
				return "", "", 0, fmt.Errorf("orchestrator: RunRequest.files key %q 不帶 %q 前綴", name, policy.FilesPrefix)
			}
			files[rel] = []byte(s)
		}
	}
	var payload []byte
	if pl, ok := rr["payload"].(string); ok {
		payload = []byte(pl)
	}
	if err := p.Runner.StageWitness(ctx, runID, files, payload); err != nil {
		return "", "", 0, fmt.Errorf("orchestrator: 注入 staging %s: %w", runID, err)
	}

	spec, err := RunRequestToRunSpec(rr, p.SnapshotID, seccomp, p.SnapshotDir)
	if err != nil {
		return "", "", 0, err
	}
	args, err := sandbox.DockerArgs(spec, p.SnapshotDir)
	if err != nil {
		return "", "", 0, err
	}
	cid, err := p.Runner.Create(args)
	if err != nil {
		return "", "", 0, err
	}

	timeout, err := reqInt(rr, "timeout_sec")
	if err != nil {
		return "", "", 0, err
	}
	// Start 以 ctx 傳播呼叫端取消（使用者取消／Prove(ctx) 取消即時終止容器；
	// P2-2）；timeout 逾時語意不變（§17.1 host 端強制）。
	exit, err = p.Runner.Start(ctx, cid, timeout)
	if err != nil {
		return "", "", 0, err
	}

	// 收回產物（§17.6）：artifacts 到 evidence/runs/<runID>/。
	artDir, err = evidence.RunDirFor(p.RunDir, runID)
	if err != nil {
		return "", "", exit, err
	}
	// Reclaim 套與 run 容器同一份 seccomp／hardening（§17.6-2、§23-8；P2-2）。
	if rerr := p.Runner.Reclaim(ctx, cid, runID, artDir, seccomp); rerr != nil {
		return "", "", exit, fmt.Errorf("orchestrator: reclaim %s: %w", runID, rerr)
	}

	// evidence：run_result 落 EV（含 nonce 供離線 replay）。
	evID, err = p.Journal.NextID("EV")
	if err != nil {
		return "", evID, exit, err
	}
	doc := map[string]any{
		"kind":           "run_result",
		"run_id":         runID,
		"kind_label":     kind,
		"finding_id":     findingID,
		"image":          strField(rr, "image"),
		"exit_code":      int64(exit),
		"nonce":          nonce,
		"artifacts_dir":  filepath.ToSlash(artDir),
		"schema_version": domain.SchemasVersion,
		"generated_by":   "orchestrator",
		"snapshot_id":    p.SnapshotID,
	}
	if _, _, werr := p.Store.Write(doc, evID); werr != nil {
		return "", evID, exit, fmt.Errorf("orchestrator: 寫 evidence %s: %w", evID, werr)
	}
	if _, err := p.Journal.Append("run_completed", findingID, map[string]any{
		"run_id": runID, "kind": kind, "exit_code": int64(exit), "evidence_id": evID,
	}); err != nil {
		return "", evID, exit, err
	}
	if _, err := p.Journal.Append("evidence_written", findingID, map[string]any{
		"evidence_id": evID, "run_id": runID,
	}); err != nil {
		return "", evID, exit, err
	}
	return artDir, evID, exit, nil
}

// checkOracle 以 pack 的 vuln／touch rule 判定收回的 artifacts。
// 環境問題（artifact 缺檔等）與「未命中」嚴格分離：第二回傳值非 nil 即環境問題（§19）。
func (p *Prover) checkOracle(in ProveInput, kind, runID, nonce, which string) (bool, error) {
	specOracle := strField(in.Spec, "oracle_id")
	if specOracle == "" {
		return false, fmt.Errorf("orchestrator: spec 缺 oracle_id")
	}
	var entry *packs.OracleEntry
	var err error
	if which == "vuln" {
		entry, err = p.Pack.Oracle(specOracle)
	} else {
		if v, verr := p.Pack.Oracle(specOracle); verr == nil && v.Touch != nil {
			entry, err = p.Pack.Oracle(*v.Touch)
		} else if verr == nil {
			return false, fmt.Errorf("orchestrator: oracle %q 無 paired touch rule", specOracle)
		} else {
			err = verr
		}
	}
	if err != nil {
		return false, fmt.Errorf("orchestrator: 解析 oracle（%s）: %w", which, err)
	}
	rule, err := OracleRule(entry)
	if err != nil {
		return false, err
	}
	artDir := filepath.Join(p.RunDir, "evidence", "runs", runID)
	res, err := oracles.Check(rule.Rule, nonce, artDir)
	if err != nil {
		return false, fmt.Errorf("orchestrator: oracle %s 判定失敗: %w", oracleID(kind, which), err)
	}
	return res.Result, nil
}

// journalBudget 記錄 budget_updated（分類非空時）。
func (p *Prover) journalBudget(findingID string, v budget.Verdict) {
	if v.Class == "" {
		return
	}
	_, _ = p.Journal.Append("budget_updated", findingID, map[string]any{
		"failure_class": string(v.Class), "oracle_misfired": v.OracleMisfired,
		"guardrail": v.Guardrail,
	})
}

// benignPayload 取 pack manifest 的 benign payload 內容（negative/positive 控制 run 用）。
func (p *Prover) benignPayload() (string, error) {
	for _, pl := range p.Pack.Manifest.Payloads {
		if pl.Kind == "benign" {
			if pl.Content == "" {
				return "", fmt.Errorf("orchestrator: pack benign payload %q 內容為空", pl.ID)
			}
			return pl.Content, nil
		}
	}
	return "", fmt.Errorf("orchestrator: pack %q 缺 benign payload（控制 run 無法組裝）", p.Pack.Manifest.PackID)
}

// cloneSpec 淺拷貝 spec（payload 覆寫不污染呼叫端）。
func cloneSpec(spec map[string]any) map[string]any {
	out := make(map[string]any, len(spec)+1)
	for k, v := range spec {
		out[k] = v
	}
	return out
}

func strField(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

func oracleID(kind, which string) string {
	return kind + "/" + which
}