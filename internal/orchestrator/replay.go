// replay.go：離線 replay 驗證（§22 M0b）。
// 從 evidence 的 run_result EV 反查每個 run 的 nonce 與 artifacts 目錄，
// 以同一 nonce 重跑 host 端 oracle checker，比對 Prove 當下的判定一致。
// 呼叫端連續呼叫兩次（×2）即為 §22 的「replay 一致性」。
package orchestrator

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aegis-dev/aegis/internal/evidence"
	"github.com/aegis-dev/aegis/internal/oracles"
	"github.com/aegis-dev/aegis/internal/packs"
)

// ReplayCheck 以落檔 evidence 重驗每個 run 的 oracle 判定（離線、無容器）。
// 比對對象是 res.Runs 的旗標；缺 EV、nonce 不符、artifacts 缺檔或不一致皆回錯。
func ReplayCheck(pack *packs.Pack, runDir string, res *ProveResult) error {
	if res == nil || res.OracleID == "" {
		return fmt.Errorf("orchestrator: replay 缺 oracle_id 或結果")
	}
	// 1. 讀取 run_result EV：run_id → (nonce, artifacts_dir)。
	runsOnDisk, err := loadRunResults(filepath.Join(runDir, "evidence"))
	if err != nil {
		return err
	}
	for _, rec := range res.Runs {
		ev, ok := runsOnDisk[rec.RunID]
		if !ok {
			return fmt.Errorf("orchestrator: replay: run %s 無 run_result evidence", rec.RunID)
		}
		if ev.nonce != rec.Nonce {
			return fmt.Errorf("orchestrator: replay: run %s 的 nonce 與 evidence 不符", rec.RunID)
		}
		if _, err := os.Stat(ev.artifactsDir); err != nil {
			return fmt.Errorf("orchestrator: replay: run %s artifacts 缺失: %w", rec.RunID, err)
		}
		// vuln oracle 重驗。
		vuln, err := recheckRule(pack, res.OracleID, ev.nonce, ev.artifactsDir)
		if err != nil {
			return fmt.Errorf("orchestrator: replay: run %s vuln oracle: %w", rec.RunID, err)
		}
		if vuln != rec.VulnOracle {
			return fmt.Errorf("orchestrator: replay: run %s vuln oracle 不一致（ev=%v、replay=%v）", rec.RunID, rec.VulnOracle, vuln)
		}
		// touch rule 重驗（vuln oracle 的 paired touch）。
		touch, err := recheckTouch(pack, res.OracleID, ev.nonce, ev.artifactsDir)
		if err != nil {
			return fmt.Errorf("orchestrator: replay: run %s touch rule: %w", rec.RunID, err)
		}
		if touch != rec.TouchOracle {
			return fmt.Errorf("orchestrator: replay: run %s touch rule 不一致（ev=%v、replay=%v）", rec.RunID, rec.TouchOracle, touch)
		}
	}
	return nil
}

type runResult struct {
	nonce        string
	artifactsDir string
	kindLabel    string
}

// loadRunResults 掃 evidence 目錄的 run_result EV。
func loadRunResults(evidenceDir string) (map[string]runResult, error) {
	entries, err := os.ReadDir(evidenceDir)
	if err != nil {
		return nil, fmt.Errorf("orchestrator: replay: 讀 evidence 目錄: %w", err)
	}
	out := map[string]runResult{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "EV-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(evidenceDir, name))
		if err != nil {
			return nil, err
		}
		m, err := evidence.Decode(data)
		if err != nil {
			return nil, err
		}
		if m["kind"] != "run_result" {
			continue
		}
		runID, _ := m["run_id"].(string)
		nonce, _ := m["nonce"].(string)
		art, _ := m["artifacts_dir"].(string)
		kindLabel, _ := m["kind_label"].(string)
		if runID == "" || nonce == "" || art == "" {
			return nil, fmt.Errorf("orchestrator: replay: %s 欄位不完整", name)
		}
		out[runID] = runResult{nonce: nonce, artifactsDir: art, kindLabel: kindLabel}
	}
	return out, nil
}

// recheckRule 以 oracle_id 取 pack 條目並重跑 checker（純資料、無直譯器，§17.3）。
func recheckRule(pack *packs.Pack, oracleID, nonce, artifactsDir string) (bool, error) {
	entry, err := pack.Oracle(oracleID)
	if err != nil {
		return false, err
	}
	rule, err := OracleRule(entry)
	if err != nil {
		return false, err
	}
	res, err := oracles.Check(rule.Rule, nonce, artifactsDir)
	if err != nil {
		return false, err
	}
	return res.Result, nil
}

// recheckTouch 以 vuln oracle 的 paired touch rule 重跑 checker。
func recheckTouch(pack *packs.Pack, vulnOracleID, nonce, artifactsDir string) (bool, error) {
	v, err := pack.Oracle(vulnOracleID)
	if err != nil {
		return false, err
	}
	if v.Touch == nil {
		return false, fmt.Errorf("orchestrator: replay: oracle %q 無 paired touch rule", vulnOracleID)
	}
	return recheckRule(pack, *v.Touch, nonce, artifactsDir)
}