// replay.go：離線 replay 驗證（§22 M0b）。
// 從 evidence 的 run_result EV 反查每個 run 的 nonce 與 artifacts 目錄，
// 以同一 nonce 重跑 host 端 oracle checker，比對 Prove 當下的判定一致。
// 呼叫端連續呼叫兩次（×2）即為 §22 的「replay 一致性」。
package orchestrator

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aegis-dev/aegis/internal/evidence"
	"github.com/aegis-dev/aegis/internal/oracles"
	"github.com/aegis-dev/aegis/internal/packs"
)

// ReplayBundle 只依賴落檔 bundle 重驗每個 run 的 oracle 判定（離線、無容器）。
// bundle 必須包含 evidence/EV-*.json 與 evidence/runs/<run_id>/；不需要原始
// ProveResult，因此可在另一個程序或另一台機器上做自包含 replay。
func ReplayBundle(pack *packs.Pack, runDir string) error {
	runsOnDisk, err := loadRunResults(filepath.Join(runDir, "evidence"))
	if err != nil {
		return err
	}
	if len(runsOnDisk) == 0 {
		return fmt.Errorf("orchestrator: replay: bundle 沒有 run_result evidence")
	}
	for runID, ev := range runsOnDisk {
		if _, err := os.Stat(ev.artifactsDir); err != nil {
			return fmt.Errorf("orchestrator: replay: run %s artifacts 缺失: %w", runID, err)
		}
		for name, want := range ev.artifactHashes {
			b, err := os.ReadFile(filepath.Join(ev.artifactsDir, name))
			if err != nil {
				return fmt.Errorf("orchestrator: replay: run %s artifact %s 缺失: %w", runID, name, err)
			}
			h := sha256.Sum256(b)
			got := "sha256:" + hex.EncodeToString(h[:])
			if got != want {
				return fmt.Errorf("orchestrator: replay: run %s artifact %s hash 不一致", runID, name)
			}
		}
		// vuln oracle 重驗。
		vuln, err := recheckRule(pack, ev.oracleID, ev.nonce, ev.artifactsDir)
		if err != nil {
			return fmt.Errorf("orchestrator: replay: run %s vuln oracle: %w", runID, err)
		}
		if vuln != ev.vuln {
			return fmt.Errorf("orchestrator: replay: run %s vuln oracle 不一致（ev=%v、replay=%v）", runID, ev.vuln, vuln)
		}
		// touch rule 重驗（vuln oracle 的 paired touch）。
		touch, err := recheckTouch(pack, ev.oracleID, ev.nonce, ev.artifactsDir)
		if err != nil {
			return fmt.Errorf("orchestrator: replay: run %s touch rule: %w", runID, err)
		}
		if touch != ev.touch {
			return fmt.Errorf("orchestrator: replay: run %s touch rule 不一致（ev=%v、replay=%v）", runID, ev.touch, touch)
		}
	}
	return nil
}

// ReplayCheck 保留舊呼叫介面，並額外比對記憶體結果；新的呼叫端應使用
// ReplayBundle，避免把 replay 正確性綁在原始程序狀態上。
func ReplayCheck(pack *packs.Pack, runDir string, res *ProveResult) error {
	if res == nil || res.OracleID == "" {
		return fmt.Errorf("orchestrator: replay 缺 oracle_id 或結果")
	}
	if err := ReplayBundle(pack, runDir); err != nil {
		return err
	}
	runsOnDisk, err := loadRunResults(filepath.Join(runDir, "evidence"))
	if err != nil {
		return err
	}
	for _, rec := range res.Runs {
		ev, ok := runsOnDisk[rec.RunID]
		if !ok || ev.nonce != rec.Nonce || ev.vuln != rec.VulnOracle || ev.touch != rec.TouchOracle {
			return fmt.Errorf("orchestrator: replay: run %s evidence 與結果不一致", rec.RunID)
		}
	}
	return nil
}

type runResult struct {
	oracleID       string
	nonce          string
	artifactsDir   string
	kindLabel      string
	vuln           bool
	touch          bool
	artifactHashes map[string]string
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
		kind, _ := m["kind"].(string)
		if kind != "negative" && kind != "positive" && kind != "exploit" {
			continue
		}
		runID, _ := m["run_id"].(string)
		oracle, _ := m["oracle"].(map[string]any)
		oracleID, _ := oracle["oracle_id"].(string)
		if oracleID == "" {
			return nil, fmt.Errorf("orchestrator: replay: %s 缺 oracle.oracle_id", name)
		}
		nonce, _ := oracle["nonce"].(string)
		vuln, _ := oracle["result"].(bool)
		touchDoc, _ := oracle["touch"].(map[string]any)
		touch, _ := touchDoc["result"].(bool)
		rr, _ := m["run_result"].(map[string]any)
		hashes := map[string]string{}
		if raw, ok := rr["artifact_hashes"].(map[string]any); ok {
			for name, value := range raw {
				if s, ok := value.(string); ok {
					hashes[name] = s
				}
			}
		}
		if runID == "" || nonce == "" {
			return nil, fmt.Errorf("orchestrator: replay: %s 欄位不完整", name)
		}
		art := filepath.Join(filepath.Dir(evidenceDir), "evidence", "runs", runID)
		out[runID] = runResult{oracleID: oracleID, nonce: nonce, artifactsDir: art, kindLabel: kind, vuln: vuln, touch: touch, artifactHashes: hashes}
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
