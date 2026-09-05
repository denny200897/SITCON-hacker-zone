// Package e2e：M0b 決定性 SQLi E2E（SPEC §22）。
// 全程真容器：snapshot → pack → policy → sandbox 三控制 run → oracle → evidence 鏈 →
// replay ×2 一致性；外加 adversarial observer 偽造封鎖測試（review P0-01、ADR 0005）。
// docker 不可用或 pack 映像缺本地 digest 時 skip（§7.1：無本機 fallback，但不讓測試誤報）。
package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aegis-dev/aegis/internal/domain"
	"github.com/aegis-dev/aegis/internal/evidence"
	"github.com/aegis-dev/aegis/internal/inventory"
	"github.com/aegis-dev/aegis/internal/journal"
	"github.com/aegis-dev/aegis/internal/orchestrator"
	"github.com/aegis-dev/aegis/internal/orchestrator/budget"
	"github.com/aegis-dev/aegis/internal/orchestrator/snapshot"
	"github.com/aegis-dev/aegis/internal/packs"
	"github.com/aegis-dev/aegis/internal/sandbox"
)

const (
	packImageName  = "aegis-python-web"
	packImageTag   = "aegis-python-web:3.12"
	fixtureDirName = "fixtures/vuln-sqli-001"
)

// env 必備前提：pack（含 digest 記載的映像）、alpine helper、docker daemon。
func setupE2E(t *testing.T) (*orchestrator.Prover, string) {
	t.Helper()
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	packDir := filepath.Join(repoRoot, "packs", "python-web")

	runner := &sandbox.Runner{}
	if err := runner.Available(); err != nil {
		t.Skipf("docker 不可用，跳過 E2E：%v", err)
	}

	pack, err := packs.LoadWithSchemas(packDir, filepath.Join(repoRoot, "schemas"), false)
	if err != nil {
		t.Fatalf("載入 pack: %v", err)
	}

	// 映像解析（§17.10 第 1 階）：manifest 已記 digest。
	// 本地構建映像以 repo digest 定址；重建（即使全快取）會產生新 manifest digest
	//（config 時間戳），故只在 tag 整個不存在時才構建，digest 不符時以 /doctor 語意要求重錄。
	imageRef := pack.Manifest.Templates[0].Image
	if !imageExists(imageRef) {
		if tagExists() {
			t.Skipf("本地 tag 的 repo digest 與 manifest %q 不符（需以 /doctor 重錄）", imageRef)
		}
		buildPackImage(t, repoRoot)
		if !imageExists(imageRef) {
			t.Skipf("pack 映像構建後仍缺 manifest digest %q（需重錄）", imageRef)
		}
	}

	helper, ok := pack.Manifest.Images["helper/alpine"]
	if !ok {
		t.Fatal("manifest 缺 helper/alpine 映像記錄")
	}
	runner.HelperImage = helper

	// 快取與 run 目錄（全在 t.TempDir()，與使用者快取隔離）。
	runDir := filepath.Join(t.TempDir(), "run")
	cacheDir := filepath.Join(t.TempDir(), "cache")
	if os.Getenv("AEGIS_E2E_KEEP") != "" {
		// 除錯用：保留 run 目錄供檢視（正常 CI 不設此變數）。
		runDir = filepath.Join(os.TempDir(), "aegis-e2e-keep", "run")
		cacheDir = filepath.Join(os.TempDir(), "aegis-e2e-keep", "cache")
		_ = os.RemoveAll(filepath.Join(os.TempDir(), "aegis-e2e-keep"))
		for _, d := range []string{runDir, cacheDir} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, d := range []string{runDir, cacheDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	j, err := journal.Open(filepath.Join(runDir, "journal.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	store, err := evidence.NewStore(runDir)
	if err != nil {
		t.Fatal(err)
	}

	snap, err := snapshot.Create(filepath.Join(repoRoot, fixtureDirName), filepath.Join(cacheDir, "snapshots"), inventory.DefaultExcludes)
	if err != nil {
		t.Fatal(err)
	}

	// F-#### 由 journal 分配（finding 建立事件的簡化；完整 finding 流程屬 M0c/CLI）。
	findingID, err := j.NextID("F")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Append("finding_created", findingID, map[string]any{
		"fixture": fixtureDirName, "sink_type": "sql.concat",
	}); err != nil {
		t.Fatal(err)
	}

	return &orchestrator.Prover{
		Runner:         runner,
		Journal:        j,
		Store:          store,
		Pack:           pack,
		PackDir:        packDir,
		SchemasDir:     filepath.Join(repoRoot, "schemas"),
		SnapshotID:     snap.ID,
		SnapshotDir:    snap.Dir,
		RunDir:         runDir,
		CachePath:      filepath.Join(cacheDir, "images.json"),
		Budget:         budget.Budget{MaxEnv: 1, MaxHarness: 1, MaxHypotheses: 1, MaxSandboxMinutes: 10},
		PrevSpecHashes: map[string]bool{},
	}, findingID
}

// sqliWitnessSpec：手寫 WitnessSpec（M0b 決定性；M0c 起由 agent 迴圈產生）。
// ADR 0005 雙容器切分：witness 模式下模型只提供 exploit driver（打 trusted side
// harness 的 /c/ 面）與宣告式 wiring（seed 接線）；目標程式的服務由 pack 的
// target_harness.py 承接，模型碼與 observer 無網路路徑。
func sqliWitnessSpec(t *testing.T) map[string]any {
	t.Helper()
	exploitPy := `# exploit driver：從 /aegis/payload.txt 讀 payload（不自行硬編，§2.2）；
# 目標是 trusted side harness 的 /c/ 面（ADR 0005）。
import os
import urllib.parse
import urllib.request

with open("/aegis/payload.txt", encoding="utf-8") as f:
    payload = f.read().strip()
base = os.environ["AEGIS_TARGET_URL"]
url = base + "/c/" + urllib.parse.quote(payload, safe="")
try:
    with urllib.request.urlopen(url, timeout=10) as r:
        print("status", r.status)
except Exception as exc:
    # 目標回 500（error-based 注入的常見結果）不是 harness 失敗；成功由 host 端 oracle 判定。
    print("request failed:", exc)
`
	return map[string]any{
		"template_id":   "py/http-endpoint/v3",
		"oracle_id":     "sqli.error/v1",
		"run_mode":      "witness",
		"payload":       "{{NONCE}}'",
		"target_symbol": "app.UserRepo.find_by_name",
		"wiring": map[string]any{
			"setup": []any{
				map[string]any{"method": "seed", "args": []any{[]any{"alice", "bob"}}},
			},
		},
		"assumptions": []any{
			"UserRepo.find_by_name 以 f-string 將 name 串接進 SQL（error-based SQLi）",
		},
		"generated_files": map[string]any{
			"witness/exploit.py": exploitPy,
		},
	}
}

// TestM0bSqliProvenE2E：三控制 run 全綠 → PROVEN（§22 M0b 驗收主線）。
func TestM0bSqliProvenE2E(t *testing.T) {
	prover, findingID := setupE2E(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	res, err := prover.Prove(ctx, orchestrator.ProveInput{
		FindingID:    findingID,
		Reachability: "D0",
		Spec:         sqliWitnessSpec(t),
	})
	if err != nil {
		t.Fatalf("Prove 失敗: %v", err)
	}
	if res.Verification != domain.VerificationProven {
		t.Fatalf("預期 PROVEN，得 %s（failure=%s runs=%+v）", res.Verification, res.FailureClass, res.Runs)
	}
	if res.OracleID != "sqli.error/v1" {
		t.Fatalf("OracleID 不符：%q", res.OracleID)
	}
	if len(res.Runs) != 3 {
		t.Fatalf("應恰三個 run，得 %d", len(res.Runs))
	}
	// §5.2 固定順序：negative → positive → exploit。
	wantOrder := []string{"negative", "positive", "exploit"}
	for i, want := range wantOrder {
		if res.Runs[i].Kind != want {
			t.Fatalf("run 順序不符：位置 %d 得 %s，預期 %s", i, res.Runs[i].Kind, want)
		}
	}
	// 控制點事實：negative 無誤觸發、positive touch 命中、exploit oracle 命中。
	if res.Runs[0].VulnOracle {
		t.Fatal("negative run 的 vuln oracle 不應命中")
	}
	if !res.Runs[1].TouchOracle {
		t.Fatal("positive run 的 touch rule 應命中")
	}
	if !res.Runs[2].VulnOracle || res.Runs[2].Exit != 0 {
		t.Fatalf("exploit run 應 exit 0 且 vuln oracle 命中：%+v", res.Runs[2])
	}
	// 三個 run 各自 nonce 不同（§17.2：每 run 重新產生）。
	if res.Runs[0].Nonce == res.Runs[1].Nonce || res.Runs[1].Nonce == res.Runs[2].Nonce {
		t.Fatal("nonce 應逐 run 不同")
	}
	e2eVerifyChainAndReplay(t, prover.Pack, prover.RunDir, res)
}

// TestM0bObserverForgeryBlockedE2E（review P0-01 驗收）：adversarial witness
// 從不呼叫 target symbol——改為 (a) 直接對 observer:8787 進行 TCP 連線，企圖
// 假造含 nonce 的 trace 事件；(b) 把假 trace 寫進 /aegis/out/sql_trace.jsonl；
// (c) stdout 印 "PROVEN"。雙容器切分（ADR 0005）下，W 沒有到 observer 網路的
// 路由、/aegis/out 是 tmpfs（不會被收回），可信 trace 只能由真實執行目標碼的
// 容器 T 產生——未觸發 sink 即無 nonce 進 SQL → positive 控制點失敗 →
// 終態不得為 PROVEN（§22：偽造必須不可重現 PROVEN）。
func TestM0bObserverForgeryBlockedE2E(t *testing.T) {
	prover, findingID := setupE2E(t)
	spec := sqliWitnessSpec(t)
	// 移除 wiring：目標 seed 不執行；witness 換成純偽造驅動（不打 /c/）。
	delete(spec, "wiring")
	spec["generated_files"] = map[string]any{
		"witness/exploit.py": `# adversarial driver：不呼叫 target symbol，直接偽造可信事件（P0-01 攻擊面）。
import json
import os
import socket

nonce = open("/aegis/payload.txt", encoding="utf-8").read().strip()
# (a) 直攻 observer：切分模式下 driver 容器無此網路路由，必然失敗。
try:
    with socket.create_connection(("observer", 8787), timeout=5) as s:
        s.sendall(json.dumps({"op": "execute",
                              "sql": "SELECT id, name FROM users WHERE name = '%s'" % nonce,
                              "params": []}).encode("utf-8") + b"\n")
    print("observer reachable — forgery channel open")
except Exception as exc:
    print("observer unreachable (expected):", exc)
# (b) 直接寫 out volume 的 trace 檔：切分後 driver 的 /aegis/out 是 tmpfs。
try:
    with open("/aegis/out/sql_trace.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": 0, "sql": "SELECT id, name FROM users WHERE name = '%s'" % nonce,
                            "params": "[]", "error": None, "rows": 1}) + "\n")
    print("wrote forged local trace")
except Exception as exc:
    print("local trace write failed (expected):", exc)
# (c) stdout 假成功標記：永不為證據（§17.3）。
print("PROVEN", nonce)
`,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	res, err := prover.Prove(ctx, orchestrator.ProveInput{
		FindingID:    findingID,
		Reachability: "D0",
		Spec:         spec,
	})
	if err != nil {
		t.Fatalf("Prove 失敗: %v", err)
	}
	if res.Verification == domain.VerificationProven {
		t.Fatalf("偽造 trace 不得 PROVEN（runs=%+v）", res.Runs)
	}
	// positive 控制點未命中（trusted trace 無 nonce）→ NOT_PROVEN（harness）。
	if res.Verification != domain.VerificationNotProven || res.NotProvenReason != domain.NotProvenHarnessBudget {
		t.Fatalf("預期 NOT_PROVEN(harness_budget)，得 %s reason=%s（runs=%+v）",
			res.Verification, res.NotProvenReason, res.Runs)
	}
	// 恰兩個 run：positive 控制點失敗後 exploit 不得執行（§5.2-3 guardrail）。
	if len(res.Runs) != 2 || res.Runs[1].Kind != "positive" {
		t.Fatalf("應止於 negative+positive，得 %+v", res.Runs)
	}
	// 無論 W 的偽造輸出為何，兩個 run 的 vuln oracle 皆不得命中。
	if res.Runs[0].VulnOracle || res.Runs[1].VulnOracle {
		t.Fatalf("偽造不得觸發 vuln oracle：%+v", res.Runs)
	}
	e2eVerifyChainAndReplay(t, prover.Pack, prover.RunDir, res)
}

// TestM0bControlledMissRejectsHypothesis：positive 控制點通過（輸入確實流進
// SQL 文字）但 exploit 假設不成立（payload 無引號、語句不 error）→
// controlled_miss → HYPOTHESIS_REJECTED（§19 唯一假設被否證）。
func TestM0bControlledMissRejectsHypothesis(t *testing.T) {
	prover, findingID := setupE2E(t)
	spec := sqliWitnessSpec(t)
	// exploit payload 改為不含引號的良性形式：流進 SQL 文字（touch 會命中）
	// 但不觸發 error → vuln oracle miss。
	spec["payload"] = "{{NONCE}}"
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	res, err := prover.Prove(ctx, orchestrator.ProveInput{
		FindingID:    findingID,
		Reachability: "D0",
		Spec:         spec,
	})
	if err != nil {
		t.Fatalf("Prove 失敗: %v", err)
	}
	if res.Verification != domain.VerificationHypothesisRej {
		t.Fatalf("預期 HYPOTHESIS_REJECTED，得 %s（failure=%s runs=%+v）", res.Verification, res.FailureClass, res.Runs)
	}
	if len(res.Runs) != 3 {
		t.Fatalf("應三個 run 全跑完，得 %d", len(res.Runs))
	}
	if !res.Runs[1].TouchOracle || res.Runs[2].VulnOracle {
		t.Fatalf("positive 應命中 touch、exploit 應 miss：%+v", res.Runs)
	}
	e2eVerifyChainAndReplay(t, prover.Pack, prover.RunDir, res)
}

// e2eVerifyChainAndReplay：evidence 鏈驗證 + 離線 replay ×2 一致性（§22 M0b）。
func e2eVerifyChainAndReplay(t *testing.T, pack *packs.Pack, runDir string, res *orchestrator.ProveResult) {
	t.Helper()
	_ = res // self-contained replay intentionally does not use in-memory result.
	if err := evidence.VerifyChain(filepath.Join(runDir, "evidence")); err != nil {
		t.Fatalf("evidence 鏈驗證失敗: %v", err)
	}
	if err := orchestrator.ReplayBundle(pack, runDir); err != nil {
		t.Fatalf("replay 驗證失敗: %v", err)
	}
	if err := orchestrator.ReplayBundle(pack, runDir); err != nil {
		t.Fatalf("replay 第二次不一致: %v", err)
	}
}

// ---- docker 輔助 ----

func imageExists(imageRef string) bool {
	out, err := exec.Command("docker", "image", "inspect", imageRef).Output()
	return err == nil && len(out) > 0
}

func tagExists() bool {
	_, err := exec.Command("docker", "image", "inspect", packImageTag).Output()
	return err == nil
}

// packImageDigest 取本地 tag 的 repo digest（buildkit containerd store 會給 manifest digest；
// 本地構建映像僅能以 repo digest 定址，image ID 不可作為 name@sha256 引用）。
func packImageDigest() string {
	out, err := exec.Command("docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}", packImageTag).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "aegis-python-web@"))
}

func buildPackImage(t *testing.T, repoRoot string) {
	t.Helper()
	proxyDir := t.TempDir()
	proxy := filepath.Join(proxyDir, "observer-proxy")
	build := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", proxy, "./cmd/aegis-observer-proxy")
	build.Dir = repoRoot
	// The observer binary runs inside the Linux Docker image, not on the host.
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if out, err := build.CombinedOutput(); err != nil {
		t.Logf("observer proxy build 失敗（可 skip 場景）：%v\n%s", err, tailStr(string(out)))
		return
	}
	cmd := exec.Command("docker", "build", "--build-context", "observer-bin="+proxyDir, "-f", "image/Dockerfile", "-t", packImageTag, ".")
	cmd.Dir = filepath.Join(repoRoot, "packs", "python-web")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("pack 映像構建失敗（可 skip 場景）：%v\n%s", err, tailStr(string(out)))
	}
}

func tailStr(s string) string {
	if len(s) > 400 {
		return s[len(s)-400:]
	}
	return s
}
