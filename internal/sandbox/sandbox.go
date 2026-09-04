package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/aegis-dev/aegis/internal/domain"
)

// Runner 以 docker CLI 驅動沙箱（§16：os/exec 呼叫、--format json、不用 Docker SDK）。
// v1 全流水線序列，本套件不自起 goroutine（§23-1）。
type Runner struct {
	// Bin 是 docker 執行檔；空值視為 "docker"。
	Bin string

	// HelperImage 是 §17.6 artifacts 收回 helper 的映像，必為 digest 形式
	//（alpine 的 digest 由 pack manifest 記錄，§17.6）；空值或非 digest 形式時 Reclaim 拒跑。
	HelperImage string
}

// bin 回傳 docker 執行檔名（預設 "docker"）。
func (r *Runner) bin() string {
	if r.Bin == "" {
		return "docker"
	}
	return r.Bin
}

// run 執行一次 docker 子命令，capture stdout/stderr（§16），永不 panic、不跨層。
func (r *Runner) run(ctx context.Context, args ...string) (stdout, stderr []byte, err error) {
	cmd := exec.CommandContext(ctx, r.bin(), args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return outBuf.Bytes(), errBuf.Bytes(), err
}

// runTimeout 是 run 的定時版；逾時以 context 取消（host 端強制，§17.1）。
func (r *Runner) runTimeout(d time.Duration, args ...string) (stdout, stderr []byte, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return r.run(ctx, args...)
}

// wrapErr 把帶 exit code 的 docker 失敗包成顯式錯誤（stderr 尾段附上，利於分類）。
func wrapErr(op string, stderr []byte, err error) error {
	if err == nil {
		return nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return fmt.Errorf("sandbox: docker %s 失敗（exit %d）：%s", op, ee.ExitCode(), tail(stderr))
	}
	return fmt.Errorf("sandbox: docker %s 失敗：%w（stderr：%s）", op, err, tail(stderr))
}

// tail 取 stderr 尾段（去空白、截 300 字元），避免錯誤訊息被整份傾印淹沒。
func tail(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[len(s)-300:]
	}
	if s == "" {
		return "(無 stderr)"
	}
	return s
}

// ---- 可用性探測 ----

// Available 以 docker info 探測 daemon；偵測不到即回 error（§7.1：不做本機 fallback）。
func (r *Runner) Available() error {
	if _, err := exec.LookPath(r.bin()); err != nil {
		return fmt.Errorf("sandbox: 找不到 docker 執行檔 %q（§7.1：無本機 fallback）：%w", r.bin(), err)
	}
	_, stderr, err := r.runTimeout(20*time.Second, "info")
	if err != nil {
		return fmt.Errorf("sandbox: docker info 失敗（daemon 未啟動？）：%s：%w", tail(stderr), err)
	}
	return nil
}

// ---- 容器生命週期（§17.4-4 啟動序） ----

// Create 以給定參數執行 docker create，回傳容器 id。
// args 須來自 DockerArgs（閉集）；本函式不做 second-guess（§23-2：參數由 policy compiler 組）。
func (r *Runner) Create(args []string) (cid string, err error) {
	full := append([]string{"create"}, args...)
	out, stderr, err := r.runTimeout(60*time.Second, full...)
	if err != nil {
		return "", wrapErr("create", stderr, err)
	}
	cid = strings.TrimSpace(string(out))
	if cid == "" {
		return "", fmt.Errorf("sandbox: docker create 未回傳容器 id（stdout 空，stderr：%s）", tail(stderr))
	}
	return cid, nil
}

// CopyIn 以暫存檔中轉，把 content 寫入容器內 dstPath（docker cp）。
// dstPath 須為容器內絕對路徑。
//
// daemon 限制（docker 29 實測）：--read-only 容器對 rootfs／tmpfs 路徑的 docker cp
// 一律回 "container rootfs is marked read-only"；只有「named volume 掛載點內」的路徑
// 可寫。witness／payload 注入因此不走本函式，改由 StageWitness 的 per-run volume
// 機制（ADR 0002）；本函式保留給目標為 named volume 掛載點的注入（如 /aegis/out）。
func (r *Runner) CopyIn(cid, dstPath string, content []byte) error {
	if cid == "" {
		return fmt.Errorf("sandbox: CopyIn 的 cid 為空")
	}
	if !strings.HasPrefix(dstPath, "/") || strings.Contains(dstPath, "..") {
		return fmt.Errorf("sandbox: CopyIn 的 dstPath 須為容器內絕對路徑且不含 \"..\"：%q", dstPath)
	}
	tmp, err := os.CreateTemp("", "aegis-copyin-")
	if err != nil {
		return fmt.Errorf("sandbox: 建立中轉暫存檔失敗：%w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if rmErr := os.Remove(tmpName); rmErr != nil && !os.IsNotExist(rmErr) {
			// 暫存檔清不掉只影響磁碟整潔，不影響注入結果；交給 OS 暫存區回收。
			_ = rmErr
		}
	}()
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return fmt.Errorf("sandbox: 寫入中轉暫存檔失敗：%w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("sandbox: 關閉中轉暫存檔失敗：%w", err)
	}
	// 0644：注入檔須可被容器內 non-root user（65532）讀取——docker cp 會帶入
	// host 端檔案權限，預設暫存檔 0600 會讓容器使用者讀不到。
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("sandbox: 設定中轉暫存檔權限失敗：%w", err)
	}
	_, stderr, err := r.runTimeout(60*time.Second, "cp", tmpName, cid+":"+dstPath)
	if err != nil {
		return wrapErr("cp", stderr, err)
	}
	return nil
}

// Kill 以 docker kill 終止容器（host 端逾時強制與取消路徑共用）。
func (r *Runner) Kill(cid string) error {
	_, stderr, err := r.runTimeout(30*time.Second, "kill", cid)
	if err != nil {
		return wrapErr("kill", stderr, err)
	}
	return nil
}

// Start 執行 docker start -a（attached，其 exit code 即容器 exit code，§17.1）。
// 逾時由 host 端強制：context.WithTimeout 到點 → docker kill <cid> 並記 exit 124
//（macOS 無 timeout(1)，故不用外部 timeout 指令）。
// 容器以非零 exit code 結束（含 124/125/126/127）不是 Go 層錯誤——回 (code, nil)，
// 由 orchestrator 依 domain.ExitClassifies 分類（§17.1 exit code 閉集）。
func (r *Runner) Start(cid string, timeoutSec int) (exit int, err error) {
	if timeoutSec < 1 {
		return 0, fmt.Errorf("sandbox: Start 的 timeoutSec 須 >= 1，got %d", timeoutSec)
	}
	if cid == "" {
		return 0, fmt.Errorf("sandbox: Start 的 cid 為空")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.bin(), "start", "-a", cid)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	runErr := cmd.Run()

	if ctx.Err() != nil { // host 端逾時：強制 kill 容器，記 exit 124（§17.1）
		if killErr := r.Kill(cid); killErr != nil {
			return 0, fmt.Errorf("sandbox: run 逾時且 docker kill 失敗（%s）：%w", cid, killErr)
		}
		return domain.ExitTimeout, nil
	}
	var ee *exec.ExitError
	if errors.As(runErr, &ee) {
		// docker start -a 的 exit code 即容器 exit code（§17.1）；125/126/127 由分類器歸 env。
		return ee.ExitCode(), nil
	}
	if runErr != nil {
		return 0, fmt.Errorf("sandbox: docker start -a 失敗：%w（stderr：%s）", runErr, tail(errBuf.Bytes()))
	}
	return 0, nil
}

// ---- fs-diff（§17.6-1） ----

// Diff 解析 docker diff 輸出：C=modified、A=added；D=deleted 不回傳（原始輸出由
// Reclaim 完整落 fs_diff.txt）。忽略 /aegis/out（named volume）與 tmpfs 路徑 /tmp、/run
//——它們不在容器 rootfs 層，本來就不計 diff，此處為雙保險。
func (r *Runner) Diff(cid string) (added, modified []string, err error) {
	out, stderr, err := r.runTimeout(30*time.Second, "diff", cid)
	if err != nil {
		return nil, nil, wrapErr("diff", stderr, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		kind, path := line[:1], strings.TrimSpace(line[1:])
		if ignoreDiffPath(path) {
			continue
		}
		switch kind {
		case "A":
			added = append(added, path)
		case "C":
			modified = append(modified, path)
		}
	}
	return added, modified, nil
}

// ignoreDiffPath 判定 diff 路徑是否屬於不計入的掛載區（volume／tmpfs／bind 掛載點）。
// docker daemon 會在 rootfs 層建立掛載點目錄（busybox 映像本無 /target、/aegis），
// 故 /target、/aegis/out 及其父目錄 /aegis 本身都不計入。
func ignoreDiffPath(path string) bool {
	if path == "/aegis" {
		return true
	}
	for _, root := range []string{OutMountPoint, TargetMountPoint, WitnessMountPoint, PayloadPath, "/tmp", "/run"} {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}

// ---- artifacts 收回（§17.6 固定三步） ----

// Reclaim 依 §17.6 收回 run 產物：
//  1. docker diff <cid> → 原始輸出落 <destDir>/fs_diff.txt；
//  2. 收回 helper（docker run --rm，套用 hardening：cap-drop ALL／no-new-privileges／
//     read-only／non-root／network none）把 aegis-out-<runID> volume 內容 cp 到 destDir；
//  3. docker rm <cid> + docker volume rm aegis-out-<runID> 與 aegis-witness-<runID>。
//
// 禁止任何 host 目錄以可寫模式掛入證明 run 容器；收回 helper 是唯一例外（§17.6）。
func (r *Runner) Reclaim(cid, runID, destDir string) error {
	if cid == "" {
		return fmt.Errorf("sandbox: Reclaim 的 cid 為空")
	}
	if !idRe.MatchString(runID) {
		return fmt.Errorf("sandbox: Reclaim 的 runID 非法：%q", runID)
	}
	if destDir == "" || !filepath.IsAbs(destDir) || filepath.Clean(destDir) != destDir {
		return fmt.Errorf("sandbox: Reclaim 的 destDir 須為絕對且 clean 的路徑：%q", destDir)
	}

	var firstErr error
	setErr := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}

	// 1. fs-diff 原始輸出落檔（§17.6-1）。
	raw, stderr, err := r.runTimeout(30*time.Second, "diff", cid)
	if err != nil {
		setErr(wrapErr("diff", stderr, err))
	} else if wErr := os.WriteFile(filepath.Join(destDir, "fs_diff.txt"), raw, 0o644); wErr != nil {
		setErr(fmt.Errorf("sandbox: 寫入 fs_diff.txt 失敗：%w", wErr))
	}

	// 2. artifacts 收回 helper（§17.6-2）；HelperImage 必為 digest（pack manifest 記錄）。
	if !digestRe.MatchString(r.HelperImage) {
		setErr(fmt.Errorf("sandbox: HelperImage 須為 digest 形式（<name>@sha256:<64hex>，§17.6），got %q", r.HelperImage))
	} else {
		helperArgs := []string{
			"run", "--rm",
			"--cap-drop", "ALL",
			"--security-opt", "no-new-privileges:true",
			"--read-only",
			"--user", ContainerUser,
			"--network", NetworkNone,
			"-v", OutVolumePrefix+runID+":/from:ro",
			"-v", destDir+":/to",
			r.HelperImage,
			"cp", "-a", "/from/.", "/to/",
		}
		_, stderr, err := r.runTimeout(120*time.Second, helperArgs...)
		if err != nil {
			setErr(wrapErr("reclaim run", stderr, err))
		}
	}

	// 3. 刪容器與 volume（§17.6-3）；即使前面已失敗也照做，保證資源收回。
	if _, stderr, err := r.runTimeout(30*time.Second, "rm", cid); err != nil {
		setErr(wrapErr("rm", stderr, err))
	}
	if vErr := r.removeVolumeRetry(OutVolumePrefix + runID); vErr != nil {
		// volume 不存在（run 未產生產物等）已於 removeVolumeRetry 視為已收回。
		setErr(vErr)
	}
	// witness 注入 volume（ADR 0002）一併收回；不存在視為已清。
	if wErr := r.RemoveWitnessVolume(runID); wErr != nil {
		setErr(wErr)
	}
	return firstErr
}

// ---- reaper（§17.5-5、§7.1 清理與回收） ----

// psRow 是 docker ps --format json 的欄位子集（欄位名大寫駝峰；
// docker 29 的 Names 為單一字串，非陣列）。
type psRow struct {
	ID    string `json:"ID"`
	Names string `json:"Names"`
}

// Reaper 以 label aegis.run_id=<runID> 反查所有殘留容器（含已退出，-a）刪除，
// 再刪 aegis-ssrf-<runID> network（不存在則視為已清）。run 結束（含 crash／取消）
// 由 reaper 保證容器與 internal network 刪除（§7.1、§17.5-5）。
func (r *Runner) Reaper(runID string) error {
	if !idRe.MatchString(runID) {
		return fmt.Errorf("sandbox: Reaper 的 runID 非法：%q", runID)
	}
	out, stderr, err := r.runTimeout(30*time.Second,
		"ps", "-a", "--filter", "label="+LabelRunID+"="+runID, "--format", "json")
	if err != nil {
		return wrapErr("ps", stderr, err)
	}
	rows, pErr := parsePSRows(out)
	if pErr != nil {
		return fmt.Errorf("sandbox: 解析 docker ps --format json 失敗：%w", pErr)
	}
	var firstErr error
	for _, row := range rows {
		if row.ID == "" {
			continue
		}
		// -f：殘留容器可能還在跑（crash／取消路徑），一律強制刪。
		if _, stderr, err := r.runTimeout(30*time.Second, "rm", "-f", row.ID); err != nil {
			if firstErr == nil {
				firstErr = wrapErr("reaper rm", stderr, err)
			}
		}
	}
	// 刪 ssrf network（§17.5-5）；network 不存在（none profile／已清）不算失敗。
	_, stderr, err = r.runTimeout(30*time.Second, "network", "rm", SSRFNetPrefix+runID)
	if err != nil && !strings.Contains(strings.ToLower(string(stderr)), "not found") {
		if firstErr == nil {
			firstErr = wrapErr("reaper network rm", stderr, err)
		}
	}
	return firstErr
}

// parsePSRows 相容兩種 --format json 輸出：新版為 JSON 陣列、舊版為逐行 JSON 物件。
func parsePSRows(out []byte) ([]psRow, error) {
	trimmed := bytes.TrimSpace(out)
	if len(trimmed) == 0 {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var rows []psRow
		if err := json.Unmarshal(trimmed, &rows); err != nil {
			return nil, err
		}
		return rows, nil
	}
	var rows []psRow
	for _, line := range strings.Split(string(trimmed), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var row psRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
}