// stage.go：witness 注入 staging（§17.4-4 注入檔案原則；機制見 ADR 0002）。
//
// daemon 限制（docker 29 實測）：--read-only 容器的 rootfs／tmpfs 對 docker cp
// 一律回 "container rootfs is marked read-only"，僅 named volume 掛載點內可寫。
// 故注入改走 per-run named volume：
//  1. docker volume create aegis-witness-<runID>
//  2. docker create 短暫 staging 容器（helper 映像、不啟動）掛該 volume，tar 經
//     stdin 注入 witness 檔案與 payload.txt，隨即刪除 staging 容器
//  3. run 容器以 -v <vol>:/aegis/witness:ro 與 volume-subpath 單檔唯讀掛
//     /aegis/payload.txt（契約路徑不變）
//
// 安全性等價：注入仍全為檔案、無 host 可寫 bind mount；witness／payload 對 run
// 容器唯讀；staging 容器僅掛該 volume、不啟動、帶 run_id label 供 reaper 清收。
package sandbox

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path"
	"strings"
	"syscall"
	"time"
)

// StageFiles 是一次注入的內容：key 為容器內 /aegis/witness/ 下的相對路徑
// （不含 "witness/" 前綴，由呼叫端剝除），value 為檔案內容。
type StageFiles map[string][]byte

// WitnessVolumeName 組出 per-run witness volume 名。
func WitnessVolumeName(runID string) string {
	return WitnessVolumePrefix + runID
}

// validateStageName 檢查 staging 相對路徑：clean、絕對不許、".."、"." 段不許。
// （key 由 RunRequest.files 而來，最終成為容器內檔案路徑，須守住路徑形狀。）
func validateStageName(name string) error {
	if name == "" {
		return fmt.Errorf("sandbox: staging 檔名為空")
	}
	if strings.HasPrefix(name, "/") || path.IsAbs(name) {
		return fmt.Errorf("sandbox: staging 檔名須為相對路徑，拒收：%q", name)
	}
	clean := path.Clean(name)
	if clean != name {
		return fmt.Errorf("sandbox: staging 檔名須為 clean 路徑（got %q，clean 為 %q）", name, clean)
	}
	if clean == "." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "..") {
		return fmt.Errorf("sandbox: staging 檔名不得含 \"..\"：%q", name)
	}
	return nil
}

// stageTar 把 files（可含巢狀目錄）與 payload 組成 tar bytes。
// 檔名須先過 validateStageName；payload 以 PayloadStagedName 寫在 volume 根
// （subpath 掛載的來源檔，須於 docker create 前存在）。
// mode 0644、uid/gid 0：容器內 non-root user（65532）可讀。
func stageTar(files StageFiles, payload []byte) ([]byte, error) {
	names := make([]string, 0, len(files)+1)
	for name := range files {
		if err := validateStageName(name); err != nil {
			return nil, err
		}
		if name == PayloadStagedName {
			// payload 的 staging 檔名為保留名，避免覆寫混淆。
			return nil, fmt.Errorf("sandbox: staging 檔名 %q 為 payload 保留名", name)
		}
		names = append(names, name)
	}
	names = append(names, PayloadStagedName) // payload 一律存在（DockerArgs 無條件掛 subpath）

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range names {
		content := []byte(nil)
		if name != PayloadStagedName {
			content = files[name]
		} else {
			content = payload
		}
		if err := tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(content)),
		}); err != nil {
			return nil, fmt.Errorf("sandbox: tar header %s: %w", name, err)
		}
		if _, err := tw.Write(content); err != nil {
			return nil, fmt.Errorf("sandbox: tar body %s: %w", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("sandbox: tar close: %w", err)
	}
	return buf.Bytes(), nil
}

// StageWitness 執行注入 staging（ADR 0002）：建 per-run volume，經 staging 容器
// 以 tar 注入 files 與 payload（payload 空值也寫入空檔，subpath 掛載需要它存在）。
// ctx 為呼叫端取消通道：取消即時中止注入的每個 docker 步驟（P2-2）。
// staging 容器帶 label aegis.run_id，失敗殘留可由 Reaper(runID) 清收。
func (r *Runner) StageWitness(ctx context.Context, runID string, files StageFiles, payload []byte) error {
	if !idRe.MatchString(runID) {
		return fmt.Errorf("sandbox: StageWitness 的 runID 非法：%q", runID)
	}
	if !digestRe.MatchString(r.HelperImage) {
		return fmt.Errorf("sandbox: HelperImage 須為 digest 形式（<name>@sha256:<64hex>），got %q", r.HelperImage)
	}
	vol := WitnessVolumeName(runID)

	if _, stderr, err := r.runCtx(ctx, 30*time.Second, "volume", "create", vol); err != nil {
		return wrapErr("volume create", stderr, err)
	}
	tarBytes, err := stageTar(files, payload)
	if err != nil {
		return err
	}

	// staging 容器：create 後不啟動，cp 目標是 volume 掛載點（docker cp 對
	// created 容器的 volume 掛載點寫入會落進 volume，實測可行）。
	stageArgs := []string{
		"create", "--name", "aegis-stage-" + runID,
		"--label", LabelRunID + "=" + runID,
		"-v", vol + ":/stage",
		r.HelperImage, "true",
	}
	if _, stderr, err := r.runCtx(ctx, 60*time.Second, stageArgs...); err != nil {
		return wrapErr("stage create", stderr, err)
	}
	stageCid := "aegis-stage-" + runID

	// tar 經 stdin 注入（docker cp - <cid>:/stage）。
	if err := r.cpTarStdin(ctx, stageCid, "/stage", tarBytes); err != nil {
		return err
	}

	if _, stderr, err := r.runCtx(ctx, 30*time.Second, "rm", stageCid); err != nil {
		return wrapErr("stage rm", stderr, err)
	}
	return nil
}

// cpTarStdin 以 tar 流注入容器路徑（docker cp - <cid>:<dest>）。
// ctx 取消即終止 docker cp 子程序（P2-2：不得用無 context 的 exec.Command）；
// 呼叫端未設 deadline 時自套 60s 逾時（host 端強制，§17.1）。
func (r *Runner) cpTarStdin(ctx context.Context, cid, dest string, tarBytes []byte) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, r.bin(), "cp", "-", cid+":"+dest)
	// docker may be a wrapper script (and in production may spawn helper
	// processes).  Killing only the direct process leaves descendants holding
	// stdin/stderr open, so Wait can block until the host timeout.  Give the
	// command its own process group and terminate the whole group on cancel.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 2 * time.Second
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("sandbox: cp stdin pipe: %w", err)
	}
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("sandbox: docker cp - 啟動失敗：%w", err)
	}
	if _, err := stdin.Write(tarBytes); err != nil {
		_ = stdin.Close()
		_ = cmd.Wait()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("sandbox: cp tar 注入被取消：%w", ctxErr)
		}
		return fmt.Errorf("sandbox: cp tar 寫入失敗：%w", err)
	}
	if err := stdin.Close(); err != nil {
		_ = cmd.Wait()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("sandbox: cp tar 注入被取消：%w", ctxErr)
		}
		return fmt.Errorf("sandbox: cp stdin 關閉失敗：%w", err)
	}
	if err := cmd.Wait(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("sandbox: cp tar 注入被取消：%w", ctxErr)
		}
		return wrapErr("cp", errBuf.Bytes(), err)
	}
	return nil
}

// RemoveWitnessVolume 刪除 per-run witness volume（不存在視為已清）。
// 容器剛 rm 後 daemon 可能短暫回報 "volume is in use"（釋放競態），加重試。
func (r *Runner) RemoveWitnessVolume(runID string) error {
	if !idRe.MatchString(runID) {
		return fmt.Errorf("sandbox: RemoveWitnessVolume 的 runID 非法：%q", runID)
	}
	return r.removeVolumeRetry(WitnessVolumeName(runID))
}

// removeVolumeRetry 執行 docker volume rm；"no such volume" 視為已清；
// "volume is in use"（rm 後釋放競態）重試至多 3 次、間隔 1 秒。
func (r *Runner) removeVolumeRetry(name string) error {
	const attempts = 3
	var stderr []byte
	var err error
	for i := 0; i < attempts; i++ {
		_, stderr, err = r.runTimeout(30*time.Second, "volume", "rm", name)
		if err == nil {
			return nil
		}
		if strings.Contains(strings.ToLower(string(stderr)), "no such volume") {
			return nil
		}
		if !strings.Contains(strings.ToLower(string(stderr)), "volume is in use") {
			break
		}
		time.Sleep(time.Second)
	}
	return wrapErr("volume rm "+name, stderr, err)
}
