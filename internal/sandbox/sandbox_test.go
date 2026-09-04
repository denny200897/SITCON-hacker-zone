package sandbox

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aegis-dev/aegis/internal/domain"
)

// ---- docker 整合測試（docker 不可用即 skip，§22：flags 測試必須仍全過） ----

// requireDocker 探測 docker daemon；不可用時 skip 全部整合測試。
func requireDocker(t *testing.T) *Runner {
	t.Helper()
	r := &Runner{}
	if err := r.Available(); err != nil {
		t.Skipf("docker 不可用，跳過整合測試：%v", err)
	}
	return r
}

// busyboxDigestRef 取得 busybox 的 digest 引用（"busybox@sha256:…"）；映像不存在則先
// pull（§22：以 digest 記錄）。取不到 RepoDigest（如本機構建映像）即 skip。
func busyboxDigestRef(t *testing.T, r *Runner) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, _, err := r.run(ctx, "image", "inspect", "--format", "{{json .RepoDigests}}", "busybox")
	if err != nil {
		// 映像不存在 → pull；pull 也失敗（無網路等）即 skip。
		if _, _, pullErr := r.run(ctx, "pull", "-q", "busybox"); pullErr != nil {
			t.Skipf("docker pull busybox 失敗，跳過整合測試：%v", pullErr)
		}
		out, _, err = r.run(ctx, "image", "inspect", "--format", "{{json .RepoDigests}}", "busybox")
		if err != nil {
			t.Skipf("docker image inspect busybox 失敗，跳過整合測試：%v", err)
		}
	}
	var digests []string
	if jErr := json.Unmarshal(out, &digests); jErr != nil || len(digests) == 0 {
		t.Skipf("busybox 無 RepoDigest（本機構建映像？），跳過整合測試：%v", jErr)
	}
	ref := digests[0] // 形如 "busybox@sha256:…"
	if !strings.Contains(ref, "@sha256:") {
		t.Skipf("RepoDigest 非 digest 形式：%q", ref)
	}
	return ref
}

// ---- docker inspect 驗證結構（欄位取自 docker 的 container inspect JSON） ----

type inspectMount struct {
	Type        string `json:"Type"`
	Name        string `json:"Name"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
}

type inspectUlimit struct {
	Name string
	Soft uint64
	Hard uint64
}

type inspectJSON struct {
	ID             string `json:"Id"`
	User           string `json:"User"` // 部分版本在 top-level
	ReadonlyRootfs bool   `json:"ReadonlyRootfs"`
	Mounts         []inspectMount
	Config         struct {
		User   string            `json:"User"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		CapDrop        []string
		SecurityOpt    []string
		NetworkMode    string
		Memory         int64
		NanoCpus       int64
		PidsLimit      int64
		ReadonlyRootfs bool
		Privileged     bool
		AutoRemove     bool
		StopTimeout    *int
		Tmpfs          map[string]string
		Ulimits        []inspectUlimit
	} `json:"HostConfig"`
}

// dockerInspect 執行 docker inspect <cid> 並解析 JSON 陣列第一個元素。
func dockerInspect(t *testing.T, r *Runner, cid string) inspectJSON {
	t.Helper()
	out, stderr, err := r.runTimeout(30*time.Second, "inspect", cid)
	if err != nil {
		t.Fatalf("docker inspect %s 失敗：%v（stderr：%s）", cid, err, tail(stderr))
	}
	var arr []inspectJSON
	if jErr := json.Unmarshal(out, &arr); jErr != nil || len(arr) == 0 {
		t.Fatalf("docker inspect 輸出解析失敗：%v", jErr)
	}
	return arr[0]
}

// dockerState 取容器 State.Status。
func dockerState(t *testing.T, r *Runner, cid string) string {
	t.Helper()
	out, stderr, err := r.runTimeout(30*time.Second, "inspect", "--format", "{{.State.Status}}", cid)
	if err != nil {
		t.Fatalf("inspect State.Status 失敗：%v（stderr：%s）", err, tail(stderr))
	}
	return strings.TrimSpace(string(out))
}

// cleanupRun 註冊 t.Cleanup：刪容器與 aegis-out／aegis-witness volume，
// 保證測試不留殘留。
func cleanupRun(t *testing.T, r *Runner, cid, runID string) {
	t.Helper()
	t.Cleanup(func() {
		_, _, _ = r.runTimeout(30*time.Second, "rm", "-f", cid)
		_, _, _ = r.runTimeout(30*time.Second, "volume", "rm", OutVolumePrefix+runID)
		_ = r.RemoveWitnessVolume(runID)
	})
}

// stageEmptyPayload 先為 per-run witness volume 注入空 payload（ADR 0002：
// DockerArgs 無條件掛 payload subpath，docker 29 要求檔案在 docker create 前
// 已存在於 volume）。整合測試不含 exploit 流程，空檔即可；HelperImage 未設時
// 以被測映像代用（staging 容器不啟動，任何 digest-pinned 映像皆可）。
func stageEmptyPayload(t *testing.T, r *Runner, runID, img string) {
	t.Helper()
	if r.HelperImage == "" {
		r.HelperImage = img
	}
	if err := r.StageWitness(runID, StageFiles{}, []byte("")); err != nil {
		t.Fatalf("StageWitness 失敗：%v", err)
	}
}

// ensureOutVolume 把 aegis-out-<runID> volume chown 給 65532，模擬 derived image
// 對 /aegis/out 的 chown（§17.1「映像內已 chown 65532」——docker 首用 volume 時會
// 把映像內該目錄的擁有權複製進去；busybox 映像無 /aegis 目錄，volume 落在 root，
// 65532 寫不進）。此 helper 以 root 跑一次 chown，僅供測試 setup，不屬 runner 契約。
func ensureOutVolume(t *testing.T, r *Runner, runID, img string) {
	t.Helper()
	_, stderr, err := r.runTimeout(60*time.Second,
		"run", "--rm", "-v", OutVolumePrefix+runID+":/w", img, "chown", "65532:65532", "/w")
	if err != nil {
		t.Fatalf("out volume chown 失敗：%v（stderr：%s）", err, tail(stderr))
	}
}

// testSeccompFile 寫出 docker 可接受的 seccomp profile 檔。本檔僅用來驗證
// --security-opt seccomp=<path> 有被正確接線（§22 M0a）；真正的收紧版 profile
// 由 pack 提供（§17.1），內容屬 pack 資料，不在此處決定。
func testSeccompFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "seccomp.json")
	prof := `{"defaultAction":"SCMP_ACT_ALLOW"}`
	if err := os.WriteFile(path, []byte(prof), 0o644); err != nil {
		t.Fatalf("寫 seccomp profile 失敗：%v", err)
	}
	return path
}

// TestSandboxHardeningInspect：以全套 §17.1 hardening flags create 一個容器，
// 以 docker inspect 逐項驗證生效（§22 M0a 明文要求）。
func TestSandboxHardeningInspect(t *testing.T) {
	r := requireDocker(t)
	img := busyboxDigestRef(t, r)
	seccomp := testSeccompFile(t)
	runID, snapID := "R-9901", "SNAP-9901"
	snapDir := t.TempDir()

	args, err := DockerArgs(RunSpec{
		RunID: runID, SnapshotID: snapID, Image: img,
		Cmd: []string{"true"}, Network: NetworkNone,
		Seccomp: seccomp, TimeoutSec: 30,
	}, snapDir)
	if err != nil {
		t.Fatalf("DockerArgs 失敗：%v", err)
	}
	cid, err := r.Create(args)
	if err != nil {
		t.Fatalf("Create 失敗：%v", err)
	}
	cleanupRun(t, r, cid, runID)
	ins := dockerInspect(t, r, cid)

	// cap_drop = ALL（§17.1）
	if len(ins.HostConfig.CapDrop) != 1 || ins.HostConfig.CapDrop[0] != "ALL" {
		t.Errorf("CapDrop = %#v，want [ALL]", ins.HostConfig.CapDrop)
	}
	// read-only rootfs（§17.1）
	if !ins.HostConfig.ReadonlyRootfs {
		t.Errorf("ReadonlyRootfs = false，want true")
	}
	// security-opt：no-new-privileges + seccomp=<path>（§17.1）
	hasNNP, hasSeccomp := false, false
	for _, so := range ins.HostConfig.SecurityOpt {
		if so == "no-new-privileges:true" {
			hasNNP = true
		}
		if strings.HasPrefix(so, "seccomp=") {
			hasSeccomp = true
		}
	}
	if !hasNNP {
		t.Errorf("SecurityOpt 缺 no-new-privileges:true，got %#v", ins.HostConfig.SecurityOpt)
	}
	if !hasSeccomp {
		t.Errorf("SecurityOpt 缺 seccomp=<path>，got %#v", ins.HostConfig.SecurityOpt)
	}
	// non-root user 65532:65532（§17.1）
	if ins.Config.User != ContainerUser && ins.User != ContainerUser {
		t.Errorf("User = %q（Config）/ %q（top-level），want %q", ins.Config.User, ins.User, ContainerUser)
	}
	// 資源上限：memory 512m、cpus 1.0、pids 128（§17.1）
	if ins.HostConfig.Memory != 512*1024*1024 {
		t.Errorf("Memory = %d，want %d（512m）", ins.HostConfig.Memory, 512*1024*1024)
	}
	if ins.HostConfig.NanoCpus != 1_000_000_000 {
		t.Errorf("NanoCpus = %d，want 1000000000（--cpus 1.0）", ins.HostConfig.NanoCpus)
	}
	if ins.HostConfig.PidsLimit != PidsLimit {
		t.Errorf("PidsLimit = %d，want %d", ins.HostConfig.PidsLimit, PidsLimit)
	}
	// ulimit nofile=256（§17.1；docker inspect 回報的名稱為小寫 "nofile"）
	foundNoFile := false
	for _, ul := range ins.HostConfig.Ulimits {
		if strings.EqualFold(ul.Name, "nofile") {
			foundNoFile = true
			if ul.Soft != NoFileLimit || ul.Hard != NoFileLimit {
				t.Errorf("nofile ulimit = %d/%d，want 256/256", ul.Soft, ul.Hard)
			}
		}
	}
	if !foundNoFile {
		t.Errorf("Ulimits 缺 NOFILE，got %#v", ins.HostConfig.Ulimits)
	}
	// tmpfs /tmp size=64m、/run size=16m（§17.1；docker inspect 的 Tmpfs map
	// key 為容器內路徑，value 為選項串，不含 "tmpfs," 前綴與掛載點本身）
	if !strings.Contains(ins.HostConfig.Tmpfs["/tmp"], "size=64m") ||
		!strings.Contains(ins.HostConfig.Tmpfs["/run"], "size=16m") {
		t.Errorf("Tmpfs = %#v，want /tmp size=64m 與 /run size=16m", ins.HostConfig.Tmpfs)
	}
	// network none（§17.1）
	if ins.HostConfig.NetworkMode != NetworkNone {
		t.Errorf("NetworkMode = %q，want %q", ins.HostConfig.NetworkMode, NetworkNone)
	}
	// bind mount：/target 唯讀（§7.1）；/aegis/out 為可寫 named volume（§17.1）
	targetRO, outVol := false, false
	for _, m := range ins.Mounts {
		switch m.Destination {
		case TargetMountPoint:
			targetRO = !m.RW
		case OutMountPoint:
			outVol = m.Type == "volume" && m.Name == OutVolumePrefix+runID && m.RW
		}
	}
	if !targetRO {
		t.Errorf("/target mount 須為唯讀 bind，Mounts = %#v", ins.Mounts)
	}
	if !outVol {
		t.Errorf("/aegis/out 須為可寫 named volume %q，Mounts = %#v", OutVolumePrefix+runID, ins.Mounts)
	}
	// labels（§17.1）
	if ins.Config.Labels[LabelRunID] != runID || ins.Config.Labels[LabelSnapshotID] != snapID {
		t.Errorf("Labels = %#v，want run_id=%q snapshot_id=%q", ins.Config.Labels, runID, snapID)
	}
	// 禁止項：privileged／--rm（§7.1、§17.6）
	if ins.HostConfig.Privileged {
		t.Errorf("Privileged = true，want false")
	}
	if ins.HostConfig.AutoRemove {
		t.Errorf("AutoRemove = true（--rm），want false（§17.6 固定三步）")
	}
	// 註：docker 29 的 container inspect JSON 不輸出 HostConfig.StopTimeout，
	// 無法以 inspect 逐項驗證；--stop-timeout 5 由 flags_test.go 的閉集斷言覆蓋。
}

// TestSandboxStartTimeout：逾時由 host 端強制 → docker kill 並記 exit 124（§17.1）。
func TestSandboxStartTimeout(t *testing.T) {
	r := requireDocker(t)
	img := busyboxDigestRef(t, r)
	runID := "R-9902"
	snapDir := t.TempDir()

	args, err := DockerArgs(RunSpec{
		RunID: runID, SnapshotID: "SNAP-9902", Image: img,
		Cmd: []string{"sleep", "30"}, Network: NetworkNone,
		Seccomp: testSeccompFile(t), TimeoutSec: 30,
	}, snapDir)
	if err != nil {
		t.Fatalf("DockerArgs 失敗：%v", err)
	}
	cid, err := r.Create(args)
	if err != nil {
		t.Fatalf("Create 失敗：%v", err)
	}
	cleanupRun(t, r, cid, runID)

	start := time.Now()
	exit, err := r.Start(cid, 2)
	if err != nil {
		t.Fatalf("Start 逾時路徑不應回 Go 層錯誤：%v", err)
	}
	if exit != domain.ExitTimeout {
		t.Fatalf("逾時 exit = %d，want %d（§17.1）", exit, domain.ExitTimeout)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("逾時強制耗時 %v，host 端強制未生效", elapsed)
	}
	if state := dockerState(t, r, cid); state != "exited" {
		t.Errorf("逾時後容器 State.Status = %q，want exited（已 kill）", state)
	}
}

// TestSandboxCopyInAndRun：witness 以注入檔案給入（docker cp，§17.4-4），
// 容器以 grep 驗證內容（不用 stdout 判成功，§23-3）。
// 注入路徑落在 /aegis/out（named volume）——docker 29 實測：--read-only 容器僅
// volume 掛載點內可 docker cp，rootfs／tmpfs 路徑一律被 daemon 拒絕（見 CopyIn 註解）。
func TestSandboxCopyInAndRun(t *testing.T) {
	r := requireDocker(t)
	img := busyboxDigestRef(t, r)
	runID := "R-9903"
	snapDir := t.TempDir()

	args, err := DockerArgs(RunSpec{
		RunID: runID, SnapshotID: "SNAP-9903", Image: img,
		Cmd: []string{"grep", "-q", "AEGIS_TEST_NONCE", OutMountPoint + "/payload.txt"},
		Network: NetworkNone, Seccomp: testSeccompFile(t), TimeoutSec: 30,
	}, snapDir)
	if err != nil {
		t.Fatalf("DockerArgs 失敗：%v", err)
	}
	cid, err := r.Create(args)
	if err != nil {
		t.Fatalf("Create 失敗：%v", err)
	}
	cleanupRun(t, r, cid, runID)
	ensureOutVolume(t, r, runID, img)

	if err := r.CopyIn(cid, OutMountPoint+"/payload.txt", []byte("AEGIS_TEST_NONCE\n")); err != nil {
		t.Fatalf("CopyIn 失敗：%v", err)
	}
	exit, err := r.Start(cid, 30)
	if err != nil {
		t.Fatalf("Start 失敗：%v", err)
	}
	if exit != 0 {
		t.Fatalf("exit = %d，want 0（grep 應命中注入內容）", exit)
	}
}

// TestSandboxDiffIgnoresMounts：tmpfs 與 named volume 的寫入不計入 fs-diff（§17.6）。
func TestSandboxDiffIgnoresMounts(t *testing.T) {
	r := requireDocker(t)
	img := busyboxDigestRef(t, r)
	runID := "R-9904"
	snapDir := t.TempDir()

	args, err := DockerArgs(RunSpec{
		RunID: runID, SnapshotID: "SNAP-9904", Image: img,
		Cmd: []string{"sh", "-c", "echo a > /tmp/x && echo b > /aegis/out/observer.jsonl"},
		Network: NetworkNone, Seccomp: testSeccompFile(t), TimeoutSec: 30,
	}, snapDir)
	if err != nil {
		t.Fatalf("DockerArgs 失敗：%v", err)
	}
	cid, err := r.Create(args)
	if err != nil {
		t.Fatalf("Create 失敗：%v", err)
	}
	cleanupRun(t, r, cid, runID)
	ensureOutVolume(t, r, runID, img) // busybox 映像未 chown /aegis/out，先補給 65532

	exit, err := r.Start(cid, 30)
	if err != nil {
		t.Fatalf("Start 失敗：%v", err)
	}
	if exit != 0 {
		t.Fatalf("exit = %d，want 0", exit)
	}
	added, modified, err := r.Diff(cid)
	if err != nil {
		t.Fatalf("Diff 失敗：%v", err)
	}
	if len(added) != 0 || len(modified) != 0 {
		t.Fatalf("Diff = added %#v modified %#v；tmpfs／volume 寫入不應計入", added, modified)
	}
}

// TestSandboxReclaim：§17.6 三步收回（fs_diff.txt 落檔 → helper cp → 刪容器與 volume）。
func TestSandboxReclaim(t *testing.T) {
	r := requireDocker(t)
	img := busyboxDigestRef(t, r)
	r.HelperImage = busyboxDigestRef(t, r) // 收回 helper 映像（§17.6：digest 形式）
	runID := "R-9905"
	snapDir := t.TempDir()
	destDir := t.TempDir()

	args, err := DockerArgs(RunSpec{
		RunID: runID, SnapshotID: "SNAP-9905", Image: img,
		Cmd: []string{"sh", "-c", "echo artifact > /aegis/out/observer.jsonl"},
		Network: NetworkNone, Seccomp: testSeccompFile(t), TimeoutSec: 30,
	}, snapDir)
	if err != nil {
		t.Fatalf("DockerArgs 失敗：%v", err)
	}
	cid, err := r.Create(args)
	if err != nil {
		t.Fatalf("Create 失敗：%v", err)
	}
	ensureOutVolume(t, r, runID, img) // busybox 映像未 chown /aegis/out，先補給 65532
	if _, err := r.Start(cid, 30); err != nil {
		t.Fatalf("Start 失敗：%v", err)
	}

	if err := r.Reclaim(cid, runID, destDir); err != nil {
		t.Fatalf("Reclaim 失敗：%v", err)
	}
	// fs_diff.txt 應已落檔（§17.6-1）；寫入全在 tmpfs／volume 時內容可為空。
	if _, err := os.Stat(filepath.Join(destDir, "fs_diff.txt")); err != nil {
		t.Fatalf("fs_diff.txt 未落檔：%v", err)
	}
	// artifact 應已收回（§17.6-2）。
	got, err := os.ReadFile(filepath.Join(destDir, "observer.jsonl"))
	if err != nil {
		t.Fatalf("artifact 未收回：%v", err)
	}
	if !strings.Contains(string(got), "artifact") {
		t.Fatalf("artifact 內容不符：%q", got)
	}
	// 容器與 volume 應已刪除（§17.6-3）。
	if _, stderr, err := r.runTimeout(30*time.Second, "inspect", cid); err == nil {
		t.Fatalf("容器 %s 應已刪除（stderr：%s）", cid, tail(stderr))
	}
	if _, _, err := r.runTimeout(30*time.Second, "volume", "inspect", OutVolumePrefix+runID); err == nil {
		t.Fatalf("volume %s 應已刪除", OutVolumePrefix+runID)
	}
}

// TestSandboxReaper：以 label 反查殘留容器並刪除；ssrf network 不存在不算失敗（§17.5-5）。
func TestSandboxReaper(t *testing.T) {
	r := requireDocker(t)
	img := busyboxDigestRef(t, r)
	runID := "R-9906"
	snapDir := t.TempDir()

	args, err := DockerArgs(RunSpec{
		RunID: runID, SnapshotID: "SNAP-9906", Image: img,
		Cmd: []string{"sleep", "120"}, Network: NetworkNone,
		Seccomp: testSeccompFile(t), TimeoutSec: 30,
	}, snapDir)
	if err != nil {
		t.Fatalf("DockerArgs 失敗：%v", err)
	}
	cid, err := r.Create(args)
	if err != nil {
		t.Fatalf("Create 失敗：%v", err)
	}
	t.Cleanup(func() { // reaper 失敗時的保底清理
		_, _, _ = r.runTimeout(30*time.Second, "rm", "-f", cid)
		_, _, _ = r.runTimeout(30*time.Second, "volume", "rm", OutVolumePrefix+runID)
	})

	if err := r.Reaper(runID); err != nil {
		t.Fatalf("Reaper 失敗：%v", err)
	}
	if _, _, err := r.runTimeout(30*time.Second, "inspect", cid); err == nil {
		t.Fatalf("Reaper 後容器 %s 仍存在", cid)
	}
	// none profile 沒有 ssrf network；Reaper 對 network 不存在應為 no-op 成功。
	if err := r.Reaper(runID); err != nil {
		t.Fatalf("Reaper 二次呼叫（無 network）不應失敗：%v", err)
	}
}