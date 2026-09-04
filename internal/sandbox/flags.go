// Package sandbox 實作 Docker runner（SPEC §17.1、§17.6、§7.1）。
// docker CLI 一律以 os/exec 呼叫、輸出以 --format json 解析（§16）；
// 不使用 Docker SDK，也不引入 docker client library。
//
// 純函式優先：flags.go 不碰 docker，未裝 docker 也能完整測試。
package sandbox

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// ---- 常數閉集（§17.1 canonical run flags 的數值；不得由呼叫端放寬） ----

const (
	// ContainerUser 是 run 容器與收回 helper 的 non-root user（§17.1）。
	ContainerUser = "65532:65532"

	// TargetMountPoint 是目標 repo snapshot 在容器內的唯讀掛載點。
	TargetMountPoint = "/target"

	// OutMountPoint 是 run 產物的 named volume 掛載點（唯一可寫區之一，§17.1）。
	OutMountPoint = "/aegis/out"

	// WitnessMountPoint 是 policy compiler 注入 witness 檔案的目錄（§17.1）。
	WitnessMountPoint = "/aegis/witness"

	// PayloadPath 是 exploit 讀取 payload 的固定路徑（§17.1、§17.2）。
	PayloadPath = "/aegis/payload.txt"

	// OutVolumePrefix／SSRFNetPrefix 組出 per-run 的 named volume 與 ssrf network 名。
	OutVolumePrefix = "aegis-out-"
	SSRFNetPrefix   = "aegis-ssrf-"

	// WitnessVolumePrefix 組出 per-run 的注入 staging volume 名（§17.4-4 的
	// docker cp 機制在 docker 29 對 --read-only rootfs 不可行，ADR 0002）。
	WitnessVolumePrefix = "aegis-witness-"

	// PayloadStagedName 是 payload 在 witness volume 內的檔名；以 volume-subpath
	// 掛成容器內 PayloadPath（契約路徑不變，ADR 0002）。
	PayloadStagedName = "payload.txt"

	// LabelRunID／LabelSnapshotID 供 reaper 以 label 反查殘留容器（§17.5-5）。
	LabelRunID      = "aegis.run_id"
	LabelSnapshotID = "aegis.snapshot_id"

	// 資源上限（§17.1）：pids/memory/cpus/nofile/stop-timeout。
	PidsLimit      = 128
	MemoryLimit    = "512m"
	CPUsLimit      = "1.0"
	NoFileLimit    = 256
	StopTimeoutSec = 5

	// TmpfsSpecs 是唯讀 rootfs 之外僅有的兩塊限定大小 tmpfs（§7.1、§17.1）。
	TmpfsTmp = "/tmp:rw,size=64m,noexec"
	TmpfsRun = "/run:rw,size=16m"
)

// NetworkNone 與 NetworkSSRFInternal 是 RunSpec.Network 的閉集（§7.1 build/run 分離；
// run 選互斥的 none 或 ssrf-internal，不得 publish host port）。
const (
	NetworkNone         = "none"
	NetworkSSRFInternal = "ssrf-internal"
)

// RunSpec 是 policy compiler 給 runner 的 run 請求（§17.1）。
// Network、Image、TimeoutSec 全由 policy 決定，不接受模型輸入（§17.1 括注）。
type RunSpec struct {
	RunID      string   // §21.2 ID 規則（如 R-0001）；組 volume/network/label 名
	SnapshotID string   // §21.2 ID 規則；只進 label
	Image      string   // 必為 <name>@sha256:<64hex> digest 形式；可變 tag 拒絕（§7.1）
	Cmd        []string // 容器啟動指令（entrypoint 契約見 §17.1）
	Network    string   // NetworkNone | NetworkSSRFInternal（閉集）
	Seccomp    string   // seccomp profile 的 host 路徑（pack 提供；空值即拒組，§23-8）
	TimeoutSec int      // host 端強制逾時秒數（Start 用；預設 60s/run，§7.1）
	// Env 是 service 接線環境變數（AEGIS_SERVICE_CMD／AEGIS_SERVICE_PORT／
	// AEGIS_HEALTH_PATH）；值來自 policy RunRequest.service，不是模型輸入。
	// 每項須為 KEY=VALUE 形式，KEY 符合 [A-Za-z_][A-Za-z0-9_]*。
	Env []string
}

var envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

var (
	digestRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./:@-]*@sha256:[a-f0-9]{64}$`)
	idRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
)

// HardeningFlags 組出 §17.1 canonical hardening flags 的共用閉集（不含 network、
// 掛載、label、cmd）。正式 run 容器（DockerArgs）與 §17.6-2 收回 helper 必須共用
// 本函式——收回 helper 不得出現「較寬鬆」的部分清單（P2-2：seccomp／memory／cpus／
// pids／nofile／tmpfs 一律同源）。缺 seccomp profile 即拒組（§23-8：不放寬 hardening）。
func HardeningFlags(seccomp string) ([]string, error) {
	if seccomp == "" {
		return nil, fmt.Errorf("sandbox: 缺 seccomp profile 路徑（§23-8：不放寬 hardening）")
	}
	return []string{
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges:true",
		"--security-opt", "seccomp=" + seccomp,
		"--user", ContainerUser,
		"--read-only",
		"--tmpfs", TmpfsTmp,
		"--tmpfs", TmpfsRun,
		"--pids-limit", fmt.Sprintf("%d", PidsLimit),
		"--memory", MemoryLimit,
		"--cpus", CPUsLimit,
		"--ulimit", fmt.Sprintf("nofile=%d", NoFileLimit),
	}, nil
}

// DockerArgs 依 §17.1 組出 docker create 的完整參數閉集（不含 "docker" 與 "create" 本身；
// 順序固定，供 unit test 以 reflect.DeepEqual 逐項斷言、§22 M0a 以 docker inspect 驗證生效）。
// 映像非 digest 形式（@sha256:64hex）→ 回 error（可變 tag 拒絕，§7.1）。
func DockerArgs(req RunSpec, snapshotDir string) ([]string, error) {
	if !idRe.MatchString(req.RunID) {
		return nil, fmt.Errorf("sandbox: RunID 非法（須符合 [A-Za-z0-9][A-Za-z0-9_.-]{0,127}）：%q", req.RunID)
	}
	if !idRe.MatchString(req.SnapshotID) {
		return nil, fmt.Errorf("sandbox: SnapshotID 非法（須符合 [A-Za-z0-9][A-Za-z0-9_.-]{0,127}）：%q", req.SnapshotID)
	}
	if !digestRe.MatchString(req.Image) {
		// §7.1：映像檔僅接受 digest，可變 tag 一律拒絕。
		return nil, fmt.Errorf("sandbox: image 須為 digest 形式（<name>@sha256:<64hex>），拒收：%q", req.Image)
	}
	if req.TimeoutSec < 1 {
		return nil, fmt.Errorf("sandbox: TimeoutSec 須 >= 1，got %d", req.TimeoutSec)
	}
	cleanDir, err := canonicalHostDir(snapshotDir)
	if err != nil {
		return nil, err
	}

	// --network：閉集二選一（§7.1）。none 容器內仍有自身 loopback；
	// ssrf-internal 只能連 listener sidecar（M2），network 名固定 aegis-ssrf-<run_id>（§17.5）。
	var netArgs []string
	switch req.Network {
	case NetworkNone:
		netArgs = []string{"--network", NetworkNone}
	case NetworkSSRFInternal:
		netArgs = []string{"--network", SSRFNetPrefix + req.RunID}
	default:
		return nil, fmt.Errorf("sandbox: Network 須為 %q 或 %q，got %q", NetworkNone, NetworkSSRFInternal, req.Network)
	}

	// --env：service 接線環境變數（entrypoint 契約）；KEY=VALUE 形式檢查後逐項加入。
	// 校驗先行（任一非法即整組拒絕），參數仍依 canonical 順序組裝。
	var envArgs []string
	for _, e := range req.Env {
		if !envKeyRe.MatchString(e) {
			return nil, fmt.Errorf("sandbox: Env 須為 KEY=VALUE 形式（KEY=[A-Za-z_][A-Za-z0-9_]*），拒收：%q", e)
		}
		envArgs = append(envArgs, "--env", e)
	}

	// §17.1 canonical run flags——閉集；與 §17.6-2 收回 helper 同源（HardeningFlags）。
	// 新增或調整須同步改 flags_test.go 的逐項斷言。
	hardening, err := HardeningFlags(req.Seccomp)
	if err != nil {
		return nil, err
	}
	args := append([]string{}, hardening...)
	args = append(args, netArgs...)
	args = append(args, envArgs...)
	args = append(args,
		// 目標 repo 以 content snapshot 唯讀掛載（§7.1）；禁止任何 host 目錄以可寫模式掛入（§17.6）。
		"--mount", fmt.Sprintf("type=bind,src=%s,dst=%s,readonly", cleanDir, TargetMountPoint),
		// run 產物以 named volume 收回（§17.1、§17.6），映像內已 chown 65532。
		"-v", OutVolumePrefix+req.RunID+":"+OutMountPoint,
		// witness 注入（ADR 0002）：per-run named volume 以唯讀掛入——
		// 注入檔案在 docker create 前由 StageWitness 落入 volume。
		"-v", WitnessVolumePrefix+req.RunID+":"+WitnessMountPoint+":ro",
		// payload 以同一 volume 的 volume-subpath 掛成固定契約路徑 PayloadPath
		//（單檔唯讀；docker ≥25 支援，ADR 0002）。
		"--mount", "type=volume,src="+WitnessVolumePrefix+req.RunID+",dst="+PayloadPath+
			",volume-subpath="+PayloadStagedName+",readonly",
		"--stop-timeout", fmt.Sprintf("%d", StopTimeoutSec),
		"--label", LabelRunID+"="+req.RunID,
		"--label", LabelSnapshotID+"="+req.SnapshotID,
		req.Image,
	)
	// cmd 逐項 append（exec 呼叫、無 shell，不涉注入；但空字串會被 docker 當空參數，仍拒收）。
	for _, c := range req.Cmd {
		if c == "" {
			return nil, fmt.Errorf("sandbox: Cmd 含空字串")
		}
		args = append(args, c)
	}
	return args, nil
}

// canonicalHostDir 驗證 snapshot 目錄為絕對、clean、不含 ".."（§7.1：掛載來源
// realpath canonicalization + symlink 防護由 snapshot 端負責；此處守住路徑形狀）。
func canonicalHostDir(dir string) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("sandbox: snapshotDir 為空")
	}
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("sandbox: snapshotDir 須為絕對路徑：%q", dir)
	}
	clean := filepath.Clean(dir)
	if clean != dir {
		return "", fmt.Errorf("sandbox: snapshotDir 須為 clean 路徑（got %q，clean 為 %q）", dir, clean)
	}
	if strings.Contains(clean, "..") {
		return "", fmt.Errorf("sandbox: snapshotDir 不得含 \"..\"：%q", clean)
	}
	return clean, nil
}

