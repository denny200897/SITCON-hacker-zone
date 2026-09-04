package sandbox

import (
	"reflect"
	"strings"
	"testing"
)

// digestImg 產生合法 digest 形式映像字串（§7.1：僅接受 @sha256:<64hex>）。
func digestImg(name string) string {
	const hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 64 hex
	return name + "@sha256:" + hex64
}

// TestDockerArgsCanonicalFlagSet 逐項斷言 §17.1 canonical run flags（§22 M0a：
// hardening 每條 flag 有 unit test）。
func TestDockerArgsCanonicalFlagSet(t *testing.T) {
	req := RunSpec{
		RunID:      "R-0001",
		SnapshotID: "SNAP-0001",
		Image:      digestImg("aegis/python-web"),
		Cmd:        []string{"python", "/aegis/entrypoint.py"},
		Network:    NetworkNone,
		Seccomp:    "/host/packs/python-web/seccomp.json",
		TimeoutSec: 60,
	}
	got, err := DockerArgs(req, "/home/u/.cache/aegis/snapshots/SNAP-0001")
	if err != nil {
		t.Fatalf("DockerArgs 回傳錯誤：%v", err)
	}
	want := []string{
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges:true",
		"--security-opt", "seccomp=/host/packs/python-web/seccomp.json",
		"--user", "65532:65532",
		"--read-only",
		"--tmpfs", "/tmp:rw,size=64m,noexec",
		"--tmpfs", "/run:rw,size=16m",
		"--pids-limit", "128",
		"--memory", "512m",
		"--cpus", "1.0",
		"--ulimit", "nofile=256",
		"--network", "none",
		"--mount", "type=bind,src=/home/u/.cache/aegis/snapshots/SNAP-0001,dst=/target,readonly",
		"-v", "aegis-out-R-0001:/aegis/out",
		"-v", "aegis-witness-R-0001:/aegis/witness:ro",
		"--mount", "type=volume,src=aegis-witness-R-0001,dst=/aegis/payload.txt,volume-subpath=payload.txt,readonly",
		"--stop-timeout", "5",
		"--label", "aegis.run_id=R-0001",
		"--label", "aegis.snapshot_id=SNAP-0001",
		digestImg("aegis/python-web"),
		"python", "/aegis/entrypoint.py",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DockerArgs 非閉集順序：\n got = %#v\nwant = %#v", got, want)
	}
}

// TestDockerArgsSSRFNetwork：ssrf-internal → network 名固定 aegis-ssrf-<run_id>（§17.5-1）。
func TestDockerArgsSSRFNetwork(t *testing.T) {
	req := RunSpec{
		RunID: "R-0042", SnapshotID: "SNAP-0042",
		Image: digestImg("aegis/python-web"), Cmd: []string{"true"},
		Network: NetworkSSRFInternal, Seccomp: "/h/seccomp.json", TimeoutSec: 60,
	}
	got, err := DockerArgs(req, "/snap/SNAP-0042")
	if err != nil {
		t.Fatalf("DockerArgs 回傳錯誤：%v", err)
	}
	if !containsPair(got, "--network", "aegis-ssrf-R-0042") {
		t.Fatalf("ssrf-internal 應組出 --network aegis-ssrf-R-0042，got %#v", got)
	}
	// ssrf network 是 --internal 內網（§17.5），不得 publish host port。
	for i, a := range got {
		if a == "-p" || a == "--publish" || a == "--net" {
			t.Errorf("參數 %d 為 %q，不得出現 publish／--net 縮寫", i, a)
		}
	}
}

// TestDockerArgsRejectsMutableTag：可變 tag 一律拒絕（§7.1）。
func TestDockerArgsRejectsMutableTag(t *testing.T) {
	cases := map[string]string{
		"可變 tag":        "aegis/python-web:latest",
		"固定 tag":        "alpine:3.20",
		"純名稱":           "busybox",
		"digest 長度不足":   "busybox@sha256:abcd",
		"digest 非 hex":  "busybox@sha256:" + strings.Repeat("g", 64),
		"digest 大寫 hex": "busybox@sha256:" + strings.ToUpper(digestImg("x")[len("x@sha256:"):]),
		"空映像":           "",
		"digest 後帶 tag": "busybox@sha256:" + strings.Repeat("a", 64) + ":latest",
	}
	for name, img := range cases {
		req := RunSpec{
			RunID: "R-0001", SnapshotID: "SNAP-0001", Image: img,
			Cmd: []string{"true"}, Network: NetworkNone,
			Seccomp: "/h/seccomp.json", TimeoutSec: 60,
		}
		if _, err := DockerArgs(req, "/snap/SNAP-0001"); err == nil {
			t.Errorf("%s（%q）應被拒收，卻成功組出參數", name, img)
		}
	}
}

// TestDockerArgsRejectsBadInput：其餘非法輸入逐一擋下（§22 M0a adversarial：`..` 路徑等）。
func TestDockerArgsRejectsBadInput(t *testing.T) {
	base := RunSpec{
		RunID: "R-0001", SnapshotID: "SNAP-0001", Image: digestImg("busybox"),
		Cmd: []string{"true"}, Network: NetworkNone, Seccomp: "/h/seccomp.json", TimeoutSec: 60,
	}
	// mutate 回傳測試用的 snapshotDir（其餘非法經由改 req 欄位注入）。
	cases := []struct {
		name   string
		mutate func(*RunSpec) string
	}{
		{"缺 seccomp profile", func(r *RunSpec) string { r.Seccomp = ""; return "/snap/S" }},
		{"TimeoutSec 為 0", func(r *RunSpec) string { r.TimeoutSec = 0; return "/snap/S" }},
		{"TimeoutSec 負值", func(r *RunSpec) string { r.TimeoutSec = -5; return "/snap/S" }},
		{"Network 非閉集", func(r *RunSpec) string { r.Network = "host"; return "/snap/S" }},
		{"Network 空值", func(r *RunSpec) string { r.Network = ""; return "/snap/S" }},
		{"RunID 非法字元", func(r *RunSpec) string { r.RunID = "R/0001"; return "/snap/S" }},
		{"RunID 空值", func(r *RunSpec) string { r.RunID = ""; return "/snap/S" }},
		{"SnapshotID 非法字元", func(r *RunSpec) string { r.SnapshotID = "S X"; return "/snap/S" }},
		{"snapshotDir 相對路徑", func(r *RunSpec) string { return "snapshots/S" }},
		{"snapshotDir 含 ..", func(r *RunSpec) string { return "/snap/../etc" }},
		{"snapshotDir 空值", func(r *RunSpec) string { return "" }},
		{"snapshotDir 非 clean", func(r *RunSpec) string { return "/snap//S" }},
		{"Cmd 含空字串", func(r *RunSpec) string { r.Cmd = []string{"sh", ""}; return "/snap/S" }},
		{"Env 無 =", func(r *RunSpec) string { r.Env = []string{"AEGIS_SERVICE_PORT"}; return "/snap/S" }},
		{"Env KEY 以數字開頭", func(r *RunSpec) string { r.Env = []string{"9K=v"}; return "/snap/S" }},
		{"Env KEY 含連字號", func(r *RunSpec) string { r.Env = []string{"A-B=v"}; return "/snap/S" }},
		{"Env 空字串項", func(r *RunSpec) string { r.Env = []string{""}; return "/snap/S" }},
	}
	for _, c := range cases {
		req := base
		snapDir := c.mutate(&req)
		if _, err := DockerArgs(req, snapDir); err == nil {
			t.Errorf("%s：應被拒收", c.name)
		}
	}
}

// TestDockerArgsEnvPassthrough：合法 KEY=VALUE 逐項以 --env 注入，順序保持。
func TestDockerArgsEnvPassthrough(t *testing.T) {
	req := RunSpec{
		RunID: "R-0001", SnapshotID: "SNAP-0001", Image: digestImg("busybox"),
		Cmd: []string{"true"}, Network: NetworkNone, Seccomp: "/h/seccomp.json",
		TimeoutSec: 60,
		Env:        []string{"AEGIS_SERVICE_CMD=python /aegis/witness/app.py", "AEGIS_SERVICE_PORT=8000", "AEGIS_HEALTH_PATH=/healthz"},
	}
	got, err := DockerArgs(req, "/snap/S")
	if err != nil {
		t.Fatalf("DockerArgs 回傳錯誤：%v", err)
	}
	want := []string{"AEGIS_SERVICE_CMD=python /aegis/witness/app.py", "AEGIS_SERVICE_PORT=8000", "AEGIS_HEALTH_PATH=/healthz"}
	// 逐項存在且相對順序保持（env 區塊位於 canonical 順序中的 netArgs 之後，
	// 位置不綁死，改以「前次命中位置必須遞增」驗證順序）。
	pos := -1
	for _, w := range want {
		found := -1
		for i := pos + 1; i+1 < len(got); i++ {
			if got[i] == "--env" && got[i+1] == w {
				found = i
				break
			}
		}
		if found < 0 {
			t.Fatalf("--env %q 缺漏或順序錯誤（完整輸出 %q）", w, got)
		}
		pos = found
	}
}

// TestDockerArgsCmdPassthrough：cmd 原樣附在映像之後（exec 呼叫、無 shell）。
func TestDockerArgsCmdPassthrough(t *testing.T) {
	req := RunSpec{
		RunID: "R-0001", SnapshotID: "SNAP-0001", Image: digestImg("busybox"),
		Cmd: []string{"sh", "-c", "echo hi"}, Network: NetworkNone,
		Seccomp: "/h/seccomp.json", TimeoutSec: 60,
	}
	got, err := DockerArgs(req, "/snap/S")
	if err != nil {
		t.Fatalf("DockerArgs 回傳錯誤：%v", err)
	}
	i := lastIndexOf(got, digestImg("busybox"))
	if i < 0 {
		t.Fatalf("映像未出現在參數中：%#v", got)
	}
	tail := got[i+1:]
	if !reflect.DeepEqual(tail, []string{"sh", "-c", "echo hi"}) {
		t.Fatalf("cmd 尾段不符：got %#v", tail)
	}
}

// TestDockerArgsNoWritableHostMount：參數閉集不得出現可寫 bind mount 或 docker socket。
func TestDockerArgsNoWritableHostMount(t *testing.T) {
	req := RunSpec{
		RunID: "R-0001", SnapshotID: "SNAP-0001", Image: digestImg("busybox"),
		Cmd: []string{"true"}, Network: NetworkNone, Seccomp: "/h/seccomp.json", TimeoutSec: 60,
	}
	got, err := DockerArgs(req, "/snap/S")
	if err != nil {
		t.Fatalf("DockerArgs 回傳錯誤：%v", err)
	}
	joined := strings.Join(got, "\x00")
	for _, bad := range []string{"/var/run/docker.sock", "--privileged", "--pid=host", "--device"} {
		if strings.Contains(joined, bad) {
			t.Errorf("canonical flags 不得含 %q", bad)
		}
	}
	// 唯一 bind mount 是唯讀的 /target（§7.1）。
	if !containsPair(got, "--mount", "type=bind,src=/snap/S,dst=/target,readonly") {
		t.Fatalf("應恰有一條唯讀 /target bind mount，got %#v", got)
	}
}

// ---- 小工具（不引入 testify，§16） ----

func containsPair(args []string, flag, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}

func lastIndexOf(args []string, s string) int {
	for i := len(args) - 1; i >= 0; i-- {
		if args[i] == s {
			return i
		}
	}
	return -1
}