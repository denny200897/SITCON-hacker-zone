package sandbox

import (
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// TestDockerArgsSplitTarget：雙容器切分（ADR 0005）下 DockerArgs 組出容器 T
//（trusted side）的參數——掛 /target＋out＋witness volume，但不掛 payload
// subpath（payload 只屬於容器 W）。
func TestDockerArgsSplitTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a POSIX host path")
	}
	req := RunSpec{
		RunID:      "R-0001",
		SnapshotID: "SNAP-0001",
		Image:      digestImg("aegis/python-web"),
		Cmd:        []string{"python", "/aegis/entrypoint.py"},
		Network:    NetworkSSRFInternal,
		Seccomp:    "/host/packs/python-web/seccomp.json",
		TimeoutSec: 60,
		Env:        []string{"AEGIS_SERVICE_CMD=python /aegis/pack/target_harness.py", "AEGIS_ROLE=target"},
		Driver: &DriverSpec{
			Cmd: []string{"python", "/aegis/entrypoint.py"},
			Env: []string{"AEGIS_TARGET_URL=http://target:8000", "AEGIS_ROLE=driver"},
		},
	}
	got, err := DockerArgs(req, "/home/u/.cache/aegis/snapshots/SNAP-0001")
	if err != nil {
		t.Fatalf("DockerArgs（target）回傳錯誤：%v", err)
	}
	joined := stringArgs(got)
	if strings.Contains(joined, "volume-subpath") {
		t.Fatalf("容器 T 不得掛 payload subpath：%s", joined)
	}
	for _, want := range []string{
		"--network", SSRFNetPrefix + "R-0001",
		"--mount", "type=bind,src=/home/u/.cache/aegis/snapshots/SNAP-0001,dst=/target,readonly",
		"-v", OutVolumePrefix + "R-0001:/aegis/out",
		"-v", WitnessVolumePrefix + "R-0001:/aegis/witness:ro",
	} {
		if !contains(got, want) {
			t.Fatalf("容器 T 參數缺 %q：%s", want, joined)
		}
	}
	if got[len(got)-2:] == nil || got[len(got)-2] != "python" || got[len(got)-1] != "/aegis/entrypoint.py" {
		t.Fatalf("容器 T cmd 尾段錯誤：%#v", got[len(got)-2:])
	}
}

// TestDockerDriverArgs：容器 W（模型 driver）的參數閉集（ADR 0005）——
// 只進 driver network、掛 witness volume＋payload subpath、/aegis/out 為
// tmpfs（模型碼寫不進會被收回的 artifact）、無 /target 掛載、無 out volume。
func TestDockerDriverArgs(t *testing.T) {
	req := RunSpec{
		RunID:      "R-0002",
		SnapshotID: "SNAP-0002",
		Image:      digestImg("aegis/python-web"),
		Cmd:        []string{"python", "/aegis/entrypoint.py"},
		Network:    NetworkSSRFInternal,
		Seccomp:    "/host/packs/python-web/seccomp.json",
		TimeoutSec: 60,
		Driver: &DriverSpec{
			Cmd: []string{"python", "/aegis/entrypoint.py"},
			Env: []string{"AEGIS_TARGET_URL=http://target:8000", "AEGIS_ROLE=driver"},
		},
	}
	got, err := DockerDriverArgs(req)
	if err != nil {
		t.Fatalf("DockerDriverArgs 回傳錯誤：%v", err)
	}
	joined := stringArgs(got)
	for _, want := range []string{
		"--network", DriverNetPrefix + "R-0002",
		"-v", WitnessVolumePrefix + "R-0002:/aegis/witness:ro",
		"--mount", "type=volume,src=" + WitnessVolumePrefix + "R-0002,dst=/aegis/payload.txt,volume-subpath=payload.txt,readonly",
		"--tmpfs", DriverOutTmpfs,
		"--env", "AEGIS_TARGET_URL=http://target:8000",
		"--env", "AEGIS_ROLE=driver",
	} {
		if !contains(got, want) {
			t.Fatalf("容器 W 參數缺 %q：%s", want, joined)
		}
	}
	// 信任邊界（ADR 0005）：不得出現 /target 掛載、out volume、observer 網路。
	if strings.Contains(joined, "dst=/target") || strings.Contains(joined, "type=bind") {
		t.Fatalf("容器 W 不得掛 /target：%s", joined)
	}
	if strings.Contains(joined, OutVolumePrefix) || strings.Contains(joined, SSRFNetPrefix) {
		t.Fatalf("容器 W 不得掛 out volume 或進 observer 網路：%s", joined)
	}
	if got[len(got)-2] != "python" || got[len(got)-1] != "/aegis/entrypoint.py" {
		t.Fatalf("容器 W cmd 尾段錯誤：%#v", got[len(got)-2:])
	}
}

// TestDockerDriverArgsRequiresSplit：非切分模式呼叫 DockerDriverArgs 拒組。
func TestDockerDriverArgsRequiresSplit(t *testing.T) {
	req := RunSpec{RunID: "R-0001", SnapshotID: "SN-0001", Image: digestImg("aegis/x"), TimeoutSec: 60, Seccomp: "/s.json"}
	if _, err := DockerDriverArgs(req); err == nil {
		t.Fatal("Driver 為空時 DockerDriverArgs 應拒組")
	}
}

// TestHardeningSharedBetweenSplitContainers：切分下兩容器與 legacy 容器共用同一份
// hardening 前綴（§17.1 閉集不因切分放寬）。
func TestHardeningSharedBetweenSplitContainers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a POSIX host path")
	}
	seccomp := "/host/packs/python-web/seccomp.json"
	req := RunSpec{
		RunID: "R-0001", SnapshotID: "SNAP-0001", Image: digestImg("aegis/python-web"),
		Cmd: []string{"x"}, Network: NetworkSSRFInternal, Seccomp: seccomp, TimeoutSec: 60,
		Driver: &DriverSpec{Cmd: []string{"x"}, Env: []string{"AEGIS_ROLE=driver"}},
	}
	target, err := DockerArgs(req, "/snap")
	if err != nil {
		t.Fatal(err)
	}
	driver, err := DockerDriverArgs(req)
	if err != nil {
		t.Fatal(err)
	}
	hardening, err := HardeningFlags(seccomp)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(target[:len(hardening)], hardening) {
		t.Fatalf("容器 T 未共用完整 hardening：%#v", target[:len(hardening)])
	}
	if !reflect.DeepEqual(driver[:len(hardening)], hardening) {
		t.Fatalf("容器 W 未共用完整 hardening：%#v", driver[:len(hardening)])
	}
}

func stringArgs(args []string) string { return strings.Join(args, "\x00") }

func contains(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}