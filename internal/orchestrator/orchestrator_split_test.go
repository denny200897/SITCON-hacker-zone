package orchestrator

import (
	"reflect"
	"strings"
	"testing"
)

// TestRunRequestToRunSpecDriver：雙容器切分（ADR 0005）的翻譯——RunSpec 描述容器
// T（補 AEGIS_ROLE=target），Driver 翻譯容器 W（不含 AEGIS_SERVICE_CMD／
// AEGIS_OBSERVER_ADDR）。
func TestRunRequestToRunSpecDriver(t *testing.T) {
	rr := map[string]any{
		"run_id":  "R-0001",
		"kind":    "exploit",
		"image":   "aegis-python-web@sha256:" + strings64,
		"cmd":     []any{"/aegis/entrypoint.py", "--template", "py/http-endpoint/v3"},
		"network": "ssrf-internal",
		"service": map[string]any{
			"cmd": "python /aegis/pack/target_harness.py", "port": int64(8000), "wait_for": "GET /healthz",
		},
		"driver": map[string]any{
			"cmd":        []any{"/aegis/entrypoint.py", "--template", "py/http-endpoint/v3"},
			"network":    "driver-internal",
			"target_url": "http://target:8000",
		},
		"observer": map[string]any{
			"image":   "aegis-observer@sha256:" + strings64,
			"address": "observer:8787",
		},
		"timeout_sec": int64(60),
	}
	spec, err := RunRequestToRunSpec(rr, "SN-abc", "/pack/sandbox/seccomp.json", "/snap/dir")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Driver == nil {
		t.Fatal("driver 欄應翻譯為 RunSpec.Driver")
	}
	if want := []string{"/aegis/entrypoint.py", "--template", "py/http-endpoint/v3"}; !reflect.DeepEqual(spec.Driver.Cmd, want) {
		t.Fatalf("driver.cmd 不符：%v", spec.Driver.Cmd)
	}
	wantDEnv := []string{"AEGIS_TARGET_URL=http://target:8000", "AEGIS_ROLE=driver", "AEGIS_HEALTH_PATH=/healthz"}
	if !reflect.DeepEqual(spec.Driver.Env, wantDEnv) {
		t.Fatalf("driver env 不符：%v", spec.Driver.Env)
	}
	// 容器 T 補 role；service 接線照舊。
	foundRole := false
	foundObserverAddr := false
	for _, e := range spec.Env {
		switch {
		case e == "AEGIS_ROLE=target":
			foundRole = true
		case strings.HasPrefix(e, "AEGIS_OBSERVER_ADDR="):
			foundObserverAddr = true
		}
	}
	if !foundRole || !foundObserverAddr {
		t.Fatalf("容器 T env 應含 AEGIS_ROLE=target 與 AEGIS_OBSERVER_ADDR：%v", spec.Env)
	}

	// driver.network 非閉集成員 → 拒收（fail-closed）。
	bad := map[string]any{}
	for k, v := range rr {
		bad[k] = v
	}
	bad["driver"] = map[string]any{"cmd": []any{"x"}, "network": "bridge", "target_url": "http://target:8000"}
	if _, err := RunRequestToRunSpec(bad, "SN-abc", "/s.json", "/snap"); err == nil {
		t.Fatal("driver.network 非 driver-internal 應拒收")
	}
}

// TestTargetFiles：target.files（policy 編譯的 binding）的前綴翻譯。
func TestTargetFiles(t *testing.T) {
	rr := map[string]any{
		"target": map[string]any{
			"files": map[string]any{"target/binding.json": `{"module":"app"}`},
		},
	}
	files, err := TargetFiles(rr)
	if err != nil {
		t.Fatal(err)
	}
	if string(files["binding.json"]) != `{"module":"app"}` {
		t.Fatalf("binding 翻譯不符：%v", files)
	}
	// 無 target 欄 → nil（單容器流程）。
	if f, err := TargetFiles(map[string]any{}); err != nil || f != nil {
		t.Fatalf("無 target 欄應回 (nil, nil)：%v %v", f, err)
	}
	// 鍵不帶前綴 → 錯。
	bad := map[string]any{"target": map[string]any{"files": map[string]any{"binding.json": "x"}}}
	if _, err := TargetFiles(bad); err == nil {
		t.Fatal("缺 target/ 前綴應回錯")
	}
}