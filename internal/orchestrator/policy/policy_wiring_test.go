package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCompileSplitContainerWiring：observer-backed run（雙容器切分，ADR 0005）的
// RunRequest 須帶 driver（容器 W）與 target.files（policy 編譯的 binding）。
func TestCompileSplitContainerWiring(t *testing.T) {
	spec := baseSpec()
	spec["target_symbol"] = "app.UserRepo.find_by_name"
	spec["wiring"] = map[string]any{
		"setup": []any{
			map[string]any{"method": "seed", "args": []any{[]any{"alice", "{{NONCE}}"}}},
			map[string]any{"method": "warmup", "args": []any{"x", 3, true, nil}},
		},
	}
	in := compileInput(spec, nil)
	in.PackView.(*stubPack).templates["py/http-endpoint/v3"].ObserverImage = "aegis-observer@sha256:" + strings.Repeat("cd", 32)
	rr, err := Compile(in, testNonce)
	if err != nil {
		t.Fatalf("split policy compile 失敗：%v", err)
	}

	// driver（容器 W）：固定 cmd／network／target_url。
	drv, ok := rr["driver"].(map[string]any)
	if !ok {
		t.Fatalf("缺 driver：%#v", rr)
	}
	if dnet, _ := drv["network"].(string); dnet != DriverNetwork {
		t.Fatalf("driver.network 應為 %q：%v", DriverNetwork, drv["network"])
	}
	if turl, _ := drv["target_url"].(string); turl != "http://target:8000" {
		t.Fatalf("driver.target_url 不符：%v", drv["target_url"])
	}
	dcmd, _ := drv["cmd"].([]any)
	if len(dcmd) != 3 || dcmd[0] != "/aegis/entrypoint.py" || dcmd[2] != "py/http-endpoint/v3" {
		t.Fatalf("driver.cmd 不符：%v", dcmd)
	}

	// target.files：binding.json 為純資料（module/class/method＋setup；nonce 已替換）。
	tgt, ok := rr["target"].(map[string]any)
	if !ok {
		t.Fatalf("缺 target：%#v", rr)
	}
	tfiles, ok := tgt["files"].(map[string]any)
	if !ok {
		t.Fatalf("target.files 型別錯誤：%T", tgt["files"])
	}
	binding, _ := tfiles[BindingFileKey].(string)
	var bd struct {
		Module string `json:"module"`
		Class  string `json:"class"`
		Method string `json:"method"`
		Setup  []struct {
			Method string `json:"method"`
			Args   []any  `json:"args"`
		} `json:"setup"`
	}
	if err := json.Unmarshal([]byte(binding), &bd); err != nil {
		t.Fatalf("binding.json 非 JSON：%v\n%s", err, binding)
	}
	if bd.Module != "app" || bd.Class != "UserRepo" || bd.Method != "find_by_name" {
		t.Fatalf("binding symbol 不符：%s/%s/%s", bd.Module, bd.Class, bd.Method)
	}
	if len(bd.Setup) != 2 || bd.Setup[0].Method != "seed" || len(bd.Setup[0].Args) != 1 {
		t.Fatalf("binding setup 不符：%s", binding)
	}
	if strings.Contains(binding, "{{NONCE}}") {
		t.Fatalf("binding 內 nonce 應已替換：%s", binding)
	}

	// 容器 T 的 cmd 仍是 entrypoint（role 由 orchestrator 依 driver 鍵補上）。
	if cmd, ok := rr["cmd"].([]any); !ok || cmd[0] != "/aegis/entrypoint.py" {
		t.Fatalf("頂層 cmd 應描述容器 T：%v", rr["cmd"])
	}
}

// TestCompileSplitContainerRequiresValidWiring：wiring 的閉集驗證。
func TestCompileSplitContainerRequiresValidWiring(t *testing.T) {
	observer := func(in *Input) {
		in.PackView.(*stubPack).templates["py/http-endpoint/v3"].ObserverImage = "aegis-observer@sha256:" + strings.Repeat("cd", 32)
	}
	cases := []struct {
		name   string
		wiring any
		want   string
	}{
		{"arg 為物件（不可執行形狀）", map[string]any{
			"setup": []any{map[string]any{"method": "seed", "args": []any{map[string]any{"k": "v"}}}},
		}, ReasonBadWiring},
		{"method 非 identifier", map[string]any{
			"setup": []any{map[string]any{"method": "seed; DROP", "args": []any{}}},
		}, ReasonBadWiring},
		{"setup 非陣列", map[string]any{"setup": "boom"}, ReasonBadWiring},
		{"超過筆數上限", func() any {
			setup := []any{}
			for i := 0; i < WiringCallsMax+1; i++ {
				setup = append(setup, map[string]any{"method": "warm", "args": []any{}})
			}
			return map[string]any{"setup": setup}
		}(), ReasonBadWiring},
	}
	for _, tc := range cases {
		spec := baseSpec()
		spec["wiring"] = tc.wiring
		expectReject(t, compileInput(spec, observer), tc.want)
	}

	// 金鑰樣式（§17.9-5）：wiring 與 payload／files 同等對待（掃描器命中即拒）。
	spec := baseSpec()
	spec["wiring"] = map[string]any{
		"setup": []any{map[string]any{"method": "set", "args": []any{"AKIAEXAMPLE0000000000"}}},
	}
	in := compileInput(spec, observer)
	in.SecretScan = (&secretSpy{hits: true}).scan
	expectReject(t, in, ReasonSecretInSpec)
}