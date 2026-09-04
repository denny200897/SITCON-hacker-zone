package doctor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aegis-dev/aegis/internal/llm"
	"github.com/aegis-dev/aegis/internal/packs"
	"github.com/aegis-dev/aegis/internal/settings"
)

// 本檔所有測試零 docker daemon、零外部網路：docker／pack 載入以本包的
// unexported 函式縫替換；provider 連通以 httptest server 搭配 adapter 的
// baseURL 注入點（§16：測試僅標準庫 testing／testing/httptest）。
// package var 縫是全包共享狀態，故不 t.Parallel（§23-1 序列模型）。

const digest64 = "612e103c134210bfcf49b7ef9393418f3f25da16937f44ba77c3dba0c0b6e77c"

func findCheck(t *testing.T, checks []Check, name string) Check {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("找不到檢查項 %q（實得 %v）", name, checks)
	return Check{}
}

func packWithImage(ref string) *packs.Pack {
	return &packs.Pack{
		Dir: "/packs/python-web",
		Manifest: &packs.Manifest{
			PackID:    "python-web",
			Version:   "1.0.0",
			Templates: []packs.TemplateEntry{{TemplateID: "py/http-endpoint/v3", Image: ref}},
		},
	}
}

// packSeams 一次替換 pack 檢查相關縫並註冊還原，回傳記錄構建呼叫次數的指標。
func packSeams(t *testing.T, pack *packs.Pack, cache map[string]string, imageExists bool, digests []string) *int {
	t.Helper()
	builds := 0
	loadPackFn = func(dir string) (*packs.Pack, error) { return pack, nil }
	imageExistsFn = func(ctx context.Context, bin, ref string) bool { return imageExists }
	readImagesJSONFn = func(path string) map[string]string { return cache }
	dockerBuildFn = func(ctx context.Context, bin, dir, tag string) error { builds++; return nil }
	repoDigestsFn = func(ctx context.Context, bin, ref string) ([]string, error) { return digests, nil }
	// recordImageFn 維持真實 orchestrator.RecordImage：驗證真的落檔。
	t.Cleanup(func() {
		loadPackFn = loadPack
		imageExistsFn = dockerImageExists
		readImagesJSONFn = readImagesJSON
		dockerBuildFn = dockerBuild
		repoDigestsFn = dockerRepoDigests
	})
	return &builds
}

// ---- docker 檢查 ----

func TestDockerCheckMissingFailsWithDetail(t *testing.T) {
	// docker-missing → 檢查失敗且 detail 帶診斷（§3.3 /doctor）。
	dockerVersionFn = func(ctx context.Context, bin string) (string, error) {
		if bin != "docker" {
			t.Errorf("bin = %q, want docker（空值預設）", bin)
		}
		return "", fmt.Errorf("doctor: 找不到 docker 執行檔 %q（§7.1：無本機 fallback）", bin)
	}
	t.Cleanup(func() { dockerVersionFn = dockerVersion })

	checks := Run(context.Background(), Options{})
	c := findCheck(t, checks, "docker")
	if c.OK {
		t.Errorf("docker 缺失時 OK = true, detail = %q", c.Detail)
	}
	if !strings.Contains(c.Detail, "docker") {
		t.Errorf("detail 缺 docker 診斷 = %q", c.Detail)
	}
}

func TestDockerCheckOKViaRealExec(t *testing.T) {
	// 以假 docker script 走真實 os/exec 路徑（§16：docker CLI 以 os/exec 呼叫），
	// 驗證 `docker version --format …` 的呼叫形狀與版本行擷取。
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-docker")
	body := "#!/bin/sh\nif [ \"$1\" = version ]; then echo '27.0.3（server 27.0.3）'; fi\nexit 0\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	// 不替換 dockerVersionFn：走真實 dockerVersion（exec.Command + LookPath）。
	checks := Run(context.Background(), Options{DockerBin: script})
	c := findCheck(t, checks, "docker")
	if !c.OK {
		t.Fatalf("fake docker 應通過，detail = %q", c.Detail)
	}
	if !strings.Contains(c.Detail, "27.0.3") {
		t.Errorf("detail 缺版本行 = %q", c.Detail)
	}
}

func TestDockerCheckDaemonDownFails(t *testing.T) {
	dockerVersionFn = func(ctx context.Context, bin string) (string, error) {
		return "", errors.New("doctor: docker version 失敗（daemon 未啟動？）：Cannot connect to the Docker daemon")
	}
	t.Cleanup(func() { dockerVersionFn = dockerVersion })
	checks := Run(context.Background(), Options{})
	c := findCheck(t, checks, "docker")
	if c.OK || !strings.Contains(c.Detail, "daemon") {
		t.Errorf("OK = %v, detail = %q", c.OK, c.Detail)
	}
}

// ---- semgrep 檢查（§6：binary 存在性由 /doctor 檢查） ----

func TestSemgrepCheckLookPath(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		lookPathFn = func(name string) (string, error) {
			return "", fmt.Errorf("exec: %q: executable file not found in $PATH", name)
		}
		t.Cleanup(func() { lookPathFn = exec.LookPath })
		checks := Run(context.Background(), Options{})
		c := findCheck(t, checks, "semgrep")
		if c.OK || !strings.Contains(c.Detail, "semgrep") {
			t.Errorf("OK = %v, detail = %q", c.OK, c.Detail)
		}
	})
	t.Run("found", func(t *testing.T) {
		lookPathFn = func(name string) (string, error) {
			if name != "semgrep" {
				t.Errorf("name = %q", name)
			}
			return "/usr/local/bin/semgrep", nil
		}
		t.Cleanup(func() { lookPathFn = exec.LookPath })
		checks := Run(context.Background(), Options{})
		c := findCheck(t, checks, "semgrep")
		if !c.OK || !strings.Contains(c.Detail, "/usr/local/bin/semgrep") {
			t.Errorf("OK = %v, detail = %q", c.OK, c.Detail)
		}
	})
}

// ---- pack 映像檢查（§17.10） ----

func TestPackCheckPreRecordedImagesJSONNoBuild(t *testing.T) {
	// images.json 預先記錄 digest → OK、不構建（§17.10 第 3 階記錄在案）。
	ref := "aegis-python-web@sha256:" + digest64
	builds := packSeams(t, packWithImage(ref), map[string]string{ref: ref}, false, nil)

	// CachePath 指到 t.TempDir（readImagesJSONFn 已替換，路徑僅作非空判斷）。
	cachePath := filepath.Join(t.TempDir(), "images.json")
	checks := Run(context.Background(), Options{PackDirs: []string{"/packs/python-web"}, CachePath: cachePath})
	c := findCheck(t, checks, "pack:python-web")
	if !c.OK {
		t.Fatalf("預錄 images.json 應 OK，detail = %q", c.Detail)
	}
	if *builds != 0 {
		t.Errorf("builds = %d, want 0（快取命中免構建）", *builds)
	}
	if !strings.Contains(c.Detail, "images.json") {
		t.Errorf("detail 應註明快取命中 = %q", c.Detail)
	}
}

func TestPackCheckDigestLocalNoBuild(t *testing.T) {
	// manifest 記載 digest 且本機有該 digest 映像 → OK、不構建（§17.10 第 1 階）。
	ref := "aegis-python-web@sha256:" + digest64
	builds := packSeams(t, packWithImage(ref), nil, true, nil)

	checks := Run(context.Background(), Options{PackDirs: []string{"/packs/python-web"}})
	c := findCheck(t, checks, "pack:python-web")
	if !c.OK {
		t.Fatalf("本機 digest 映像應 OK，detail = %q", c.Detail)
	}
	if *builds != 0 {
		t.Errorf("builds = %d, want 0", *builds)
	}
}

func TestPackCheckBuildInvokedAndRecorded(t *testing.T) {
	// 本機無映像、無快取記錄 → 構建縫被呼叫，且 RecordImage 落檔 t.TempDir 快取。
	ref := "aegis-python-web@sha256:" + digest64
	builtDigest := "aegis-python-web@sha256:" + strings.Repeat("ab", 32)
	builds := packSeams(t, packWithImage(ref), nil, false, []string{builtDigest})

	cachePath := filepath.Join(t.TempDir(), "cache", "images.json") // 子目錄由 RecordImage 建立
	checks := Run(context.Background(), Options{PackDirs: []string{"/packs/python-web"}, CachePath: cachePath})
	c := findCheck(t, checks, "pack:python-web")
	if !c.OK {
		t.Fatalf("構建＋記錄成功應 OK，detail = %q", c.Detail)
	}
	if *builds != 1 {
		t.Errorf("builds = %d, want 1", *builds)
	}
	// 以真實 orchestrator.RecordImage 寫入，讀回驗證 ref→digest 記錄在案。
	imgs := readImagesJSON(cachePath)
	if imgs[ref] != builtDigest {
		t.Errorf("images.json[%q] = %q, want %q", ref, imgs[ref], builtDigest)
	}
	// ADR 0002 決策三：重建 digest 與 manifest 記載不同時，detail 須提示重錄。
	if !strings.Contains(c.Detail, "重錄") {
		t.Errorf("detail 應提示重錄 manifest = %q", c.Detail)
	}
}

func TestPackCheckBuildFailureNotOK(t *testing.T) {
	ref := "aegis-python-web@sha256:" + digest64
	packSeams(t, packWithImage(ref), nil, false, nil)
	dockerBuildFn = func(ctx context.Context, bin, dir, tag string) error {
		return errors.New("doctor: docker build 失敗：failed to solve: 拉取基底映像失敗")
	}
	t.Cleanup(func() { dockerBuildFn = dockerBuild })
	checks := Run(context.Background(), Options{PackDirs: []string{"/packs/python-web"}})
	c := findCheck(t, checks, "pack:python-web")
	if c.OK || !strings.Contains(c.Detail, "失敗") {
		t.Errorf("OK = %v, detail = %q", c.OK, c.Detail)
	}
}

func TestPackCheckNoRepoDigestNotOK(t *testing.T) {
	// RepoDigests 為空（classic store 本地構建未 push）→ 未通過（ADR 0002 決策三）。
	ref := "aegis-python-web@sha256:" + digest64
	builds := packSeams(t, packWithImage(ref), nil, false, []string{})
	checks := Run(context.Background(), Options{PackDirs: []string{"/packs/python-web"}})
	c := findCheck(t, checks, "pack:python-web")
	if c.OK || *builds != 1 {
		t.Errorf("OK = %v, builds = %d, detail = %q", c.OK, *builds, c.Detail)
	}
}

func TestPackCheckLoadFailureNotOK(t *testing.T) {
	loadPackFn = func(dir string) (*packs.Pack, error) {
		return nil, errors.New("packs: manifest 驗證失敗（拒載）: bad json")
	}
	t.Cleanup(func() { loadPackFn = loadPack })
	checks := Run(context.Background(), Options{PackDirs: []string{"/packs/python-web"}})
	c := findCheck(t, checks, "pack:python-web")
	if c.OK || !strings.Contains(c.Detail, "載入失敗") {
		t.Errorf("OK = %v, detail = %q", c.OK, c.Detail)
	}
}

func TestPackCheckBuildTimeoutApplied(t *testing.T) {
	// BuildTimeout 必須進入 build 的 context（顯式 7s 須被採用；0 → 600s 由
	// buildTimeoutOf 的分支邏輯保證，此處驗證注入路徑）。
	ref := "aegis-python-web@sha256:" + digest64
	packSeams(t, packWithImage(ref), nil, false, []string{ref})
	var got time.Duration
	dockerBuildFn = func(ctx context.Context, bin, dir, tag string) error {
		dl, _ := ctx.Deadline()
		got = time.Until(dl)
		return nil
	}
	t.Cleanup(func() { dockerBuildFn = dockerBuild })
	checks := Run(context.Background(), Options{PackDirs: []string{"/packs/python-web"}, BuildTimeout: 7 * time.Second})
	c := findCheck(t, checks, "pack:python-web")
	if !c.OK {
		t.Fatalf("detail = %q", c.Detail)
	}
	if got < 6*time.Second || got > 8*time.Second {
		t.Errorf("build deadline = %v, want ~7s", got)
	}
}

// ---- provider 連通檢查（§3.3：host 端一次極小呼叫） ----

// anthropicShape／openaiShape 回傳各供應商形狀的最小有效回應。
func anthropicShape(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"id":"msg_01","type":"message","role":"assistant","model":"claude-haiku-4-5","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}`)
}

func openaiShape(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"id":"cmpl-1","object":"chat.completion","model":"qwen3:32b","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
}

func TestProviderConnectivityOK(t *testing.T) {
	// anthropic 形與 openai-compat 形各一：httptest 依路徑回對應最小回應。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/chat/completions"):
			openaiShape(w)
		default: // anthropic SDK 走 <base>/v1/messages
			anthropicShape(w)
		}
	}))
	defer srv.Close()

	o := Options{
		Providers: map[string]settings.Provider{
			"anthropic":   {Type: "anthropic", BaseURL: srv.URL},
			"my-ollama":   {Type: "openai-compat", BaseURL: srv.URL},
			"no-base-url": {Type: "openai-compat", BaseURL: ""},
		},
		ResolveKey: func(name string) (string, string, error) { return "sk-test-0123456789abcdef", "env", nil },
	}
	checks := Run(context.Background(), o)

	if c := findCheck(t, checks, "provider:anthropic"); !c.OK {
		t.Errorf("anthropic 連通應 OK，detail = %q", c.Detail)
	}
	if c := findCheck(t, checks, "provider:my-ollama"); !c.OK {
		t.Errorf("openai-compat 連通應 OK，detail = %q", c.Detail)
	}
	// openai-compat 缺 base_url → 失敗（§3.3 /provider add 必填）。
	if c := findCheck(t, checks, "provider:no-base-url"); c.OK {
		t.Errorf("缺 base_url 應失敗，detail = %q", c.Detail)
	}
}

func TestProviderKeyUnset(t *testing.T) {
	// 金鑰未解析 → OK=false、detail 固定「金鑰未設定」（永不回顯金鑰，§3.3）。
	o := Options{
		Providers: map[string]settings.Provider{"anthropic": {Type: "anthropic"}},
		ResolveKey: func(name string) (string, string, error) {
			return "", "", errors.New("credentials: key not found")
		},
	}
	checks := Run(context.Background(), o)
	c := findCheck(t, checks, "provider:anthropic")
	if c.OK {
		t.Errorf("無金鑰應失敗")
	}
	if c.Detail != "金鑰未設定" {
		t.Errorf("detail = %q, want 金鑰未設定", c.Detail)
	}
}

func TestProviderKeyUnsetEmptyKey(t *testing.T) {
	o := Options{
		Providers:  map[string]settings.Provider{"p": {Type: "anthropic"}},
		ResolveKey: func(name string) (string, string, error) { return "", "env", nil },
	}
	checks := Run(context.Background(), o)
	if c := findCheck(t, checks, "provider:p"); c.OK || c.Detail != "金鑰未設定" {
		t.Errorf("OK = %v, detail = %q", c.OK, c.Detail)
	}
}

func TestProviderResolveKeyNilSkips(t *testing.T) {
	// ResolveKey=nil → 跳過金鑰步驟（仍列出項目並註明，見 checkProviders 的 ASK）。
	o := Options{Providers: map[string]settings.Provider{"p": {Type: "anthropic"}}}
	checks := Run(context.Background(), o)
	if c := findCheck(t, checks, "provider:p"); !c.OK || !strings.Contains(c.Detail, "略過") {
		t.Errorf("OK = %v, detail = %q", c.OK, c.Detail)
	}
}

func TestProviderErrorTextNeverContainsKey(t *testing.T) {
	// 401 並在回應體回顯金鑰（供應商把 header echo 回來的最壞情形）：
	// detail 經出口遮蔽後不得含金鑰字串（§23-6）。
	const key = "sk-ant-SECRET-echoed-key-0123456789"
	for _, tc := range []struct {
		name    string
		ptype   string
		handler http.HandlerFunc
	}{
		{
			name:  "anthropic",
			ptype: "anthropic",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintf(w, `{"type":"error","error":{"type":"authentication_error","message":"invalid api key %s"}}`, key)
			},
		},
		{
			name:  "openai-compat",
			ptype: "openai-compat",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintf(w, `{"error":{"message":"invalid api key %s"}}`, key)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			o := Options{
				Providers: map[string]settings.Provider{"p": {Type: tc.ptype, BaseURL: srv.URL}},
				ResolveKey: func(name string) (string, string, error) {
					return key, "env", nil
				},
			}
			checks := Run(context.Background(), o)
			c := findCheck(t, checks, "provider:p")
			if c.OK {
				t.Fatalf("401 應失敗，detail = %q", c.Detail)
			}
			if strings.Contains(c.Detail, key) {
				t.Fatalf("detail 洩漏金鑰：%q", c.Detail)
			}
			if !strings.Contains(c.Detail, "401") {
				t.Errorf("detail 應含 HTTP 狀態碼以供分類（§18.3）：%q", c.Detail)
			}
		})
	}
}

// probeCapture 是記錄 Chat 收到 context deadline 的 adapter 縫替換（§23-1：
// 單一 adapter 介面，無 goroutine）。
type probeCapture struct {
	deadline time.Duration
}

func (p *probeCapture) Chat(ctx context.Context, req llm.ChatRequest) (llm.Response, error) {
	if dl, ok := ctx.Deadline(); ok {
		p.deadline = time.Until(dl)
	}
	return llm.Response{Model: req.Model, StopReason: llm.StopEndTurn}, nil
}

func (p *probeCapture) Provider() string { return "p" }

func TestProviderConnectTimeoutApplied(t *testing.T) {
	// ConnectTimeout 必須進入 Chat 的 context（顯式 5s 須被採用）。
	cap := &probeCapture{}
	newAdapterFn = func(name string, p settings.Provider, key string) (llm.Adapter, error) {
		return cap, nil
	}
	t.Cleanup(func() { newAdapterFn = newAdapter })
	o := Options{
		Providers:      map[string]settings.Provider{"p": {Type: "anthropic"}},
		ResolveKey:     func(name string) (string, string, error) { return "k", "env", nil },
		ConnectTimeout: 5 * time.Second,
	}
	checks := Run(context.Background(), o)
	c := findCheck(t, checks, "provider:p")
	if !c.OK {
		t.Errorf("detail = %q", c.Detail)
	}
	if cap.deadline < 4*time.Second || cap.deadline > 6*time.Second {
		t.Errorf("connect deadline = %v, want ~5s", cap.deadline)
	}
	// 極小呼叫形狀（§3.3）：MaxTokens 16、非串流、無 tools、單則短訊息。
	// （req 形狀由 adapter 測試覆蓋；此處驗證 doctor 端的請求組裝。）
	o2 := o
	var lastReq llm.ChatRequest
	newAdapterFn = func(name string, p settings.Provider, key string) (llm.Adapter, error) {
		return &reqCapture{last: &lastReq}, nil
	}
	checks = Run(context.Background(), o2)
	_ = findCheck(t, checks, "provider:p")
	if lastReq.MaxTokens != probeMaxTokens || lastReq.Stream {
		t.Errorf("MaxTokens = %d, Stream = %v, want %d/false", lastReq.MaxTokens, lastReq.Stream, probeMaxTokens)
	}
	if len(lastReq.Messages) != 1 || len(lastReq.Tools) != 0 {
		t.Errorf("Messages = %d, Tools = %d, want 單則無工具", len(lastReq.Messages), len(lastReq.Tools))
	}
}

type reqCapture struct {
	last *llm.ChatRequest
}

func (r *reqCapture) Chat(ctx context.Context, req llm.ChatRequest) (llm.Response, error) {
	*r.last = req
	return llm.Response{StopReason: llm.StopEndTurn}, nil
}

func (r *reqCapture) Provider() string { return "p" }

// ---- Run 序列與輸出形狀 ----

func TestRunOrderAndShape(t *testing.T) {
	// 檢查項順序固定：docker → semgrep → pack:* → provider:*（§3.3 /doctor 序），
	// provider 以名稱排序（確定性輸出）。金鑰未解析路徑避免任何網路呼叫。
	ref := "aegis-python-web@sha256:" + digest64
	packSeams(t, packWithImage(ref), nil, true, nil)
	dockerVersionFn = func(ctx context.Context, bin string) (string, error) {
		return "27.0.3（server 27.0.3）", nil
	}
	t.Cleanup(func() { dockerVersionFn = dockerVersion })
	lookPathFn = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	t.Cleanup(func() { lookPathFn = exec.LookPath })

	o := Options{
		PackDirs: []string{"/packs/python-web"},
		Providers: map[string]settings.Provider{
			"b-provider": {Type: "anthropic"},
			"a-provider": {Type: "anthropic"},
		},
		ResolveKey: func(name string) (string, string, error) { return "", "", errors.New("credentials: key not found") },
	}
	checks := Run(context.Background(), o)
	want := []string{"docker", "semgrep", "pack:python-web", "provider:a-provider", "provider:b-provider"}
	if len(checks) != len(want) {
		t.Fatalf("checks = %d, want %d：%v", len(checks), len(want), checks)
	}
	for i, name := range want {
		if checks[i].Name != name {
			t.Errorf("checks[%d].Name = %q, want %q", i, checks[i].Name, want[i])
		}
	}
	for _, c := range checks {
		if c.Detail == "" {
			t.Errorf("check %q 的 detail 為空", c.Name)
		}
	}
}

func TestPackLoadFailureDetailNotExposingUnknown(t *testing.T) {
	// 載入失敗的 detail 不應為空且指向拒載分類（§6.4 errors.Is 判別由呼叫端做）。
	loadPackFn = func(dir string) (*packs.Pack, error) {
		return nil, fmt.Errorf("packs: %w：pack schema_version=2，core 支援 1", packs.ErrABI)
	}
	t.Cleanup(func() { loadPackFn = loadPack })
	checks := Run(context.Background(), Options{PackDirs: []string{"/packs/python-web"}})
	c := findCheck(t, checks, "pack:python-web")
	if c.OK || !strings.Contains(c.Detail, "schema_version") {
		t.Errorf("OK = %v, detail = %q", c.OK, c.Detail)
	}
}

func TestTruncRuneSafe(t *testing.T) {
	// 中文訊息截尾不得切出非法 rune（rune 邊界安全）。
	long := strings.Repeat("診斷訊息", 200) // 400 runes
	got := trunc(long)
	if got == long {
		t.Fatal("應被截尾")
	}
	if !strings.HasSuffix(got, "…（截尾）") {
		t.Errorf("尾標缺失：%q", got[len(got)-20:])
	}
	if n := len([]rune(strings.TrimSuffix(got, "…（截尾）"))); n != detailMax {
		t.Errorf("截後 rune 數 = %d, want %d", n, detailMax)
	}
	// truncTail 同理取尾段。
	tail := truncTail(long)
	if !strings.HasPrefix(tail, "…（截尾）") {
		t.Errorf("truncTail 前標缺失：%q", tail[:20])
	}
	if n := len([]rune(strings.TrimPrefix(tail, "…（截尾）"))); n != detailMax {
		t.Errorf("truncTail 截後 rune 數 = %d, want %d", n, detailMax)
	}
	if truncTail("   ") != "(無輸出)" {
		t.Errorf("空輸入應收斂為佔位：%q", truncTail("   "))
	}
}

func TestBuildTagAndShortRef(t *testing.T) {
	if got := buildTag("aegis-python-web@sha256:"+digest64, "1.0.0"); got != "aegis-python-web:1.0.0" {
		t.Errorf("buildTag = %q", got)
	}
	if got := buildTag("plain-ref", ""); got != "plain-ref:doctor" {
		t.Errorf("buildTag = %q", got)
	}
	if got := shortRef("aegis-python-web@sha256:" + digest64); got != "aegis-python-web@sha256:612e103c1342" {
		t.Errorf("shortRef = %q", got)
	}
	if got := shortRef("plain-ref"); got != "plain-ref" {
		t.Errorf("shortRef = %q", got)
	}
	if !isDigestRef("aegis-python-web@sha256:" + digest64) {
		t.Error("digest 形式應判 true")
	}
	if isDigestRef("aegis-python-web:3.12") || isDigestRef("aegis-python-web@sha256:zz") {
		t.Error("非 digest 形式應判 false")
	}
	if pickRepoDigest([]string{"registry.example/aegis-x@sha256:" + digest64}) == "" {
		t.Error("含 registry 前綴的 repo digest 應可挑出")
	}
	if pickRepoDigest([]string{"aegis-x:latest"}) != "" {
		t.Error("非 digest 定址應回空")
	}
}