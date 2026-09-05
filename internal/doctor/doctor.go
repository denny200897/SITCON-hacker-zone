// Package doctor 實作 /doctor 體檢（SPEC §3.3、§17.10）。
//
// /doctor 逐項檢查（序列、無 goroutine，§23-1）：
//
//  1. "docker"：以 os/exec 呼叫 docker version（§16：不用 Docker SDK）。
//  2. "semgrep"：binary 存在性（§6：semgrep 以 os/exec 呼叫，存在性由 /doctor 檢查）。
//  3. "pack:<name>"：載入 pack 後逐模板映像依 §17.10 解析——本地既有 digest 映像
//     → 本地 images.json 記錄 → 皆無則本地構建（§17.10：/doctor 是唯一核准的
//     構建點，policy compiler 與 prove **不自動構建**），digest 以
//     orchestrator.RecordImage 寫入 ~/.cache/aegis/images.json。
//  4. "provider:<name>"：金鑰解析（由呼叫端注入 credentials.Manager.Resolve，
//     §3.3 解析序）→ 經 internal/llm adapter 對供應商 base_url 做一次極小的
//     host 端呼叫（單句訊息、無 tools、非串流）。
//
// 金鑰防洩（§23-6）：金鑰只經 ResolveKey 取得後交給 adapter；檢查 detail
// 一律不回顯金鑰，回傳前以本輪已登錄金鑰做 redaction（internal/redaction.Redact）。
package doctor

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/aegis-dev/aegis/internal/credentials"
	"github.com/aegis-dev/aegis/internal/llm"
	"github.com/aegis-dev/aegis/internal/orchestrator"
	"github.com/aegis-dev/aegis/internal/packs"
	"github.com/aegis-dev/aegis/internal/redaction"
	"github.com/aegis-dev/aegis/internal/settings"
)

// Check 是單一體檢項目的結果；Detail 面向 /doctor 的 tabwriter 輸出（§16），
// 保證不含金鑰內容（§23-6）。
type Check struct {
	Name   string
	OK     bool
	Detail string
}

// Options 是 Run 的輸入。零值欄位的預設見各欄註解；本結構刻意不含
// exec／網路依賴，單元測試以本檔尾端的 unexported 函式縫（package vars）替換。
type Options struct {
	// DockerBin 是 docker 執行檔；空值 → "docker"（§16 os/exec 慣例）。
	DockerBin string
	// PackDirs 是待檢查的 pack 目錄（絕對路徑；各自含 manifest.json 與 image/Dockerfile）。
	PackDirs []string
	// SchemasDir 非空時明示 embedded/materialized schemas，避免依賴目前工作目錄。
	SchemasDir string
	// CachePath 是 ~/.cache/aegis/images.json（§17.10 digest 記錄）；空值表示
	// 只檢查不記錄（記錄步驟略過、構建後仍須取得 repo digest 才算通過）。
	CachePath string
	// BuildTimeout 是單次 docker build 的上界；0 → 600s。
	BuildTimeout time.Duration
	// Providers 是待連通測試的供應商定義（§3.1 aegis.toml／settings.toml 的
	// [providers] 節；金鑰不在設定檔，§23-6）。
	Providers map[string]settings.Provider
	// Models 是已解析的角色路由（role → provider/model-id）。provider 探測必須
	// 使用這裡實際設定的 model，不得讓相容端點自行挑選預設模型。
	Models map[string]string
	// ResolveKey 是金鑰解析注入點（正式路徑：credentials.Manager.Resolve，
	// §3.3 解析序）；nil → 跳過金鑰步驟（見 checkProviders 內的 ASK 註記）。
	ResolveKey func(providerName string) (key string, source string, err error)
	// ConnectTimeout 是單次供應商連通呼叫的上界；0 → 30s。
	ConnectTimeout time.Duration
	// SemgrepBin 是 semgrep 執行檔；空值 → "semgrep"（§6）。
	SemgrepBin string
}

// ---- 預設值與小工具 ----

const (
	// OpenAI-compatible reasoning models may spend part of max_tokens on hidden
	// reasoning. A 16-token probe can return HTTP 200 with no visible content and
	// look like a refusal. 256 is still cheap but leaves room for a visible reply.
	probeMaxTokens = 256

	// probeTimeout 是 docker version／docker image inspect 等短探測的固定上界
	//（與 internal/sandbox.Available 的 20s 探測慣例一致）。
	probeTimeout = 20 * time.Second

	// detailMax 是單一 Check.Detail 的長度上界（rune 計）；超長截尾，
	// 避免 docker build 輸出整份傾印淹沒 tabwriter。
	detailMax = 300
)

func dockerBin(o Options) string {
	if o.DockerBin == "" {
		return "docker"
	}
	return o.DockerBin
}

func buildTimeoutOf(o Options) time.Duration {
	if o.BuildTimeout <= 0 {
		return 600 * time.Second
	}
	return o.BuildTimeout
}

func connectTimeoutOf(o Options) time.Duration {
	if o.ConnectTimeout <= 0 {
		return 30 * time.Second
	}
	return o.ConnectTimeout
}

// trunc 把字串截到 detailMax 個 rune（rune 邊界安全，中文訊息不切半）。
func trunc(s string) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) > detailMax {
		return string(r[:detailMax]) + "…（截尾）"
	}
	return s
}

// truncTail 取字串尾段（去空白、rune 邊界安全）——docker build 失敗的
// 有用訊息在輸出尾端，取尾不取頭（與 internal/sandbox 的 tail 慣例一致）。
func truncTail(s string) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) > detailMax {
		return "…（截尾）" + string(r[len(r)-detailMax:])
	}
	if s == "" {
		return "(無輸出)"
	}
	return s
}

// ---- Run ----

// Run 依 §3.3 /doctor 的檢查序列執行體檢：docker → semgrep → pack 映像（§17.10）
// → provider 連通。全序列、無 goroutine（§23-1）；回傳的每個 Detail 已做金鑰遮蔽。
func Run(ctx context.Context, o Options) []Check {
	checks := []Check{}
	checks = append(checks, checkDocker(ctx, o))
	checks = append(checks, checkSemgrep(o))
	checks = append(checks, checkPacks(ctx, o)...)

	// 金鑰防洩（§23-6）：本輪成功解析的金鑰登錄進 secrets，回傳前對所有
	// Detail 做遮蔽——涵蓋供應商把標頭 echo 進錯誤體、或上游錯誤訊息
	// 夾帶金鑰的情形（llm adapter 自身亦遮蔽，此處是 doctor 出口的最後一道閘）。
	var secrets []string
	checks = append(checks, checkProviders(ctx, o, &secrets)...)
	for i := range checks {
		checks[i].Detail = redaction.Redact(checks[i].Detail, secrets)
	}
	return checks
}

// ---- 檢查 1：docker（§16：os/exec 呼叫 docker CLI） ----

func checkDocker(ctx context.Context, o Options) Check {
	bin := dockerBin(o)
	vctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	v, err := dockerVersionFn(vctx, bin)
	if err != nil {
		return Check{Name: "docker", OK: false, Detail: trunc(err.Error())}
	}
	return Check{Name: "docker", OK: true, Detail: "docker 可用：" + v}
}

// dockerVersion 以 `docker version --format …` 取 client／server 版本行。
// daemon 未啟動時 exit code 非 0，stderr 尾段即是診斷訊息。
//
// ASK（§23：不自行選擇）：版本輸出的擷取形式有兩個選項——
// (a) `--format '{{.Client.Version}}（server {{.Server.Version}}）'`（採用：一行、
//
//	可直接放入 tabwriter，且 §16 規定 docker 輸出用 --format）；
//
// (b) 純 `docker version` 後由 harness 抓 "Version:" 行（輸出多行、解析易碎）。
// daemon 掛掉時 (a) 的 Go template 會失敗、exit 非 0，錯誤訊息仍可取得。
func dockerVersion(ctx context.Context, bin string) (string, error) {
	if _, err := exec.LookPath(bin); err != nil {
		return "", fmt.Errorf("doctor: 找不到 docker 執行檔 %q（§7.1：無本機 fallback）：%w", bin, err)
	}
	cmd := exec.CommandContext(ctx, bin, "version", "--format", "{{.Client.Version}}（server {{.Server.Version}}）")
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &outBuf, &errBuf
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("doctor: docker version 失敗（daemon 未啟動？）：%s：%w", truncTail(errBuf.String()), err)
	}
	return strings.TrimSpace(outBuf.String()), nil
}

// ---- 檢查 2：semgrep（§6：binary 存在性由 /doctor 檢查） ----

func checkSemgrep(o Options) Check {
	bin := o.SemgrepBin
	if bin == "" {
		bin = "semgrep"
	}
	path, err := lookPathFn(bin)
	if err != nil {
		return Check{Name: "semgrep", OK: false,
			Detail: trunc(fmt.Sprintf("找不到 semgrep 執行檔 %q（§6：os/exec 呼叫，無 library 綁定）：%v", bin, err))}
	}
	return Check{Name: "semgrep", OK: true, Detail: "semgrep 位於 " + path}
}

// ---- 檢查 3：pack 映像（§17.10） ----

// loadPack 是 pack 載入的正式路徑。
//
// ASK：allowCommunity 以 false 呼叫（與 e2e／prove 慣例一致——未啟用的
// community pack 在 /doctor 應以載入失敗呈現，而非靜默通過）。另一選項是
// (b) 把 allowCommunity 提升為 Options 欄位由呼叫端決定。另外 packs.Load 的
// schemas 目錄靠 cwd 向上搜尋（開發期慣例）；若 CLI 層已知 repo 根，
// 建議在 Options 增加 SchemasDir 欄位改用 packs.LoadWithSchemas 明示路徑，
// 避免使用者從任意目錄啟動時載入失敗。
func loadPack(dir string) (*packs.Pack, error) {
	return packs.Load(dir, false)
}

func checkPacks(ctx context.Context, o Options) []Check {
	dirs := append([]string(nil), o.PackDirs...)
	sort.Strings(dirs) // 確定性輸出（§23：序列執行；輸出順序不依 map 迭代）
	out := []Check{}
	bin := dockerBin(o)
	for _, dir := range dirs {
		name := filepath.Base(dir)
		var pack *packs.Pack
		var err error
		if o.SchemasDir != "" {
			pack, err = packs.LoadWithSchemas(dir, o.SchemasDir, false)
		} else {
			pack, err = loadPackFn(dir)
		}
		if err != nil {
			out = append(out, Check{Name: "pack:" + name, OK: false,
				Detail: trunc("pack 載入失敗（拒載，§6.4）：" + err.Error())})
			continue
		}
		out = append(out, checkPackImages(ctx, o, bin, dir, pack))
	}
	return out
}

// checkPackImages 對單一 pack 的所有模板映像依 §17.10 解析序逐一定址：
//
//  1. manifest 已記 digest 且本機 docker 有該 digest 映像 → OK，免構建。
//  2. images.json 已記錄該參照的 digest → OK，免構建（§17.10 第 3 階記錄在案）。
//  3. 皆無 → 本地構建（§17.10：/doctor 是核准構建點，prove 不自動構建），
//     以 docker inspect 取 repo digest 後 RecordImage 落檔。
func checkPackImages(ctx context.Context, o Options, bin, dir string, pack *packs.Pack) Check {
	name := filepath.Base(dir)
	c := Check{Name: "pack:" + name}

	cache := map[string]string{}
	if o.CachePath != "" {
		cache = readImagesJSONFn(o.CachePath)
	}

	var notes, problems []string
	seen := map[string]bool{}
	for _, t := range pack.Manifest.Templates {
		ref := t.Image
		if ref == "" {
			problems = append(problems, fmt.Sprintf("template %q 缺 image 記載（§6.3）", t.TemplateID))
			continue
		}
		if seen[ref] {
			continue
		}
		seen[ref] = true

		// 1) manifest digest 已在本地（§17.10 解析序第 1 階）。
		if isDigestRef(ref) && imageExistsFn(ctx, bin, ref) {
			notes = append(notes, fmt.Sprintf("%s digest 已在本地（免構建）", shortRef(ref)))
			continue
		}
		// 2) images.json 已記錄（§17.10 解析序第 3 階；本機缺映像時 policy
		//    仍以記錄的 digest 定址，此處不算失敗、也不重複構建）。
		if d := cache[ref]; d != "" && imageExistsFn(ctx, bin, d) {
			notes = append(notes, fmt.Sprintf("%s 已記錄於 images.json（免構建）", shortRef(ref)))
			continue
		}
		// 3) 本地構建（核准構建點，§17.10）。
		note, problem := buildAndRecord(ctx, o, bin, dir, pack.Manifest.Version, ref)
		if note != "" {
			notes = append(notes, note)
		}
		if problem != "" {
			problems = append(problems, problem)
		}
	}

	c.OK = len(problems) == 0
	detail := strings.Join(notes, "；")
	if detail != "" && len(problems) > 0 {
		detail += "；"
	}
	detail += strings.Join(problems, "；")
	if detail == "" {
		// pack 合法但未宣告任何 template 映像：列出空狀態而非空白。
		detail = "無模板映像（manifest 未宣告 template）"
	}
	c.Detail = trunc(detail)
	return c
}

// buildAndRecord 執行一次本地構建並把 repo digest 記錄進 images.json。
// 回傳 (note, problem)：problem 非空表示本映像未通過。
func buildAndRecord(ctx context.Context, o Options, bin, dir, version, ref string) (note, problem string) {
	tag := buildTag(ref, version)
	//
	// ASK：任務文字寫 `docker build -t <tag> <packdir>/image`（context=pack 的
	// image/ 子目錄）；但 repo 內 docs/adr/0002-m0b-e2e.md「決策三」固定
	// context 須為 pack 根目錄、命令為 `docker build -f image/Dockerfile -t <tag> .`
	//（Dockerfile 的 COPY sandbox/、templates/ 以 pack 根解析）。兩者衝突，
	// 此處採 ADR（context=pack 根）。若要以 image/ 為 context，須同步改
	// Dockerfile 的 COPY 路徑。
	bctx, cancel := context.WithTimeout(ctx, buildTimeoutOf(o))
	defer cancel()
	if err := dockerBuildFn(bctx, bin, dir, tag); err != nil {
		return "", fmt.Sprintf("構建 %s 失敗（§17.10 本地構建）：%s", tag, truncTail(err.Error()))
	}

	// 取 repo digest（ADR 0002 決策三：本地構建映像僅能以 RepoDigests 定址，
	// image ID 不可作為 name@sha256: 引用）。
	//
	// ASK（inspect 輸出解析）：採 `--format {{json .RepoDigests}}` 解析 JSON
	// 陣列再挑第一個合法 64-hex digest（空陣列可明確判別、錯誤訊息可控）。
	// 另一選項是 e2e 慣例 `{{index .RepoDigests 0}}` 純文字——空陣列時 Go
	// template 直接報錯，訊息不易分類。本地構建（classic store、未 push）
	// 的 RepoDigests 可能為空，此時判未通過並提示需 containerd image store
	// 或 push。
	digests, err := repoDigestsFn(ctx, bin, tag)
	if err != nil {
		return "", fmt.Sprintf("docker inspect %s 失敗：%s", tag, truncTail(err.Error()))
	}
	digest := pickRepoDigest(digests)
	if digest == "" {
		return "", fmt.Sprintf("%s 無可用 RepoDigests（本地構建映像僅能以 repo digest 定址；需 containerd image store 或 push 後重試）", tag)
	}

	if o.CachePath != "" {
		if err := recordImageFn(o.CachePath, ref, digest); err != nil {
			return "", fmt.Sprintf("images.json 記錄失敗（§17.10）：%v", err)
		}
	}
	note = fmt.Sprintf("%s 本地構建完成，digest %s 已記錄", shortRef(ref), shortRef(digest))
	// ADR 0002 決策三：每次 docker build（即使全快取命中）都會產生新的
	// manifest digest（config 時間戳）；manifest 原記 digest 與重建所得不同時，
	// 需重錄 manifest 後 prove 才能以 manifest digest 定址。
	if isDigestRef(ref) && digest != ref {
		note += "（注意：與 manifest 記載的 digest 不同，需重錄 manifest，見 docs/adr/0002 決策三）"
	}
	return note, ""
}

// buildTag 由映像參照與 pack 版本組出構建 tag。
//
// ASK：tag 形式採 <name>:<pack_version>（例 aegis-python-web:1.0.0；
// pack 的 Dockerfile 註解亦以版本為人類可讀 tag 慣例）。另一選項是固定
// ":doctor" tag（易與正式 tag 區分，但同一 pack 多版本會互相覆蓋）。
// name 段取 digest 前綴（packs.checkDigest 保證 name 段無 ":"）。
func buildTag(ref, version string) string {
	name := ref
	if i := strings.LastIndex(ref, "@sha256:"); i >= 0 {
		name = ref[:i]
	}
	if version == "" {
		version = "doctor"
	}
	return name + ":" + version
}

// isDigestRef 檢查映像參照為 <name>@sha256:<64hex> 形式（與
// orchestrator.isDigestImage 同一閉集判準；該函式未輸出，故在此重述）。
func isDigestRef(ref string) bool {
	i := strings.LastIndex(ref, "@sha256:")
	if i < 0 {
		return false
	}
	d := ref[i+len("@sha256:"):]
	if len(d) != 64 {
		return false
	}
	_, err := hex.DecodeString(d)
	return err == nil
}

// pickRepoDigest 自 docker inspect 的 RepoDigests 取第一個合法 digest 定址
// （"name@sha256:<64hex>" 形式）；無合法項回空字串。
func pickRepoDigest(digests []string) string {
	for _, d := range digests {
		if isDigestRef(d) {
			return d
		}
	}
	return ""
}

// shortRef 把長 digest 參照縮成顯示用短形（name@sha256:前 12 位）。
func shortRef(ref string) string {
	i := strings.LastIndex(ref, "@sha256:")
	if i < 0 || len(ref) <= i+len("@sha256:") {
		return ref
	}
	head := ref[:i+len("@sha256:")]
	d := ref[i+len("@sha256:"):]
	if len(d) > 12 {
		d = d[:12]
	}
	return head + d
}

// readImagesJSON 讀 §17.10 的 ~/.cache/aegis/images.json（{"images": {ref: digest}}）。
// 檔案不存在或格式不符回空 map（miss 收場，不炸呼叫端——與
// orchestrator.lookupImagesJSON 的容錯一致）。
//
// ASK：§17.10 文字說快取鍵為 `<pack_id>@<pack_version>`，但既有
// orchestrator.RecordImage／lookupImagesJSON 以「映像參照名」為鍵（policy
// compiler 第 3 階以此查詢）。/doctor 必須與 policy compiler 共用同一鍵序，
// 故採 orchestrator 的 ref 鍵序（否則記錄會查不到）。若要改為 pack_id@version
// 鍵，須一併改 orchestrator 的記錄／查詢兩端。
type imagesDoc struct {
	Images map[string]string `json:"images"`
}

func readImagesJSON(path string) map[string]string {
	m := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	var doc imagesDoc
	if err := json.Unmarshal(data, &doc); err != nil || doc.Images == nil {
		return m
	}
	return doc.Images
}

// ---- docker 輔助（§16：os/exec、capture stdout/stderr、不用 Docker SDK） ----

// dockerImageExists 以 `docker image inspect <ref>` 探測本機映像
// （exit 0 即存在；與 tests/e2e 的 imageExists 同一判準）。
func dockerImageExists(ctx context.Context, bin, ref string) bool {
	tctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	cmd := exec.CommandContext(tctx, bin, "image", "inspect", ref)
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	return cmd.Run() == nil
}

// dockerBuild 執行 `docker build -f image/Dockerfile -t <tag> .`，context 為
// pack 根目錄（cmd.Dir=packDir；COPY sandbox/、templates/ 需以 pack 根解析，
// docs/adr/0002 決策三）。輸出整併 capture，失敗時取尾段供診斷。
func dockerBuild(ctx context.Context, bin, dir, tag string) error {
	cleanup, observerDir, err := prepareObserverBinary(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
	cmd := exec.CommandContext(ctx, bin, "build", "--build-context", "observer-bin="+observerDir, "-f", filepath.Join("image", "Dockerfile"), "-t", tag, ".")
	cmd.Dir = dir
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("doctor: docker build %s 失敗：%s：%w", tag, truncTail(buf.String()), err)
	}
	return nil
}

// prepareObserverBinary injects the same static Go proxy into the pack build
// context. It is temporary and removed immediately after docker build.
func prepareObserverBinary(ctx context.Context) (func(), string, error) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		return func() {}, "", fmt.Errorf("doctor: 無法定位 observer proxy source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	dir, err := os.MkdirTemp("", "aegis-observer-bin-")
	if err != nil {
		return func() {}, "", fmt.Errorf("doctor: 建立 observer build context：%w", err)
	}
	out := filepath.Join(dir, "observer-proxy")
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-buildvcs=false", "-o", out, "./cmd/aegis-observer-proxy")
	cmd.Dir = root
	// The binary is copied into a Linux pack image.  Force the target OS so
	// running /doctor on macOS (or another host OS) never produces a host-format
	// executable that fails in the observer sidecar with exec format error.
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if output, err := cmd.CombinedOutput(); err != nil {
		_ = os.RemoveAll(dir)
		return func() {}, "", fmt.Errorf("doctor: observer proxy build 失敗：%s：%w", truncTail(string(output)), err)
	}
	return func() { _ = os.RemoveAll(dir) }, dir, nil
}

// dockerRepoDigests 以 `docker image inspect --format {{json .RepoDigests}} <ref>`
// 取 RepoDigests 陣列（JSON 解析；見 buildAndRecord 內的 ASK 註記）。
func dockerRepoDigests(ctx context.Context, bin, ref string) ([]string, error) {
	tctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	cmd := exec.CommandContext(tctx, bin, "image", "inspect", "--format", "{{json .RepoDigests}}", ref)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &outBuf, &errBuf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("doctor: docker image inspect %s 失敗：%s：%w", ref, truncTail(errBuf.String()), err)
	}
	var digests []string
	if err := json.Unmarshal(bytes.TrimSpace(outBuf.Bytes()), &digests); err != nil {
		return nil, fmt.Errorf("doctor: RepoDigests 解析失敗：%w", err)
	}
	return digests, nil
}

// ---- 檢查 4：provider 連通（§3.3：host 端一次極小呼叫） ----

// checkProviders 對每個 provider：
//
//   - 金鑰未解析（Resolve 錯誤或空金鑰）→ OK=false、detail 固定「金鑰未設定」
//     （永不回顯金鑰內容，§3.3 /provider list 慣例）。
//   - 金鑰可用 → 依 §3.2 閉集建 adapter，對 base_url 做一次極小呼叫
//     （單則明確的 harmless/OK 請求、無 tools、非串流）；任何錯誤 → OK=false，detail 取
//     截尾錯誤文字（出口處再做金鑰遮蔽）。
func checkProviders(ctx context.Context, o Options, secrets *[]string) []Check {
	names := make([]string, 0, len(o.Providers))
	for name := range o.Providers {
		names = append(names, name)
	}
	sort.Strings(names) // 確定性輸出

	out := []Check{}
	for _, name := range names {
		p := o.Providers[name]
		c := Check{Name: "provider:" + name}

		if o.ResolveKey == nil {
			// ASK：ResolveKey=nil（未注入金鑰解析）時的呈現。採 (a) 仍列出
			// 該 provider、標記通過並註明略過——/doctor 的項目清單保持完整，
			// 呼叫端（CLI 層）看得出「沒測」與「通過」的差別。選項 (b)：
			// 完全省略該 provider 的檢查項（清單變短，但使用者可能誤以為
			// 沒有該 provider）。
			c.OK = true
			c.Detail = "略過連通測試：未提供金鑰解析（ResolveKey=nil）"
			out = append(out, c)
			continue
		}

		key, source, err := o.ResolveKey(name)
		if err != nil || key == "" {
			// 解析失敗一律收斂為「金鑰未設定」：detail 永不攜帶金鑰內容，
			// 也不攜帶可能含敏感內容的內部錯誤細節（§23-6）。
			_ = source // source 僅供 /status 顯示（§3.3）；/doctor 不需要
			c.OK = false
			c.Detail = "金鑰未設定"
			out = append(out, c)
			continue
		}
		*secrets = append(*secrets, key)

		ad, err := newAdapterFn(name, p, key)
		if err != nil {
			c.OK = false
			c.Detail = trunc(err.Error())
			out = append(out, c)
			continue
		}

		model, role := probeModelForProvider(name, o.Models)
		if len(o.Models) == 0 { // 相容純套件呼叫；有路由時正式 CLI 一律傳入。
			model, role = probeModelFn(credentials.ProviderType(p.Type)), "probe-default"
		}
		if model == "" && len(o.Models) > 0 {
			c.OK = false
			c.Detail = "未被任何角色路由引用，無法決定連通測試模型"
			out = append(out, c)
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, connectTimeoutOf(o))
		requestRole := llm.RoleRecon
		if role != "probe-default" {
			requestRole = llm.Role(role)
		}
		req := llm.ChatRequest{
			Role:     requestRole,
			Model:    model,
			Messages: []llm.Message{{Role: "user", Content: []llm.ContentBlock{{Type: "text", Text: "This is a harmless API connectivity check. Reply with exactly OK."}}}},
			// Leave enough output budget for reasoning-model compatibility.
			MaxTokens: probeMaxTokens,
			Stream:    false, // 非串流；無 tools（§3.3：極小呼叫）
		}
		resp, err := ad.Chat(cctx, req)
		cancel()

		if err != nil {
			c.OK = false
			c.Detail = trunc(err.Error()) // 出口統一遮蔽金鑰（Run 尾端）
		} else if resp.StopReason == llm.StopRefusal {
			c.OK = false
			c.Detail = fmt.Sprintf("API 已連通，但模型未提供可用回覆（role=%s，requested_model=%s，actual_model=%s，category=%s）；empty_response 請改用支援 Chat Completions 文字輸出的模型，其他 category 請更換未拒絕資安用途的模型", role, model, resp.Model, resp.RefusalCategory)
		} else if model != "" && resp.Model != "" && resp.Model != model {
			c.OK = false
			c.Detail = fmt.Sprintf("模型路由不一致（role=%s，requested_model=%s，actual_model=%s，stop_reason=%s）", role, model, resp.Model, resp.StopReason)
		} else {
			c.OK = true
			c.Detail = fmt.Sprintf("連通正常（type=%s，role=%s，requested_model=%s，actual_model=%s，stop_reason=%s）", p.Type, role, model, resp.Model, resp.StopReason)
		}
		out = append(out, c)
	}
	return out
}

func probeModelForProvider(provider string, models map[string]string) (string, string) {
	for _, role := range []string{settings.RoleRecon, settings.RoleReviewer, settings.RoleTriager, settings.RoleProver, settings.RoleReporter} {
		ref := models[role]
		name, id, ok := strings.Cut(ref, "/")
		if !ok || name != provider || id == "" {
			continue
		}
		return id, role
	}
	return "", ""
}

// newAdapter 依 §3.2 閉集建構 adapter；BaseURL 交由 adapter 注入
// （anthropic 可空 → 官方端點；openai-compat 必填，§3.3 /provider add）。
func newAdapter(name string, p settings.Provider, key string) (llm.Adapter, error) {
	switch credentials.ProviderType(p.Type) {
	case credentials.ProviderTypeAnthropic:
		return llm.NewAnthropic(key, p.BaseURL), nil
	case credentials.ProviderTypeOpenAICompat:
		if p.BaseURL == "" {
			return nil, fmt.Errorf("doctor: provider %q 為 openai-compat 但 base_url 未設定（§3.3）", name)
		}
		return llm.NewOpenAICompat(name, p.BaseURL, key, probeModelFn(credentials.ProviderTypeOpenAICompat)), nil
	default:
		return nil, fmt.Errorf("doctor: provider %q 類型 %q 不在閉集（anthropic｜openai-compat，§3.2）", name, p.Type)
	}
}

// 探測用 model id（見 checkProviders 內 ASK 註記）。
const (
	anthropicProbeModel    = "claude-haiku-4-5" // §4 角色表 recon 欄（最便宜）
	openAICompatProbeModel = ""                 // 無通用預設；空值交由端點決定
)

func probeModel(pt credentials.ProviderType) string {
	switch pt {
	case credentials.ProviderTypeAnthropic:
		return anthropicProbeModel
	default:
		return openAICompatProbeModel
	}
}

// ---- 測試縫（unexported package vars） ----
//
// 正式路徑即各真實實作；單元測試以 stub 替換（存檔原值、t.Cleanup 還原），
// 使 docker／pack 載入／adapter 皆可在無 docker、無網路下測試（§23：測試僅
// 標準庫 testing；httptest 用於 provider 連通）。
var (
	dockerVersionFn  = dockerVersion
	lookPathFn       = exec.LookPath
	loadPackFn       = loadPack
	imageExistsFn    = dockerImageExists
	dockerBuildFn    = dockerBuild
	repoDigestsFn    = dockerRepoDigests
	readImagesJSONFn = readImagesJSON
	recordImageFn    = orchestrator.RecordImage
	newAdapterFn     = newAdapter
	probeModelFn     = probeModel
)
