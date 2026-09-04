// Package orchestrator 串接 policy → sandbox → oracles → evidence/journal（SPEC §5.2、§17）。
// 本檔是「整合縫」：packs→policy adapter、映像解析（§17.10）、RunRequest→RunSpec 轉換。
// 容器請求永遠由 policy compiler 組裝，orchestrator 只做資料翻譯與執行（§23-2）。
package orchestrator

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aegis-dev/aegis/internal/evidence"
	"github.com/aegis-dev/aegis/internal/orchestrator/policy"
	"github.com/aegis-dev/aegis/internal/oracles"
	"github.com/aegis-dev/aegis/internal/packs"
	"github.com/aegis-dev/aegis/internal/sandbox"
)

// ---- packs → policy adapter（§17.9-1：policy 透過 PackView 解析 manifest） ----

// packAdapter 把 *packs.Pack 轉接成 policy.PackView。
// Template 條目的 image 欄位依 §17.10 解析序取 digest：
// manifest 已記 digest → 直接用；否則視為映像參照名，查 manifest.images，再查本地 images.json。
type packAdapter struct {
	pack      *packs.Pack
	cachePath string // ~/.cache/aegis/images.json；空值表示不查本地快取
}

// NewPackView 回傳滿足 policy.PackView 的 adapter。
func NewPackView(pack *packs.Pack, cachePath string) policy.PackView {
	return &packAdapter{pack: pack, cachePath: cachePath}
}

func (a *packAdapter) Template(id string) (*policy.Template, error) {
	t, err := a.pack.Template(id)
	if err != nil {
		return nil, err
	}
	img, err := a.resolveImage(t.Image)
	if err != nil {
		return nil, fmt.Errorf("orchestrator: template %q: %w", id, err)
	}
	return &policy.Template{
		TemplateID:   t.TemplateID,
		Family:       t.Family,
		RunMode:      t.RunMode,
		AllowedFiles: t.AllowedFiles,
		ServiceCmd:   t.ServiceCmd,
		ServicePort:  t.ServicePort,
		WaitFor:      t.WaitFor,
		Image:        img,
	}, nil
}

func (a *packAdapter) Oracle(id string) (*policy.Oracle, error) {
	o, err := a.pack.Oracle(id)
	if err != nil {
		return nil, err
	}
	return &policy.Oracle{OracleID: o.OracleID, Family: o.Family, Touch: o.Touch}, nil
}

// resolveImage 依 §17.10 映像解析序：digest → manifest.images → 本地 images.json。
// 三步皆無 → error（呼叫端歸 ENV_ERROR；不自動構建，§17.10）。
func (a *packAdapter) resolveImage(ref string) (string, error) {
	if isDigestImage(ref) {
		return ref, nil
	}
	if d, ok := a.pack.Manifest.Images[ref]; ok && isDigestImage(d) {
		return d, nil
	}
	if a.cachePath != "" && ref != "" {
		if d, ok := lookupImagesJSON(a.cachePath, ref); ok && isDigestImage(d) {
			return d, nil
		}
	}
	return "", fmt.Errorf("映像 %q 無 digest 可用（§17.10 解析序用盡；請以 /doctor 本地構建後重錄 digest）", ref)
}

// isDigestImage 檢查映像參照為 <name>@sha256:<64hex> 形式。
func isDigestImage(ref string) bool {
	idx := strings.LastIndex(ref, "@sha256:")
	if idx < 0 {
		return false
	}
	d := ref[idx+len("@sha256:"):]
	return len(d) == 64 && !strings.ContainsAny(d, "ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ")
}

// lookupImagesJSON 讀 ~/.cache/aegis/images.json（映像參照名 → digest）。
// 檔案不存在或格式不符回 (\"\", false)——§17.10 的最後一階以 miss 收場，不炸呼叫端。
func lookupImagesJSON(path, ref string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	m, err := evidence.Decode(data)
	if err != nil {
		return "", false
	}
	images, ok := m["images"].(map[string]any)
	if !ok {
		return "", false
	}
	v, _ := images[ref].(string)
	return v, v != ""
}

// RecordImage 把「映像參照名 → digest」寫入 ~/.cache/aegis/images.json
//（§17.10 的本地記錄；由 /doctor 與 pack replay 測試在建置後呼叫）。
func RecordImage(cachePath, ref, digest string) error {
	if ref == "" || !isDigestImage(digest) {
		return fmt.Errorf("orchestrator: RecordImage 參數非法（ref=%q digest=%q）", ref, digest)
	}
	doc := map[string]any{"images": map[string]any{}}
	if data, err := os.ReadFile(cachePath); err == nil {
		if m, derr := evidence.Decode(data); derr == nil {
			if imgs, ok := m["images"].(map[string]any); ok {
				doc["images"] = imgs
			}
		}
	}
	doc["images"].(map[string]any)[ref] = digest
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		return fmt.Errorf("orchestrator: 建立快取目錄: %w", err)
	}
	b, err := evidence.CanonicalBytes(doc)
	if err != nil {
		return err
	}
	if err := os.WriteFile(cachePath, b, 0o644); err != nil {
		return fmt.Errorf("orchestrator: 寫入 images.json: %w", err)
	}
	return nil
}

// ---- runner nonce（§17.2：nonce 由 runner 產生、prover 事前未知） ----

// NewNonce 以 crypto/rand 產生 16 byte 的 32 hex 字元 nonce。
func NewNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("orchestrator: 產生 nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// ---- AST 靜態解析（§17.9-2 的注入實作） ----

// ASTCheckStatic 是 §17.9-2 target_symbol 靜態解析的 v1 實作：
// 以符號路徑（module[.Class][.method]）對 snapshot 的 .py 檔做靜態存在性檢查——
// module 對應檔案路徑、其餘段以 "class X"／"def X"／"X =" 文字層解析。
// 誠實邊界：這是文字層而非完整 AST；升級為 ast_helper（pack capabilities）時
// 保留同簽名替換（M0c），呼叫端契約不變。
func ASTCheck(snapshotDir, targetSymbol string) error {
	if snapshotDir == "" {
		return fmt.Errorf("orchestrator: ASTCheck 的 snapshotDir 為空")
	}
	if targetSymbol == "" {
		return fmt.Errorf("orchestrator: ASTCheck 的 targetSymbol 為空")
	}
	segs := strings.Split(targetSymbol, ".")
	for _, s := range segs {
		if s == "" {
			return fmt.Errorf("orchestrator: targetSymbol 含空段：%q", targetSymbol)
		}
	}
	modulePath := filepath.Join(snapshotDir, filepath.FromSlash(strings.Join(segs[:1], "/"))+".py")
	// module 段允許 package 形式（pkg/mod.py）；v1 先解析頂層 module 檔。
	if _, err := os.Stat(modulePath); err != nil {
		return fmt.Errorf("orchestrator: module %q 在 snapshot 中不存在", segs[0])
	}
	data, err := os.ReadFile(modulePath)
	if err != nil {
		return fmt.Errorf("orchestrator: 讀取 %s: %w", modulePath, err)
	}
	text := string(data)
	for _, seg := range segs[1:] {
		patterns := []string{
			"class " + seg,
			"def " + seg,
			seg + " =",
		}
		found := false
		for _, p := range patterns {
			if strings.Contains(text, p) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("orchestrator: 符號 %q 在 module %q 中未靜態解析到", seg, segs[0])
		}
	}
	return nil
}

// ---- RunRequest → RunSpec（orchestrator 只翻譯、不決策；§23-2） ----

// jsonStr／jsonInt 從 RunRequest map 取值（map 由 policy assemble 組出，
// 內容已過 schema 驗證；此處防禦性轉型，缺值即錯）。
func reqStr(rr map[string]any, key string) (string, error) {
	v, ok := rr[key].(string)
	if !ok || v == "" {
		return "", fmt.Errorf("orchestrator: RunRequest.%s 缺值或非字串", key)
	}
	return v, nil
}

// RunRequestToRunSpec 把 policy 組出的 RunRequest 翻譯成 sandbox.RunSpec。
// seccomp 路徑由 pack 提供（RunRequest 不含 host 路徑）；snapshotDir 來自 orchestrator 持有的快照。
func RunRequestToRunSpec(rr map[string]any, snapshotID, seccompPath, snapshotDir string) (sandbox.RunSpec, error) {
	runID, err := reqStr(rr, "run_id")
	if err != nil {
		return sandbox.RunSpec{}, err
	}
	image, err := reqStr(rr, "image")
	if err != nil {
		return sandbox.RunSpec{}, err
	}
	network, err := reqStr(rr, "network")
	if err != nil {
		return sandbox.RunSpec{}, err
	}
	rawCmd, ok := rr["cmd"].([]any)
	if !ok || len(rawCmd) == 0 {
		return sandbox.RunSpec{}, fmt.Errorf("orchestrator: RunRequest.cmd 缺值或非陣列")
	}
	cmd := make([]string, 0, len(rawCmd))
	for _, c := range rawCmd {
		s, ok := c.(string)
		if !ok || s == "" {
			return sandbox.RunSpec{}, fmt.Errorf("orchestrator: RunRequest.cmd 含非字串或空項")
		}
		cmd = append(cmd, s)
	}
	n, err := reqInt(rr, "timeout_sec")
	if err != nil {
		return sandbox.RunSpec{}, err
	}
	env, err := ServiceEnv(rr)
	if err != nil {
		return sandbox.RunSpec{}, err
	}
	return sandbox.RunSpec{
		RunID:      runID,
		SnapshotID: snapshotID,
		Image:      image,
		Cmd:        cmd,
		Network:    network,
		Seccomp:    seccompPath,
		TimeoutSec: n,
		Env:        env,
	}, nil
}

// reqInt 取 RunRequest 的整數欄位（json.Number 或 int64）。
func reqInt(rr map[string]any, key string) (int, error) {
	switch v := rr[key].(type) {
	case int64:
		return int(v), nil
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return 0, fmt.Errorf("orchestrator: RunRequest.%s 非整數：%v", key, err)
		}
		return int(n), nil
	}
	return 0, fmt.Errorf("orchestrator: RunRequest.%s 缺值或非整數", key)
}

// ServiceEnv 把 RunRequest.service 翻譯成 entrypoint 契約環境變數（§17.1）。
// wait_for 形如 "GET /healthz" → AEGIS_HEALTH_PATH=/healthz。
func ServiceEnv(rr map[string]any) ([]string, error) {
	svc, ok := rr["service"].(map[string]any)
	if !ok {
		return nil, nil // 無 service（純 exploit 容器）不接線
	}
	cmd, ok := svc["cmd"].(string)
	if !ok || cmd == "" {
		return nil, fmt.Errorf("orchestrator: RunRequest.service.cmd 缺值")
	}
	env := []string{"AEGIS_SERVICE_CMD=" + cmd}
	if p, err := svcInt(svc, "port"); err == nil && p > 0 {
		env = append(env, fmt.Sprintf("AEGIS_SERVICE_PORT=%d", p))
	}
	if wf, ok := svc["wait_for"].(string); ok {
		path := parseWaitFor(wf)
		if path != "" {
			env = append(env, "AEGIS_HEALTH_PATH="+path)
		}
	}
	return env, nil
}

// svcInt 取 service 子物件的整數欄位。
func svcInt(svc map[string]any, key string) (int, error) {
	switch v := svc[key].(type) {
	case int64:
		return int(v), nil
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return 0, err
		}
		return int(n), nil
	}
	return 0, fmt.Errorf("orchestrator: service.%s 缺值或非整數", key)
}

// parseWaitFor 從 "GET /healthz" 取路徑段（無路徑段回空）。
func parseWaitFor(wf string) string {
	fields := strings.Fields(wf)
	if len(fields) >= 2 && strings.HasPrefix(fields[1], "/") {
		return fields[1]
	}
	if len(fields) == 1 && strings.HasPrefix(fields[0], "/") {
		return fields[0]
	}
	return ""
}

// ---- oracles rule 組裝（pack 純資料 → checker Rule） ----

// OracleRule 把 pack 的 oracle 條目轉成 checker 的 Rule（純資料轉換，無直譯器，§17.3）。
func OracleRule(o *packs.OracleEntry) (oracles.Rule, error) {
	r := oracles.Rule{
		OracleID: o.OracleID,
		Family:   o.Family,
		Rule: oracles.Condition{
			Artifact:  o.Rule.Artifact,
			Kind:      oracles.ConditionKind(o.Rule.Kind),
			Field:     o.Rule.Field,
			Threshold: o.Rule.Threshold,
		},
	}
	if o.Touch != nil {
		r.Touch = *o.Touch
	}
	// 條件完整性檢查（checker 的 validate 為未導出；此處以等價規則把關，
	// Check 本身執行前仍會再驗一次）。
	if r.Rule.Artifact == "" || strings.Contains(r.Rule.Artifact, "/") {
		return oracles.Rule{}, fmt.Errorf("orchestrator: oracle %q 的 rule.artifact 非法：%q", o.OracleID, o.Rule.Artifact)
	}
	if !r.Rule.Kind.Valid() {
		return oracles.Rule{}, fmt.Errorf("orchestrator: oracle %q 的 rule.kind 非閉集成員：%q", o.OracleID, o.Rule.Kind)
	}
	return r, nil
}

// SeccompPath 回傳 pack 的 seccomp profile host 路徑（§23-8：缺檔即拒跑）。
func SeccompPath(packDir string) (string, error) {
	p := filepath.Join(packDir, "sandbox", "seccomp.json")
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("orchestrator: pack seccomp profile 不存在 %s: %w", p, err)
	}
	return p, nil
}