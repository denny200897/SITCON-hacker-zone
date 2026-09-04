// Package packs 實作 versioned Pack ABI loader（SPEC §6.4）。
//
// pack 是有版本契約的模組：core 載入前逐項驗證 manifest——schema 驗證、
// ABI 版本協商、runner 能力、內容 sha256 對照、oracle paired touch rule
//（§17.3）、trust level、映像 digest 形式——任一不匹配即拒載，
// 不做部分載入（§6.4「不匹配即拒載」）。
//
// 載入後的 Pack 是唯讀表：core 只讀 manifest 資料（模板、oracle 規則、
// sink→impact 映射、detector 路徑），永不執行 pack 內的可執行鉤子。
package packs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aegis-dev/aegis/internal/schemav"
)

// CorePackABI 是 core 支援的 pack manifest ABI 版本。pack manifest 的
// schema_version 必須與此一致，否則拒載（§6.4 schema_version 協商）。
const CorePackABI = 1

// CoreCapabilities 是 core 支援的 runner 能力集合（§6.4）。
// headless_browser 尚未支援；pack 宣告 core 沒有的能力即拒載。
var CoreCapabilities = []string{"internal_network", "deps_helper", "ast_helper"}

// 拒載分類 sentinel（以 errors.Is 判別）；實際錯誤一律以
// fmt.Errorf("packs: ...: %w") 包裝回傳。
var (
	// ErrManifest 表示 manifest 缺漏、不符 pack_manifest schema 或 id 重複。
	ErrManifest = errors.New("packs: manifest 不合法")
	// ErrABI 表示 pack 的 schema_version 與 core 支援的 ABI 版本不匹配。
	ErrABI = errors.New("packs: ABI 版本不匹配")
	// ErrHash 表示 manifest 記載的 sha256 與檔案／內容實際值不符（§6.4）。
	ErrHash = errors.New("packs: 內容 hash 不符")
	// ErrTouch 表示 oracle 家族的 paired touch rule 缺漏（§17.3）。
	ErrTouch = errors.New("packs: oracle touch 缺漏")
	// ErrTrust 表示 community pack 未明示啟用（allowCommunity=false）。
	ErrTrust = errors.New("packs: community pack 未啟用")
	// ErrCapability 表示 pack 宣告了 core 不支援的能力（§6.4）。
	ErrCapability = errors.New("packs: 不支援的能力")
	// ErrImage 表示映像未以 digest 形式記載（§6.3、§7.1：可變 tag 一律拒絕）。
	ErrImage = errors.New("packs: 映像非 digest 形式")
)

// ---- Manifest 型別（欄位對齊 schemas/pack_manifest.schema.json） ----

// DetectorEntry 是宣告式偵測規則（semgrep YAML／regex spec）條目。
type DetectorEntry struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
}

// TemplateEntry 是 witness／direct 共用的模板條目。
type TemplateEntry struct {
	TemplateID   string   `json:"template_id"`
	Family       string   `json:"family"`
	RunMode      string   `json:"run_mode"` // witness | direct | both
	Path         string   `json:"path"`
	SHA256       string   `json:"sha256"`
	AllowedFiles []string `json:"allowed_files"`
	ServiceCmd   string   `json:"service_cmd,omitempty"`
	ServicePort  int      `json:"service_port,omitempty"`
	WaitFor      string   `json:"wait_for,omitempty"`
	Image        string   `json:"image"` // 必為 name@sha256:<hex> digest 形式
}

// RuleEntry 是 oracle 的參數化判定規則（條件種類是 checker 內的封閉 enum，
// rule 不得帶可執行碼，§17.3）。
type RuleEntry struct {
	Artifact  string `json:"artifact"`
	Kind      string `json:"kind"`
	Field     string `json:"field,omitempty"`
	Threshold int    `json:"threshold,omitempty"`
}

// OracleEntry 是機械化判定規則條目。Touch 為 paired touch rule 的
// oracle_id；nil 表示本條即是 touch rule（家族內恰一條，§17.3）。
type OracleEntry struct {
	OracleID string    `json:"oracle_id"`
	Family   string    `json:"family"`
	Touch    *string   `json:"touch"`
	Rule     RuleEntry `json:"rule"`
	SHA256   string    `json:"sha256"`
}

// PayloadEntry 是 canary 化良性探測載荷（內容內嵌於 manifest）。
type PayloadEntry struct {
	ID      string `json:"id"`
	Family  string `json:"family"`
	Kind    string `json:"kind"` // benign | canary
	Content string `json:"content"`
	SHA256  string `json:"sha256"`
}

// SinkTypeEntry 是 sink type → impact 映射（§20.2；core 只讀表，
// 數值由 pack 提供，新 pack 擴家族不用改 core）。
type SinkTypeEntry struct {
	Type   string `json:"type"`
	Family string `json:"family"`
	Impact string `json:"impact"` // high | medium | low
}

// TestEntry 是 pack 自帶 fixture 測試（含 replay；CI 強制執行，§6.4）。
type TestEntry struct {
	Name string `json:"name"`
	Kind string `json:"kind"` // replay | detector | oracle
}

// Manifest 對應 schemas/pack_manifest.schema.json 的全部欄位。
type Manifest struct {
	PackID        string            `json:"pack_id"`
	Version       string            `json:"version"`
	SchemaVersion int               `json:"schema_version"`
	Capabilities  []string          `json:"capabilities"`
	Detectors     []DetectorEntry   `json:"detectors"`
	Templates     []TemplateEntry   `json:"templates"`
	Oracles       []OracleEntry     `json:"oracles"`
	Payloads      []PayloadEntry    `json:"payloads,omitempty"`
	Images        map[string]string `json:"images,omitempty"`
	SinkTypes     []SinkTypeEntry   `json:"sink_types"`
	TrustLevel    string            `json:"trust_level"` // bundled | community
	Tests         []TestEntry       `json:"tests,omitempty"`
}

// Pack 是驗證通過的已載入 pack（唯讀表）。
type Pack struct {
	Dir      string
	Manifest *Manifest

	templates map[string]*TemplateEntry
	oracles   map[string]*OracleEntry
	impacts   map[string]string // sink type → impact
}

// Template 以 template_id 取得模板條目；不存在即回傳錯誤。
func (p *Pack) Template(id string) (*TemplateEntry, error) {
	t, ok := p.templates[id]
	if !ok {
		return nil, fmt.Errorf("packs: template %q 不存在於 pack %q", id, p.Manifest.PackID)
	}
	return t, nil
}

// Oracle 以 oracle_id 取得 oracle 條目；不存在即回傳錯誤。
func (p *Pack) Oracle(id string) (*OracleEntry, error) {
	o, ok := p.oracles[id]
	if !ok {
		return nil, fmt.Errorf("packs: oracle %q 不存在於 pack %q", id, p.Manifest.PackID)
	}
	return o, nil
}

// Impact 回傳 sink type 對應的 impact（§20.2 映射表來自 pack manifest，
// core 只讀）；查無此 sink type 時第二個回傳值為 false。
func (p *Pack) Impact(sinkType string) (string, bool) {
	impact, ok := p.impacts[sinkType]
	return impact, ok
}

// DetectorPaths 回傳 semgrep 規則檔清單（manifest 順序）。
func (p *Pack) DetectorPaths() []string {
	paths := make([]string, 0, len(p.Manifest.Detectors))
	for _, d := range p.Manifest.Detectors {
		paths = append(paths, d.Path)
	}
	return paths
}

// OraclePath 回傳 oracle 檔在 pack 內的固定路徑（慣例：oracles/<oracle_id>.json，
// oracle_id 中的 "/" 以 "_" 取代——manifest schema 不記 oracle 檔路徑，
// 以此確定性行為對照 sha256）。
func OraclePath(oracleID string) string {
	return filepath.Join("oracles", strings.ReplaceAll(oracleID, "/", "_")+".json")
}

// ---- 載入 ----

// Load 以 packDir 載入並驗證 pack，schemas 目錄自動搜尋（自 cwd 向上找含
// schemas/pack_manifest.schema.json 的目錄）。allowCommunity=false 時
// trust_level=community 的 pack 拒載。正式呼叫端建議改用 LoadWithSchemas
// 明示 schemas 路徑。
func Load(packDir string, allowCommunity bool) (*Pack, error) {
	dir, err := findSchemasDir()
	if err != nil {
		return nil, err
	}
	return LoadWithSchemas(packDir, dir, allowCommunity)
}

// LoadWithSchemas 以明示的 schemas 目錄載入並驗證 pack。任一驗證失敗即
// 回傳錯誤（errors.Is 可判別拒載分類），不回傳部分載入的 Pack。
func LoadWithSchemas(packDir, schemasDir string, allowCommunity bool) (*Pack, error) {
	if packDir == "" {
		return nil, fmt.Errorf("packs: packDir 不可為空")
	}
	manifestPath := filepath.Join(packDir, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("packs: 讀取 %s: %w", manifestPath, err)
	}

	// 1. schema 驗證（§5：schema 是唯一機讀真源）。
	reg := schemav.New()
	if err := reg.LoadDir(schemasDir); err != nil {
		return nil, fmt.Errorf("packs: 載入 schemas 目錄 %s: %w", schemasDir, err)
	}
	if err := reg.Validate("pack_manifest", data); err != nil {
		return nil, fmt.Errorf("packs: manifest 驗證失敗（拒載）: %w", errors.Join(ErrManifest, err))
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("packs: 解析 manifest: %w", errors.Join(ErrManifest, err))
	}

	// 2. ABI 版本協商（§6.4）：不匹配即拒載。
	if m.SchemaVersion != CorePackABI {
		return nil, fmt.Errorf("packs: %w：pack schema_version=%d，core 支援 %d", ErrABI, m.SchemaVersion, CorePackABI)
	}

	// 3. runner 能力檢查（§6.4）：pack 要求 core 沒有的能力即拒載。
	supported := map[string]bool{}
	for _, c := range CoreCapabilities {
		supported[c] = true
	}
	for _, c := range m.Capabilities {
		if !supported[c] {
			return nil, fmt.Errorf("packs: %w：%q（pack_id=%q）", ErrCapability, c, m.PackID)
		}
	}

	// 4. trust level（§6.4）：community 需明示啟用並警告。
	if m.TrustLevel == "community" && !allowCommunity {
		return nil, fmt.Errorf("packs: %w：pack_id=%q 需以 allowCommunity 明示啟用", ErrTrust, m.PackID)
	}

	// 5. id 唯一性（查表語意前提）。
	if err := checkUniqueIDs(&m); err != nil {
		return nil, err
	}

	// 6. 逐個驗 hash（§6.4）：templates 檔、oracle 檔、payloads 內嵌內容。
	if err := verifyHashes(packDir, &m); err != nil {
		return nil, err
	}

	// 7. 映像一律 digest（§6.3、§7.1：可變 tag 一律拒絕）。
	if err := verifyImages(&m); err != nil {
		return nil, err
	}

	// 8. oracle paired touch rule（§17.3）：touch 缺漏為拒載條件。
	if err := validateTouch(m.Oracles); err != nil {
		return nil, err
	}

	p := &Pack{Dir: packDir, Manifest: &m,
		templates: map[string]*TemplateEntry{},
		oracles:   map[string]*OracleEntry{},
		impacts:   map[string]string{},
	}
	for i := range m.Templates {
		p.templates[m.Templates[i].TemplateID] = &m.Templates[i]
	}
	for i := range m.Oracles {
		p.oracles[m.Oracles[i].OracleID] = &m.Oracles[i]
	}
	for _, st := range m.SinkTypes {
		p.impacts[st.Type] = st.Impact
	}
	return p, nil
}

// ---- 驗證輔助 ----

// checkUniqueIDs 檢查 template_id／oracle_id／sink type 不重複。
func checkUniqueIDs(m *Manifest) error {
	seenTpl := map[string]bool{}
	for _, t := range m.Templates {
		if seenTpl[t.TemplateID] {
			return fmt.Errorf("packs: %w：重複的 template_id %q", ErrManifest, t.TemplateID)
		}
		seenTpl[t.TemplateID] = true
	}
	seenOracle := map[string]bool{}
	for _, o := range m.Oracles {
		if seenOracle[o.OracleID] {
			return fmt.Errorf("packs: %w：重複的 oracle_id %q", ErrManifest, o.OracleID)
		}
		seenOracle[o.OracleID] = true
	}
	seenSink := map[string]bool{}
	for _, st := range m.SinkTypes {
		if seenSink[st.Type] {
			return fmt.Errorf("packs: %w：重複的 sink type %q", ErrManifest, st.Type)
		}
		seenSink[st.Type] = true
	}
	return nil
}

// safeJoin 將 pack 內相對路徑 join 到 packDir，拒絕絕對路徑與越出 packDir
// 的路徑（§7.1 掛載來源 canonicalization 的 pack 側對應）。
func safeJoin(packDir, rel string) (string, error) {
	if rel == "" {
		return "", fmt.Errorf("packs: 空 path")
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("packs: path %q 不可為絕對路徑", rel)
	}
	clean := filepath.Clean(rel)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("packs: path %q 越出 pack 目錄", rel)
	}
	return filepath.Join(packDir, clean), nil
}

// verifyHashes 逐個驗證 templates[].path 檔、detectors[].path 檔（有記載
// sha256 時）、oracles 對應檔與 payloads[].content 的 sha256（§6.4）。
func verifyHashes(packDir string, m *Manifest) error {
	for _, t := range m.Templates {
		path, err := safeJoin(packDir, t.Path)
		if err != nil {
			return fmt.Errorf("packs: template %q: %w", t.TemplateID, err)
		}
		if err := verifyFileHash(path, t.SHA256); err != nil {
			return fmt.Errorf("packs: template %q: %w", t.TemplateID, err)
		}
	}
	for _, d := range m.Detectors {
		if d.SHA256 == "" {
			continue // schema 未強制 detector 記載 hash；有記載才驗
		}
		path, err := safeJoin(packDir, d.Path)
		if err != nil {
			return fmt.Errorf("packs: detector %q: %w", d.ID, err)
		}
		if err := verifyFileHash(path, d.SHA256); err != nil {
			return fmt.Errorf("packs: detector %q: %w", d.ID, err)
		}
	}
	for _, o := range m.Oracles {
		path, err := safeJoin(packDir, OraclePath(o.OracleID))
		if err != nil {
			return fmt.Errorf("packs: oracle %q: %w", o.OracleID, err)
		}
		if err := verifyFileHash(path, o.SHA256); err != nil {
			return fmt.Errorf("packs: oracle %q: %w", o.OracleID, err)
		}
	}
	for _, pl := range m.Payloads {
		if err := verifyBytesHash([]byte(pl.Content), pl.SHA256); err != nil {
			return fmt.Errorf("packs: payload %q: %w", pl.ID, err)
		}
	}
	return nil
}

// verifyFileHash 比對檔案內容的 sha256 與記載值；不符即拒載（§6.4）。
func verifyFileHash(path, want string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("packs: %w：讀取 %s: %v", ErrHash, path, err)
	}
	return verifyBytesHash(data, want)
}

func verifyBytesHash(data []byte, want string) error {
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if got != strings.ToLower(want) {
		return fmt.Errorf("packs: %w：sha256 應為 %s，實得 %s", ErrHash, want, got)
	}
	return nil
}

// verifyImages 檢查所有映像記載（templates[].image 與 images 表）皆為
// name@sha256:<hex> digest 形式；可變 tag 一律拒絕（§6.3、§7.1）。
func verifyImages(m *Manifest) error {
	for i := range m.Templates {
		if err := checkDigest(m.Templates[i].Image); err != nil {
			return fmt.Errorf("packs: template %q: %w", m.Templates[i].TemplateID, err)
		}
	}
	for name, image := range m.Images {
		if err := checkDigest(image); err != nil {
			return fmt.Errorf("packs: images[%q]: %w", name, err)
		}
	}
	return nil
}

// checkDigest 驗證映像參照為 digest 形式（名稱段不含 tag 的 ":"）。
func checkDigest(image string) error {
	idx := strings.LastIndex(image, "@sha256:")
	if idx < 0 {
		return fmt.Errorf("packs: %w：%q 未含 @sha256: digest", ErrImage, image)
	}
	name, digest := image[:idx], image[idx+len("@sha256:"):]
	if name == "" {
		return fmt.Errorf("packs: %w：%q 缺映像名稱", ErrImage, image)
	}
	if strings.Contains(name, ":") {
		return fmt.Errorf("packs: %w：%q 含可變 tag（名稱段不得有 \":\"）", ErrImage, image)
	}
	if _, err := hex.DecodeString(digest); err != nil || len(digest) != 64 {
		return fmt.Errorf("packs: %w：%q 的 digest 非 64 位 hex", ErrImage, image)
	}
	return nil
}

// validateTouch 檢查每個 oracle 家族必附 paired touch rule（§17.3 簡化判定）：
// 同 family 恰有一條 touch==null 的 rule、至少一條被 touch 引用的 rule，
// 且每個非 null 的 touch 必須指向同 family 存在的 oracle_id。
func validateTouch(oracles []OracleEntry) error {
	byFamily := map[string][]*OracleEntry{}
	for i := range oracles {
		o := &oracles[i]
		byFamily[o.Family] = append(byFamily[o.Family], o)
	}
	for family, group := range byFamily {
		bases := 0 // touch==null 的 rule（touch rule 本體）
		refs := 0  // 被 touch 引用的 rule
		for _, o := range group {
			if o.Touch == nil {
				bases++
				continue
			}
			refs++
			target := *o.Touch
			found := false
			for _, t := range group {
				if t.OracleID == target {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("packs: %w：family %q 的 oracle %q touch 指向同 family 不存在的 oracle_id %q",
					ErrTouch, family, o.OracleID, target)
			}
		}
		if bases != 1 {
			return fmt.Errorf("packs: %w：family %q 必須恰有一條 touch==null 的 rule，實得 %d", ErrTouch, family, bases)
		}
		if refs < 1 {
			return fmt.Errorf("packs: %w：family %q 缺少被 touch 引用的 rule（§17.3 paired touch）", ErrTouch, family)
		}
	}
	return nil
}

// findSchemasDir 自 cwd 向上搜尋含 schemas/pack_manifest.schema.json 的
// 目錄（開發期慣例；正式呼叫端以 LoadWithSchemas 明示路徑）。
func findSchemasDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("packs: 取得工作目錄: %w", err)
	}
	for {
		cand := filepath.Join(wd, "schemas")
		if st, err := os.Stat(filepath.Join(cand, "pack_manifest.schema.json")); err == nil && !st.IsDir() {
			return cand, nil
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			break
		}
		wd = parent
	}
	return "", fmt.Errorf("packs: 自工作目錄向上找不到 schemas 目錄（請改用 LoadWithSchemas 明示路徑）")
}