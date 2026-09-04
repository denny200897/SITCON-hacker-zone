// Package inventory 實作 Stage 0：檔案樹、框架偵測、依賴清單、路由表、入口面
// （SPEC §4 Stage 0）。純 Go、零 LLM。
package inventory

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// DefaultExcludes 是 §7.2 路徑政策的預設排除清單（閉集；送 LLM 前與 snapshot 共用）。
// 預設排除 .env、私鑰、憑證儲存、build artifacts、.git、__pycache__/*.pyc、.venv/venv/.tox。
var DefaultExcludes = []string{
	".git",
	".env",
	".venv", "venv", ".tox",
	"__pycache__",
	"node_modules",
	"dist", "build",
	".aegis", "out",
}

// IsExcluded 判定相對路徑是否被排除：任一層路徑元件命中 exclude 即排除；
// 檔名 *.pyc 與私密金鑰樣式檔名一律排除。
func IsExcluded(rel string) bool {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for _, p := range parts {
		for _, e := range DefaultExcludes {
			if p == e {
				return true
			}
		}
	}
	base := parts[len(parts)-1]
	if strings.HasSuffix(base, ".pyc") {
		return true
	}
	for _, suf := range []string{".pem", ".key", ".p12", ".pfx", ".jks"} {
		if strings.HasSuffix(base, suf) {
			return true
		}
	}
	for _, name := range []string{"id_rsa", "id_ed25519", "id_ecdsa", "credentials.json"} {
		if base == name {
			return true
		}
	}
	return false
}

// File 是 inventory 記錄的單一檔案。
type File struct {
	Path     string `json:"path"`
	Bytes    int64  `json:"bytes"`
	Language string `json:"language"`
	Module   string `json:"module,omitempty"`
}

// Route 是抽出的 HTTP route。
type Route struct {
	Method        string `json:"method"`
	Path          string `json:"path"`
	HandlerFile   string `json:"handler_file"`
	HandlerLine   int    `json:"handler_line"`
	HandlerSymbol string `json:"handler_symbol"`
}

// Entrypoint 是既有輸入面（ACD D0 判定的素材，§2.1）。
type Entrypoint struct {
	Kind   string `json:"kind"` // http_handler | cli | env | file_read | other
	File   string `json:"file"`
	Line   int    `json:"line"`
	Symbol string `json:"symbol"`
	Detail string `json:"detail,omitempty"`
}

// Inventory 是 Stage 0 產出（對應 schemas/inventory.schema.json）。
type Inventory struct {
	SnapshotID   string       `json:"snapshot_id,omitempty"`
	Files        []File       `json:"files"`
	Frameworks   []string     `json:"frameworks"`
	Routes       []Route      `json:"routes"`
	Entrypoints  []Entrypoint `json:"entrypoints"`
	Dependencies []Dependency `json:"dependencies"`
	Notes        []string     `json:"notes,omitempty"`
}

type Dependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  string `json:"source"`
}

// Build 走訪 root 產生 inventory（不含 snapshot 複製——那是 orchestrator/snapshot 的職責）。
func Build(root string) (*Inventory, error) {
	inv := &Inventory{}
	fwSet := map[string]bool{}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			if IsExcluded(rel) {
				return filepath.SkipDir
			}
			return nil
		}
		if IsExcluded(rel) {
			return nil
		}
		// symlink 一律跳過（§16：不跟隨——跟隨會讀到 repo 外檔案，T8）
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		lang := languageOf(d.Name())
		f := File{Path: filepath.ToSlash(rel), Bytes: info.Size(), Language: lang}
		f.Module = moduleOf(rel)
		inv.Files = append(inv.Files, f)

		if lang == "python" {
			data, err := os.ReadFile(path)
			if err == nil {
				src := string(data)
				for _, fw := range detectFrameworks(src) {
					fwSet[fw] = true
				}
				inv.Routes = append(inv.Routes, extractRoutes(rel, src)...)
				inv.Entrypoints = append(inv.Entrypoints, extractEntrypoints(rel, src)...)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	deps, notes, err := readDeps(root)
	if err != nil {
		return nil, err
	}
	inv.Dependencies = deps
	inv.Notes = notes
	inv.Frameworks = sortedKeys(fwSet)
	if len(inv.Frameworks) == 0 {
		inv.Frameworks = []string{"unknown"}
	}
	sort.Slice(inv.Files, func(i, j int) bool { return inv.Files[i].Path < inv.Files[j].Path })
	sort.Slice(inv.Routes, func(i, j int) bool {
		if inv.Routes[i].HandlerFile != inv.Routes[j].HandlerFile {
			return inv.Routes[i].HandlerFile < inv.Routes[j].HandlerFile
		}
		return inv.Routes[i].HandlerLine < inv.Routes[j].HandlerLine
	})
	return inv, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func languageOf(name string) string {
	switch {
	case strings.HasSuffix(name, ".py"):
		return "python"
	case name == "requirements.txt" || strings.HasSuffix(name, ".toml"):
		return "toml"
	default:
		return "other"
	}
}

// moduleOf 把 "app/db.py" 轉成 "app.db"。
func moduleOf(rel string) string {
	s := strings.TrimSuffix(filepath.ToSlash(rel), ".py")
	return strings.ReplaceAll(s, "/", ".")
}

// ---- 框架偵測 ----

func detectFrameworks(src string) []string {
	var out []string
	if strings.Contains(src, "from fastapi") || strings.Contains(src, "import fastapi") {
		out = append(out, "fastapi")
	}
	if strings.Contains(src, "from flask") || strings.Contains(src, "import flask") {
		out = append(out, "flask")
	}
	if strings.Contains(src, "from django") || strings.Contains(src, "import django") {
		out = append(out, "django")
	}
	return out
}

// ---- 路由抽取（FastAPI / Flask 裝飾器；Django 由 §14.3 之後的 milestone 補強）----

var routeRe = regexp.MustCompile(`(?m)@(\w+)\.(get|post|put|delete|patch|route)\(\s*["']([^"']*)["']`)
var methodsRe = regexp.MustCompile(`methods\s*=\s*\[\s*["']([A-Za-z]+)["']`)
var callTailRe = regexp.MustCompile(`\([^\n]*`)

// decoratorCall 回傳裝飾器括號內的單行內容（供 methods= 解析）。
func decoratorCall(src string, off int) string {
	return callTailRe.FindString(src[off:])
}

type routeMatch struct {
	method, path, symbol string
	line                 int
}

// symbolAt 找路由裝飾器之後的下一個 def 名稱。
func symbolAfter(src string, off int) string {
	rest := src[off:]
	loc := regexp.MustCompile(`(?m)^\s*def\s+(\w+)|(async\s+def\s+(\w+))`).FindStringIndex(rest)
	if loc == nil {
		return ""
	}
	return strings.TrimSpace(regexp.MustCompile(`def\s+(\w+)`).FindStringSubmatch(rest[loc[0]:loc[1]])[1])
}

func extractRoutes(file, src string) []Route {
	var out []Route
	for _, loc := range routeRe.FindAllStringSubmatchIndex(src, -1) {
		// groups: 1=router obj, 2=method(get/post/...) or route, 3=path
		method := ""
		if loc[4] >= 0 {
			method = src[loc[4]:loc[5]]
		}
		// Flask 的 @obj.route(...)：預設 GET，除非 methods=[...] 指明
		if method == "route" || method == "" {
			call := decoratorCall(src, loc[1])
			method = ""
			for _, mm := range methodsRe.FindAllStringSubmatch(call, -1) {
				method = mm[1]
			}
			if method == "" {
				method = "get"
			}
		}
		path := src[loc[6]:loc[7]]
		sym := symbolAfter(src, loc[1])
		line := 1 + strings.Count(src[:loc[0]], "\n")
		if method == "" || path == "" {
			continue
		}
		out = append(out, Route{
			Method:        strings.ToUpper(method),
			Path:          path,
			HandlerFile:   file,
			HandlerLine:   line,
			HandlerSymbol: sym,
		})
	}
	return out
}

// ---- 入口面抽取（env / file_read）----

var osEnvRe = regexp.MustCompile(`os\.environ(?:\.get)?\(\s*["']([A-Za-z0-9_]+)["']`)
var openRe = regexp.MustCompile(`open\(\s*([^),]+)`)

type lineMatch struct {
	name  string
	line  int
	match string
}

func scanLines(re *regexp.Regexp, src string) []lineMatch {
	var out []lineMatch
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		name := m[1]
		line := 1 + strings.Count(src[:strings.Index(src, m[0])], "\n")
		out = append(out, lineMatch{name: name, line: line, match: m[0]})
	}
	return out
}

func extractEntrypoints(file, src string) []Entrypoint {
	var out []Entrypoint
	for _, e := range scanLines(osEnvRe, src) {
		out = append(out, Entrypoint{Kind: "env", File: file, Line: e.line, Symbol: e.name})
	}
	for _, e := range scanLines(openRe, src) {
		out = append(out, Entrypoint{Kind: "file_read", File: file, Line: e.line, Symbol: strings.TrimSpace(e.name)})
	}
	return out
}

// ---- 依賴清單 ----

var reqLineRe = regexp.MustCompile(`^([A-Za-z0-9_.\-]+)([<>=~!]+[^;\s]+)?`)

func readDeps(root string) ([]Dependency, []string, error) {
	var out []Dependency
	var notes []string

	// requirements.txt
	if data, err := os.ReadFile(filepath.Join(root, "requirements.txt")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
				continue
			}
			m := reqLineRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			v := strings.TrimLeft(m[2], "<>=~!")
			if v == "" {
				v = "unpinned"
			}
			out = append(out, Dependency{Name: m[1], Version: v, Source: "requirements.txt"})
		}
	} else {
		notes = append(notes, "requirements.txt 不存在或不可讀")
	}

	// pyproject.toml：只抓 [project] dependencies 的名稱（v1 不解析完整 TOML 語意）
	if data, err := os.ReadFile(filepath.Join(root, "pyproject.toml")); err == nil {
		inDeps := false
		for _, line := range strings.Split(string(data), "\n") {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, "[") {
				inDeps = strings.HasPrefix(t, "[project.dependencies]") ||
					strings.Contains(t, "dependencies") && !strings.HasPrefix(t, "[[")
				continue
			}
			if inDeps && strings.HasPrefix(t, "\"") {
				m := reqLineRe.FindStringSubmatch(strings.Trim(t, `",`))
				if m != nil {
					v := strings.TrimLeft(m[2], "<>=~!")
					if v == "" {
						v = "unpinned"
					}
					out = append(out, Dependency{Name: m[1], Version: v, Source: "pyproject.toml"})
				}
			}
		}
	}
	return out, notes, nil
}
