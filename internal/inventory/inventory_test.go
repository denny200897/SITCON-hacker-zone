package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanLinesReportsEachRepeatedMatchAtItsOwnLine(t *testing.T) {
	src := "x = os.environ.get(\"TOKEN\")\n# gap\ny = os.environ.get(\"TOKEN\")\n"
	matches := scanLines(osEnvRe, src)
	if len(matches) != 2 || matches[0].line != 1 || matches[1].line != 3 {
		t.Fatalf("matches = %#v", matches)
	}
}

func writeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, c := range files {
		abs := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestBuildFlaskApp(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app.py": `from flask import Flask
app = Flask(__name__)

@app.route("/users/<name>", methods=["GET", "POST"])
def get_user(name):
    return name

@app.post("/items")
def create_item():
    return "ok"
`,
		"db.py": `import os
from flask import Flask

DB_PATH = os.environ.get("AEGIS_DB_PATH", "/tmp/db.sqlite3")

def load_config():
    with open("config.yaml") as f:
        return f.read()
`,
		"requirements.txt": "flask==3.0.0\n# comment\nrequests>=2.31\n",
	})
	inv, err := Build(root)
	if err != nil {
		t.Fatal(err)
	}

	// 框架
	if len(inv.Frameworks) != 1 || inv.Frameworks[0] != "flask" {
		t.Fatalf("frameworks = %v", inv.Frameworks)
	}

	// 路由：裝飾器 + handler symbol
	if len(inv.Routes) != 2 {
		t.Fatalf("routes = %+v", inv.Routes)
	}
	r0 := inv.Routes[0]
	if r0.Method != "GET" || r0.Path != "/users/<name>" || r0.HandlerSymbol != "get_user" || r0.HandlerLine != 4 {
		t.Fatalf("route0 = %+v", r0)
	}

	// 入口面
	kinds := map[string]int{}
	for _, e := range inv.Entrypoints {
		kinds[e.Kind]++
	}
	if kinds["env"] != 1 || kinds["file_read"] != 1 {
		t.Fatalf("entrypoints = %+v", inv.Entrypoints)
	}

	// 依賴
	if len(inv.Dependencies) != 2 || inv.Dependencies[0].Name != "flask" || inv.Dependencies[0].Version != "2.31" && inv.Dependencies[1].Version != "2.31" {
		t.Fatalf("deps = %+v", inv.Dependencies)
	}

	// 檔案排序
	for i := 1; i < len(inv.Files); i++ {
		if inv.Files[i-1].Path > inv.Files[i].Path {
			t.Fatalf("files not sorted: %s > %s", inv.Files[i-1].Path, inv.Files[i].Path)
		}
	}
}

func TestIsExcluded(t *testing.T) {
	cases := map[string]bool{
		".git/config":           true,
		".env":                  true,
		"app/.env":              true,
		"venv/lib/x.py":         true,
		"app/__pycache__/a.pyc": true,
		"server.pem":            true,
		"id_rsa":                true,
		"app/db.py":             false,
		"requirements.txt":      false,
		"venvsomething/x.py":    false, // 前綴命中不算——元件比對
	}
	for rel, want := range cases {
		if got := IsExcluded(rel); got != want {
			t.Errorf("IsExcluded(%q) = %v want %v", rel, got, want)
		}
	}
}

func TestBuildSkipsExcluded(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"app.py":                "x = 1\n",
		".env":                  "SECRET=1\n",
		"server.key":            "k\n",
		"__pycache__/a.pyc":     "x",
		"venv/lib/x.py":         "y = 2\n",
		".git/hooks/pre-commit": "#!/bin/sh\n",
	})
	inv, err := Build(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Files) != 1 || inv.Files[0].Path != "app.py" {
		t.Fatalf("files = %+v", inv.Files)
	}
}

func TestSymlinkNotFollowed(t *testing.T) {
	// WalkDir 不跟隨 symlink：外部檔案不得進 inventory
	root := writeRepo(t, map[string]string{"a.py": "x = 1\n"})
	external := filepath.Join(t.TempDir(), "secret.py")
	if err := os.WriteFile(external, []byte("SECRET_TOKEN=zzz\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, "leak.py")); err != nil {
		t.Skipf("host cannot create symlinks: %v", err)
	}
	inv, err := Build(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range inv.Files {
		if f.Path == "leak.py" {
			t.Fatalf("symlinked external file entered inventory: %+v", f)
		}
	}
}

func TestModuleOf(t *testing.T) {
	if got := moduleOf("app/db.py"); got != "app.db" {
		t.Fatalf("got %s", got)
	}
	if got := moduleOf("main.py"); got != "main" {
		t.Fatalf("got %s", got)
	}
}
