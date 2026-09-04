package sandbox

import (
	"archive/tar"
	"bytes"
	"io"
	"strings"
	"testing"
)

// TestValidateStageName：staging 相對路徑閉集（§22 adversarial：路徑形狀）。
func TestValidateStageName(t *testing.T) {
	valid := []string{"app.py", "sub/mod.py", "a/b/c.py"}
	for _, name := range valid {
		if err := validateStageName(name); err != nil {
			t.Errorf("合法路徑 %q 被拒：%v", name, err)
		}
	}
	invalid := map[string]string{
		"空字串":     "",
		"絕對路徑":    "/app.py",
		"含 ..":    "../app.py",
		"中段 ..":   "sub/../app.py",
		"非 clean": "./app.py",
		"尾斜線":     "app/",
	}
	for name, v := range invalid {
		if err := validateStageName(v); err == nil {
			t.Errorf("非法路徑 %s（%q）應被拒", name, v)
		}
	}
}

// TestStageTar：payload 恆在（PayloadStagedName）、內容正確、mode 0644、
// 保留名衝突拒收、非法路徑拒收。
func TestStageTar(t *testing.T) {
	got, err := stageTar(StageFiles{
		"app.py":     []byte("APP"),
		"sub/mod.py": []byte("MOD"),
	}, []byte("PAYLOAD"))
	if err != nil {
		t.Fatalf("stageTar 失敗：%v", err)
	}
	tr := tar.NewReader(bytes.NewReader(got))
	seen := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar 解析失敗：%v", err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("tar 內容讀取失敗：%v", err)
		}
		seen[hdr.Name] = string(body)
		if hdr.Mode != 0o644 {
			t.Errorf("檔案 %s mode = %o，須 0644（容器內 non-root 可讀）", hdr.Name, hdr.Mode)
		}
	}
	if seen["app.py"] != "APP" || seen["sub/mod.py"] != "MOD" {
		t.Fatalf("witness 檔案內容不符：%#v", seen)
	}
	if seen[PayloadStagedName] != "PAYLOAD" {
		t.Fatalf("payload.txt 應恆存在且內容為 payload，得 %q", seen[PayloadStagedName])
	}
}

// TestStageTarPayloadAlwaysPresent：payload 空值也須有空檔（subpath 掛載需存在）。
func TestStageTarPayloadAlwaysPresent(t *testing.T) {
	got, err := stageTar(StageFiles{"app.py": []byte("APP")}, nil)
	if err != nil {
		t.Fatalf("stageTar 失敗：%v", err)
	}
	if !bytes.Contains(got, []byte(PayloadStagedName)) {
		t.Fatal("payload.txt 項應存在於 tar（即使 payload 為空）")
	}
}

func TestStageTarRejects(t *testing.T) {
	cases := map[string]StageFiles{
		"payload 保留名衝突": {"payload.txt": []byte("x")},
		"絕對路徑":          {"/app.py": []byte("x")},
		"含 ..":          {"../app.py": []byte("x")},
	}
	for name, files := range cases {
		if _, err := stageTar(files, []byte("p")); err == nil {
			t.Errorf("%s：應被拒收", name)
		}
	}
}

// TestWitnessVolumeName：volume 名與 reclaim/flags 所用一致。
func TestWitnessVolumeName(t *testing.T) {
	if got := WitnessVolumeName("R-0001"); got != "aegis-witness-R-0001" {
		t.Fatalf("WitnessVolumeName(R-0001) = %q", got)
	}
	if !strings.HasPrefix(WitnessVolumeName("R-0002"), WitnessVolumePrefix) {
		t.Fatal("volume 名須帶 prefix")
	}
}