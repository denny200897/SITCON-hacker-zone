package evidence

import (
	"encoding/json"
	"strings"
	"testing"
)

// §22 M0a：canonical JSON 各 fixture 測試。

func TestCanonicalStable(t *testing.T) {
	m := map[string]any{"b": int64(2), "a": "x"}
	b1, err := CanonicalBytes(m)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := CanonicalBytes(m)
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Fatalf("two serializations differ: %q vs %q", b1, b2)
	}
}

func TestCanonicalKeyOrderSorted(t *testing.T) {
	b, err := CanonicalBytes(map[string]any{"zebra": int64(1), "apple": int64(2), "mango": int64(3)})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"apple":2,"mango":3,"zebra":1}`
	if string(b) != want {
		t.Fatalf("got %s want %s", b, want)
	}
}

func TestCanonicalNonASCIIKeySorted(t *testing.T) {
	// UTF-8 byte 序排序（碼點序）
	b, err := CanonicalBytes(map[string]any{"中": int64(1), "英": int64(2), "a": int64(3)})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(b); got != `{"a":3,"中":1,"英":2}` {
		t.Fatalf("got %s", got)
	}
}

func TestCanonicalJSONNumberRoundTrip(t *testing.T) {
	// json.Number 原字面輸出：0.10 不得變成 0.1
	src := `{"confidence": 0.10, "count": 42}`
	m, err := Decode([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	b, err := CanonicalBytes(m)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(b); got != `{"confidence":0.10,"count":42}` {
		t.Fatalf("got %s", got)
	}
}

func TestCanonicalNoHTMLEscape(t *testing.T) {
	b, err := CanonicalBytes(map[string]any{"expr": "a < b & c > d"})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(b); got != `{"expr":"a < b & c > d"}` {
		t.Fatalf("got %s", got)
	}
}

func TestCanonicalNoTrailingNewline(t *testing.T) {
	b, err := CanonicalBytes(map[string]any{"k": "v"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(string(b), "\n") {
		t.Fatalf("trailing newline: %q", b)
	}
}

func TestHashDeterministicAndPrefixed(t *testing.T) {
	m := map[string]any{"a": int64(1)}
	h1, _ := Hash(m)
	h2, _ := Hash(m)
	if h1 != h2 {
		t.Fatalf("hash differs: %s vs %s", h1, h2)
	}
	if !strings.HasPrefix(h1, "sha256:") || len(h1) != len("sha256:")+64 {
		t.Fatalf("bad hash form: %s", h1)
	}
}

func TestNumFormatsFixedTwo(t *testing.T) {
	if got := Num(0.6); got.String() != "0.60" {
		t.Fatalf("Num(0.6) = %s", got)
	}
	if got := Num(0.9); got.String() != "0.90" {
		t.Fatalf("Num(0.9) = %s", got)
	}
}

func TestStructHashRejectedByConvention(t *testing.T) {
	// §21.4 規則 1：canonical/hash 的輸入邊界拒絕 struct，避免欄位宣告順序
	// 被誤當成穩定的 canonical map 順序。
	type s struct {
		B int `json:"b"`
		A int `json:"a"`
	}
	if _, err := CanonicalBytes(s{2, 1}); err == nil {
		t.Fatal("struct canonical input accepted")
	}
	if _, err := Hash(s{2, 1}); err == nil {
		t.Fatal("struct hash input accepted")
	}
}

func TestDecodeRejectsBadJSON(t *testing.T) {
	if _, err := Decode([]byte("not json")); err == nil {
		t.Fatal("expected error")
	}
}

func TestDecodeTopLevelNonObject(t *testing.T) {
	if _, err := Decode([]byte(`[1,2]`)); err == nil {
		t.Fatal("expected error for non-object top level")
	}
}

func TestRawNumber(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal([]byte(`{"n":1.5}`), &m); err == nil {
		// 裸 Unmarshal 的 float64 進 hash 路徑是被禁止的——確認 Decode 才是正路
		if _, ok := m["n"].(float64); !ok {
			t.Fatal("precondition")
		}
	}
	dec, err := Decode([]byte(`{"n":1.5}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := dec["n"].(json.Number); !ok {
		t.Fatalf("Decode must produce json.Number, got %T", dec["n"])
	}
}
