// Package evidence 實作 content-addressed evidence bundle（SPEC §5.3、§21.4）。
// canonical() 是全工具唯一的序列化路徑：待 hash 物件一律 map[string]any、
// 解碼一律經 UseNumber() 的 json.Decoder（§21.4 規則 1–3）。
package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strconv"
)

// CanonicalVersion 是 canonical 序列化規則版本（§21.4），隨被 hash 物件綁定。
const CanonicalVersion = "canonical-v1"

// canonical 依 §21.4 落地：sorted keys（encoding/json 對 map 的保證）、
// 無空白（Encoder 預設）、無尾換行、SetEscapeHTML(false)。
// v 必為 map[string]any——禁止對 struct 做 canonical hash（欄位依宣告順序、不排序）。
func canonical(v any) ([]byte, error) {
	if _, ok := v.(map[string]any); !ok {
		return nil, fmt.Errorf("evidence: canonical input must be map[string]any, got %T", v)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // 否則 < > & 會被轉義成 < 等形式
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil // Encoder 恆附尾換行
}

// Hash 以 canonical 序列化計 sha256，輸出前綴 sha256:<hex>。
// 物件必須已是 map[string]any 且數值欄位使用 int64／json.Number（規則 4）。
func Hash(v any) (string, error) {
	b, err := canonical(v)
	if err != nil {
		return "", err
	}
	return "sha256:" + fmt.Sprintf("%x", sha256.Sum256(b)), nil
}

// CanonicalBytes 回傳 canonical 序列化的原始 byte（測試與 manifest 重算用）。
func CanonicalBytes(v any) ([]byte, error) { return canonical(v) }

// Decode 以 json.Decoder＋UseNumber() 解碼 JSON 檔／字串為 map[string]any。
// 所有進 hash 路徑的資料一律經此解碼（規則 2：json.Number 原字面 round-trip）。
func Decode(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("evidence: decode: %w", err)
	}
	return m, nil
}

// Num 以 json.Number 產生定點小數字面（規則 4：confidence 兩位小數等），
// 不得讓裸 float64 進待 hash 物件。
func Num(v float64) json.Number {
	return json.Number(strconv.FormatFloat(v, 'f', 2, 64))
}

// Int 以 int64 產生整數值（規則 4）。
func Int(v int64) int64 { return v }
