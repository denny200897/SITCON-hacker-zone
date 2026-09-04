// Package redaction 實作 §7.2 的金鑰偵測與遮蔽——封閉樣式清單的單一真源。
// 送 LLM 前與落盤前共用同一份清單（§7.2）。
//
// 鐵則（§16）：樣式一律 RE2 語法，清單內禁止 lookahead 與 backreference——
// regexp.MustCompile 編譯這兩類語法本來就會失敗，此處僅能靠測試鎖定清單內容為閉集。
package redaction

import "regexp"

// pattern 是清單中的一條樣式：名稱供 Scan 回報使用（只回報類別、不回報內容，
// 以免命中字串本身造成二次洩漏，§7.2）。
type pattern struct {
	name string
	re   *regexp.Regexp
}

// patterns 是封閉樣式清單（§7.2）。順序即回報順序。
// 新增樣式必須改本檔——RE2，不得使用 lookahead／backreference。
var patterns = []pattern{
	// AWS access key id（20 字元、AKIA 開頭）。
	{"aws_key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	// Anthropic API key 前綴。前綴本身即足以判定，不要求後綴長度；
	// 完整金鑰（sk-ant- 加 20+ 字元）同時命中 sk-{20,}，見 Scan 的去重。
	{"anthropic_key", regexp.MustCompile(`sk-ant-`)},
	// 泛用 sk- 風格金鑰（OpenAI、DeepSeek、自架端點等）：前綴後接 20+ 英數。
	{"generic_sk", regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`)},
	// GitHub PAT（classic ghp_ 與 OAuth gho_）。
	{"github_token", regexp.MustCompile(`ghp_|gho_`)},
	// PEM 私鑰。BEGIN 與 PRIVATE KEY 間可為 RSA/EC/OPENSSH/ENCRYPTED 等標記；
	// 檔尾可能跨行，以 (?s) 讓 . 吃進換行。END 段設為可選——被截斷的私鑰
	// （只有檔頭與 base64、缺 -----END）同樣是洩漏，偵測閘寧可誤報也不漏報。
	{"private_key", regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----(.*?-----END [A-Z ]*PRIVATE KEY-----)?`)},
	// Slack token（xoxb/xoxa/xoxp/xoxr/xoxs 開頭）。
	{"slack_token", regexp.MustCompile(`xox[baprs]-`)},
	// 通用賦值洩漏：api_key/secret/password/token 後接 = 或 : 再接 8+ 非空白字元。
	{"kv_secret", regexp.MustCompile(`(?i)(api_?key|secret|password|token)\s*[=:]\s*\S{8,}`)},
}

// Patterns 回傳封閉樣式清單的編譯結果——單一真源，送 LLM 前與落盤前共用（§7.2）。
// 回傳的是共用 slice，呼叫端不得修改。
func Patterns() []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		out[i] = p.re
	}
	return out
}

// patternNames 回傳清單內樣式名稱的閉集（供測試鎖定，不對外承諾穩定）。
func patternNames() []string {
	out := make([]string, len(patterns))
	for i, p := range patterns {
		out[i] = p.name
	}
	return out
}