package redaction

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// TestPatternsClosedSet 鎖定清單為閉集（§7.2、§16）：名稱集合與數量必須完全一致，
// 新增／刪除 pattern 必須修改本測試——防止清單靜默漂移。
func TestPatternsClosedSet(t *testing.T) {
	want := []string{
		"aws_key",
		"anthropic_key",
		"generic_sk",
		"github_token",
		"private_key",
		"slack_token",
		"kv_secret",
	}
	if got := patternNames(); !reflect.DeepEqual(got, want) {
		t.Fatalf("patterns 清單漂移：got %v, want %v（§7.2 封閉清單，新增須改測試）", got, want)
	}
	if got, want := len(Patterns()), len(want); got != want {
		t.Fatalf("Patterns() 長度 = %d, want %d", got, want)
	}
}

// TestPatternsCompiled 逐條檢查 Patterns() 為非 nil 編譯結果；
// 若清單含 RE2 不支援的 lookahead／backreference，套件載入時 MustCompile 即失敗，
// 本測試為冗餘防線。
func TestPatternsCompiled(t *testing.T) {
	for i, re := range Patterns() {
		if re == nil {
			t.Fatalf("Patterns()[%d] = nil", i)
		}
	}
}

// TestPatternsNoLookaheadNoBackreference 以語法掃描自我檢查（§16 硬規則）：
// 清單內任何樣式不得含 lookahead（(?= (?! (?<= (?<! 或 backreference（\1..\9）語法。
func TestPatternsNoLookaheadNoBackreference(t *testing.T) {
	for i, re := range Patterns() {
		s := re.String()
		for _, bad := range []string{"(?=", "(?!", "(?<=", "(?<!"} {
			if strings.Contains(s, bad) {
				t.Errorf("Patterns()[%d] %q 含 lookahead 語法 %q（RE2 禁用，§16）", i, s, bad)
			}
		}
		for j := 1; j <= 9; j++ {
			if strings.Contains(s, `\`+string(rune('0'+j))) {
				t.Errorf("Patterns()[%d] %q 含 backreference \\%d（RE2 禁用，§16）", i, s, j)
			}
		}
	}
}

// TestScanPerPattern 逐 pattern 各一正例一反例（任務要求）。
func TestScanPerPattern(t *testing.T) {
	type pc struct {
		pattern string
		pos     string
		neg     string
	}
	list := []pc{
		{"aws_key", "AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7"},
		{"anthropic_key", "sk-ant-api03-0123456789abcdefghij", "prefix alone: sk-ant"},
		{"generic_sk", "sk-0123456789abcdefghij0123456789", "sk-short12"},
		{"github_token", "ghp_0123456789abcdefghijklmnopqrstuvwxyz", "gho without underscore"},
		{"private_key", "", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"},
		{"slack_token", "xoxb-123456789012-abcdef", "xoxa"},
		{"kv_secret", "API_KEY=supersecretvalue1", "api_key = short"},
	}
	for _, c := range list {
		if c.pos != "" && !contains(Scan(c.pos), c.pattern) {
			t.Errorf("%s 正例未命中：%s → %v", c.pattern, c.pos, Scan(c.pos))
		}
		if got := Scan(c.neg); len(got) != 0 {
			t.Errorf("%s 反例誤命中：%s → %v", c.pattern, c.neg, got)
		}
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// TestScanMultiLinePrivateKey 私鑰檔頭與檔尾跨行（(?s) 行為）。
func TestScanMultiLinePrivateKey(t *testing.T) {
	text := "some header\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\nabc\n-----END RSA PRIVATE KEY-----\ntrailing text"
	got := Scan(text)
	if !contains(got, "private_key") {
		t.Errorf("跨行私鑰未命中 private_key：%v", got)
	}
	// EC 標記與 OPENSSH 標記也要命中。
	for _, head := range []string{"EC", "OPENSSH", "ENCRYPTED"} {
		p := "-----BEGIN " + head + " PRIVATE KEY-----\nAAAA\n-----END " + head + " PRIVATE KEY-----"
		if !contains(Scan(p), "private_key") {
			t.Errorf("%s 私鑰未命中：%v", head, Scan(p))
		}
	}
	// 被截斷的私鑰（僅檔頭、缺 END）同樣是洩漏，必須命中。
	truncated := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA+abc123"
	if !contains(Scan(truncated), "private_key") {
		t.Errorf("截斷私鑰未命中 private_key：%v", Scan(truncated))
	}
}

// TestScanSkAntPrefixClarification 釐清 sk-ant- 與 sk-[A-Za-z0-9]{20,} 的行為：
//   - 前綴 "sk-ant-" 一律命中 anthropic_key（不論後綴長度）——這是刻意設計：
//     Anthropic 金鑰格式含連字號，"sk-" 後的連續 [A-Za-z0-9] 在 "ant-" 處中斷，
//     因此 sk-[A-Za-z0-9]{20,} 抓不到 sk-ant- 開頭的金鑰，前綴樣式是必要補位。
//   - 兩樣式在同一字串上不會同時命中（"sk-ant-" 的連字號必使 {20,} 中斷於 3 字元）。
func TestScanSkAntPrefixClarification(t *testing.T) {
	full := "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890"
	got := Scan(full)
	if !contains(got, "anthropic_key") {
		t.Errorf("完整 sk-ant 金鑰應命中 anthropic_key：%v", got)
	}
	if contains(got, "generic_sk") {
		t.Errorf("sk-ant- 金鑰含連字號，generic_sk 的 {20,} 應中斷而不命中：%v", got)
	}
	prefixOnly := "sk-ant-"
	got = Scan(prefixOnly)
	if !contains(got, "anthropic_key") {
		t.Errorf("sk-ant- 前綴應命中 anthropic_key：%v", got)
	}
	if contains(got, "generic_sk") {
		t.Errorf("sk-ant- 前綴不應命中 generic_sk：%v", got)
	}
	// 對照：無連字號的 sk- 長金鑰走 generic_sk。
	if got := Scan("sk-0123456789abcdefghij0123456789"); !contains(got, "generic_sk") || contains(got, "anthropic_key") {
		t.Errorf("sk-{20,} 金鑰應只命中 generic_sk：%v", got)
	}
}

// TestScanDedupAndOrder 同一樣式重複命中只回報一次，順序與清單一致。
func TestScanDedupAndOrder(t *testing.T) {
	text := "AKIAIOSFODNN7EXAMPLE\nAKIA0123456789ABCDEF\nmore AKIAIOSFODNN7EXAMPLE"
	got := Scan(text)
	if !reflect.DeepEqual(got, []string{"aws_key"}) {
		t.Errorf("重複命中應去重為單一 aws_key：%v", got)
	}
	multi := "xoxb-abc AKIAIOSFODNN7EXAMPLE sk-0123456789abcdefghij0123456789"
	got = Scan(multi)
	want := []string{"aws_key", "generic_sk", "slack_token"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("順序應與清單一致：got %v, want %v", got, want)
	}
}

// TestScanEmpty 空字串與無命中回傳空結果。
func TestScanEmpty(t *testing.T) {
	if got := Scan(""); len(got) != 0 {
		t.Errorf("空字串不應命中：%v", got)
	}
	if got := Scan("plain text with nothing suspicious"); len(got) != 0 {
		t.Errorf("無命中應為空：%v", got)
	}
}

// TestHasSecret gate 判定：任一命中即 true。
func TestHasSecret(t *testing.T) {
	if !HasSecret("token: averylongsecretvalue") {
		t.Error("HasSecret(kv 正例) = false, want true")
	}
	if !HasSecret("-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----") {
		t.Error("HasSecret(private_key 正例) = false, want true")
	}
	if HasSecret("nothing to see here") {
		t.Error("HasSecret(反例) = true, want false")
	}
}

// TestRedactRedaction 以已登錄金鑰蓋掉，空清單無操作。
func TestRedact(t *testing.T) {
	text := "calling https://api.anthropic.com with sk-ant-api03-abcdefghijklmnopqrst and nothing else"
	key := "sk-ant-api03-abcdefghijklmnopqrst"
	got := Redact(text, []string{key})
	if strings.Contains(got, key) {
		t.Errorf("Redact 後金鑰仍在輸出：%s", got)
	}
	if !strings.Contains(got, "***REDACTED***") {
		t.Errorf("Redact 後應含佔位字串：%s", got)
	}
	// 空清單為無操作。
	if got := Redact(text, nil); got != text {
		t.Errorf("空清單 Redact 應無操作：got %q", got)
	}
	if got := Redact(text, []string{}); got != text {
		t.Errorf("空 slice Redact 應無操作：got %q", got)
	}
	// 多把金鑰逐一蓋掉。
	multi := "key1 sk-abc123def456ghi789jk key2 xoxb-123456789012-abcdef"
	got = Redact(multi, []string{"sk-abc123def456ghi789jk", "xoxb-123456789012-abcdef"})
	if strings.Contains(got, "sk-abc") || strings.Contains(got, "xoxb-12345") {
		t.Errorf("多把金鑰未全部遮蔽：%s", got)
	}
	if strings.Count(got, "***REDACTED***") != 2 {
		t.Errorf("佔位字串數量錯誤：%s", got)
	}
	// 空字串金鑰跳過（避免把 ReplaceAll("") 的怪異行為引進來）。
	if got := Redact(text, []string{""}); got != text {
		t.Errorf("空金鑰應跳過：got %q", got)
	}
}

// TestRedactAndScanComposition 落盤前組合：先 Redact 自身金鑰，再 Scan 確認殘留 secrets。
// 注意：Redact 只處理已登錄金鑰，repo 內疑似 secrets 仍須以 Scan 攔（§7.2 兩者獨立）。
func TestRedactAndScanComposition(t *testing.T) {
	text := "Authorization: Bearer sk-ant-api03-abcdefghijklmnopqrst; repo leak AKIAIOSFODNN7EXAMPLE"
	cleaned := Redact(text, []string{"sk-ant-api03-abcdefghijklmnopqrst"})
	if strings.Contains(cleaned, "sk-ant-api03") {
		t.Errorf("自身金鑰未遮蔽：%s", cleaned)
	}
	// repo 內的 AWS key 不因 Redact 消失，仍須被 Scan 抓到。
	if !contains(Scan(cleaned), "aws_key") {
		t.Errorf("repo secrets 應仍被 Scan 抓到：%v", Scan(cleaned))
	}
}

// TestPatternsRegexLiteralMatches 確保 Patterns() 編譯結果可直接用於 MatchString。
func TestPatternsRegexLiteralMatches(t *testing.T) {
	re := Patterns()[0] // aws_key
	if !re.MatchString("AKIAIOSFODNN7EXAMPLE") {
		t.Error("Patterns()[0] 無法比對 AWS key")
	}
	var _ *regexp.Regexp = re
}