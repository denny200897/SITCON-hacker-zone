package redaction

import "strings"

// redacted 是遮蔽後的佔位字串（§7.2：以已登錄金鑰做替換時統一蓋掉）。
const redacted = "***REDACTED***"

// Scan 掃描 text 是否命中封閉樣式清單（§7.2），回傳命中的 pattern 描述名稱
// （如 "aws_key"、"private_key"）——刻意不回傳命中內容本身，避免洩漏路徑多一條。
// 同一樣式只回報一次；順序與清單順序一致。無命中回傳空 slice（非 nil 保證不作要求）。
func Scan(text string) []string {
	var out []string
	seen := make(map[string]bool, len(patterns))
	for _, p := range patterns {
		if seen[p.name] {
			continue
		}
		if p.re.MatchString(text) {
			seen[p.name] = true
			out = append(out, p.name)
		}
	}
	return out
}

// HasSecret 回報 text 是否命中任一 repo-secrets 樣式（§7.2：
// 送 LLM 前與落盤前的 gate 判定；policy 的 secret_in_spec 亦以此為準，§17.9-5）。
func HasSecret(text string) bool {
	for _, p := range patterns {
		if p.re.MatchString(text) {
			return true
		}
	}
	return false
}

// Redact 以已登錄金鑰清單 secrets 對 text 做遮蔽：金鑰出現之處一律以
// "***REDACTED***" 蓋掉。空清單為無操作。以字面比對（不做 regex 轉義）——
// 金鑰是 caller 自 keychain／credentials.toml 登錄的確切字串，逐字出現即須遮蔽。
func Redact(text string, secrets []string) string {
	for _, s := range secrets {
		if s == "" {
			continue
		}
		text = strings.ReplaceAll(text, s, redacted)
	}
	return text
}