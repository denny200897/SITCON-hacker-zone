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

// Mask 以封閉樣式清單（§7.2）對 text 做 span 級遮蔽：每個命中的完整匹配段
// （含 private_key 的跨行段）一律以 "***REDACTED***" 蓋掉，回傳遮蔽後文字與
// 命中樣式名稱清單（去重、與清單順序一致）。無命中回傳原文與空 slice。
//
// 語意（ADR 0006）：供 trusted artifact 落盤使用——樣式命中可能是誤報（如
// sqlite 錯誤訊息「unrecognized token: <nonce>」必撞 kv_secret），整段拒收會
// 讓 oracle 證據連同 nonce 一起消失；遮蔽保留其餘內容供 oracle 判讀，命中
// 樣式名由呼叫端記入 evidence（artifact_redactions），不作靜默處理。
func Mask(text string) (string, []string) {
	var names []string
	seen := make(map[string]bool, len(patterns))
	for _, p := range patterns {
		locs := p.re.FindAllStringIndex(text, -1)
		if len(locs) == 0 {
			continue
		}
		// 由後往前替換，避免位移失效。
		for i := len(locs) - 1; i >= 0; i-- {
			loc := locs[i]
			text = text[:loc[0]] + redacted + text[loc[1]:]
		}
		if !seen[p.name] {
			seen[p.name] = true
			names = append(names, p.name)
		}
	}
	return text, names
}