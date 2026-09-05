package tui

import "strings"

type language string

const (
	languageEnglish language = "en"
	languageChinese language = "zh-TW"
)

type copyText struct {
	tagline, bannerHint, placeholder, starting, hiddenInput string
	secretHint, normalHint, languageChanged, languageUsage  string
	preferenceError, copySuccess, copyError                 string
}

var translations = map[language]copyText{
	languageEnglish: {
		tagline:         "Code Security Review Agent Harness",
		bannerHint:      "Pick an action with ↑↓ and Enter · or type a command · Ctrl+C to exit",
		placeholder:     "Type a command or /help …",
		starting:        "Starting…",
		hiddenInput:     "(input hidden)",
		secretHint:      "  🔒 Secret input · Enter to save · never displayed or stored as plaintext",
		normalHint:      "  /help commands · Tab complete · /copy or Ctrl+Y copy · ↑↓/PgUp scroll",
		languageChanged: "Interface language changed to English.",
		languageUsage:   "Usage: /lang en | zh",
		preferenceError: "Could not save language preference: ",
		copySuccess:     "Transcript copied to the clipboard.",
		copyError:       "Could not copy transcript: ",
	},
	languageChinese: {
		tagline:         "程式碼資安審查 Agent Harness",
		bannerHint:      "用 ↑↓ 與 Enter 選擇動作 · 或直接輸入指令 · Ctrl+C 離開",
		placeholder:     "輸入指令或 /help …",
		starting:        "啟動中…",
		hiddenInput:     "（已隱藏輸入）",
		secretHint:      "  🔒 密鑰輸入模式 · Enter 儲存 · 內容永不顯示或以明文落盤",
		normalHint:      "  /help 指令 · Tab 補全 · /copy 或 Ctrl+Y 複製 · ↑↓/PgUp 捲動",
		languageChanged: "介面語言已切換為繁體中文。",
		languageUsage:   "用法：/lang en | zh",
		preferenceError: "無法儲存語言偏好：",
		copySuccess:     "已將完整記錄複製到剪貼簿。",
		copyError:       "無法複製記錄：",
	},
}

type slashCommand struct {
	name, english, chinese string
}

var slashCommands = []slashCommand{
	{"/help", "show every command", "顯示所有指令"},
	{"/status", "provider, key, routing, and Docker status", "供應商、金鑰、路由與 Docker 狀態"},
	{"/doctor", "check Docker, images, and provider connectivity", "檢查 Docker、映像與供應商連線"},
	{"/provider", "list | add <name> | remove <name>", "list | add <名稱> | remove <名稱>"},
	{"/key", "set <provider> | clear <provider>", "set <供應商> | clear <供應商>"},
	{"/model", "list | set <role|all> <ref> | reset", "list | set <角色|all> <ref> | reset"},
	{"/lang", "en | zh (change interface language)", "en | zh（切換介面語言）"},
	{"/copy", "copy the full transcript to the clipboard", "複製完整記錄到剪貼簿"},
	{"/clear", "clear the screen (keeps your session)", "清除畫面（不離開工作階段）"},
	{"/review", "scan, prove, replay, and report", "掃描、實證、重驗並產生報告"},
	{"/scan", "scan the target repository", "掃描目標 repo"},
	{"/prove", "prove a finding", "實證指定 finding"},
	{"/report", "generate findings, SARIF, and Markdown", "產生 findings、SARIF 與 Markdown"},
	{"/replay", "revalidate an evidence bundle offline", "離線重驗 evidence bundle"},
}

func normalizeLanguage(value string) language {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "zh", "zh-tw", "zh_hant", "chinese", "中文":
		return languageChinese
	default:
		return languageEnglish
	}
}

func commandDescription(command slashCommand, lang language) string {
	if lang == languageChinese {
		return command.chinese
	}
	return command.english
}
