// Package tui 是 Aegis 的對話式終端機介面（TUI），以 Bubble Tea + Lipgloss
// 呈現，底層完全重用 internal/console 的 REPL 指令邏輯（見 tui.go）。
//
// 品牌色：截圖按鈕的青綠漸層（teal → green）。此檔集中管理 logo 與配色，
// 讓視覺調整不必動到互動邏輯。
package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/lucasb-eyer/go-colorful"
)

// 品牌漸層端點（取自「Install Aegis CLI」按鈕）：左青、右綠。
var (
	brandFrom = mustColor("#4FD1C5") // teal.400
	brandTo   = mustColor("#48BB78") // green.400
)

func mustColor(hex string) colorful.Color {
	c, err := colorful.Hex(hex)
	if err != nil {
		panic("tui: 無效的品牌色 " + hex + ": " + err.Error())
	}
	return c
}

// asciiLogo 是 "AEGIS" 的 ANSI Shadow 字體圖樣。漸層由 gradientBlock 逐欄套用。
const asciiLogo = ` █████╗ ███████╗ ██████╗ ██╗███████╗
██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
███████║█████╗  ██║  ███╗██║███████╗
██╔══██║██╔══╝  ██║   ██║██║╚════██║
██║  ██║███████╗╚██████╔╝██║███████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝`

// gradientText 對單行文字逐字元套用 from→to 的水平漸層。
func gradientText(s string, from, to colorful.Color) string {
	runes := []rune(s)
	n := len(runes)
	if n == 0 {
		return s
	}
	var b strings.Builder
	for i, r := range runes {
		t := 0.0
		if n > 1 {
			t = float64(i) / float64(n-1)
		}
		c := from.BlendLuv(to, t).Clamped()
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(c.Hex())).Render(string(r)))
	}
	return b.String()
}

// gradientBlock 對多行區塊逐「欄」套用漸層——同一欄的所有列共用同一色，
// 讓 ASCII logo 呈現整齊的左青右綠過渡（而非每列各自重來）。
func gradientBlock(block string, from, to colorful.Color) string {
	lines := strings.Split(block, "\n")
	width := 0
	for _, ln := range lines {
		if w := len([]rune(ln)); w > width {
			width = w
		}
	}
	if width == 0 {
		return block
	}
	var out strings.Builder
	for li, ln := range lines {
		if li > 0 {
			out.WriteByte('\n')
		}
		for col, r := range []rune(ln) {
			t := float64(col) / float64(width-1)
			c := from.BlendLuv(to, t).Clamped()
			out.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(c.Hex())).Render(string(r)))
		}
	}
	return out.String()
}

// banner 產生啟動橫幅：漸層 logo + 標語。width 供未來置中使用（目前左對齊）。
func banner() string {
	logo := gradientBlock(asciiLogo, brandFrom, brandTo)
	tagline := gradientText("程式碼資安審查 Agent Harness", brandFrom, brandTo)
	hint := lipgloss.NewStyle().Foreground(lipgloss.Color("#7A8A87")).
		Render("輸入 /help 顯示指令 · Enter 送出 · Ctrl+C 離開")
	return logo + "\n\n  " + tagline + "\n  " + hint
}
