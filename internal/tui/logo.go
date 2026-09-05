package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/lucasb-eyer/go-colorful"
)

// Brand cyan, sampled from the AEGIS block logo: a light glow tone blended into
// the sky-blue block fill. Drives the logo gradient plus the prompt, cursor, and
// input-border accents so the whole interface reads as one hue.
var (
	brandFrom = mustColor("#8CE0F7")
	brandTo   = mustColor("#3AAEDD")
)

func mustColor(hex string) colorful.Color {
	c, err := colorful.Hex(hex)
	if err != nil {
		panic("tui: invalid brand color " + hex + ": " + err.Error())
	}
	return c
}

// AEGIS wordmark in the FIGlet "ANSI Shadow" font.
const asciiLogo = ` █████╗ ███████╗ ██████╗ ██╗███████╗
██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
███████║█████╗  ██║  ███╗██║███████╗
██╔══██║██╔══╝  ██║   ██║██║╚════██║
██║  ██║███████╗╚██████╔╝██║███████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝`

func gradientText(s string, from, to colorful.Color) string {
	runes := []rune(s)
	if len(runes) == 0 {
		return s
	}
	var b strings.Builder
	for i, r := range runes {
		t := 0.0
		if len(runes) > 1 {
			t = float64(i) / float64(len(runes)-1)
		}
		c := from.BlendLuv(to, t).Clamped()
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(c.Hex())).Render(string(r)))
	}
	return b.String()
}

func gradientBlock(block string, from, to colorful.Color) string {
	lines := strings.Split(block, "\n")
	width := 0
	for _, line := range lines {
		if w := len([]rune(line)); w > width {
			width = w
		}
	}
	if width == 0 {
		return block
	}
	var out strings.Builder
	for lineIndex, line := range lines {
		if lineIndex > 0 {
			out.WriteByte('\n')
		}
		for column, r := range []rune(line) {
			t := 0.0
			if width > 1 {
				t = float64(column) / float64(width-1)
			}
			c := from.BlendLuv(to, t).Clamped()
			out.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(c.Hex())).Render(string(r)))
		}
	}
	return out.String()
}

func banner(words copyText, width int) string {
	logo := asciiLogo
	// ANSI Shadow is intentionally wide. On a narrow terminal, showing the
	// full glyph would make lipgloss grow the frame and the terminal clip it.
	// Keep the brand visible with a compact fallback until the window is wide
	// enough to render the complete ANSI Shadow wordmark.
	if width > 0 && ansi.StringWidth(strings.Split(asciiLogo, "\n")[0]) > width {
		logo = "AEGIS"
	}
	logo = gradientBlock(logo, brandFrom, brandTo)
	tagline := gradientText(words.tagline, brandFrom, brandTo)
	hint := lipgloss.NewStyle().Foreground(lipgloss.Color("#7A8A87")).Render(words.bannerHint)
	return logo + "\n\n" + tagline + "\n" + hint
}
