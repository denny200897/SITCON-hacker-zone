package tui

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/aegis-dev/aegis/internal/approval"
	"github.com/aegis-dev/aegis/internal/settings"
)

func TestDragAutoScrollPreservesAnchorAndStopsOnRelease(t *testing.T) {
	m := &model{w: 100, h: 30, lang: languageEnglish, ti: textinput.New()}
	m.layout()
	m.appendRaw(strings.Repeat("output line\n", 100))
	m.vp.SetYOffset(30)
	m.handleMouseSelection(tea.MouseMsg{Button: tea.MouseButtonLeft, Action: tea.MouseActionPress, Y: 5})
	anchor := m.selection.startLine
	m.selection.endY = 2 + m.vp.Height
	before := m.vp.YOffset
	m.scrollSelection()
	if m.vp.YOffset != before+1 || m.selection.startLine != anchor {
		t.Fatal("downward drag must scroll while keeping its document anchor")
	}
	m.selection.endY = 0
	m.scrollSelection()
	if m.vp.YOffset != before || m.selection.startLine != anchor {
		t.Fatal("upward drag must scroll while keeping its document anchor")
	}
	m.selection.final = true
	m.scrollSelection()
	if m.vp.YOffset != before {
		t.Fatal("finished selection must not scroll")
	}
}

func TestCompleteFillsUniqueCommandAndSharedPrefix(t *testing.T) {
	tests := map[string]string{
		"/he":  "/help ",   // unique match: full command + trailing space
		"/rev": "/review ", // unique match despite /report, /replay sharing a prefix
		"/re":  "/re",      // /review, /report, /replay share only "/re"
		"/z":   "/z",       // no match: unchanged
		"/rep": "/rep",     // /report, /replay share "/rep"; no forward progress
		"hi":   "hi",       // not a slash command: unchanged
	}
	for input, want := range tests {
		m := &model{ti: textinput.New()}
		m.ti.SetValue(input)
		m.complete()
		if got := m.ti.Value(); got != want {
			t.Errorf("complete(%q) => %q, want %q", input, got, want)
		}
	}
}

func TestViewStaysInsideNarrowTerminal(t *testing.T) {
	m := &model{w: 56, h: 24, lang: languageEnglish, menu: &menuNode{}}
	m.ti = textinput.New()
	m.menu = rootMenu(m)
	m.layout()
	view := m.View()
	if got := lipgloss.Width(view); got > m.w {
		t.Fatalf("view width = %d, exceeds terminal width %d", got, m.w)
	}
	if got := lipgloss.Height(view); got > m.h {
		t.Fatalf("view height = %d, exceeds terminal height %d", got, m.h)
	}
}

func TestChineseLanguageLocalizesMenusAndWizard(t *testing.T) {
	m := &model{w: 100, h: 40, lang: languageChinese, menu: rootMenu(nil)}
	m.ti = textinput.New()
	if got := m.menuView(); !strings.Contains(got, "檢視儲存庫") || strings.Contains(got, "Review a repository") {
		t.Fatalf("root menu was not localized: %s", got)
	}
	m.menu = providersMenu()
	if got := m.menuView(); !strings.Contains(got, "新增供應商") || strings.Contains(got, "Add a provider") {
		t.Fatalf("provider menu was not localized: %s", got)
	}
	reviewWizard(m)
	if got := m.wizardView(); !strings.Contains(got, "檢視儲存庫") || !strings.Contains(got, "儲存庫路徑") {
		t.Fatalf("wizard was not localized: %s", got)
	}
}

func TestClearScreenWipesTranscriptAndHeaderShowsBanner(t *testing.T) {
	m := &model{lang: languageEnglish}
	m.transcript.WriteString("some earlier review output that should be wiped\n")
	m.clearScreen()
	if strings.Contains(m.transcript.String(), "earlier review output") {
		t.Fatalf("clearScreen left prior output:\n%s", m.transcript.String())
	}
	// The banner lives in header() (centered chrome), not the transcript.
	if !strings.Contains(m.header(), translations[languageEnglish].tagline) {
		t.Fatalf("header did not render the banner:\n%s", m.header())
	}
}

func TestCompleteIgnoresInputWithArguments(t *testing.T) {
	m := &model{ti: textinput.New()}
	m.ti.SetValue("/model set")
	m.complete()
	if got := m.ti.Value(); got != "/model set" {
		t.Errorf("complete left argument input as %q, want unchanged", got)
	}
}

func TestMainCommandOpensGuidedUI(t *testing.T) {
	m := &model{lang: languageEnglish, ti: textinput.New()}

	if handled, _ := m.handleMainCommand("providers"); !handled {
		t.Fatal("providers was not recognized as a main command")
	}
	if m.menu == nil || m.menu.parent == nil {
		t.Fatal("providers did not open its submenu")
	}

	m.menu = nil
	if handled, _ := m.handleMainCommand("review"); !handled {
		t.Fatal("review was not recognized as a main command")
	}
	if m.wizard == nil {
		t.Fatal("review did not open its guided wizard")
	}
}

func TestNormalizeLanguageDefaultsToEnglish(t *testing.T) {
	tests := map[string]language{
		"":        languageEnglish,
		"en":      languageEnglish,
		"unknown": languageEnglish,
		"zh":      languageChinese,
		"zh-TW":   languageChinese,
		"中文":      languageChinese,
	}
	for input, want := range tests {
		if got := normalizeLanguage(input); got != want {
			t.Errorf("normalizeLanguage(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestAddWatchFlagForInteractiveAICommands(t *testing.T) {
	tests := map[string]string{
		"/review .":            "/review . --watch",
		"/scan --target .":     "/scan --target . --watch",
		"/prove --watch":       "/prove --watch",
		"/report --watch=true": "/report --watch=true",
		"/replay":              "/replay",
		"/help":                "/help",
	}
	for input, want := range tests {
		if got := addWatchFlag(input); got != want {
			t.Errorf("addWatchFlag(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNativeBuildApprovalUsesArrowKeysAndEnter(t *testing.T) {
	m := &model{
		ti: textinput.New(), w: 100,
		approvalResp: make(chan approval.Decision, 1),
		approvalReq:  make(chan approval.BuildRequest, 1),
	}
	req := approval.BuildRequest{Pack: "go-web", Image: "golang@sha256:test", BuildDir: "/packs/go-web", Network: "pinned", RunNetwork: "none"}
	updated, _ := m.Update(approvalMsg(req))
	m = updated.(*model)
	if m.approval == nil || !strings.Contains(m.approvalView(), "golang@sha256:test") {
		t.Fatal("approval modal was not rendered")
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = updated.(*model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(*model)
	if m.approval != nil {
		t.Fatal("approval modal remained open after Enter")
	}
	if got := <-m.approvalResp; got != approval.AllowRun {
		t.Fatalf("decision=%v, want AllowRun", got)
	}
}

func TestSaveLanguagePersistsChinesePreference(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.toml")
	m := &model{settingsPath: path, lang: languageChinese}
	if err := m.saveLanguage(); err != nil {
		t.Fatal(err)
	}
	cfg, err := settings.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UI.Language != "zh-TW" {
		t.Fatalf("UI.Language = %q, want zh-TW", cfg.UI.Language)
	}
}
