package tui

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/textinput"

	"github.com/aegis-dev/aegis/internal/settings"
)

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

func TestCopyTranscriptStripsANSI(t *testing.T) {
	old := writeClipboard
	t.Cleanup(func() { writeClipboard = old })
	var copied string
	writeClipboard = func(value string) error {
		copied = value
		return nil
	}
	m := &model{}
	m.transcript.WriteString("\x1b[31mdoctor result\x1b[0m\n")
	msg, ok := m.copyTranscript()().(copyResultMsg)
	if !ok {
		t.Fatal("copy command returned unexpected message type")
	}
	if msg.err != nil {
		t.Fatal(msg.err)
	}
	if copied != "doctor result\n" {
		t.Fatalf("copied transcript = %q, want plain text", copied)
	}
}
