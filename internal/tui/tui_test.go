package tui

import (
	"path/filepath"
	"testing"

	"github.com/aegis-dev/aegis/internal/settings"
)

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
