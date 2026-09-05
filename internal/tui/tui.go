package tui

import (
	"context"
	"io"
	"strings"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/aegis-dev/aegis/internal/console"
	"github.com/aegis-dev/aegis/internal/settings"
)

// Run starts the full-screen interface while reusing the console command
// dispatcher. English is the default; /lang en|zh changes and persists it.
func Run(deps console.Deps) error {
	m := newModel(deps)
	// Keep terminal-native drag selection and Cmd+C available. Keyboard scrolling
	// still controls the viewport, so mouse tracking is unnecessary here.
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

type (
	outputMsg     string
	doneMsg       error
	secretMsg     string
	copyResultMsg struct{ err error }
)

type model struct {
	vp    viewport.Model
	ti    textinput.Model
	ready bool
	w, h  int

	transcript strings.Builder
	pipeW      *io.PipeWriter
	outCh      chan string
	doneCh     chan error
	secretReq  chan string
	secretResp chan string

	settingsPath string
	lang         language
	inSecret     bool
	exiting      bool
}

func newModel(deps console.Deps) *model {
	lang := languageEnglish
	if cfg, err := settings.Load(deps.UserConfigPath); err == nil {
		lang = normalizeLanguage(cfg.UI.Language)
	}
	reader, writer := io.Pipe()
	m := &model{
		pipeW: writer, outCh: make(chan string, 64), doneCh: make(chan error, 1),
		secretReq: make(chan string, 1), secretResp: make(chan string, 1),
		settingsPath: deps.UserConfigPath, lang: lang,
	}
	deps.In = reader
	deps.Out = chanWriter{m.outCh}
	deps.ReadSecret = func(prompt string) ([]byte, error) {
		m.secretReq <- prompt
		return []byte(<-m.secretResp), nil
	}
	if deps.Context == nil {
		deps.Context = context.Background()
	}
	go func() { m.doneCh <- console.Run(deps) }()

	ti := textinput.New()
	ti.Prompt = ""
	ti.Focus()
	ti.CharLimit = 0
	ti.Cursor.Style = lipgloss.NewStyle().Foreground(lipgloss.Color(brandTo.Hex()))
	m.ti = ti
	m.applyLanguage()
	m.transcript.WriteString(banner(translations[m.lang]))
	m.transcript.WriteString("\n\n")
	return m
}

func (m *model) Init() tea.Cmd {
	return tea.Batch(m.waitOutput(), m.waitDone(), m.waitSecret(), textinput.Blink)
}

func (m *model) waitOutput() tea.Cmd { return func() tea.Msg { return outputMsg(<-m.outCh) } }
func (m *model) waitDone() tea.Cmd   { return func() tea.Msg { return doneMsg(<-m.doneCh) } }
func (m *model) waitSecret() tea.Cmd { return func() tea.Msg { return secretMsg(<-m.secretReq) } }

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var commands []tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		m.layout()
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "ctrl+d":
			m.exiting = true
			_ = m.pipeW.Close()
			return m, tea.Quit
		case "enter":
			return m, m.submit()
		case "ctrl+y":
			return m, m.copyTranscript()
		case "pgup", "pgdown", "up", "down":
			var command tea.Cmd
			m.vp, command = m.vp.Update(msg)
			commands = append(commands, command)
		}
	case outputMsg:
		line := string(msg)
		if !strings.HasPrefix(line, "aegis 互動模式") {
			m.appendRaw(line)
		}
		commands = append(commands, m.waitOutput())
	case secretMsg:
		m.inSecret = true
		m.ti.EchoMode = textinput.EchoPassword
		m.ti.Placeholder = string(msg)
		commands = append(commands, m.waitSecret())
	case doneMsg:
		if !m.exiting {
			return m, tea.Quit
		}
	case copyResultMsg:
		if msg.err != nil {
			m.appendLine(errorStyle.Render(translations[m.lang].copyError + msg.err.Error()))
		} else {
			m.appendLine(successStyle.Render(translations[m.lang].copySuccess))
		}
	}
	if _, ok := msg.(tea.KeyMsg); ok || m.ready {
		var command tea.Cmd
		m.ti, command = m.ti.Update(msg)
		commands = append(commands, command)
	}
	return m, tea.Batch(commands...)
}

func (m *model) submit() tea.Cmd {
	value := m.ti.Value()
	m.ti.Reset()
	words := translations[m.lang]
	if m.inSecret {
		m.inSecret = false
		m.ti.EchoMode = textinput.EchoNormal
		m.ti.Placeholder = words.placeholder
		m.appendLine(promptStyle.Render("› ") + dimStyle.Render(words.hiddenInput))
		m.secretResp <- value
		return nil
	}

	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	m.appendLine(promptStyle.Render("› ") + userStyle.Render(trimmed))
	if trimmed == "exit" || trimmed == "quit" {
		m.exiting = true
		_ = m.pipeW.Close()
		return tea.Quit
	}
	if trimmed == "/help" {
		m.showHelp()
		return nil
	}
	if trimmed == "/copy" {
		return m.copyTranscript()
	}
	if m.handleLanguageCommand(trimmed) {
		return nil
	}
	// Interactive reviews expose the public AI response and tool-event stream by
	// default. The plain CLI remains opt-in through --watch.
	trimmed = addWatchFlag(trimmed)
	go func() { _, _ = io.WriteString(m.pipeW, trimmed+"\n") }()
	return nil
}

func (m *model) copyTranscript() tea.Cmd {
	plainText := ansi.Strip(m.transcript.String())
	return func() tea.Msg { return copyResultMsg{err: writeClipboard(plainText)} }
}

func (m *model) showHelp() {
	heading := "Commands"
	if m.lang == languageChinese {
		heading = "可用指令"
	}
	m.appendLine(cmdStyle.Bold(true).Render(heading))
	for _, command := range slashCommands {
		m.appendLine("  " + cmdStyle.Render(command.name) + "  " + commandDescription(command, m.lang))
	}
}

func (m *model) handleLanguageCommand(line string) bool {
	fields := strings.Fields(line)
	if len(fields) == 0 || (fields[0] != "/lang" && fields[0] != "/language") {
		return false
	}
	if len(fields) != 2 {
		m.appendLine(errorStyle.Render(translations[m.lang].languageUsage))
		return true
	}
	value := strings.ToLower(fields[1])
	if value != "en" && value != "english" && value != "zh" && value != "zh-tw" && fields[1] != "中文" {
		m.appendLine(errorStyle.Render(translations[m.lang].languageUsage))
		return true
	}
	m.lang = normalizeLanguage(fields[1])
	m.applyLanguage()
	m.appendLine(successStyle.Render(translations[m.lang].languageChanged))
	if err := m.saveLanguage(); err != nil {
		m.appendLine(errorStyle.Render(translations[m.lang].preferenceError + err.Error()))
	}
	return true
}

func (m *model) saveLanguage() error {
	cfg, err := settings.Load(m.settingsPath)
	if err != nil {
		return err
	}
	cfg.UI.Language = string(m.lang)
	return settings.SaveUser(m.settingsPath, cfg)
}

func (m *model) applyLanguage() {
	if m.inSecret {
		return
	}
	m.ti.Placeholder = translations[m.lang].placeholder
}

func addWatchFlag(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return line
	}
	switch fields[0] {
	case "/review", "/scan", "/prove", "/report":
		for _, field := range fields[1:] {
			if field == "--watch" || strings.HasPrefix(field, "--watch=") {
				return line
			}
		}
		return line + " --watch"
	default:
		return line
	}
}

func (m *model) appendRaw(value string) {
	m.transcript.WriteString(value)
	m.syncViewport()
}

func (m *model) appendLine(value string) {
	m.transcript.WriteString(value)
	m.transcript.WriteByte('\n')
	m.syncViewport()
}

func (m *model) syncViewport() {
	if !m.ready {
		return
	}
	m.vp.SetContent(m.wrap(m.transcript.String()))
	m.vp.GotoBottom()
}

func (m *model) wrap(value string) string {
	if m.w <= 2 {
		return value
	}
	return lipgloss.NewStyle().Width(m.w - 2).Render(value)
}

func (m *model) layout() {
	viewportHeight := m.h - 4
	if viewportHeight < 1 {
		viewportHeight = 1
	}
	if !m.ready {
		m.vp = viewport.New(m.w, viewportHeight)
		m.ready = true
	} else {
		m.vp.Width = m.w
		m.vp.Height = viewportHeight
	}
	m.ti.Width = max(m.w-6, 1)
	m.syncViewport()
}

func (m *model) View() string {
	words := translations[m.lang]
	if !m.ready {
		return words.starting
	}
	prompt := promptStyle.Render(" › ")
	if m.inSecret {
		prompt = lipgloss.NewStyle().Foreground(lipgloss.Color(brandFrom.Hex())).Render(" 🔒 ")
	}
	width := max(m.w-2, 1)
	box := inputBox.Width(width).Render(prompt + m.ti.View())
	return m.vp.View() + "\n" + box + "\n" + m.hintLine()
}

func (m *model) hintLine() string {
	words := translations[m.lang]
	if m.inSecret {
		return dimStyle.Render(words.secretHint)
	}
	value := strings.TrimSpace(m.ti.Value())
	if strings.HasPrefix(value, "/") {
		var hits []string
		for _, command := range slashCommands {
			if strings.HasPrefix(command.name, value) {
				hits = append(hits, cmdStyle.Render(command.name)+dimStyle.Render(" "+commandDescription(command, m.lang)))
			}
		}
		if len(hits) > 0 {
			if len(hits) > 3 {
				hits = hits[:3]
			}
			return "  " + strings.Join(hits, dimStyle.Render(" · "))
		}
	}
	return dimStyle.Render(words.normalHint)
}

var (
	promptStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color(brandTo.Hex())).Bold(true)
	userStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#E6EDEB")).Bold(true)
	cmdStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color(brandFrom.Hex()))
	dimStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("#6B7A77"))
	errorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#F87171"))
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color(brandTo.Hex()))
	inputBox     = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color(brandFrom.Hex())).Padding(0, 1)
)

type chanWriter struct{ ch chan string }

func (w chanWriter) Write(p []byte) (int, error) {
	w.ch <- string(p)
	return len(p), nil
}

var writeClipboard = clipboard.WriteAll
