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
	// Enable wheel events so the output viewport can be browsed without leaving
	// the full-screen interface. Keyboard scrolling remains available too.
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())
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

	menu   *menuNode // the action menu shown at the bottom
	wizard *wizard   // active guided prompt, or nil
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
	// Start in command mode. The root action menu opens after a main command;
	// submenus and guided choices then use ↑↓ + Enter.
	m.menu = nil
	// The banner is chrome, not conversation: it is rendered by syncViewport,
	// so it stays out of the transcript that /copy captures.
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
	case tea.MouseMsg:
		var command tea.Cmd
		m.vp, command = m.vp.Update(msg)
		commands = append(commands, command)
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" || msg.String() == "ctrl+d" {
			m.exiting = true
			_ = m.pipeW.Close()
			return m, tea.Quit
		}
		switch {
		case m.inSecret:
			if msg.String() == "enter" {
				return m, m.submit()
			}
			// other keys fall through to the input field
		case m.wizard != nil:
			if command, handled := m.wizardKey(msg); handled {
				return m, command
			}
			// free-text wizard steps fall through to the input field
		default:
			switch msg.String() {
			case "ctrl+y":
				return m, m.copyTranscript()
			case "up":
				if m.menu != nil {
					m.menuMove(-1)
					return m, nil
				}
			case "down":
				if m.menu != nil {
					m.menuMove(1)
					return m, nil
				}
			case "esc":
				m.goBack()
				return m, nil
			case "tab":
				// Complete a typed slash command; never insert a literal Tab.
				m.complete()
				return m, nil
			case "enter":
				return m, m.submit()
			case "pgup", "pgdown":
				var command tea.Cmd
				m.vp, command = m.vp.Update(msg)
				commands = append(commands, command)
			}
		}
	case outputMsg:
		line := string(msg)
		if !strings.HasPrefix(line, "aegis interactive mode") {
			m.appendRaw(line)
		}
		commands = append(commands, m.waitOutput())
	case secretMsg:
		m.inSecret = true
		m.ti.EchoMode = textinput.EchoPassword
		m.ti.Placeholder = string(msg)
		m.resize()
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
		m.resize()
		m.secretResp <- value
		return nil
	}

	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		// Empty input + Enter activates the highlighted menu item.
		if m.wizard == nil && m.menu != nil {
			return m.activateMenu()
		}
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
	if trimmed == "/clear" {
		m.clearScreen()
		return nil
	}
	if m.handleLanguageCommand(trimmed) {
		return nil
	}
	if m.menu == nil {
		if handled, command := m.handleMainCommand(trimmed); handled {
			return command
		}
	}
	// Interactive reviews expose the public AI response and tool-event stream by
	// default. The plain CLI remains opt-in through --watch.
	trimmed = addWatchFlag(trimmed)
	go func() { _, _ = io.WriteString(m.pipeW, trimmed+"\n") }()
	return nil
}

// handleMainCommand enters the guided UI for an exact top-level command.
// Commands with arguments continue through the console dispatcher so the
// traditional CLI remains available.
func (m *model) handleMainCommand(line string) (bool, tea.Cmd) {
	fields := strings.Fields(line)
	if len(fields) != 1 {
		return false, nil
	}
	command := strings.TrimPrefix(strings.ToLower(fields[0]), "/")
	root := rootMenu(m)
	for i := range root.items {
		if rootCommandName(i, command) {
			m.menu = root
			m.menu.cursor = i
			return true, m.activateMenu()
		}
	}
	return false, nil
}

func rootCommandName(index int, command string) bool {
	aliases := [...]map[string]bool{
		{"review": true},
		{"scan": true},
		{"provider": true, "providers": true},
		{"model": true, "models": true},
		{"status": true},
		{"doctor": true},
		{"lang": true, "language": true},
		{"clear": true},
		{"quit": true, "exit": true},
	}
	return aliases[index][command]
}

// complete performs Tab-completion on the slash command being typed: with one
// match it fills the full command and a trailing space (ready for arguments);
// with several it extends the input to their longest common prefix, leaving the
// candidate list visible in the hint line. It only acts on the first token, so
// Tab is inert once a command and its arguments are being entered.
func (m *model) complete() {
	value := m.ti.Value()
	if !strings.HasPrefix(value, "/") || strings.ContainsAny(value, " \t") {
		return
	}
	var hits []string
	for _, command := range slashCommands {
		if strings.HasPrefix(command.name, value) {
			hits = append(hits, command.name)
		}
	}
	if len(hits) == 0 {
		return
	}
	if len(hits) == 1 {
		m.ti.SetValue(hits[0] + " ")
		m.ti.CursorEnd()
		return
	}
	if prefix := longestCommonPrefix(hits); len(prefix) > len(value) {
		m.ti.SetValue(prefix)
		m.ti.CursorEnd()
	}
}

func longestCommonPrefix(values []string) string {
	if len(values) == 0 {
		return ""
	}
	prefix := values[0]
	for _, value := range values[1:] {
		for !strings.HasPrefix(value, prefix) {
			prefix = prefix[:len(prefix)-1]
			if prefix == "" {
				return ""
			}
		}
	}
	return prefix
}

// clearScreen empties the transcript and repaints the banner, like Claude
// Code's /clear — a fresh screen without leaving interactive mode. The audit
// logs and any run artifacts on disk are untouched.
func (m *model) clearScreen() {
	m.transcript.Reset()
	m.menu = nil
	m.syncViewport()
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
	wasAtBottom := m.vp.AtBottom()
	m.vp.SetContent(m.header() + "\n\n" + m.wrap(m.transcript.String()))
	if wasAtBottom {
		m.vp.GotoBottom()
	}
}

// header is the left-aligned banner (logo, tagline, hint) shown at the top of
// the scrollback.
func (m *model) header() string {
	width := 0
	if m.w > 0 {
		width = m.contentWidth()
	}
	result := banner(translations[m.lang], width)
	if m.compactLayout() {
		// Keep the actual ANSI Shadow wordmark in short terminals. Only remove
		// secondary banner copy; replacing the logo with plain text looks broken.
		logo := asciiLogo
		if width > 0 && lipgloss.Width(logo) > width {
			logo = "AEGIS"
		}
		result = gradientBlock(logo, brandFrom, brandTo) + "\n" +
			gradientText(translations[m.lang].tagline, brandFrom, brandTo)
	}
	if width == 0 {
		return result
	}
	// The outer frame is centered, but the original CLI composition is
	// intentionally left-aligned: logo, menu, and input share the same visual
	// starting edge.
	return lipgloss.NewStyle().Width(width).Align(lipgloss.Left).Render(result)
}

func (m *model) compactLayout() bool {
	return m.h > 0 && m.h < 30
}

func (m *model) wrap(value string) string {
	return lipgloss.NewStyle().Width(m.contentWidth()).Render(value)
}

// contentWidth is the usable width inside the outer app frame: screen width
// minus the frame's border (2) and horizontal padding (4).
func (m *model) contentWidth() int {
	w := m.w - appFrameHorizontal
	if w < 1 {
		w = 1
	}
	return w
}

func (m *model) layout() {
	if !m.ready {
		m.vp = viewport.New(m.contentWidth(), 1)
		m.ready = true
	}
	// Leave room for the input prompt plus the input box border/padding. The
	// textinput width is the editable content width, not the rendered box width.
	m.ti.Width = max(m.contentWidth()-10, 1)
	m.resize()
}

// resize fits the viewport to whatever space the bottom control block leaves,
// so the outer frame always fills the screen exactly.
func (m *model) resize() {
	if !m.ready {
		return
	}
	controlH := lipgloss.Height(m.controlBlock())
	vpHeight := m.h - appFrameVertical - controlH
	if vpHeight < 1 {
		vpHeight = 1
	}
	m.vp.Width = m.contentWidth()
	m.vp.Height = vpHeight
	m.syncViewport()
}

func (m *model) View() string {
	if !m.ready {
		return translations[m.lang].starting
	}
	inner := m.vp.View() + "\n" + m.controlBlock()
	frame := appFrame.Width(m.contentWidth()).Render(inner)
	if m.w > 0 {
		// Keep the frame itself narrower than the terminal by a small gutter, then
		// place it centrally. Without PlaceHorizontal, lipgloss leaves all spare
		// cells on the right, which makes the interface look lopsided.
		return lipgloss.PlaceHorizontal(m.w, lipgloss.Center, frame)
	}
	return frame
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
			BorderForeground(lipgloss.Color(frameColor)).Padding(0, 1)
	// appFrame is the single rounded border wrapping the whole interface.
	appFrame = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color(frameColor)).Padding(1, 2)
)

// Dim frame color, and the space the outer app frame consumes: rounded border
// (1 each side) plus padding (2 left/right, 1 top/bottom).
const (
	frameColor         = "#33474A"
	appFrameHorizontal = 2 + 4 // border + horizontal padding
	// lipgloss's rounded border contributes one additional terminal row on
	// render (corner/edge handling), so reserve the measured five rows.
	appFrameVertical = 5
)

type chanWriter struct{ ch chan string }

func (w chanWriter) Write(p []byte) (int, error) {
	w.ch <- string(p)
	return len(p), nil
}

var writeClipboard = clipboard.WriteAll
