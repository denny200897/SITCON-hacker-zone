package tui

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/aegis-dev/aegis/internal/console"
)

// slashCommands 是輸入框的即時提示來源（與 console.dispatch 支援的指令一致）。
var slashCommands = []struct{ name, desc string }{
	{"/help", "顯示所有指令"},
	{"/status", "供應商、金鑰、路由、Docker 狀態"},
	{"/doctor", "體檢（Docker、映像、供應商連通）"},
	{"/provider", "list | add <name> | remove <name>"},
	{"/key", "set <provider> | clear <provider>"},
	{"/model", "list | set <role|all> <ref> | reset"},
	{"/review", "一鍵掃描、實證、重驗並產生報告"},
	{"/scan", "僅掃描目標 repo"},
	{"/prove", "證明指定 finding"},
	{"/report", "產生 findings、SARIF 與 Markdown 報告"},
	{"/replay", "離線重驗 evidence bundle"},
}

// Run 啟動對話式 TUI。deps 由 cmd 層組裝（Keyring / Doctor / RunCommand 等），
// 本函式覆寫其中的 In / Out / ReadSecret，讓底層 console.Run 的輸入輸出接到
// 終端機 UI；所有 slash 指令邏輯完全重用，不另立第二套實作。
func Run(deps console.Deps) error {
	m := newModel(deps)
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())
	_, err := p.Run()
	return err
}

// ── 訊息型別 ─────────────────────────────────────────────────────────────
type (
	outputMsg  string // console 輸出的一段文字
	doneMsg    error  // console.Run 結束（EOF / quit）
	secretMsg  string // console 透過 ReadSecret 索取密鑰，附提示文字
)

type model struct {
	vp    viewport.Model
	ti    textinput.Model
	ready bool
	w, h  int

	transcript strings.Builder // 累積的對話內容（含 ANSI）

	pipeW      *io.PipeWriter
	outCh      chan string
	doneCh     chan error
	secretReq  chan string
	secretResp chan string

	inSecret bool
	exiting  bool
}

func newModel(deps console.Deps) *model {
	pr, pw := io.Pipe()
	m := &model{
		pipeW:      pw,
		outCh:      make(chan string, 64),
		doneCh:     make(chan error, 1),
		secretReq:  make(chan string, 1),
		secretResp: make(chan string, 1),
	}

	// 覆寫 I/O：console 從 pipe 讀取使用者輸入，輸出推入 outCh。
	deps.In = pr
	deps.Out = chanWriter{m.outCh}
	deps.ReadSecret = func(prompt string) ([]byte, error) {
		m.secretReq <- prompt
		return []byte(<-m.secretResp), nil
	}
	if deps.Context == nil {
		deps.Context = context.Background()
	}

	go func() {
		err := console.Run(deps)
		m.doneCh <- err
	}()

	ti := textinput.New()
	ti.Placeholder = "輸入指令或 /help …"
	ti.Prompt = ""
	ti.Focus()
	ti.CharLimit = 0
	ti.Cursor.Style = lipgloss.NewStyle().Foreground(lipgloss.Color(brandTo.Hex()))
	m.ti = ti

	m.transcript.WriteString(banner())
	m.transcript.WriteString("\n\n")
	return m
}

func (m *model) Init() tea.Cmd {
	return tea.Batch(m.waitOutput(), m.waitDone(), m.waitSecret(), textinput.Blink)
}

// ── tea.Cmd：跨 goroutine 等待事件 ──────────────────────────────────────
func (m *model) waitOutput() tea.Cmd {
	return func() tea.Msg { return outputMsg(<-m.outCh) }
}
func (m *model) waitDone() tea.Cmd {
	return func() tea.Msg { return doneMsg(<-m.doneCh) }
}
func (m *model) waitSecret() tea.Cmd {
	return func() tea.Msg { return secretMsg(<-m.secretReq) }
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		m.layout()

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "ctrl+d":
			m.exiting = true
			_ = m.pipeW.Close() // EOF → console.Run 收尾
			return m, tea.Quit
		case "enter":
			return m, m.submit()
		case "pgup", "pgdown", "up", "down":
			var cmd tea.Cmd
			m.vp, cmd = m.vp.Update(msg)
			cmds = append(cmds, cmd)
		}

	case outputMsg:
		line := string(msg)
		// 略過 console 開場白（TUI 已有 banner）。
		if !strings.HasPrefix(line, "aegis 互動模式") {
			m.appendRaw(line)
		}
		cmds = append(cmds, m.waitOutput())

	case secretMsg:
		m.inSecret = true
		m.ti.EchoMode = textinput.EchoPassword
		m.ti.Placeholder = string(msg)
		cmds = append(cmds, m.waitSecret())

	case doneMsg:
		if !m.exiting {
			return m, tea.Quit
		}
	}

	// 一般按鍵交給輸入框（含捲動鍵已在上面處理）。
	if _, ok := msg.(tea.KeyMsg); ok || m.ready {
		var cmd tea.Cmd
		m.ti, cmd = m.ti.Update(msg)
		cmds = append(cmds, cmd)
	}
	return m, tea.Batch(cmds...)
}

// submit 處理 Enter：密鑰模式回傳給 console.ReadSecret；否則把整行寫入 pipe。
func (m *model) submit() tea.Cmd {
	val := m.ti.Value()
	m.ti.Reset()

	if m.inSecret {
		m.inSecret = false
		m.ti.EchoMode = textinput.EchoNormal
		m.ti.Placeholder = "輸入指令或 /help …"
		m.appendLine(promptStyle.Render("› ") + dimStyle.Render("（已隱藏輸入）"))
		m.secretResp <- val
		return nil
	}

	trimmed := strings.TrimSpace(val)
	if trimmed == "" {
		return nil
	}
	m.appendLine(promptStyle.Render("› ") + userStyle.Render(trimmed))
	if trimmed == "exit" || trimmed == "quit" {
		m.exiting = true
		_ = m.pipeW.Close()
		return tea.Quit
	}
	// 寫入 pipe → console 讀取並派工，輸出經 outCh 回流。
	go func() { _, _ = io.WriteString(m.pipeW, val+"\n") }()
	return nil
}

// ── 內容累積與版面 ───────────────────────────────────────────────────────
func (m *model) appendRaw(s string) {
	m.transcript.WriteString(s)
	m.syncViewport()
}
func (m *model) appendLine(s string) {
	m.transcript.WriteString(s)
	m.transcript.WriteString("\n")
	m.syncViewport()
}
func (m *model) syncViewport() {
	if !m.ready {
		return
	}
	m.vp.SetContent(m.wrap(m.transcript.String()))
	m.vp.GotoBottom()
}

func (m *model) wrap(s string) string {
	if m.w <= 0 {
		return s
	}
	return lipgloss.NewStyle().Width(m.w - 2).Render(s)
}

func (m *model) layout() {
	inputH := 3 // 邊框 + 一行
	hintH := 1
	vpH := m.h - inputH - hintH
	if vpH < 1 {
		vpH = 1
	}
	if !m.ready {
		m.vp = viewport.New(m.w, vpH)
		m.ready = true
	} else {
		m.vp.Width = m.w
		m.vp.Height = vpH
	}
	m.ti.Width = m.w - 6
	m.syncViewport()
}

// ── View ─────────────────────────────────────────────────────────────────
func (m *model) View() string {
	if !m.ready {
		return "啟動中…"
	}
	prompt := promptStyle.Render(" › ")
	if m.inSecret {
		prompt = lipgloss.NewStyle().Foreground(lipgloss.Color(brandFrom.Hex())).Render(" 🔒 ")
	}
	box := inputBox.Width(m.w - 2).Render(prompt + m.ti.View())
	return m.vp.View() + "\n" + box + "\n" + m.hintLine()
}

// hintLine 顯示 slash 提示（輸入以 / 開頭時）或簡短狀態。
func (m *model) hintLine() string {
	v := strings.TrimSpace(m.ti.Value())
	if m.inSecret {
		return dimStyle.Render("  🔒 密鑰輸入模式 · Enter 儲存 · 內容永不顯示或落盤明文")
	}
	if strings.HasPrefix(v, "/") {
		var hits []string
		for _, c := range slashCommands {
			if strings.HasPrefix(c.name, v) {
				hits = append(hits, cmdStyle.Render(c.name)+dimStyle.Render(" "+c.desc))
			}
		}
		if len(hits) > 0 {
			if len(hits) > 3 {
				hits = hits[:3]
			}
			return "  " + strings.Join(hits, dimStyle.Render(" · "))
		}
	}
	return dimStyle.Render("  /help 指令 · ↑↓/PgUp 捲動 · Ctrl+C 離開")
}

// ── 樣式 ─────────────────────────────────────────────────────────────────
var (
	promptStyle = lipgloss.NewStyle().Foreground(lipgloss.Color(brandTo.Hex())).Bold(true)
	userStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#E6EDEB")).Bold(true)
	cmdStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color(brandFrom.Hex()))
	dimStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#6B7A77"))
	inputBox    = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color(brandFrom.Hex())).
			Padding(0, 1)
)

// chanWriter 把 console 的輸出（io.Writer）轉發到 channel，供 TUI 逐段消費。
type chanWriter struct{ ch chan string }

func (w chanWriter) Write(p []byte) (int, error) {
	w.ch <- string(p)
	return len(p), nil
}

var _ = fmt.Sprint // 保留 fmt 以便日後除錯輸出
