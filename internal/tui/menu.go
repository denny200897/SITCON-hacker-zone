package tui

// Menu-driven navigation layer over the console REPL. Actions are chosen with
// ↑↓ + Enter instead of typed; the same commands are still typeable in the
// input box, which stays visible below the menu. Selecting an action either
// runs a command, opens a submenu, or starts a short guided wizard whose
// answers are composed into the exact command line(s) sent to the console pipe.

import (
	"io"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/aegis-dev/aegis/internal/settings"
)

// menuNode is one navigable menu: a list of choices, optionally nested under a
// parent so Esc can walk back up.
type menuNode struct {
	items  []menuItem
	cursor int
	parent *menuNode
}

type menuItem struct {
	label   string
	desc    string
	labelZH string
	descZH  string
	// act performs the item; it may open a submenu, start a wizard, or run a
	// command, and returns any resulting tea.Cmd.
	act func(m *model) tea.Cmd
}

func (it menuItem) text(lang language) (string, string) {
	if lang == languageChinese {
		return firstNonEmpty(it.labelZH, it.label), it.descZH
	}
	return it.label, it.desc
}

// wizStep is one guided prompt. With options it is a select (↑↓ + Enter);
// without, it is free text entered in the input box. skip omits the step based
// on earlier answers.
type wizStep struct {
	prompt   string
	promptZH string
	key      string
	options  []wizOption
	skip     func(values map[string]string) bool
}

type wizOption struct{ label, labelZH, value string }

// wizard is a short sequence of steps that builds one or more command lines.
type wizard struct {
	title   string
	titleZH string
	steps   []wizStep
	idx     int
	cursor  int
	values  map[string]string
	build   func(m *model, values map[string]string) tea.Cmd
}

func (w *wizard) current() wizStep { return w.steps[w.idx] }

func (m *model) wizardPrompt(step wizStep) string {
	if m.lang == languageChinese && step.promptZH != "" {
		return step.promptZH
	}
	return step.prompt
}

// --- menu construction -------------------------------------------------------

func rootMenu(m *model) *menuNode {
	return &menuNode{items: []menuItem{
		{label: "Review a repository", labelZH: "檢視儲存庫", desc: "scan → prove → report", descZH: "掃描 → 實證 → 報告", act: reviewWizard},
		{label: "Scan a repository", labelZH: "掃描儲存庫", desc: "scan only", descZH: "僅執行掃描", act: scanWizard},
		{label: "Providers & API keys", labelZH: "供應商與 API 金鑰", desc: "add, set key, remove", descZH: "新增、設定金鑰、移除", act: func(m *model) tea.Cmd { m.openMenu(providersMenu()); return nil }},
		{label: "Model routing", labelZH: "模型路由", desc: "which model runs each role", descZH: "設定各角色使用的模型", act: func(m *model) tea.Cmd { m.openMenu(modelsMenu()); return nil }},
		{label: "Status", labelZH: "狀態", desc: "providers, keys, routing, Docker", descZH: "供應商、金鑰、路由、Docker", act: runCmd("/status", "status")},
		{label: "Doctor", labelZH: "系統檢查", desc: "check Docker, images, connectivity", descZH: "檢查 Docker、映像與連線", act: runCmd("/doctor", "doctor")},
		{label: "Language", labelZH: "語言", desc: "English / 中文", descZH: "English / 中文", act: func(m *model) tea.Cmd { m.openMenu(languageMenu()); return nil }},
		{label: "Clear screen", labelZH: "清除畫面", act: func(m *model) tea.Cmd { m.clearScreen(); return nil }},
		{label: "Quit", labelZH: "離開", act: func(m *model) tea.Cmd { m.exiting = true; _ = m.pipeW.Close(); return tea.Quit }},
	}}
}

func providersMenu() *menuNode {
	return &menuNode{items: []menuItem{
		{label: "List providers", labelZH: "列出供應商", act: runCmd("/provider list", "provider list")},
		{label: "Add a provider", labelZH: "新增供應商", act: addProviderWizard},
		{label: "Set an API key", labelZH: "設定 API 金鑰", act: setKeyWizard},
		{label: "Remove a provider", labelZH: "移除供應商", act: removeProviderWizard},
		backItem(),
	}}
}

func modelsMenu() *menuNode {
	return &menuNode{items: []menuItem{
		{label: "Show current routing", labelZH: "查看目前路由", act: runCmd("/model list", "model list")},
		{label: "Set a model", labelZH: "設定模型", act: setModelWizard},
		{label: "Reset overrides", labelZH: "重設覆寫設定", act: runCmd("/model reset", "model reset")},
		backItem(),
	}}
}

func languageMenu() *menuNode {
	return &menuNode{items: []menuItem{
		{label: "English", labelZH: "English", act: func(m *model) tea.Cmd { m.setLanguage("en"); return nil }},
		{label: "中文 (Traditional)", labelZH: "繁體中文", act: func(m *model) tea.Cmd { m.setLanguage("zh"); return nil }},
		backItem(),
	}}
}

func backItem() menuItem {
	return menuItem{label: "‹ Back", labelZH: "‹ 返回", act: func(m *model) tea.Cmd { m.goBack(); return nil }}
}

// --- wizards -----------------------------------------------------------------

func reviewWizard(m *model) tea.Cmd {
	m.startWizard(&wizard{
		title: "Review a repository", titleZH: "檢視儲存庫",
		steps: []wizStep{{prompt: "Repository path (Enter = current directory)", promptZH: "儲存庫路徑（直接按 Enter 使用目前目錄）", key: "path"}},
		build: func(m *model, v map[string]string) tea.Cmd {
			path := firstNonEmpty(v["path"], ".")
			return m.run("/review "+shellQuote(path)+" --watch", "review "+path)
		},
	})
	return nil
}

func scanWizard(m *model) tea.Cmd {
	m.startWizard(&wizard{
		title: "Scan a repository", titleZH: "掃描儲存庫",
		steps: []wizStep{{prompt: "Repository path (Enter = current directory)", promptZH: "儲存庫路徑（直接按 Enter 使用目前目錄）", key: "path"}},
		build: func(m *model, v map[string]string) tea.Cmd {
			path := firstNonEmpty(v["path"], ".")
			return m.run("/scan --target "+shellQuote(path)+" --watch", "scan "+path)
		},
	})
	return nil
}

func addProviderWizard(m *model) tea.Cmd {
	m.startWizard(&wizard{
		title: "Add a provider", titleZH: "新增供應商",
		steps: []wizStep{
			{prompt: "Provider name (e.g. anthropic, openrouter, local)", promptZH: "供應商名稱（例如 anthropic、openrouter、local）", key: "name"},
			{prompt: "Provider type", promptZH: "供應商類型", key: "type", options: []wizOption{
				{label: "Anthropic", labelZH: "Anthropic", value: "anthropic"},
				{label: "OpenAI-compatible", labelZH: "OpenAI 相容", value: "openai-compat"},
				{label: "OpenRouter", labelZH: "OpenRouter", value: "openrouter"},
			}},
			{prompt: "Base URL (Enter = provider default)", promptZH: "Base URL（直接按 Enter 使用供應商預設值）", key: "base",
				skip: func(v map[string]string) bool { return v["type"] == "anthropic" }},
		},
		build: func(m *model, v map[string]string) tea.Cmd {
			// Feed the console's interactive sub-prompts as extra lines: the type,
			// and (only for the openai-compat / openrouter branches, which read it)
			// the base URL.
			lines := []string{"/provider add " + v["name"], v["type"]}
			if v["type"] != "anthropic" {
				lines = append(lines, v["base"])
			}
			return m.runLines("provider add "+v["name"]+" ("+v["type"]+")", lines...)
		},
	})
	return nil
}

func setKeyWizard(m *model) tea.Cmd {
	opts := m.providerOptions()
	if len(opts) == 0 {
		m.appendLine(dimStyle.Render(translations[m.lang].noProviders))
		return nil
	}
	m.startWizard(&wizard{
		title: "Set an API key", titleZH: "設定 API 金鑰",
		steps: []wizStep{{prompt: "Which provider?", promptZH: "選擇供應商", key: "name", options: opts}},
		build: func(m *model, v map[string]string) tea.Cmd {
			// The console then requests the key via ReadSecret, which the model
			// surfaces as the hidden-input prompt automatically.
			return m.run("/key set "+v["name"], "key set "+v["name"])
		},
	})
	return nil
}

func removeProviderWizard(m *model) tea.Cmd {
	opts := m.providerOptions()
	if len(opts) == 0 {
		message := "No providers to remove."
		if m.lang == languageChinese {
			message = "目前沒有可移除的供應商。"
		}
		m.appendLine(dimStyle.Render(message))
		return nil
	}
	m.startWizard(&wizard{
		title: "Remove a provider", titleZH: "移除供應商",
		steps: []wizStep{{prompt: "Which provider?", promptZH: "選擇供應商", key: "name", options: opts}},
		build: func(m *model, v map[string]string) tea.Cmd {
			// If the provider is still referenced by a model route the console asks
			// to confirm; the user can type yes (the input box stays available).
			return m.run("/provider remove "+v["name"], "provider remove "+v["name"])
		},
	})
	return nil
}

func setModelWizard(m *model) tea.Cmd {
	m.startWizard(&wizard{
		title: "Set a model", titleZH: "設定模型",
		steps: []wizStep{
			{prompt: "Which role?", promptZH: "選擇角色", key: "role", options: []wizOption{
				{label: "All roles at once", labelZH: "全部角色", value: "all"},
				{label: "Recon", labelZH: "偵查", value: "recon"},
				{label: "Reviewer", labelZH: "審查", value: "reviewer"},
				{label: "Triager", labelZH: "分流", value: "triager"},
				{label: "Prover", labelZH: "實證", value: "prover"},
				{label: "Reporter", labelZH: "報告", value: "reporter"},
			}},
			{prompt: "Model reference  provider/model-id  (e.g. anthropic/claude-opus-4-8)", promptZH: "模型引用 provider/model-id（例如 anthropic/claude-opus-4-8）", key: "ref"},
		},
		build: func(m *model, v map[string]string) tea.Cmd {
			return m.run("/model set "+v["role"]+" "+v["ref"], "model set "+v["role"]+" "+v["ref"])
		},
	})
	return nil
}

// --- model helpers -----------------------------------------------------------

func runCmd(line, echo string) func(m *model) tea.Cmd {
	return func(m *model) tea.Cmd { return m.run(line, echo) }
}

// run echoes the action and writes one command line to the console pipe.
func (m *model) run(line, echo string) tea.Cmd {
	return m.runLines(echo, line)
}

// runLines echoes the action and writes several lines (a command plus any
// pre-filled answers to the console's interactive sub-prompts) to the pipe.
func (m *model) runLines(echo string, lines ...string) tea.Cmd {
	// Executing an action ends the menu interaction. Results stay in the
	// transcript and the next action starts from the command prompt.
	m.menu = nil
	if echo != "" {
		m.appendLine(promptStyle.Render("› ") + userStyle.Render(echo))
	}
	go func() {
		for _, l := range lines {
			_, _ = io.WriteString(m.pipeW, l+"\n")
		}
	}()
	return nil
}

func (m *model) openMenu(child *menuNode) {
	child.parent = m.menu
	child.cursor = 0
	m.menu = child
	m.resize()
}

func (m *model) goBack() {
	if m.menu != nil && m.menu.parent != nil {
		parent := m.menu.parent
		if parent.parent == nil {
			// The root menu is an implementation detail of the command router;
			// do not expose the full action list after leaving a submenu.
			m.menu = nil
		} else {
			m.menu = parent
		}
		m.resize()
	}
}

func (m *model) menuMove(delta int) {
	if m.menu == nil || len(m.menu.items) == 0 {
		return
	}
	n := len(m.menu.items)
	m.menu.cursor = (m.menu.cursor + delta%n + n) % n
}

func (m *model) activateMenu() tea.Cmd {
	if m.menu == nil || len(m.menu.items) == 0 {
		return nil
	}
	return m.menu.items[m.menu.cursor].act(m)
}

func (m *model) startWizard(w *wizard) {
	w.idx, w.cursor = 0, 0
	w.values = map[string]string{}
	m.wizard = w
	// A wizard is the interaction for the command that was entered; the root
	// action list should not remain visible behind it.
	m.menu = nil
	if w.current().options == nil {
		m.ti.Reset()
		m.ti.Placeholder = m.wizardPrompt(w.current())
	}
	m.resize()
}

func (m *model) cancelWizard() {
	m.wizard = nil
	m.ti.Reset()
	m.applyLanguage()
	m.resize()
}

// wizardKey handles a key while a wizard is active. handled=false means the key
// should fall through to the text input (free-text steps).
func (m *model) wizardKey(msg tea.KeyMsg) (tea.Cmd, bool) {
	step := m.wizard.current()
	switch msg.String() {
	case "esc":
		m.cancelWizard()
		return nil, true
	case "up":
		if step.options != nil {
			n := len(step.options)
			m.wizard.cursor = (m.wizard.cursor - 1 + n) % n
		}
		return nil, true
	case "down":
		if step.options != nil {
			n := len(step.options)
			m.wizard.cursor = (m.wizard.cursor + 1) % n
		}
		return nil, true
	case "enter":
		if step.options != nil {
			m.wizard.values[step.key] = step.options[m.wizard.cursor].value
		} else {
			m.wizard.values[step.key] = strings.TrimSpace(m.ti.Value())
			m.ti.Reset()
		}
		return m.wizardAdvance(), true
	}
	// Option steps swallow all other keys; text steps let the input box handle them.
	return nil, step.options != nil
}

func (m *model) wizardAdvance() tea.Cmd {
	w := m.wizard
	w.idx++
	for w.idx < len(w.steps) && w.steps[w.idx].skip != nil && w.steps[w.idx].skip(w.values) {
		w.idx++
	}
	if w.idx >= len(w.steps) {
		build, values := w.build, w.values
		m.wizard = nil
		m.ti.Reset()
		m.applyLanguage()
		m.resize()
		return build(m, values)
	}
	w.cursor = 0
	if w.current().options == nil {
		m.ti.Reset()
		m.ti.Placeholder = m.wizardPrompt(w.current())
	}
	m.resize()
	return nil
}

func (m *model) setLanguage(code string) {
	m.lang = normalizeLanguage(code)
	m.applyLanguage()
	m.menu = nil
	if err := m.saveLanguage(); err != nil {
		m.appendLine(errorStyle.Render(translations[m.lang].preferenceError + err.Error()))
		return
	}
	m.appendLine(successStyle.Render(translations[m.lang].languageChanged))
}

// providerOptions lists configured providers (repo + user layers) as wizard
// choices.
func (m *model) providerOptions() []wizOption {
	seen := map[string]bool{}
	for _, path := range []string{"aegis.toml", m.settingsPath} {
		if cfg, err := settings.Load(path); err == nil {
			for name := range cfg.Providers {
				seen[name] = true
			}
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	opts := make([]wizOption, len(names))
	for i, name := range names {
		opts[i] = wizOption{label: name, value: name}
	}
	return opts
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// shellQuote wraps a value in double quotes when it contains whitespace, so the
// console's quote-aware splitter keeps it as one argument.
func shellQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t") {
		return s
	}
	return "\"" + strings.ReplaceAll(s, "\"", "\\\"") + "\""
}

// --- rendering ---------------------------------------------------------------

var (
	menuArrowStyle = lipgloss.NewStyle().Foreground(lipgloss.Color(brandTo.Hex())).Bold(true)
	menuSelStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#E6EDEB")).Bold(true)
	menuTitleStyle = lipgloss.NewStyle().Foreground(lipgloss.Color(brandFrom.Hex())).Bold(true)
)

// controlBlock is the bottom region: the active wizard, or the action menu plus
// the always-visible input box and a hint line.
func (m *model) controlBlock() string {
	switch {
	case m.wizard != nil:
		return m.wizardView()
	case m.inSecret:
		return m.inputBoxView() + "\n" + dimStyle.Render(strings.TrimSpace(translations[m.lang].secretHint))
	default:
		return m.menuView()
	}
}

func (m *model) menuView() string {
	if m.menu == nil {
		var b strings.Builder
		b.WriteString(m.inputBoxView() + "\n")
		b.WriteString(m.menuHint())
		return lipgloss.NewStyle().Width(m.contentWidth()).Render(b.String())
	}
	var b strings.Builder
	for i, it := range m.menu.items {
		label, desc := it.text(m.lang)
		if i == m.menu.cursor {
			b.WriteString(menuArrowStyle.Render("▸ ") + menuSelStyle.Render(label))
		} else {
			b.WriteString("  " + label)
		}
		if desc != "" && !m.compactLayout() {
			b.WriteString(dimStyle.Render("  — " + desc))
		}
		b.WriteByte('\n')
	}
	b.WriteString(m.inputBoxView() + "\n")
	if !m.compactLayout() {
		b.WriteString(m.menuHint())
	}
	return lipgloss.NewStyle().Width(m.contentWidth()).Render(b.String())
}

func (m *model) menuHint() string {
	value := strings.TrimSpace(m.ti.Value())
	if m.menu == nil && !strings.HasPrefix(value, "/") {
		return dimStyle.Render(translations[m.lang].mainCommandHint)
	}
	// Typing a slash shows command suggestions; otherwise show the menu keys.
	if strings.HasPrefix(value, "/") {
		return m.hintLine()
	}
	return dimStyle.Render(translations[m.lang].chooseHint)
}

func (m *model) wizardView() string {
	step := m.wizard.current()
	title := m.wizard.title
	prompt := step.prompt
	if m.lang == languageChinese {
		if m.wizard.titleZH != "" {
			title = m.wizard.titleZH
		}
		if step.promptZH != "" {
			prompt = step.promptZH
		}
	}
	var b strings.Builder
	b.WriteString(menuTitleStyle.Render(title) + "\n")
	b.WriteString(dimStyle.Render(prompt) + "\n")
	if step.options != nil {
		for i, opt := range step.options {
			label := opt.label
			if m.lang == languageChinese && opt.labelZH != "" {
				label = opt.labelZH
			}
			if i == m.wizard.cursor {
				b.WriteString(menuArrowStyle.Render("▸ ") + menuSelStyle.Render(label) + "\n")
			} else {
				b.WriteString("  " + label + "\n")
			}
		}
		b.WriteString(dimStyle.Render(translations[m.lang].wizardCancel))
		return b.String()
	}
	b.WriteString(m.inputBoxView() + "\n")
	b.WriteString(dimStyle.Render(translations[m.lang].wizardContinue))
	return b.String()
}

func (m *model) inputBoxView() string {
	prompt := promptStyle.Render(" › ")
	if m.inSecret {
		prompt = lipgloss.NewStyle().Foreground(lipgloss.Color(brandFrom.Hex())).Render(" 🔒 ")
	}
	// Width is the inner content width; account for the input box's border and
	// horizontal padding so the rendered box stays inside the app frame.
	return inputBox.Width(max(m.contentWidth()-7, 1)).Render(prompt + m.ti.View())
}
