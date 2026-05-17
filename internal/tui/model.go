package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/runner"
)

// --------------------------------------------------------------------------
// State machine
// --------------------------------------------------------------------------

type state int

const (
	stateMenu state = iota
	stateEngagementNew
	stateEngagementList
	stateEngagementSwitch
	stateFindings
	stateModuleList
	stateModuleConfirm
	stateReport
	stateHelp
)

// --------------------------------------------------------------------------
// Messages
// --------------------------------------------------------------------------

type (
	tickMsg        time.Time
	engLoadedMsg   struct{ eng *engagement.Engagement }
	findingsMsg    struct{ findings []*engagement.Finding }
	engListMsg     struct{ list []*engagement.Engagement }
	reportReadyMsg struct {
		content string
		path    string
	}
	errMsg struct{ err error }
)

func tickCmd() tea.Cmd {
	return tea.Tick(30*time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// --------------------------------------------------------------------------
// Input field (minimal, no external dep)
// --------------------------------------------------------------------------

type inputField struct {
	label string
	value string
}

func (f *inputField) handleKey(key string) {
	switch key {
	case "backspace", "ctrl+h":
		if len(f.value) > 0 {
			f.value = f.value[:len(f.value)-1]
		}
	case "ctrl+u":
		f.value = ""
	default:
		if len(key) == 1 {
			f.value += key
		}
	}
}

// --------------------------------------------------------------------------
// Model
// --------------------------------------------------------------------------

type Model struct {
	state          state
	width          int
	height         int
	activeEng      *engagement.Engagement
	engList        []*engagement.Engagement
	findings       []*engagement.Finding
	allEngagements []*engagement.Engagement
	selectedModule runner.Module
	pendingModule  string // set before tea.Quit so main loop can run it
	menuCursor     int
	menuItems      []menuItem
	subMenuCursor  int
	subMenuItems   []menuItem
	engFields      [3]inputField
	engFieldCursor int
	reportContent  string
	reportPath     string
	statusMsg      string
	statusIsError  bool
	findingScroll  int
	reportScroll   int
	engListCursor  int
}

// PendingModule returns the module key that should be run after the TUI exits,
// or an empty string if the user quit normally.
func (m Model) PendingModule() string { return m.pendingModule }

type menuItem struct {
	key   string
	label string
	sub   bool // true = opens submenu, false = direct action
	state state
}

func buildMainMenu() []menuItem {
	return []menuItem{
		{key: "1", label: "Intelligence & OSINT"},
		{key: "2", label: "Offensive Operations"},
		{key: "3", label: "Post-Exploitation"},
		{key: "4", label: "Active Directory"},
		{key: "5", label: "Advanced Modules"},
		{key: "", label: ""},
		{key: "E", label: "Engagement Manager"},
		{key: "F", label: "View Findings"},
		{key: "R", label: "Generate Report"},
		{key: "", label: ""},
		{key: "?", label: "Help"},
		{key: "Q", label: "Quit"},
	}
}

func NewModel() Model {
	m := Model{
		state:     stateMenu,
		menuItems: buildMainMenu(),
		engFields: [3]inputField{
			{label: "Engagement Name"},
			{label: "Target (IP / CIDR / domain)"},
			{label: "Scope"},
		},
	}
	return m
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		loadActiveEng(),
		tickCmd(),
	)
}

func loadActiveEng() tea.Cmd {
	return func() tea.Msg {
		eng, _ := engagement.Active()
		return engLoadedMsg{eng: eng}
	}
}

func loadFindings(engID string) tea.Cmd {
	return func() tea.Msg {
		ff, _ := engagement.RecentFindings(50)
		if engID != "" {
			ff2, _ := engagement.Findings(engID)
			if len(ff2) > 0 {
				ff = ff2
			}
		}
		return findingsMsg{findings: ff}
	}
}

func loadEngList() tea.Cmd {
	return func() tea.Msg {
		list, _ := engagement.All()
		return engListMsg{list: list}
	}
}

// --------------------------------------------------------------------------
// Update
// --------------------------------------------------------------------------

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		return m, tea.Batch(loadActiveEng(), tickCmd())

	case engLoadedMsg:
		m.activeEng = msg.eng
		return m, nil

	case findingsMsg:
		m.findings = msg.findings
		return m, nil

	case engListMsg:
		m.allEngagements = msg.list
		return m, nil

	case reportReadyMsg:
		m.reportContent = msg.content
		m.reportPath = msg.path
		m.state = stateReport
		m.reportScroll = 0
		return m, nil

	case errMsg:
		m.statusMsg = msg.err.Error()
		m.statusIsError = true
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Global exits
	if key == "ctrl+c" {
		return m, tea.Quit
	}

	switch m.state {

	// ── Main Menu ─────────────────────────────────────────────────────────
	case stateMenu:
		switch key {
		case "up", "k":
			if m.menuCursor > 0 {
				m.menuCursor--
				for m.menuCursor > 0 && m.menuItems[m.menuCursor].key == "" {
					m.menuCursor--
				}
			}
		case "down", "j":
			if m.menuCursor < len(m.menuItems)-1 {
				m.menuCursor++
				for m.menuCursor < len(m.menuItems)-1 && m.menuItems[m.menuCursor].key == "" {
					m.menuCursor++
				}
			}
		case "enter", " ":
			if m.menuCursor < len(m.menuItems) {
				return m.activateMenuItem(m.menuItems[m.menuCursor].key)
			}
		case "1":
			return m.openCategoryMenu("Intelligence & OSINT")
		case "2":
			return m.openCategoryMenu("Offensive Operations")
		case "3":
			return m.openCategoryMenu("Post-Exploitation")
		case "4":
			return m.openCategoryMenu("Active Directory")
		case "5":
			return m.openCategoryMenu("Advanced")
		case "e", "E":
			m.state = stateEngagementList
			return m, loadEngList()
		case "f", "F":
			m.state = stateFindings
			engID := ""
			if m.activeEng != nil {
				engID = m.activeEng.ID
			}
			return m, loadFindings(engID)
		case "r", "R":
			if m.activeEng == nil {
				m.statusMsg = "No active engagement. Create one with [E]."
				m.statusIsError = true
				return m, nil
			}
			return m, generateReport(m.activeEng.ID)
		case "?":
			m.state = stateHelp
		case "q", "Q":
			return m, tea.Quit
		}

	// ── Module sub-menu ───────────────────────────────────────────────────
	case stateModuleList:
		switch key {
		case "up", "k":
			if m.subMenuCursor > 0 {
				m.subMenuCursor--
			}
		case "down", "j":
			if m.subMenuCursor < len(m.subMenuItems)-1 {
				m.subMenuCursor++
			}
		case "enter", " ":
			if m.subMenuCursor < len(m.subMenuItems) {
				modKey := m.subMenuItems[m.subMenuCursor].key
				for _, mod := range runner.Registry {
					if mod.Key == modKey {
						m.selectedModule = mod
						m.state = stateModuleConfirm
						return m, nil
					}
				}
			}
		case "esc", "q":
			m.state = stateMenu
		}

	// ── Module confirm ────────────────────────────────────────────────────
	case stateModuleConfirm:
		switch key {
		case "y", "Y", "enter":
			m.pendingModule = m.selectedModule.Key
			return m, tea.Quit
		case "n", "N", "esc":
			m.state = stateModuleList
		}

	// ── Engagement list ───────────────────────────────────────────────────
	case stateEngagementList:
		switch key {
		case "up", "k":
			if m.engListCursor > 0 {
				m.engListCursor--
			}
		case "down", "j":
			if m.engListCursor < len(m.allEngagements)-1 {
				m.engListCursor++
			}
		case "n", "N":
			m.state = stateEngagementNew
			m.engFieldCursor = 0
			for i := range m.engFields {
				m.engFields[i].value = ""
			}
		case "enter", "s", "S":
			if m.engListCursor < len(m.allEngagements) {
				eng := m.allEngagements[m.engListCursor]
				engagement.SetActive(eng.ID)
				m.activeEng = eng
				m.statusMsg = fmt.Sprintf("Active engagement set: %s", eng.Name)
				m.statusIsError = false
				m.state = stateMenu
			}
		case "esc", "q":
			m.state = stateMenu
		}

	// ── New Engagement form ───────────────────────────────────────────────
	case stateEngagementNew:
		switch key {
		case "tab", "down":
			m.engFieldCursor = (m.engFieldCursor + 1) % len(m.engFields)
		case "shift+tab", "up":
			m.engFieldCursor = (m.engFieldCursor - 1 + len(m.engFields)) % len(m.engFields)
		case "enter":
			if m.engFieldCursor < len(m.engFields)-1 {
				m.engFieldCursor++
			} else {
				// Submit
				name := strings.TrimSpace(m.engFields[0].value)
				if name == "" {
					m.statusMsg = "Engagement name is required."
					m.statusIsError = true
					return m, nil
				}
				eng, err := engagement.Create(
					name,
					strings.TrimSpace(m.engFields[1].value),
					strings.TrimSpace(m.engFields[2].value),
				)
				if err != nil {
					m.statusMsg = fmt.Sprintf("Error: %v", err)
					m.statusIsError = true
					return m, nil
				}
				m.activeEng = eng
				m.statusMsg = fmt.Sprintf("Engagement created: %s", eng.Name)
				m.statusIsError = false
				m.state = stateMenu
				return m, nil
			}
		case "esc":
			m.state = stateEngagementList
		default:
			m.engFields[m.engFieldCursor].handleKey(key)
		}

	// ── Findings viewer ───────────────────────────────────────────────────
	case stateFindings:
		switch key {
		case "up", "k":
			if m.findingScroll > 0 {
				m.findingScroll--
			}
		case "down", "j":
			m.findingScroll++
		case "esc", "q":
			m.state = stateMenu
		}

	// ── Report viewer ────────────────────────────────────────────────────
	case stateReport:
		switch key {
		case "up", "k":
			if m.reportScroll > 0 {
				m.reportScroll--
			}
		case "down", "j":
			m.reportScroll++
		case "esc", "q":
			m.state = stateMenu
		}

	// ── Help ──────────────────────────────────────────────────────────────
	case stateHelp:
		if key == "esc" || key == "q" {
			m.state = stateMenu
		}
	}

	return m, nil
}

func (m Model) activateMenuItem(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "1":
		return m.openCategoryMenu("Intelligence & OSINT")
	case "2":
		return m.openCategoryMenu("Offensive Operations")
	case "3":
		return m.openCategoryMenu("Post-Exploitation")
	case "4":
		return m.openCategoryMenu("Active Directory")
	case "5":
		return m.openCategoryMenu("Advanced")
	case "E":
		m.state = stateEngagementList
		return m, loadEngList()
	case "F":
		m.state = stateFindings
		engID := ""
		if m.activeEng != nil {
			engID = m.activeEng.ID
		}
		return m, loadFindings(engID)
	case "R":
		if m.activeEng == nil {
			m.statusMsg = "No active engagement. Create one with [E]."
			m.statusIsError = true
			return m, nil
		}
		return m, generateReport(m.activeEng.ID)
	case "Q":
		return m, tea.Quit
	}
	return m, nil
}

func (m Model) openCategoryMenu(category string) (Model, tea.Cmd) {
	mods := runner.ByCategory(category)
	items := make([]menuItem, len(mods))
	for i, mod := range mods {
		items[i] = menuItem{key: mod.Key, label: fmt.Sprintf("%-20s  %s", mod.Name, runner.ShortDesc(mod.Description, 50))}
	}
	m.subMenuItems = items
	m.subMenuCursor = 0
	m.state = stateModuleList
	return m, nil
}

func generateReport(engID string) tea.Cmd {
	return func() tea.Msg {
		content, path, err := engagement.GenerateMarkdown(engID)
		if err != nil {
			return errMsg{err: err}
		}
		return reportReadyMsg{content: content, path: path}
	}
}

// --------------------------------------------------------------------------
// View
// --------------------------------------------------------------------------

func (m Model) View() string {
	switch m.state {
	case stateEngagementNew:
		return m.viewNewEngagement()
	case stateEngagementList:
		return m.viewEngagementList()
	case stateFindings:
		return m.viewFindings()
	case stateModuleList:
		return m.viewModuleList()
	case stateModuleConfirm:
		return m.viewModuleConfirm()
	case stateReport:
		return m.viewReport()
	case stateHelp:
		return m.viewHelp()
	default:
		return m.viewMainMenu()
	}
}

const banner = `
██████╗  █████╗ ██╗   ██╗ ██████╗ ██╗██████╗
██╔══██╗██╔══██╗██║   ██║██╔═══██╗██║██╔══██╗
██║  ██║███████║██║   ██║██║   ██║██║██║  ██║
██║  ██║██╔══██║╚██╗ ██╔╝██║   ██║██║██║  ██║
██████╔╝██║  ██║ ╚████╔╝ ╚██████╔╝██║██████╔╝
╚═════╝ ╚═╝  ╚═╝  ╚═══╝   ╚═════╝ ╚═╝╚═════╝`

func (m Model) viewMainMenu() string {
	var sb strings.Builder

	// Banner
	sb.WriteString(StyleBanner.Render(banner))
	sb.WriteString("\n")
	sb.WriteString(StyleSubtitle.Render("  ghost in the net  ·  operator-grade red team engagement platform") + "\n")
	sb.WriteString(StyleDivider.Render(strings.Repeat("─", 65)) + "\n\n")

	// Engagement status
	sb.WriteString("  ")
	sb.WriteString(StyleLabel.Render("ENGAGEMENT  "))
	if m.activeEng != nil {
		sb.WriteString(StyleEngagementActive.Render(m.activeEng.Name))
		if m.activeEng.Target != "" {
			sb.WriteString(StyleLabel.Render("  →  ") + StyleValue.Render(m.activeEng.Target))
		}
		if len(m.findings) > 0 {
			stats := engagement.FindingStats(m.activeEng.ID)
			sb.WriteString("  ")
			if stats["CRITICAL"] > 0 {
				sb.WriteString(StyleFindingCritical.Render(fmt.Sprintf("● %dC", stats["CRITICAL"])) + " ")
			}
			if stats["HIGH"] > 0 {
				sb.WriteString(StyleFindingHigh.Render(fmt.Sprintf("● %dH", stats["HIGH"])) + " ")
			}
		}
	} else {
		sb.WriteString(StyleEngagementNone.Render("none active"))
	}
	sb.WriteString("\n\n")

	// Menu categories
	catKeys := []struct{ k, label string }{
		{"1", "Intelligence & OSINT"},
		{"2", "Offensive Operations"},
		{"3", "Post-Exploitation"},
		{"4", "Active Directory"},
		{"5", "Advanced Modules"},
	}

	for i, item := range catKeys {
		cursor := "  "
		sel := m.menuCursor == i
		keyStr := StyleMenuKey.Render("[" + item.k + "]")
		labelStr := item.label
		if sel {
			cursor = StyleCyan("> ")
			labelStr = StyleMenuItemSelected.Render(" " + item.label + " ")
		} else {
			labelStr = StyleMenuItem.Render(item.label)
		}
		sb.WriteString(cursor + keyStr + "  " + labelStr + "\n")
	}

	sb.WriteString("\n")
	sb.WriteString(StyleDivider.Render(strings.Repeat("─", 40)) + "\n")

	engagementItems := []struct{ k, label string }{
		{"E", "Engagement Manager"},
		{"F", "View Findings"},
		{"R", "Generate Report"},
	}
	systemItems := []struct{ k, label string }{
		{"?", "Help"},
		{"Q", "Quit"},
	}

	offset := len(catKeys) + 1
	for i, item := range engagementItems {
		cursor := "  "
		sel := m.menuCursor == offset+i
		keyStr := StyleMenuKey.Render("[" + item.k + "]")
		var labelStr string
		if sel {
			cursor = StyleCyan("> ")
			labelStr = StyleMenuItemSelected.Render(" " + item.label + " ")
		} else {
			labelStr = StyleMenuItem.Render(item.label)
		}
		sb.WriteString(cursor + keyStr + "  " + labelStr + "\n")
	}

	sb.WriteString("\n")
	for i, item := range systemItems {
		cursor := "  "
		sel := m.menuCursor == offset+len(engagementItems)+1+i
		keyStr := StyleMenuKey.Render("[" + item.k + "]")
		var labelStr string
		if sel {
			cursor = StyleCyan("> ")
			labelStr = StyleMenuItemSelected.Render(" " + item.label + " ")
		} else {
			labelStr = StyleMenuItem.Render(item.label)
		}
		sb.WriteString(cursor + keyStr + "  " + labelStr + "\n")
	}

	// Status bar
	if m.statusMsg != "" {
		sb.WriteString("\n")
		if m.statusIsError {
			sb.WriteString("  " + StyleError.Render("✗ "+m.statusMsg) + "\n")
		} else {
			sb.WriteString("  " + StyleSuccess.Render("✓ "+m.statusMsg) + "\n")
		}
	}

	sb.WriteString("\n")
	sb.WriteString(StyleHelp.Render("  ↑/↓ navigate  ·  enter select  ·  number keys for quick access  ·  ctrl+c quit"))
	sb.WriteString("\n")

	return sb.String()
}

func (m Model) viewModuleList() string {
	var sb strings.Builder
	sb.WriteString(StyleBanner.Render(banner) + "\n\n")

	if len(m.subMenuItems) == 0 {
		sb.WriteString(StyleError.Render("  No modules in this category.\n"))
	} else {
		sb.WriteString(StyleMenuTitle.Render("  Select Module") + "\n\n")
		for i, item := range m.subMenuItems {
			if i == m.subMenuCursor {
				sb.WriteString("  " + StyleMenuItemSelected.Render(" "+item.label+" ") + "\n")
			} else {
				sb.WriteString("  " + StyleMenuKey.Render("  ") + StyleMenuItem.Render(item.label) + "\n")
			}
		}
	}

	sb.WriteString("\n" + StyleHelp.Render("  ↑/↓ navigate  ·  enter select  ·  esc back"))
	return sb.String()
}

func (m Model) viewModuleConfirm() string {
	var sb strings.Builder
	sb.WriteString(StyleBanner.Render(banner) + "\n\n")
	sb.WriteString(StyleMenuTitle.Render("  Launch Module") + "\n\n")
	sb.WriteString("  " + StyleLabel.Render("Module:  ") + StyleValue.Render(m.selectedModule.Name) + "\n")
	sb.WriteString("  " + StyleLabel.Render("Category: ") + StyleValue.Render(m.selectedModule.Category) + "\n\n")
	sb.WriteString("  " + StyleMenuItem.Render(m.selectedModule.Description) + "\n\n")

	if m.activeEng != nil {
		sb.WriteString("  " + StyleLabel.Render("Engagement: ") + StyleEngagementActive.Render(m.activeEng.Name) + "\n\n")
	} else {
		sb.WriteString("  " + StyleWarning.Render("⚠  No active engagement — findings won't be tracked.\n\n"))
	}

	sb.WriteString("  " + StylePrompt.Render("Launch? [y/N]  "))
	sb.WriteString(StyleHelp.Render("· esc back"))
	return sb.String()
}

func (m Model) viewNewEngagement() string {
	var sb strings.Builder
	sb.WriteString(StyleBanner.Render(banner) + "\n\n")
	sb.WriteString(StyleMenuTitle.Render("  New Engagement") + "\n\n")

	for i, f := range m.engFields {
		selected := i == m.engFieldCursor
		label := StyleLabel.Render(f.label)
		var val string
		if selected {
			val = StyleInput.Render(f.value + "█")
		} else {
			val = StyleValue.Render(f.value)
			if val == "" {
				val = StyleHelp.Render("(empty)")
			}
		}
		prefix := "  "
		if selected {
			prefix = StyleCyan("> ")
		}
		sb.WriteString(prefix + label + "\n  " + val + "\n\n")
	}

	sb.WriteString(StyleHelp.Render("  tab/↑↓ switch fields  ·  enter next/submit  ·  esc back"))
	return sb.String()
}

func (m Model) viewEngagementList() string {
	var sb strings.Builder
	sb.WriteString(StyleBanner.Render(banner) + "\n\n")
	sb.WriteString(StyleMenuTitle.Render("  Engagement Manager") + "\n\n")

	if len(m.allEngagements) == 0 {
		sb.WriteString(StyleLabel.Render("  No engagements yet.\n\n"))
	} else {
		sb.WriteString(StyleTableHeader.Render(
			fmt.Sprintf("  %-30s  %-20s  %-10s  %-8s\n",
				"Name", "Target", "Status", "Created",
			),
		))
		sb.WriteString(StyleDivider.Render("  "+strings.Repeat("─", 74)) + "\n")
		for i, eng := range m.allEngagements {
			active := ""
			if m.activeEng != nil && eng.ID == m.activeEng.ID {
				active = StyleGreen(" ★ ")
			}
			line := fmt.Sprintf("  %-30s  %-20s  %-10s  %-8s%s",
				truncate(eng.Name, 28),
				truncate(eng.Target, 18),
				eng.Status,
				eng.CreatedAt.Format("01-02"),
				active,
			)
			if i == m.engListCursor {
				sb.WriteString(StyleMenuItemSelected.Render(line) + "\n")
			} else {
				sb.WriteString(StyleTableRow.Render(line) + "\n")
			}
		}
	}

	sb.WriteString("\n")
	sb.WriteString(StyleHelp.Render("  [N] new engagement  ·  enter/[S] set active  ·  ↑/↓ navigate  ·  esc back"))
	return sb.String()
}

func (m Model) viewFindings() string {
	var sb strings.Builder
	sb.WriteString(StyleBanner.Render(banner) + "\n\n")

	title := "  Recent Findings"
	if m.activeEng != nil {
		title = fmt.Sprintf("  Findings — %s", m.activeEng.Name)
	}
	sb.WriteString(StyleMenuTitle.Render(title) + "\n\n")

	if len(m.findings) == 0 {
		sb.WriteString(StyleLabel.Render("  No findings recorded yet.\n"))
		sb.WriteString(StyleHelp.Render("  Run modules to collect findings.\n"))
	} else {
		visible := m.findings
		start := m.findingScroll
		if start > len(visible)-1 {
			start = 0
		}
		lines := 0
		maxLines := m.height - 12
		for _, f := range visible[start:] {
			if lines >= maxLines {
				break
			}
			sevStyle := SeverityStyle(f.Severity)
			sev := sevStyle.Render(fmt.Sprintf("%-8s", f.Severity))
			module := StyleLabel.Render(fmt.Sprintf("%-15s", truncate(f.Module, 14)))
			target := StyleValue.Render(truncate(f.Target, 20))
			ts := StyleHelp.Render(f.CreatedAt.Format("01-02 15:04"))
			sb.WriteString(fmt.Sprintf("  %s  %s  %s  %s\n", sev, module, target, ts))
			if f.Title != "" {
				sb.WriteString(StyleMenuItem.Render("    "+truncate(f.Title, 70)) + "\n")
			}
			sb.WriteString("\n")
			lines += 2
		}
	}

	sb.WriteString(StyleHelp.Render("  ↑/↓ scroll  ·  esc back"))
	return sb.String()
}

func (m Model) viewReport() string {
	var sb strings.Builder
	sb.WriteString(StyleBanner.Render(banner) + "\n\n")
	sb.WriteString(StyleSuccess.Render("  ✓ Report Generated") + "\n")
	if m.reportPath != "" {
		sb.WriteString(StyleLabel.Render("  Saved to: ") + StyleValue.Render(m.reportPath) + "\n\n")
	}

	lines := strings.Split(m.reportContent, "\n")
	start := m.reportScroll
	if start >= len(lines) {
		start = 0
	}
	maxLines := m.height - 10
	end := start + maxLines
	if end > len(lines) {
		end = len(lines)
	}
	for _, line := range lines[start:end] {
		if strings.HasPrefix(line, "# ") {
			sb.WriteString(StyleMenuTitle.Render("  "+line[2:]) + "\n")
		} else if strings.HasPrefix(line, "## ") {
			sb.WriteString(StyleSectionHeader.Render("  "+line[3:]) + "\n")
		} else if strings.HasPrefix(line, "---") {
			sb.WriteString(StyleDivider.Render("  "+strings.Repeat("─", 60)) + "\n")
		} else {
			sb.WriteString("  " + StyleMenuItem.Render(line) + "\n")
		}
	}

	sb.WriteString("\n" + StyleHelp.Render("  ↑/↓ scroll  ·  esc back"))
	return sb.String()
}

func (m Model) viewHelp() string {
	var sb strings.Builder
	sb.WriteString(StyleBanner.Render(banner) + "\n\n")
	sb.WriteString(StyleMenuTitle.Render("  Keyboard Reference") + "\n\n")

	help := []struct{ k, d string }{
		{"1-5", "Open module category"},
		{"↑ / ↓  or  j / k", "Navigate"},
		{"enter", "Select / confirm"},
		{"esc", "Back"},
		{"E", "Engagement Manager — create & switch engagements"},
		{"F", "View findings for the active engagement"},
		{"R", "Generate Markdown report for active engagement"},
		{"Q / ctrl+c", "Quit"},
		{"", ""},
		{"davoid new <name>", "Create engagement from CLI"},
		{"davoid list", "List all engagements"},
		{"davoid report", "Generate report for active engagement"},
	}
	for _, h := range help {
		if h.k == "" {
			sb.WriteString("\n")
			continue
		}
		sb.WriteString("  " + StyleMenuKey.Render(fmt.Sprintf("%-28s", h.k)) + StyleMenuItem.Render(h.d) + "\n")
	}
	sb.WriteString("\n" + StyleHelp.Render("  esc back"))
	return sb.String()
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

func StyleCyan(s string) string {
	return lipgloss.NewStyle().Foreground(colorCyan).Bold(true).Render(s)
}

func StyleGreen(s string) string {
	return lipgloss.NewStyle().Foreground(colorGreen).Bold(true).Render(s)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

