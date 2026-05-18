package tui

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/playbook"
	"github.com/bryanparreira/davoid/internal/runner"
	"github.com/bryanparreira/davoid/internal/targets"
	"github.com/bryanparreira/davoid/internal/updater"
	"github.com/bryanparreira/davoid/internal/vault"
)

// --------------------------------------------------------------------------
// State machine
// --------------------------------------------------------------------------

type state int

const (
	stateMenu state = iota
	stateEngagementNew
	stateEngagementList
	stateEngagementHub
	stateFindings
	stateModuleList
	stateModuleConfirm
	stateReport
	stateHelp
	stateVault
	stateTargets
	stateNotes
	stateNoteAdd
	stateTimeline
	statePlaybooks
	statePlaybookConfirm
)

// --------------------------------------------------------------------------
// Messages
// --------------------------------------------------------------------------

type engNote struct {
	Content   string
	CreatedAt time.Time
}

type (
	tickMsg           time.Time
	engLoadedMsg      struct{ eng *engagement.Engagement }
	findingsMsg       struct{ findings []*engagement.Finding }
	engListMsg        struct{ list []*engagement.Engagement }
	netInfoMsg        struct{ ip, gateway, vpn string }
	updateCheckMsg    struct{ latest string }
	updateProgressMsg struct{ line string }
	reportReadyMsg    struct {
		content string
		path    string
	}
	vaultMsg    struct{ creds []*vault.Credential }
	targetsMsg  struct{ hosts []*targets.Host; netmap string }
	notesMsg    struct{ notes []engNote }
	timelineMsg struct{ events []engagement.TimelineEvent }
	errMsg      struct{ err error }
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
	version        string
	localIP        string
	gateway        string
	vpn            string
	latestVersion  string
	updating       bool
	updateStatus   string
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
	// vault
	vaultCreds  []*vault.Credential
	vaultScroll int
	// targets
	targetHosts  []*targets.Host
	targetNetmap string
	targetScroll int
	// notes
	notesList   []engNote
	noteInput   inputField
	noteScroll  int
	// timeline
	timelineItems  []engagement.TimelineEvent
	timelineScroll int
	// playbooks
	playbookCursor   int
	selectedPlaybook playbook.Playbook
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
		{key: "1", label: "Recon & OSINT"},
		{key: "2", label: "Network Attacks"},
		{key: "3", label: "Social Engineering"},
		{key: "4", label: "Exploitation"},
		{key: "5", label: "Post-Exploitation"},
		{key: "6", label: "Active Directory"},
		{key: "7", label: "WiFi & Wireless"},
		{key: "8", label: "Advanced"},
		{key: "", label: ""},
		{key: "P", label: "Playbooks ▸"},
		{key: "E", label: "Engagement ▸"},
		{key: "", label: ""},
		{key: "?", label: "Help"},
		{key: "Q", label: "Quit"},
	}
}

func NewModel(version string) Model {
	m := Model{
		state:     stateMenu,
		version:   version,
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
		loadNetInfo(),
		checkUpdate(),
		tickCmd(),
	)
}

func loadNetInfo() tea.Cmd {
	return func() tea.Msg {
		return netInfoMsg{ip: getLocalIP(), gateway: getGateway(), vpn: getVPN()}
	}
}

func getVPN() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		name := iface.Name
		if strings.HasPrefix(name, "tun") || strings.HasPrefix(name, "tap") || strings.HasPrefix(name, "wg") {
			addrs, _ := iface.Addrs()
			if len(addrs) > 0 {
				return name
			}
		}
	}
	if os.Getenv("PROXYCHAINS_CONF_FILE") != "" || os.Getenv("PROXYCHAINS4_CONF_FILE") != "" {
		return "proxychains"
	}
	return ""
}

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "unavailable"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func getGateway() string {
	if runtime.GOOS == "linux" {
		return gatewayLinux()
	}
	return gatewayDarwin()
}

func gatewayLinux() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "unavailable"
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if fields[1] == "00000000" { // default route
			b, err := hex.DecodeString(fields[2])
			if err != nil || len(b) < 4 {
				continue
			}
			ip := net.IP([]byte{b[3], b[2], b[1], b[0]})
			return ip.String()
		}
	}
	return "unavailable"
}

func gatewayDarwin() string {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return "unavailable"
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		}
	}
	return "unavailable"
}

func checkUpdate() tea.Cmd {
	return func() tea.Msg {
		latest := updater.CheckLatest()
		return updateCheckMsg{latest: latest}
	}
}

func runUpdate(latest string) tea.Cmd {
	return func() tea.Msg {
		ch := updater.Update(latest)
		var last string
		for line := range ch {
			last = line
		}
		return updateProgressMsg{line: last}
	}
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

	case netInfoMsg:
		m.localIP = msg.ip
		m.gateway = msg.gateway
		m.vpn = msg.vpn
		return m, nil

	case timelineMsg:
		m.timelineItems = msg.events
		m.state = stateTimeline
		m.timelineScroll = 0
		return m, nil

	case updateCheckMsg:
		if updater.IsNewer(m.version, msg.latest) {
			m.latestVersion = msg.latest
		}
		return m, nil

	case updateProgressMsg:
		m.updating = false
		m.updateStatus = msg.line
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

	case vaultMsg:
		m.vaultCreds = msg.creds
		m.state = stateVault
		m.vaultScroll = 0
		return m, nil

	case targetsMsg:
		m.targetHosts = msg.hosts
		m.targetNetmap = msg.netmap
		m.state = stateTargets
		m.targetScroll = 0
		return m, nil

	case notesMsg:
		m.notesList = msg.notes
		m.state = stateNotes
		m.noteScroll = 0
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
			return m.openCategoryMenu("Recon & OSINT")
		case "2":
			return m.openCategoryMenu("Network Attacks")
		case "3":
			return m.openCategoryMenu("Social Engineering")
		case "4":
			return m.openCategoryMenu("Exploitation")
		case "5":
			return m.openCategoryMenu("Post-Exploitation")
		case "6":
			return m.openCategoryMenu("Active Directory")
		case "7":
			return m.openCategoryMenu("WiFi & Wireless")
		case "8":
			return m.openCategoryMenu("Advanced")
		case "p", "P":
			m.state = statePlaybooks
			m.playbookCursor = 0
			return m, nil
		case "e", "E":
			m.state = stateEngagementHub
			return m, nil
		case "?":
			m.state = stateHelp
		case "u", "U":
			if m.latestVersion != "" && !m.updating {
				m.updating = true
				m.updateStatus = "Downloading update..."
				return m, runUpdate(m.latestVersion)
			}
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
			m.state = stateEngagementHub
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
			m.state = stateEngagementHub
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
			m.state = stateEngagementHub
		}

	// ── Engagement Hub ────────────────────────────────────────────────────
	case stateEngagementHub:
		noEng := func() bool {
			if m.activeEng == nil {
				m.statusMsg = "No active engagement — press [N] to create one."
				m.statusIsError = true
				return true
			}
			return false
		}
		switch key {
		case "n", "N":
			m.state = stateEngagementNew
			m.engFieldCursor = 0
			for i := range m.engFields {
				m.engFields[i].value = ""
			}
		case "s", "S":
			m.state = stateEngagementList
			return m, loadEngList()
		case "f", "F":
			if noEng() {
				return m, nil
			}
			m.state = stateFindings
			return m, loadFindings(m.activeEng.ID)
		case "l", "L":
			if noEng() {
				return m, nil
			}
			return m, loadTimeline(m.activeEng.ID)
		case "r", "R":
			if noEng() {
				return m, nil
			}
			return m, generateReport(m.activeEng.ID)
		case "v", "V":
			if noEng() {
				return m, nil
			}
			return m, loadVault(m.activeEng.ID)
		case "m", "M":
			if noEng() {
				return m, nil
			}
			return m, loadTargets(m.activeEng.ID)
		case "o", "O":
			if noEng() {
				return m, nil
			}
			return m, loadNotes(m.activeEng.ID)
		case "esc", "q", "Q":
			m.state = stateMenu
		}

	// ── Timeline ──────────────────────────────────────────────────────────
	case stateTimeline:
		switch key {
		case "up", "k":
			if m.timelineScroll > 0 {
				m.timelineScroll--
			}
		case "down", "j":
			m.timelineScroll++
		case "esc", "q":
			m.state = stateEngagementHub
		}

	// ── Playbook list ─────────────────────────────────────────────────────
	case statePlaybooks:
		switch key {
		case "up", "k":
			if m.playbookCursor > 0 {
				m.playbookCursor--
			}
		case "down", "j":
			if m.playbookCursor < len(playbook.Registry)-1 {
				m.playbookCursor++
			}
		case "enter", " ":
			if m.playbookCursor < len(playbook.Registry) {
				m.selectedPlaybook = playbook.Registry[m.playbookCursor]
				m.state = statePlaybookConfirm
			}
		case "esc", "q":
			m.state = stateMenu
		}

	// ── Playbook confirm ──────────────────────────────────────────────────
	case statePlaybookConfirm:
		switch key {
		case "y", "Y", "enter":
			m.pendingModule = "playbook:" + m.selectedPlaybook.Key
			return m, tea.Quit
		case "n", "N", "esc":
			m.state = statePlaybooks
		}

	// ── Help ──────────────────────────────────────────────────────────────
	case stateHelp:
		if key == "esc" || key == "q" {
			m.state = stateMenu
		}

	// ── Credential Vault ─────────────────────────────────────────────────
	case stateVault:
		switch key {
		case "up", "k":
			if m.vaultScroll > 0 {
				m.vaultScroll--
			}
		case "down", "j":
			m.vaultScroll++
		case "esc", "q":
			m.state = stateEngagementHub
		}

	// ── Target Map ────────────────────────────────────────────────────────
	case stateTargets:
		switch key {
		case "up", "k":
			if m.targetScroll > 0 {
				m.targetScroll--
			}
		case "down", "j":
			m.targetScroll++
		case "esc", "q":
			m.state = stateEngagementHub
		}

	// ── Notes list ────────────────────────────────────────────────────────
	case stateNotes:
		switch key {
		case "up", "k":
			if m.noteScroll > 0 {
				m.noteScroll--
			}
		case "down", "j":
			m.noteScroll++
		case "a", "A":
			m.state = stateNoteAdd
			m.noteInput = inputField{label: "Note"}
		case "esc", "q":
			m.state = stateEngagementHub
		}

	// ── Note add form ─────────────────────────────────────────────────────
	case stateNoteAdd:
		switch key {
		case "enter":
			content := strings.TrimSpace(m.noteInput.value)
			if content != "" && m.activeEng != nil {
				engagement.SaveNote(m.activeEng.ID, content)
				return m, loadNotes(m.activeEng.ID)
			}
			m.state = stateNotes
		case "esc":
			m.state = stateNotes
		default:
			m.noteInput.handleKey(key)
		}
	}

	return m, nil
}

func (m Model) activateMenuItem(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "1":
		return m.openCategoryMenu("Recon & OSINT")
	case "2":
		return m.openCategoryMenu("Network Attacks")
	case "3":
		return m.openCategoryMenu("Social Engineering")
	case "4":
		return m.openCategoryMenu("Exploitation")
	case "5":
		return m.openCategoryMenu("Post-Exploitation")
	case "6":
		return m.openCategoryMenu("Active Directory")
	case "7":
		return m.openCategoryMenu("WiFi & Wireless")
	case "8":
		return m.openCategoryMenu("Advanced")
	case "P":
		m.state = statePlaybooks
		m.playbookCursor = 0
		return m, nil
	case "E":
		m.state = stateEngagementHub
		return m, nil
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

func loadTimeline(engID string) tea.Cmd {
	return func() tea.Msg {
		events, _ := engagement.Timeline(engID)
		return timelineMsg{events: events}
	}
}

func loadVault(engID string) tea.Cmd {
	return func() tea.Msg {
		creds, _ := vault.List(engID)
		return vaultMsg{creds: creds}
	}
}

func loadTargets(engID string) tea.Cmd {
	return func() tea.Msg {
		hosts, _ := targets.List(engID)
		netmap := targets.NetworkMap(engID)
		return targetsMsg{hosts: hosts, netmap: netmap}
	}
}

func loadNotes(engID string) tea.Cmd {
	return func() tea.Msg {
		raw, _ := engagement.Notes(engID)
		notes := make([]engNote, len(raw))
		for i, n := range raw {
			notes[i] = engNote{Content: n.Content, CreatedAt: n.CreatedAt}
		}
		return notesMsg{notes: notes}
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
	case stateEngagementHub:
		return m.viewEngagementHub()
	case stateTimeline:
		return m.viewTimeline()
	case stateVault:
		return m.viewVault()
	case stateTargets:
		return m.viewTargets()
	case stateNotes, stateNoteAdd:
		return m.viewNotes()
	case statePlaybooks:
		return m.viewPlaybooks()
	case statePlaybookConfirm:
		return m.viewPlaybookConfirm()
	default:
		return m.viewMainMenu()
	}
}

const bannerWide = `
██████╗  █████╗ ██╗   ██╗ ██████╗ ██╗██████╗
██╔══██╗██╔══██╗██║   ██║██╔═══██╗██║██╔══██╗
██║  ██║███████║██║   ██║██║   ██║██║██║  ██║
██║  ██║██╔══██║╚██╗ ██╔╝██║   ██║██║██║  ██║
██████╔╝██║  ██║ ╚████╔╝ ╚██████╔╝██║██████╔╝
╚═════╝ ╚═╝  ╚═╝  ╚═══╝   ╚═════╝ ╚═╝╚═════╝`

const bannerSmall = `
 ___   _   _   _  ___  ___ ___
|   \ /_\ | | | |/ _ \|_ _|   \
| |) / _ \| |_| | (_) || || |) |
|___/_/ \_|\___/ \___/|___|___/`

func (m Model) banner() string {
	return bannerWide
}

func (m Model) viewMainMenu() string {
	var sb strings.Builder

	// Banner
	sb.WriteString(StyleBanner.Render(m.banner()))
	sb.WriteString("\n")
	sb.WriteString(StyleSubtitle.Render("  ghost in the net  ·  operator-grade red team engagement platform") + "\n")
	sb.WriteString(StyleDivider.Render(strings.Repeat("─", 65)) + "\n")

	// Network info + version
	localIP := m.localIP
	if localIP == "" {
		localIP = "..."
	}
	gateway := m.gateway
	if gateway == "" {
		gateway = "..."
	}
	sb.WriteString("  ")
	sb.WriteString(StyleLabel.Render("IP  "))
	sb.WriteString(StyleValue.Render(localIP))
	sb.WriteString(StyleLabel.Render("   GW  "))
	sb.WriteString(StyleValue.Render(gateway))
	sb.WriteString(StyleLabel.Render("   v"))
	sb.WriteString(StyleValue.Render(m.version))
	if m.vpn != "" {
		sb.WriteString("  " + StyleSuccess.Render("VPN "+m.vpn))
	}
	if m.latestVersion != "" {
		sb.WriteString("  " + StyleWarning.Render("↑ "+m.latestVersion+" [U]"))
	}
	sb.WriteString("\n")

	// Update status
	if m.updateStatus != "" {
		if strings.HasPrefix(m.updateStatus, "Error") {
			sb.WriteString("  " + StyleError.Render(m.updateStatus) + "\n")
		} else {
			sb.WriteString("  " + StyleSuccess.Render(m.updateStatus) + "\n")
		}
	} else if m.updating {
		sb.WriteString("  " + StyleLabel.Render("Updating...") + "\n")
	}
	sb.WriteString("\n")

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
		{"1", "Recon & OSINT"},
		{"2", "Network Attacks"},
		{"3", "Social Engineering"},
		{"4", "Exploitation"},
		{"5", "Post-Exploitation"},
		{"6", "Active Directory"},
		{"7", "WiFi & Wireless"},
		{"8", "Advanced"},
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
		{"P", "Playbooks ▸"},
		{"E", "Engagement ▸"},
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
	sb.WriteString(StyleBanner.Render(m.banner()) + "\n\n")

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
	sb.WriteString(StyleBanner.Render(m.banner()) + "\n\n")
	sb.WriteString(StyleMenuTitle.Render("  Launch Module") + "\n\n")
	sb.WriteString("  " + StyleLabel.Render("Module:  ") + StyleValue.Render(m.selectedModule.Name) + "\n")
	sb.WriteString("  " + StyleLabel.Render("Category: ") + StyleValue.Render(m.selectedModule.Category) + "\n\n")
	sb.WriteString("  " + StyleMenuItem.Render(m.selectedModule.Description) + "\n\n")

	if m.activeEng != nil {
		sb.WriteString("  " + StyleLabel.Render("Engagement: ") + StyleEngagementActive.Render(m.activeEng.Name) + "\n")
		if m.activeEng.Scope != "" {
			sb.WriteString("  " + StyleLabel.Render("Scope:      ") + StyleHelp.Render(m.activeEng.Scope) + "\n")
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("  " + StyleWarning.Render("⚠  No active engagement — findings won't be tracked.\n\n"))
	}

	sb.WriteString("  " + StylePrompt.Render("Launch? [y/N]  "))
	sb.WriteString(StyleHelp.Render("· esc back"))
	return sb.String()
}

func (m Model) viewNewEngagement() string {
	var sb strings.Builder
	sb.WriteString(StyleBanner.Render(m.banner()) + "\n\n")
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
	sb.WriteString(StyleBanner.Render(m.banner()) + "\n\n")
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
	sb.WriteString(StyleBanner.Render(m.banner()) + "\n\n")

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
	sb.WriteString(StyleBanner.Render(m.banner()) + "\n\n")
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
	sb.WriteString(StyleBanner.Render(m.banner()) + "\n\n")
	sb.WriteString(StyleMenuTitle.Render("  Keyboard Reference") + "\n\n")

	help := []struct{ k, d string }{
		{"1-8", "Open module category  (7=WiFi  8=Advanced)"},
		{"↑ / ↓  or  j / k", "Navigate"},
		{"enter", "Select / confirm"},
		{"esc", "Back"},
		{"E", "Engagement Manager — create & switch engagements"},
		{"F", "View findings for the active engagement"},
		{"R", "Generate Markdown report for active engagement"},
		{"V", "Credential Vault — harvested creds from all modules"},
		{"T", "Target Map — discovered hosts & network topology"},
		{"N", "Notes — add/view engagement notes"},
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

func (m Model) viewEngagementHub() string {
	var sb strings.Builder
	sb.WriteString(StyleBanner.Render(m.banner()) + "\n\n")
	sb.WriteString(StyleMenuTitle.Render("  Engagement Hub") + "\n")

	if m.activeEng != nil {
		sb.WriteString("  " + StyleLabel.Render("Active: ") + StyleEngagementActive.Render(m.activeEng.Name))
		if m.activeEng.Target != "" {
			sb.WriteString(StyleLabel.Render("  →  ") + StyleValue.Render(m.activeEng.Target))
		}
		if m.activeEng.Scope != "" {
			sb.WriteString(StyleLabel.Render("  scope: ") + StyleHelp.Render(m.activeEng.Scope))
		}
	} else {
		sb.WriteString("  " + StyleEngagementNone.Render("no active engagement"))
	}
	sb.WriteString("\n\n")

	sb.WriteString(StyleDivider.Render("  "+strings.Repeat("─", 44)) + "\n\n")

	rows := []struct{ k, label, desc string }{
		{"N", "New Engagement", "start a new op"},
		{"S", "Switch / List", "set active engagement"},
		{"", "", ""},
		{"F", "Findings", "view all findings for active engagement"},
		{"L", "Timeline", "chronological activity log"},
		{"R", "Report", "generate Markdown / PDF report"},
		{"", "", ""},
		{"V", "Credential Vault", "harvested credentials"},
		{"M", "Target Map", "network topology + discovered hosts"},
		{"O", "Notes", "engagement notes"},
	}

	for _, r := range rows {
		if r.k == "" {
			sb.WriteString("\n")
			continue
		}
		key := StyleMenuKey.Render(fmt.Sprintf("  [%s]", r.k))
		label := StyleMenuItem.Render(fmt.Sprintf("  %-20s", r.label))
		desc := StyleHelp.Render(r.desc)
		sb.WriteString(key + label + desc + "\n")
	}

	sb.WriteString("\n" + StyleDivider.Render("  "+strings.Repeat("─", 44)) + "\n")

	if m.statusMsg != "" {
		if m.statusIsError {
			sb.WriteString("  " + StyleError.Render("✗ "+m.statusMsg) + "\n")
		} else {
			sb.WriteString("  " + StyleSuccess.Render("✓ "+m.statusMsg) + "\n")
		}
	}

	sb.WriteString("\n" + StyleHelp.Render("  key to select  ·  esc back"))
	return sb.String()
}

func (m Model) viewTimeline() string {
	var sb strings.Builder
	sb.WriteString(StyleBanner.Render(m.banner()) + "\n\n")

	title := "  Timeline"
	if m.activeEng != nil {
		title = fmt.Sprintf("  Timeline — %s", m.activeEng.Name)
	}
	sb.WriteString(StyleMenuTitle.Render(title) + "\n\n")

	if len(m.timelineItems) == 0 {
		sb.WriteString(StyleLabel.Render("  No activity recorded yet.\n"))
	} else {
		start := m.timelineScroll
		if start > len(m.timelineItems)-1 {
			start = 0
		}
		maxLines := m.height - 10
		count := 0
		for _, ev := range m.timelineItems[start:] {
			if count >= maxLines {
				break
			}
			ts := StyleHelp.Render(ev.Time.Format("01-02 15:04"))
			var kindBadge string
			if ev.Kind == "finding" {
				kindBadge = SeverityStyle(ev.Severity).Render(fmt.Sprintf("%-8s", ev.Severity))
			} else {
				kindBadge = StyleLabel.Render("NOTE    ")
			}
			sb.WriteString(fmt.Sprintf("  %s  %s  %s\n", ts, kindBadge, StyleMenuItem.Render(truncate(ev.Title, 55))))
			if ev.Detail != "" {
				sb.WriteString(StyleHelp.Render(fmt.Sprintf("              %s", truncate(ev.Detail, 60))) + "\n")
				count++
			}
			count++
		}
		sb.WriteString(StyleHelp.Render(fmt.Sprintf("\n  %d event(s) total", len(m.timelineItems))))
	}

	sb.WriteString("\n\n" + StyleHelp.Render("  ↑/↓ scroll  ·  esc back"))
	return sb.String()
}

func (m Model) viewVault() string {
	var sb strings.Builder
	sb.WriteString(StyleBanner.Render(m.banner()) + "\n\n")

	title := "  Credential Vault"
	if m.activeEng != nil {
		title = fmt.Sprintf("  Credential Vault — %s", m.activeEng.Name)
	}
	sb.WriteString(StyleMenuTitle.Render(title) + "\n\n")

	if len(m.vaultCreds) == 0 {
		sb.WriteString(StyleLabel.Render("  No credentials captured yet.\n"))
		sb.WriteString(StyleHelp.Render("  Run modules (phishing, sniff, looter) to harvest creds.\n"))
	} else {
		sb.WriteString(StyleTableHeader.Render(
			fmt.Sprintf("  %-12s  %-18s  %-20s  %-20s  %-8s\n",
				"Source", "Host", "Username", "Secret", "Kind"),
		))
		sb.WriteString(StyleDivider.Render("  "+strings.Repeat("─", 80)) + "\n")

		visible := m.vaultCreds
		start := m.vaultScroll
		if start > len(visible)-1 {
			start = 0
		}
		maxLines := m.height - 12
		count := 0
		for _, c := range visible[start:] {
			if count >= maxLines {
				break
			}
			secret := strings.Repeat("*", min(len(c.Secret), 8))
			line := fmt.Sprintf("  %-12s  %-18s  %-20s  %-20s  %-8s",
				truncate(c.Source, 10),
				truncate(c.Host, 16),
				truncate(c.Username, 18),
				truncate(secret, 18),
				c.Kind,
			)
			sb.WriteString(StyleTableRow.Render(line) + "\n")
			count++
		}
		sb.WriteString(StyleHelp.Render(fmt.Sprintf("\n  %d credential(s) total", len(m.vaultCreds))))
	}

	sb.WriteString("\n\n" + StyleHelp.Render("  ↑/↓ scroll  ·  esc back"))
	return sb.String()
}

func (m Model) viewTargets() string {
	var sb strings.Builder
	sb.WriteString(StyleBanner.Render(m.banner()) + "\n\n")

	title := "  Target Inventory"
	if m.activeEng != nil {
		title = fmt.Sprintf("  Target Inventory — %s", m.activeEng.Name)
	}
	sb.WriteString(StyleMenuTitle.Render(title) + "\n\n")

	if len(m.targetHosts) == 0 {
		sb.WriteString(StyleLabel.Render("  No hosts discovered yet.\n"))
		sb.WriteString(StyleHelp.Render("  Run Net-Mapper to populate the target inventory.\n"))
	} else {
		netmapLines := strings.Split(m.targetNetmap, "\n")
		start := m.targetScroll
		if start > len(netmapLines)-1 {
			start = 0
		}
		maxLines := m.height - 10
		end := start + maxLines
		if end > len(netmapLines) {
			end = len(netmapLines)
		}
		for _, line := range netmapLines[start:end] {
			if strings.Contains(line, "NETWORK MAP") || strings.Contains(line, "──") {
				sb.WriteString(StyleDivider.Render(line) + "\n")
			} else if strings.Contains(line, "[") {
				sb.WriteString(StyleMenuKey.Render(line) + "\n")
			} else if strings.Contains(line, "OS:") || strings.Contains(line, "Ports:") {
				sb.WriteString(StyleHelp.Render(line) + "\n")
			} else {
				sb.WriteString(StyleValue.Render(line) + "\n")
			}
		}
		sb.WriteString(StyleHelp.Render(fmt.Sprintf("\n  %d host(s) discovered", len(m.targetHosts))))
	}

	sb.WriteString("\n\n" + StyleHelp.Render("  ↑/↓ scroll  ·  esc back"))
	return sb.String()
}

func (m Model) viewNotes() string {
	var sb strings.Builder
	sb.WriteString(StyleBanner.Render(m.banner()) + "\n\n")

	title := "  Engagement Notes"
	if m.activeEng != nil {
		title = fmt.Sprintf("  Notes — %s", m.activeEng.Name)
	}
	sb.WriteString(StyleMenuTitle.Render(title) + "\n\n")

	if m.state == stateNoteAdd {
		sb.WriteString(StyleLabel.Render("  New Note\n\n"))
		sb.WriteString("  " + StyleLabel.Render(m.noteInput.label+":") + "\n")
		sb.WriteString("  " + StyleInput.Render(m.noteInput.value+"█") + "\n\n")
		sb.WriteString(StyleHelp.Render("  enter save  ·  esc cancel"))
		return sb.String()
	}

	if len(m.notesList) == 0 {
		sb.WriteString(StyleLabel.Render("  No notes yet.\n\n"))
	} else {
		start := m.noteScroll
		if start > len(m.notesList)-1 {
			start = 0
		}
		maxLines := m.height - 12
		count := 0
		for _, n := range m.notesList[start:] {
			if count >= maxLines {
				break
			}
			ts := StyleHelp.Render(n.CreatedAt.Format("2006-01-02 15:04"))
			sb.WriteString("  " + ts + "\n")
			sb.WriteString("  " + StyleMenuItem.Render(truncate(n.Content, 76)) + "\n\n")
			count += 3
		}
	}

	sb.WriteString(StyleHelp.Render("  [A] add note  ·  ↑/↓ scroll  ·  esc back"))
	return sb.String()
}

func (m Model) viewPlaybooks() string {
	var sb strings.Builder
	sb.WriteString(StyleBanner.Render(m.banner()) + "\n\n")
	sb.WriteString(StyleMenuTitle.Render("  Attack Playbooks") + "\n")
	sb.WriteString(StyleHelp.Render("  Pre-built module chains — one key launches a full kill chain") + "\n\n")
	sb.WriteString(StyleDivider.Render("  "+strings.Repeat("─", 60)) + "\n\n")

	for i, pb := range playbook.Registry {
		cat := StyleHelp.Render(fmt.Sprintf("[%s]", pb.Category))
		label := fmt.Sprintf("  %-22s %s", pb.Name, cat)
		desc := StyleHelp.Render(truncate(pb.Description, 55))

		if i == m.playbookCursor {
			sb.WriteString(StyleMenuItemSelected.Render(label) + "\n")
			sb.WriteString("  " + desc + "\n\n")
		} else {
			sb.WriteString(StyleMenuItem.Render(label) + "\n")
		}
	}

	sb.WriteString("\n" + StyleHelp.Render("  ↑/↓ navigate  ·  enter select  ·  esc back"))
	return sb.String()
}

func (m Model) viewPlaybookConfirm() string {
	var sb strings.Builder
	pb := m.selectedPlaybook
	sb.WriteString(StyleBanner.Render(m.banner()) + "\n\n")
	sb.WriteString(StyleMenuTitle.Render("  Launch Playbook") + "\n\n")
	sb.WriteString("  " + StyleLabel.Render("Name:      ") + StyleValue.Render(pb.Name) + "\n")
	sb.WriteString("  " + StyleLabel.Render("Category:  ") + StyleValue.Render(pb.Category) + "\n")
	sb.WriteString("  " + StyleLabel.Render("Modules:   ") + StyleValue.Render(fmt.Sprintf("%d steps", len(pb.Modules))) + "\n\n")
	sb.WriteString("  " + StyleMenuItem.Render(pb.Description) + "\n\n")

	sb.WriteString(StyleDivider.Render("  "+strings.Repeat("─", 40)) + "\n\n")
	for i, key := range pb.Modules {
		icon := "  ├──"
		if i == len(pb.Modules)-1 {
			icon = "  └──"
		}
		sb.WriteString(StyleHelp.Render(fmt.Sprintf("%s [%d] %s", icon, i+1, key)) + "\n")
	}
	sb.WriteString("\n")

	if m.activeEng != nil {
		sb.WriteString("  " + StyleLabel.Render("Engagement: ") + StyleEngagementActive.Render(m.activeEng.Name) + "\n\n")
	} else {
		sb.WriteString("  " + StyleWarning.Render("⚠  No active engagement — findings won't be tracked.") + "\n\n")
	}

	sb.WriteString("  " + StylePrompt.Render("Launch? [y/N]  ") + StyleHelp.Render("· esc back"))
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

