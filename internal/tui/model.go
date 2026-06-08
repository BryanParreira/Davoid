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

	"github.com/bryanparreira/davoid/internal/campaign"
	"github.com/bryanparreira/davoid/internal/config"
	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/playbook"
	"github.com/bryanparreira/davoid/internal/opsec"
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
	stateCampaign
	stateOpsec
	stateChecklist
	stateGraph
	stateDashboard      // engagement overview landing
	stateSettings       // inline config editor
	stateSearch         // search overlay (layered over any list)
	stateCompare        // multi-engagement comparison
	stateModuleRunning  // streaming module output
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
	updateProgressMsg struct {
		line string
		done bool
		ch   <-chan string
	}
	reportReadyMsg    struct {
		content string
		path    string
	}
	vaultMsg    struct{ creds []*vault.Credential }
	targetsMsg  struct{ hosts []*targets.Host; netmap string }
	notesMsg    struct{ notes []engNote }
	timelineMsg struct{ events []engagement.TimelineEvent }
	errMsg      struct{ err error }
	campaignDataMsg struct {
		phases      []campaign.PhaseInfo
		suggestions []campaign.Suggestion
	}
	opsecBadgeMsg     struct{ score int; label string }
	opsecReadyMsg     struct{ content string }
	checklistReadyMsg struct{ content string }
	graphReadyMsg     struct{ content string }
	playbooksMsg      struct{ list []playbook.Playbook }

	// new messages
	compareDataMsg struct {
		engA     *engagement.Engagement
		engB     *engagement.Engagement
		findingsA []*engagement.Finding
		findingsB []*engagement.Finding
	}
	moduleOutputMsg struct {
		line string
		done bool
		err  error
		ch   <-chan string
	}
	dashboardMsg struct {
		stats     dashboardStats
	}
)

func tickCmd() tea.Cmd {
	return tea.Tick(30*time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// dashboardStats holds precomputed stats shown in the dashboard view.
type dashboardStats struct {
	findingStats map[string]int
	hostCount    int
	credCount    int
	noteCount    int
	recentFindings []*engagement.Finding
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
	updateLines    []string // full scrollback of update messages
	updateCh       <-chan string
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
	hubCursor      int
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
	playbookList     []playbook.Playbook // built-in + custom
	playbookCursor   int
	selectedPlaybook playbook.Playbook
	// campaign
	campaignPhases      []campaign.PhaseInfo
	campaignSuggestions []campaign.Suggestion
	campaignCursor      int
	fromCampaign        bool // true when a module was launched from campaign view
	// opsec badge shown in main menu header
	opsecScore int
	opsecLabel string
	// opsec detail view
	opsecContent string
	opsecScroll  int
	// ptes checklist view
	checklistContent string
	checklistScroll  int
	// attack graph view
	graphContent string
	graphScroll  int

	// dashboard
	dashStats      dashboardStats
	dashboardReady bool

	// settings (inline config editor)
	settingsFields      [3]inputField // webhook URL, webhook events, Ollama URL
	settingsFieldCursor int
	settingsFromHub     bool

	// search / filter
	searchQuery   string
	searchActive  bool
	searchState   state // state we were in when search was activated
	filteredFindings  []*engagement.Finding
	filteredVaultCreds []*vault.Credential

	// multi-engagement comparison
	compareEngList    []*engagement.Engagement
	compareACursor    int
	compareBCursor    int
	compareStage      int // 0=pick A, 1=pick B, 2=view diff
	compareEngA       *engagement.Engagement
	compareEngB       *engagement.Engagement
	compareFindingsA  []*engagement.Finding
	compareFindingsB  []*engagement.Finding
	compareScroll     int

	// module streaming output
	moduleOutputLines []string
	moduleOutputScroll int
	moduleOutputDone  bool
	moduleOutputErr   error
	streamingModKey   string
}

// PendingModule returns the module key that should be run after the TUI exits,
// or an empty string if the user quit normally.
func (m Model) PendingModule() string { return m.pendingModule }

// PendingCampaign returns true if the module was launched from campaign view,
// so main loop can re-enter campaign state after the module completes.
func (m Model) PendingCampaign() bool { return m.fromCampaign }

// NewCampaignModel returns a Model that starts directly in campaign view.
func NewCampaignModel(version string) Model {
	m := NewModel(version)
	m.state = stateCampaign
	return m
}

type menuItem struct {
	key   string
	label string
	hint  string // short dimmed hint shown next to label on main menu
	desc  string // module description shown as subtitle in module list
	sub   bool   // true = opens submenu, false = direct action
	state state
}

func buildMainMenu() []menuItem {
	return []menuItem{
		{key: "C", label: "Campaign Mode", hint: "guided kill chain · smart suggestions"},
		{key: "", label: ""},
		{key: "1", label: fmt.Sprintf("Recon & OSINT  (%d)", len(runner.ByCategory("Recon & OSINT"))),      hint: "scanner · OSINT · web recon"},
		{key: "2", label: fmt.Sprintf("Network Attacks  (%d)", len(runner.ByCategory("Network Attacks"))),    hint: "MITM · traffic intercept"},
		{key: "3", label: fmt.Sprintf("Social Engineering  (%d)", len(runner.ByCategory("Social Engineering"))), hint: "phishing · C2 server"},
		{key: "4", label: fmt.Sprintf("Exploitation  (%d)", len(runner.ByCategory("Exploitation"))),       hint: "payloads · MSF · shell catcher"},
		{key: "5", label: fmt.Sprintf("Post-Exploitation  (%d)", len(runner.ByCategory("Post-Exploitation"))),  hint: "looter · cred tester · hash crack"},
		{key: "6", label: fmt.Sprintf("Active Directory  (%d)", len(runner.ByCategory("Active Directory"))),   hint: "LDAP · Kerberoast · DCSync"},
		{key: "7", label: fmt.Sprintf("WiFi & Wireless  (%d)", len(runner.ByCategory("WiFi & Wireless"))),    hint: "monitor · scan · deauth · handshake"},
		{key: "8", label: fmt.Sprintf("Advanced  (%d)", len(runner.ByCategory("Advanced"))),           hint: "AI · cloud · purple team · god mode"},
		{key: "", label: ""},
		{key: "P", label: "Playbooks",       hint: "pre-built attack chains"},
		{key: "E", label: "Engagement Hub",  hint: "findings · vault · targets · notes"},
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
		settingsFields: [3]inputField{
			{label: "Webhook URL (Discord / Slack / ntfy.sh)"},
			{label: "Webhook Events (comma-separated)"},
			{label: "Ollama URL"},
		},
	}
	return m
}

// NewDashboardModel returns a Model that starts directly in the dashboard.
func NewDashboardModel(version string) Model {
	m := NewModel(version)
	m.state = stateDashboard
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

func loadDashboard(engID string) tea.Cmd {
	return func() tea.Msg {
		stats := engagement.FindingStats(engID)
		hosts, _ := targets.List(engID)
		creds, _ := vault.List(engID)
		notes, _ := engagement.Notes(engID)
		recent, _ := engagement.Findings(engID)
		if len(recent) > 5 {
			recent = recent[:5]
		}
		return dashboardMsg{stats: dashboardStats{
			findingStats:   stats,
			hostCount:      len(hosts),
			credCount:      len(creds),
			noteCount:      len(notes),
			recentFindings: recent,
		}}
	}
}

func loadCompareData(engA, engB *engagement.Engagement) tea.Cmd {
	return func() tea.Msg {
		fa, _ := engagement.Findings(engA.ID)
		fb, _ := engagement.Findings(engB.ID)
		return compareDataMsg{engA: engA, engB: engB, findingsA: fa, findingsB: fb}
	}
}

func readModuleOutputStep(ch <-chan string) tea.Cmd {
	return func() tea.Msg {
		line, ok := <-ch
		if !ok {
			return moduleOutputMsg{done: true}
		}
		return moduleOutputMsg{line: line, ch: ch}
	}
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

func startUpdate(latest string) tea.Cmd {
	return func() tea.Msg {
		ch := updater.Update(latest)
		return updateProgressMsg{line: "Starting update...", done: false, ch: ch}
	}
}

// readUpdateStep reads one line from the update channel and schedules the next.
func readUpdateStep(ch <-chan string) tea.Cmd {
	return func() tea.Msg {
		line, ok := <-ch
		if !ok {
			return updateProgressMsg{line: "", done: true}
		}
		return updateProgressMsg{line: line, done: false, ch: ch}
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
		if engID != "" {
			ff, _ := engagement.Findings(engID)
			return findingsMsg{findings: ff}
		}
		ff, _ := engagement.RecentFindings(50)
		return findingsMsg{findings: ff}
	}
}

func loadEngList() tea.Cmd {
	return func() tea.Msg {
		list, _ := engagement.All()
		return engListMsg{list: list}
	}
}

func loadPlaybooks() tea.Cmd {
	return func() tea.Msg {
		all := make([]playbook.Playbook, len(playbook.Registry))
		copy(all, playbook.Registry)
		all = append(all, playbook.ListCustom()...)
		return playbooksMsg{list: all}
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
		if msg.eng != nil {
			cmds := []tea.Cmd{loadOpsecBadge(msg.eng.ID)}
			if m.state == stateCampaign {
				cmds = append(cmds, loadCampaignData(msg.eng.ID))
			}
			if m.state == stateDashboard || (!m.dashboardReady && m.state == stateMenu) {
				cmds = append(cmds, loadDashboard(msg.eng.ID))
				// Start at dashboard on first load if engagement is active
				if m.state == stateMenu && !m.dashboardReady {
					m.state = stateDashboard
				}
			}
			return m, tea.Batch(cmds...)
		}
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
		if msg.done {
			m.updating = false
		} else {
			if msg.line != "" {
				// Replace last line if it's a rolling percentage update
				if len(m.updateLines) > 0 && strings.HasPrefix(msg.line, "Downloading...") &&
					strings.HasPrefix(m.updateLines[len(m.updateLines)-1], "Downloading...") {
					m.updateLines[len(m.updateLines)-1] = msg.line
				} else {
					m.updateLines = append(m.updateLines, msg.line)
				}
				// Auto-quit 1.5s after successful install so new binary loads
				if strings.HasPrefix(msg.line, "✓ Updated to") {
					return m, tea.Tick(1500*time.Millisecond, func(t time.Time) tea.Msg {
						return tea.Quit()
					})
				}
			}
			if msg.ch != nil {
				return m, readUpdateStep(msg.ch)
			}
		}
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

	case campaignDataMsg:
		m.campaignPhases = msg.phases
		m.campaignSuggestions = msg.suggestions
		if m.campaignCursor >= len(msg.suggestions) {
			m.campaignCursor = 0
		}
		return m, nil

	case opsecBadgeMsg:
		m.opsecScore = msg.score
		m.opsecLabel = msg.label
		return m, nil

	case opsecReadyMsg:
		m.opsecContent = msg.content
		m.state = stateOpsec
		m.opsecScroll = 0
		return m, nil

	case checklistReadyMsg:
		m.checklistContent = msg.content
		m.state = stateChecklist
		m.checklistScroll = 0
		return m, nil

	case graphReadyMsg:
		m.graphContent = msg.content
		m.state = stateGraph
		m.graphScroll = 0
		return m, nil

	case playbooksMsg:
		m.playbookList = msg.list
		m.playbookCursor = 0
		m.state = statePlaybooks
		return m, nil

	case dashboardMsg:
		m.dashStats = msg.stats
		m.dashboardReady = true
		return m, nil

	case compareDataMsg:
		m.compareEngA = msg.engA
		m.compareEngB = msg.engB
		m.compareFindingsA = msg.findingsA
		m.compareFindingsB = msg.findingsB
		m.compareStage = 2
		m.compareScroll = 0
		return m, nil

	case moduleOutputMsg:
		if msg.done {
			m.moduleOutputDone = true
			m.moduleOutputErr = msg.err
		} else {
			if msg.line != "" {
				m.moduleOutputLines = append(m.moduleOutputLines, msg.line)
				// auto-scroll to bottom
				m.moduleOutputScroll = len(m.moduleOutputLines)
			}
			if msg.ch != nil {
				return m, readModuleOutputStep(msg.ch)
			}
		}
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

	// Global home key — back to main menu (or dashboard) from any sub-screen
	if (key == "h" || key == "H") && m.state != stateMenu && m.state != stateDashboard &&
		m.state != stateEngagementNew && m.state != stateNoteAdd && m.state != stateSettings && m.state != stateSearch {
		if m.activeEng != nil {
			m.state = stateDashboard
		} else {
			m.state = stateMenu
		}
		return m, nil
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
		case "c", "C":
			m.state = stateCampaign
			m.campaignCursor = 0
			if m.activeEng != nil {
				return m, loadCampaignData(m.activeEng.ID)
			}
			return m, nil
		case "p", "P":
			return m, loadPlaybooks()
		case "e", "E":
			m.state = stateEngagementHub
			m.hubCursor = 1 // skip section header row 0
			return m, nil
		case "?":
			m.state = stateHelp
		case "u", "U":
			if m.latestVersion != "" && !m.updating {
				m.updating = true
				m.updateLines = []string{"Connecting..."}
				return m, startUpdate(m.latestVersion)
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
		case "/":
			m.searchQuery = ""
			m.searchActive = true
			m.searchState = stateModuleList
			m.state = stateSearch
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
			// Check required external tools before launching
			if missing := checkModuleTools(m.selectedModule.Key); len(missing) > 0 {
				m.statusMsg = fmt.Sprintf("Missing tools: %s — run 'davoid doctor'", strings.Join(missing, ", "))
				m.statusIsError = true
				return m, nil
			}
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
				m.statusMsg = fmt.Sprintf("Active: %s", eng.Name)
				m.statusIsError = false
				m.state = stateEngagementHub
			}
		case "x", "X":
			if m.activeEng != nil {
				engagement.ClearActive()
				m.activeEng = nil
				m.statusMsg = "Engagement deactivated."
				m.statusIsError = false
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
		case "/":
			m.searchQuery = ""
			m.searchActive = true
			m.searchState = stateFindings
			m.filteredFindings = m.findings
			m.state = stateSearch
		case "esc", "q":
			m.searchQuery = ""
			m.filteredFindings = nil
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
		switch key {
		case "up", "k":
			rows := hubMenuRows()
			for m.hubCursor > 0 {
				m.hubCursor--
				if rows[m.hubCursor].key != "" {
					break
				}
			}
		case "down", "j":
			rows := hubMenuRows()
			for m.hubCursor < len(rows)-1 {
				m.hubCursor++
				if rows[m.hubCursor].key != "" {
					break
				}
			}
		case "enter", " ":
			rows := hubMenuRows()
			if m.hubCursor < len(rows) && rows[m.hubCursor].key != "" {
				return m.activateHubKey(rows[m.hubCursor].key)
			}
		case "n", "N", "s", "S", "f", "F", "l", "L", "r", "R", "v", "V", "m", "M", "o", "O", "i", "I", "K", "g", "G", "x", "X", "c", "C", "t", "T":
			return m.activateHubKey(key)
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
			if m.playbookCursor < len(m.playbookList)-1 {
				m.playbookCursor++
			}
		case "enter", " ":
			if m.playbookCursor < len(m.playbookList) {
				m.selectedPlaybook = m.playbookList[m.playbookCursor]
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
		case "/":
			m.searchQuery = ""
			m.searchActive = true
			m.searchState = stateVault
			m.filteredVaultCreds = m.vaultCreds
			m.state = stateSearch
		case "esc", "q":
			m.searchQuery = ""
			m.filteredVaultCreds = nil
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

	// ── Campaign view ─────────────────────────────────────────────────────
	case stateCampaign:
		switch key {
		case "up", "k":
			if m.campaignCursor > 0 {
				m.campaignCursor--
			}
		case "down", "j":
			if m.campaignCursor < len(m.campaignSuggestions)-1 {
				m.campaignCursor++
			}
		case "enter", " ":
			if m.activeEng == nil {
				m.state = stateEngagementNew
				m.engFieldCursor = 0
				for i := range m.engFields {
					m.engFields[i].value = ""
				}
				return m, nil
			}
			if m.campaignCursor < len(m.campaignSuggestions) {
				m.pendingModule = m.campaignSuggestions[m.campaignCursor].ModuleKey
				m.fromCampaign = true
				return m, tea.Quit
			}
		case "n", "N":
			m.state = stateEngagementNew
			m.engFieldCursor = 0
			for i := range m.engFields {
				m.engFields[i].value = ""
			}
		case "e", "E":
			m.state = stateEngagementHub
		case "m", "M":
			if m.activeEng == nil {
				return m, nil
			}
			var items []menuItem
			for _, mkey := range campaign.AllPhaseModules() {
				for _, mod := range runner.Registry {
					if mod.Key == mkey {
						items = append(items, menuItem{
							key:   mod.Key,
							label: fmt.Sprintf("%-20s  %s", mod.Name, runner.ShortDesc(mod.Description, 50)),
						})
						break
					}
				}
			}
			m.subMenuItems = items
			m.subMenuCursor = 0
			m.state = stateModuleList
		case "1", "2", "3", "4", "5", "6":
			if m.activeEng == nil {
				return m, nil
			}
			idx := int(key[0]-'1')
			if idx < len(m.campaignSuggestions) {
				m.pendingModule = m.campaignSuggestions[idx].ModuleKey
				m.fromCampaign = true
				return m, tea.Quit
			}
		case "r", "R":
			if m.activeEng != nil {
				return m, loadCampaignData(m.activeEng.ID)
			}
		case "esc", "q":
			m.state = stateMenu
		}

	// ── OPSEC view ───────────────────────────────────────────────────────────
	case stateOpsec:
		switch key {
		case "up", "k":
			if m.opsecScroll > 0 {
				m.opsecScroll--
			}
		case "down", "j":
			m.opsecScroll++
		case "esc", "q":
			m.state = stateEngagementHub
		}

	// ── PTES Checklist ───────────────────────────────────────────────────────
	case stateChecklist:
		switch key {
		case "up", "k":
			if m.checklistScroll > 0 {
				m.checklistScroll--
			}
		case "down", "j":
			m.checklistScroll++
		case "esc", "q":
			m.state = stateEngagementHub
		}

	// ── Attack Graph ─────────────────────────────────────────────────────────
	case stateGraph:
		switch key {
		case "up", "k":
			if m.graphScroll > 0 {
				m.graphScroll--
			}
		case "down", "j":
			m.graphScroll++
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

	// ── Dashboard ────────────────────────────────────────────────────────
	case stateDashboard:
		switch key {
		case "enter", " ", "m", "M":
			m.state = stateMenu
		case "e", "E":
			m.state = stateEngagementHub
		case "c", "C":
			m.state = stateCampaign
			m.campaignCursor = 0
			if m.activeEng != nil {
				return m, loadCampaignData(m.activeEng.ID)
			}
		case "f", "F":
			if m.activeEng != nil {
				m.state = stateFindings
				return m, loadFindings(m.activeEng.ID)
			}
		case "r", "R":
			if m.activeEng != nil {
				return m, loadDashboard(m.activeEng.ID)
			}
		case "s", "S":
			if m.activeEng != nil {
				m.state = stateSettings
				m.settingsFromHub = false
				cfg := loadConfigForSettings()
				m.settingsFields[0].value = cfg[0]
				m.settingsFields[1].value = cfg[1]
				m.settingsFields[2].value = cfg[2]
				m.settingsFieldCursor = 0
			}
		case "q", "Q":
			return m, tea.Quit
		}

	// ── Settings ──────────────────────────────────────────────────────────
	case stateSettings:
		switch key {
		case "tab", "down":
			m.settingsFieldCursor = (m.settingsFieldCursor + 1) % len(m.settingsFields)
		case "shift+tab", "up":
			m.settingsFieldCursor = (m.settingsFieldCursor - 1 + len(m.settingsFields)) % len(m.settingsFields)
		case "enter":
			if m.settingsFieldCursor < len(m.settingsFields)-1 {
				m.settingsFieldCursor++
			} else {
				saveSettings(m.settingsFields)
				m.statusMsg = "Settings saved."
				m.statusIsError = false
				if m.settingsFromHub {
					m.state = stateEngagementHub
				} else {
					m.state = stateDashboard
				}
			}
		case "ctrl+s":
			saveSettings(m.settingsFields)
			m.statusMsg = "Settings saved."
			m.statusIsError = false
			if m.settingsFromHub {
				m.state = stateEngagementHub
			} else {
				m.state = stateDashboard
			}
		case "esc":
			if m.settingsFromHub {
				m.state = stateEngagementHub
			} else {
				m.state = stateDashboard
			}
		default:
			m.settingsFields[m.settingsFieldCursor].handleKey(key)
		}

	// ── Search overlay ────────────────────────────────────────────────────
	case stateSearch:
		switch key {
		case "esc", "enter":
			m.searchActive = false
			m.state = m.searchState
		case "backspace", "ctrl+h":
			if len(m.searchQuery) > 0 {
				m.searchQuery = m.searchQuery[:len(m.searchQuery)-1]
				m.applySearch()
			}
		case "ctrl+u":
			m.searchQuery = ""
			m.applySearch()
		default:
			if len(key) == 1 {
				m.searchQuery += key
				m.applySearch()
			}
		}

	// ── Compare pick A ───────────────────────────────────────────────────
	case stateCompare:
		switch m.compareStage {
		case 0: // pick first engagement
			switch key {
			case "up", "k":
				if m.compareACursor > 0 {
					m.compareACursor--
				}
			case "down", "j":
				if m.compareACursor < len(m.compareEngList)-1 {
					m.compareACursor++
				}
			case "enter", " ":
				if m.compareACursor < len(m.compareEngList) {
					m.compareEngA = m.compareEngList[m.compareACursor]
					m.compareStage = 1
					m.compareBCursor = 0
				}
			case "esc", "q":
				m.state = stateEngagementHub
			}
		case 1: // pick second engagement
			switch key {
			case "up", "k":
				if m.compareBCursor > 0 {
					m.compareBCursor--
				}
			case "down", "j":
				if m.compareBCursor < len(m.compareEngList)-1 {
					m.compareBCursor++
				}
			case "enter", " ":
				if m.compareBCursor < len(m.compareEngList) {
					m.compareEngB = m.compareEngList[m.compareBCursor]
					return m, loadCompareData(m.compareEngA, m.compareEngB)
				}
			case "esc", "q":
				m.compareStage = 0
			}
		case 2: // view diff
			switch key {
			case "up", "k":
				if m.compareScroll > 0 {
					m.compareScroll--
				}
			case "down", "j":
				m.compareScroll++
			case "esc", "q":
				m.state = stateEngagementHub
			}
		}

	// ── Module streaming output ───────────────────────────────────────────
	case stateModuleRunning:
		switch key {
		case "up", "k":
			if m.moduleOutputScroll > 0 {
				m.moduleOutputScroll--
			}
		case "down", "j":
			m.moduleOutputScroll++
		case "enter", "esc", "q":
			if m.moduleOutputDone {
				m.state = stateMenu
			}
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
	case "C":
		m.state = stateCampaign
		m.campaignCursor = 0
		if m.activeEng != nil {
			return m, loadCampaignData(m.activeEng.ID)
		}
		return m, nil
	case "P":
		return m, loadPlaybooks()
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
		icon := " "
		if info, ok := opsec.ModuleNoise[mod.Key]; ok {
			icon = opsec.NoiseIcon(info.Level)
		}
		items[i] = menuItem{
			key:   mod.Key,
			label: icon + " " + mod.Name,
			desc:  runner.ShortDesc(mod.Description, 58),
		}
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

func loadCampaignData(engID string) tea.Cmd {
	return func() tea.Msg {
		metas := make([]campaign.ModuleMeta, len(runner.Registry))
		for i, m := range runner.Registry {
			metas[i] = campaign.ModuleMeta{Key: m.Key, Name: m.Name, Description: m.Description}
		}
		return campaignDataMsg{
			phases:      campaign.GetPhaseProgress(engID),
			suggestions: campaign.GenerateSuggestions(engID, metas),
		}
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

func loadOpsecBadge(engID string) tea.Cmd {
	return func() tea.Msg {
		ff, _ := engagement.Findings(engID)
		seen := map[string]bool{}
		var keys []string
		for _, f := range ff {
			if !seen[f.Module] {
				seen[f.Module] = true
				keys = append(keys, f.Module)
			}
		}
		score, label, _ := opsec.Score(keys)
		return opsecBadgeMsg{score: score, label: label}
	}
}

func loadOpsecView(engID string) tea.Cmd {
	return func() tea.Msg {
		ff, _ := engagement.Findings(engID)
		seen := map[string]bool{}
		var keys []string
		for _, f := range ff {
			if !seen[f.Module] {
				seen[f.Module] = true
				keys = append(keys, f.Module)
			}
		}
		score, label, breakdown := opsec.Score(keys)
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("%s  %s\n\n", opsec.ScoreBar(score), label))
		sb.WriteString(strings.Repeat("─", 64) + "\n")
		sb.WriteString(fmt.Sprintf("  %-3s  %-22s  %-8s  %s\n", "", "Module", "Noise", "Reason"))
		sb.WriteString(strings.Repeat("─", 64) + "\n")
		for _, rec := range breakdown {
			icon := opsec.NoiseIcon(rec.Level)
			sb.WriteString(fmt.Sprintf("  %s  %-22s  %-8s  %s\n", icon, rec.ModuleKey, rec.Level.String(), rec.Reason))
		}
		if len(breakdown) == 0 {
			sb.WriteString("  No modules executed yet.\n")
		}
		return opsecReadyMsg{content: sb.String()}
	}
}

func loadChecklistView(engID string) tea.Cmd {
	return func() tea.Msg {
		ff, _ := engagement.Findings(engID)
		done := map[string]bool{}
		for _, f := range ff {
			done[f.Module] = true
		}
		phases := []struct {
			name    string
			icon    string
			modules []string
			manual  []string
		}{
			{"Pre-Engagement", "①", nil, []string{
				"Define scope and rules of engagement",
				"Create engagement in Davoid  ✓",
			}},
			{"Reconnaissance", "②", []string{"osint", "scanner", "web_recon"}, nil},
			{"Network & MITM", "③", []string{"mitm", "sniff"}, nil},
			{"Social Engineering", "④", []string{"phishing", "ghost_hub"}, nil},
			{"Exploitation", "⑤", []string{"payloads", "msf_engine"}, nil},
			{"Post-Exploitation", "⑥", []string{"looter", "credops", "persistence"}, nil},
			{"Active Directory", "⑦", []string{"ad_ops"}, nil},
			{"WiFi", "⑧", []string{"wifi_monitor", "wifi_scan", "wifi_deauth", "wifi_handshake", "wifi_crack", "wifi_eviltwin"}, nil},
			{"Reporting", "⑨", nil, []string{"Generate engagement report  [davoid report]"}},
		}
		var sb strings.Builder
		sb.WriteString("PTES METHODOLOGY CHECKLIST\n")
		sb.WriteString(strings.Repeat("─", 64) + "\n\n")
		totalItems, completedItems := 0, 0
		for _, ph := range phases {
			sb.WriteString(fmt.Sprintf("%s  %s\n", ph.icon, ph.name))
			for _, mod := range ph.modules {
				check := "[ ]"
				if done[mod] {
					check = "[✓]"
					completedItems++
				}
				totalItems++
				sb.WriteString(fmt.Sprintf("  %s %s\n", check, mod))
			}
			for _, item := range ph.manual {
				sb.WriteString(fmt.Sprintf("  [·] %s\n", item))
			}
			sb.WriteString("\n")
		}
		sb.WriteString(strings.Repeat("─", 64) + "\n")
		sb.WriteString(fmt.Sprintf("Progress: %d / %d module steps completed\n", completedItems, totalItems))
		return checklistReadyMsg{content: sb.String()}
	}
}

func loadGraphView(engID string) tea.Cmd {
	return func() tea.Msg {
		ff, _ := engagement.Findings(engID)
		type modEntry struct {
			targets []string
			count   int
		}
		modMap := map[string]*modEntry{}
		order := []string{}
		seen := map[string]bool{}
		for _, f := range ff {
			if !seen[f.Module] {
				seen[f.Module] = true
				order = append(order, f.Module)
				modMap[f.Module] = &modEntry{}
			}
			modMap[f.Module].count++
			tSeen := false
			for _, t := range modMap[f.Module].targets {
				if t == f.Target {
					tSeen = true
					break
				}
			}
			if !tSeen {
				modMap[f.Module].targets = append(modMap[f.Module].targets, f.Target)
			}
		}
		var sb strings.Builder
		sb.WriteString("ATTACK GRAPH\n")
		sb.WriteString(strings.Repeat("─", 64) + "\n\n")
		if len(order) == 0 {
			sb.WriteString("  No findings recorded yet.\n")
			sb.WriteString("  Run modules to populate the attack graph.\n")
		} else {
			sb.WriteString("  [OPERATOR]\n")
			for i, mod := range order {
				entry := modMap[mod]
				connector := "  ├──"
				childConn := "  │    └──"
				if i == len(order)-1 {
					connector = "  └──"
					childConn = "       └──"
				}
				noiseInfo := opsec.ModuleNoise[mod]
				icon := opsec.NoiseIcon(noiseInfo.Level)
				sb.WriteString(fmt.Sprintf("%s %s [%s]  %d finding(s)\n", connector, mod, icon, entry.count))
				for _, t := range entry.targets {
					sb.WriteString(fmt.Sprintf("%s target: %s\n", childConn, t))
				}
			}
		}
		sb.WriteString("\n")
		sb.WriteString(strings.Repeat("─", 64) + "\n")
		sb.WriteString(fmt.Sprintf("Noise icons: %s none  %s low  %s medium  %s high\n",
			opsec.NoiseIcon(opsec.NoiseNone),
			opsec.NoiseIcon(opsec.NoiseLow),
			opsec.NoiseIcon(opsec.NoiseMedium),
			opsec.NoiseIcon(opsec.NoiseHigh),
		))
		return graphReadyMsg{content: sb.String()}
	}
}

// --------------------------------------------------------------------------
// View
// --------------------------------------------------------------------------

func (m Model) View() string {
	var content string
	switch m.state {
	case stateEngagementNew:
		content = m.viewNewEngagement()
	case stateEngagementList:
		content = m.viewEngagementList()
	case stateFindings:
		content = m.viewFindings()
	case stateModuleList:
		content = m.viewModuleList()
	case stateModuleConfirm:
		content = m.viewModuleConfirm()
	case stateReport:
		content = m.viewReport()
	case stateHelp:
		content = m.viewHelp()
	case stateEngagementHub:
		content = m.viewEngagementHub()
	case stateTimeline:
		content = m.viewTimeline()
	case stateVault:
		content = m.viewVault()
	case stateTargets:
		content = m.viewTargets()
	case stateNotes, stateNoteAdd:
		content = m.viewNotes()
	case statePlaybooks:
		content = m.viewPlaybooks()
	case statePlaybookConfirm:
		content = m.viewPlaybookConfirm()
	case stateCampaign:
		content = m.viewCampaign()
	case stateOpsec:
		content = m.viewOpsec()
	case stateChecklist:
		content = m.viewChecklist()
	case stateGraph:
		content = m.viewGraph()
	case stateDashboard:
		content = m.viewDashboard()
	case stateSettings:
		content = m.viewSettings()
	case stateSearch:
		content = m.viewSearch()
	case stateCompare:
		content = m.viewCompare()
	case stateModuleRunning:
		content = m.viewModuleRunning()
	default:
		content = m.viewMainMenu()
	}
	return content + m.statusBar()
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
	if m.width > 0 && m.width < 70 {
		return bannerSmall
	}
	return bannerWide
}

func (m Model) breadcrumb() string {
	path := []string{}
	switch m.state {
	case stateMenu:
		path = []string{"Main"}
	case stateCampaign:
		path = []string{"Main", "Campaign"}
	case statePlaybooks:
		path = []string{"Main", "Playbooks"}
	case statePlaybookConfirm:
		path = []string{"Main", "Playbooks", m.selectedPlaybook.Name}
	case stateModuleList:
		path = []string{"Main", "Modules"}
	case stateModuleConfirm:
		path = []string{"Main", "Modules", m.selectedModule.Name}
	case stateHelp:
		path = []string{"Main", "Help"}
	case stateEngagementHub:
		path = []string{"Main", "Engagement Hub"}
	case stateEngagementNew:
		path = []string{"Main", "Engagement Hub", "New"}
	case stateEngagementList:
		path = []string{"Main", "Engagement Hub", "Switch"}
	case stateFindings:
		path = []string{"Main", "Engagement Hub", "Findings"}
	case stateTimeline:
		path = []string{"Main", "Engagement Hub", "Timeline"}
	case stateReport:
		path = []string{"Main", "Engagement Hub", "Report"}
	case stateVault:
		path = []string{"Main", "Engagement Hub", "Vault"}
	case stateTargets:
		path = []string{"Main", "Engagement Hub", "Targets"}
	case stateNotes, stateNoteAdd:
		path = []string{"Main", "Engagement Hub", "Notes"}
	case stateOpsec:
		path = []string{"Main", "Engagement Hub", "OPSEC Score"}
	case stateChecklist:
		path = []string{"Main", "Engagement Hub", "Checklist"}
	case stateGraph:
		path = []string{"Main", "Engagement Hub", "Attack Graph"}
	case stateDashboard:
		path = []string{"Dashboard"}
	case stateSettings:
		path = []string{"Main", "Engagement Hub", "Settings"}
	case stateSearch:
		path = []string{"Main", "Search"}
	case stateCompare:
		path = []string{"Main", "Engagement Hub", "Compare"}
	case stateModuleRunning:
		path = []string{"Main", "Modules", "Running"}
	default:
		path = []string{"Main"}
	}
	parts := make([]string, len(path))
	for i, p := range path {
		if i == len(path)-1 {
			parts[i] = StyleValue.Render(p)
		} else {
			parts[i] = StyleHelp.Render(p)
		}
	}
	return "  " + strings.Join(parts, StyleHelp.Render(" / "))
}

func (m Model) header(title string) string {
	var sb strings.Builder
	sb.WriteString(StyleBanner.Render(m.banner()) + "\n")
	sb.WriteString(m.breadcrumb() + "\n")
	sb.WriteString(StyleDivider.Render("  "+strings.Repeat("─", 55)) + "\n")
	if title != "" {
		sb.WriteString(StyleMenuTitle.Render(title) + "\n\n")
	}
	return sb.String()
}

func (m Model) viewMainMenu() string {
	var sb strings.Builder

	// Banner
	sb.WriteString(StyleBanner.Render(m.banner()))
	sb.WriteString("\n")
	sb.WriteString(StyleSubtitle.Render("  ghost in the net  ·  operator-grade red team engagement platform") + "\n")
	sb.WriteString(m.breadcrumb() + "\n")
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
	if m.activeEng != nil && m.opsecLabel != "" {
		var badge string
		switch m.opsecLabel {
		case "QUIET", "CLEAN":
			badge = StyleSuccess.Render("OPSEC " + m.opsecLabel)
		case "MODERATE":
			badge = StyleWarning.Render("OPSEC " + m.opsecLabel)
		default:
			badge = StyleError.Render("OPSEC " + m.opsecLabel)
		}
		sb.WriteString("  " + badge)
	}
	if m.latestVersion != "" {
		sb.WriteString("  " + StyleWarning.Render("update: "+m.latestVersion+" [U]"))
	}
	sb.WriteString("\n")

	// Update status panel
	if len(m.updateLines) > 0 || m.updating {
		sb.WriteString(StyleDivider.Render("  "+strings.Repeat("─", 50)) + "\n")
		// Show last 4 lines so sudo command is always visible
		lines := m.updateLines
		if len(lines) > 4 {
			lines = lines[len(lines)-4:]
		}
		for _, line := range lines {
			switch {
			case strings.HasPrefix(line, "Error"):
				sb.WriteString("  " + StyleError.Render("✗ "+line) + "\n")
			case strings.HasPrefix(line, "✓"):
				sb.WriteString("  " + StyleSuccess.Render(line) + "\n")
			case strings.HasPrefix(line, "⚠"):
				sb.WriteString("  " + StyleWarning.Render(line) + "\n")
			case strings.HasPrefix(line, "  sudo") || strings.HasPrefix(line, "  Try"):
				sb.WriteString("  " + StyleMenuKey.Render(line) + "\n")
			case strings.HasPrefix(line, "Downloading..."):
				sb.WriteString("  " + StyleLabel.Render("⟳ "+line) + "\n")
			default:
				sb.WriteString("  " + StyleValue.Render("  "+line) + "\n")
			}
		}
		if m.updating {
			sb.WriteString("  " + StyleHelp.Render("  updating — please wait...") + "\n")
		}
		sb.WriteString(StyleDivider.Render("  "+strings.Repeat("─", 50)) + "\n")
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
				sb.WriteString(StyleFindingCritical.Render(fmt.Sprintf("C:%d", stats["CRITICAL"])) + " ")
			}
			if stats["HIGH"] > 0 {
				sb.WriteString(StyleFindingHigh.Render(fmt.Sprintf("H:%d", stats["HIGH"])) + " ")
			}
		}
	} else {
		sb.WriteString(StyleEngagementNone.Render("none active"))
	}
	sb.WriteString("\n\n")

	// Menu items — rendered directly from menuItems so cursor tracking is exact
	attackSectionPrinted := false
	for i, item := range m.menuItems {
		if item.key == "" {
			sb.WriteString("\n")
			continue
		}
		// Print "ATTACK MODULES" header before first category key
		if !attackSectionPrinted && item.key == "1" {
			sb.WriteString("  " + StyleSectionHeader.Render("ATTACK MODULES") + "\n")
			sb.WriteString(StyleDivider.Render("  "+strings.Repeat("─", 42)) + "\n")
			attackSectionPrinted = true
		}
		if item.key == "P" {
			sb.WriteString(StyleDivider.Render("  "+strings.Repeat("─", 42)) + "\n")
		}
		cursor := "  "
		selected := m.menuCursor == i
		if selected {
			cursor = StyleCyan("> ")
		}
		keyStr := StyleMenuKey.Render("[" + item.key + "]")
		var labelStr string
		switch {
		case selected:
			labelStr = StyleMenuItemSelected.Render(" " + fmt.Sprintf("%-22s", item.label) + " ")
		case item.key == "C":
			labelStr = StyleWarning.Render(fmt.Sprintf("%-24s", item.label))
		default:
			labelStr = StyleMenuItem.Render(fmt.Sprintf("%-24s", item.label))
		}
		hintStr := ""
		if item.hint != "" {
			hintStr = StyleHelp.Render("   " + item.hint)
		}
		sb.WriteString(cursor + keyStr + "  " + labelStr + hintStr + "\n")
	}

	sb.WriteString("\n")
	sb.WriteString(StyleHelp.Render("  ↑/↓  ·  enter  ·  1-8 quick jump  ·  [?] help  ·  [Q] quit"))
	sb.WriteString("\n")

	return sb.String()
}

func (m Model) viewModuleList() string {
	var sb strings.Builder

	if len(m.subMenuItems) == 0 {
		sb.WriteString(m.header(""))
		sb.WriteString(StyleError.Render("  No modules in this category.\n"))
	} else {
		sb.WriteString(m.header("  Select Module"))
		// Each item = 3 lines (name + desc + blank gap)
		maxVisible := (m.height - 14) / 3
		if maxVisible < 3 {
			maxVisible = 3
		}
		start := 0
		if m.subMenuCursor >= maxVisible {
			start = m.subMenuCursor - maxVisible + 1
		}
		end := start + maxVisible
		if end > len(m.subMenuItems) {
			end = len(m.subMenuItems)
		}
		if start > 0 {
			sb.WriteString(StyleHelp.Render(fmt.Sprintf("  ↑ %d more above\n", start)))
		}
		for i := start; i < end; i++ {
			item := m.subMenuItems[i]
			selected := i == m.subMenuCursor
			if selected {
				sb.WriteString(StyleCyan("  > ") + StyleMenuItemSelected.Render(" "+item.label+" ") + "\n")
				if item.desc != "" {
					sb.WriteString(StyleHelp.Render("      "+item.desc) + "\n")
				}
			} else {
				sb.WriteString("    " + StyleMenuItem.Render(item.label) + "\n")
				if item.desc != "" {
					sb.WriteString(StyleHelp.Render("      "+item.desc) + "\n")
				}
			}
			sb.WriteString("\n")
		}
		if end < len(m.subMenuItems) {
			sb.WriteString(StyleHelp.Render(fmt.Sprintf("  ↓ %d more below\n", len(m.subMenuItems)-end)))
		}
	}

	sb.WriteString(StyleHelp.Render("  ↑/↓ navigate  ·  enter select  ·  [/] search  ·  esc back"))
	return sb.String()
}

func (m Model) viewModuleConfirm() string {
	var sb strings.Builder
	sb.WriteString(m.header("  Launch Module"))

	// Module info in a rounded border box
	noiseDesc := ""
	if info, ok := opsec.ModuleNoise[m.selectedModule.Key]; ok {
		noiseDesc = opsec.NoiseIcon(info.Level) + "  " + info.Reason
	}
	boxWidth := 62
	if m.width > 0 && m.width < 72 {
		boxWidth = m.width - 10
	}
	boxContent := StyleLabel.Render("Module    ") + StyleValue.Bold(true).Render(m.selectedModule.Name) + "\n" +
		StyleLabel.Render("Category  ") + StyleValue.Render(m.selectedModule.Category) + "\n" +
		StyleLabel.Render("Noise     ") + StyleHelp.Render(noiseDesc) + "\n\n" +
		StyleMenuItem.Render(m.selectedModule.Description)
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorDimCyan).
		Padding(1, 2).
		Width(boxWidth).
		Render(boxContent)
	sb.WriteString("  " + box + "\n\n")

	if m.activeEng != nil {
		sb.WriteString("  " + StyleLabel.Render("Engagement  ") + StyleEngagementActive.Render(m.activeEng.Name) + "\n")
		if m.activeEng.Scope != "" {
			sb.WriteString("  " + StyleLabel.Render("Scope       ") + StyleHelp.Render(m.activeEng.Scope) + "\n")
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("  " + StyleWarning.Render("[!] No active engagement — findings won't be tracked.") + "\n\n")
	}

	yesStyle := lipgloss.NewStyle().Foreground(colorBG).Background(colorGreen).Bold(true).Padding(0, 2)
	noStyle := lipgloss.NewStyle().Foreground(colorLightGray).Border(lipgloss.NormalBorder()).BorderForeground(colorGray).Padding(0, 1)
	sb.WriteString("  " + yesStyle.Render("Y  launch") + "  " + noStyle.Render("N  back") + "\n")
	return sb.String()
}

func (m Model) viewNewEngagement() string {
	var sb strings.Builder
	sb.WriteString(m.header("  New Engagement"))

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
	sb.WriteString(m.header("  Engagement Manager"))

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
				active = StyleGreen(" [active]")
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
	sb.WriteString(StyleHelp.Render("  [N] new  ·  enter/[S] set active  ·  [X] deactivate  ·  ↑/↓ navigate  ·  esc back"))
	return sb.String()
}

func (m Model) viewFindings() string {
	var sb strings.Builder
	sb.WriteString(m.header(""))

	title := "  Recent Findings"
	if m.activeEng != nil {
		title = fmt.Sprintf("  Findings — %s", m.activeEng.Name)
	}
	sb.WriteString(StyleMenuTitle.Render(title) + "  " + fmtScroll(m.findingScroll, len(m.findings)) + "\n\n")

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

	sb.WriteString(StyleHelp.Render("  ↑/↓ scroll  ·  [H] home  ·  esc back"))
	return sb.String()
}

func (m Model) viewReport() string {
	var sb strings.Builder
	sb.WriteString(m.header(""))
	sb.WriteString(StyleSuccess.Render("  Report Generated") + "\n")
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

	sb.WriteString("\n" + StyleHelp.Render("  ↑/↓ scroll  ·  [H] home  ·  esc back"))
	return sb.String()
}

func (m Model) viewHelp() string {
	var sb strings.Builder
	sb.WriteString(m.header("  Keyboard Reference"))

	help := []struct{ k, d string }{
		{"C", "Campaign Mode — guided kill chain with smart suggestions"},
		{"1-8", "Open module category  (7=WiFi  8=Advanced)"},
		{"P", "Attack Playbooks — pre-built module chains"},
		{"E", "Engagement Hub — create, switch, findings, vault"},
		{"U", "Install available update"},
		{"", ""},
		{"↑ / ↓  or  j / k", "Navigate menus and lists"},
		{"enter", "Select / confirm / launch"},
		{"H", "Home — back to main menu from anywhere"},
		{"esc", "Back to previous screen"},
		{"Q / ctrl+c", "Quit"},
		{"", ""},
		{"In Engagement Hub", ""},
		{"X", "Deactivate current engagement (start fresh)"},
		{"N", "New engagement"},
		{"S", "Switch to a different engagement"},
		{"I", "OPSEC Score — module noise breakdown"},
		{"K", "PTES Checklist — methodology progress"},
		{"G", "Attack Graph — module execution tree"},
		{"", ""},
		{"In Campaign Mode", ""},
		{"↑ / ↓", "Navigate suggested modules"},
		{"enter", "Launch selected module"},
		{"M", "Browse all modules by kill chain phase"},
		{"R", "Refresh suggestions from engagement data"},
		{"N", "New engagement"},
		{"E", "Engagement Hub"},
		{"", ""},
		{"davoid new <name>", "Create engagement from CLI"},
		{"davoid run <module>", "Run any module directly"},
		{"davoid list", "List all engagements"},
		{"davoid report", "Generate report for active engagement"},
		{"davoid doctor", "Check tool dependencies"},
	}
	for _, h := range help {
		if h.k == "" {
			sb.WriteString("\n")
			continue
		}
		sb.WriteString("  " + StyleMenuKey.Render(fmt.Sprintf("%-28s", h.k)) + StyleMenuItem.Render(h.d) + "\n")
	}
	sb.WriteString("\n" + StyleHelp.Render("  [H] home  ·  esc back"))
	return sb.String()
}

func (m Model) viewEngagementHub() string {
	var sb strings.Builder
	sb.WriteString(m.header(""))
	sb.WriteString(StyleMenuTitle.Render("  Engagement Hub") + "\n")

	if m.activeEng != nil {
		engBox := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorDimCyan).
			Padding(0, 2).
			Render(
				StyleEngagementActive.Render(m.activeEng.Name) +
					func() string {
						if m.activeEng.Target != "" {
							return StyleLabel.Render("  →  ") + StyleValue.Render(m.activeEng.Target)
						}
						return ""
					}() +
					func() string {
						if m.activeEng.Scope != "" {
							return StyleLabel.Render("  scope: ") + StyleHelp.Render(m.activeEng.Scope)
						}
						return ""
					}(),
			)
		sb.WriteString("  " + engBox + "\n\n")
	} else {
		sb.WriteString("  " + StyleEngagementNone.Render("no active engagement — [N] to create one") + "\n\n")
	}

	rows := hubMenuRows()
	for i, r := range rows {
		if r.section != "" {
			sb.WriteString("\n  " + StyleSectionHeader.Render(r.section) + "\n")
			sb.WriteString(StyleDivider.Render("  "+strings.Repeat("─", 36)) + "\n")
			continue
		}
		if r.key == "" {
			continue
		}
		selected := m.hubCursor == i
		cursor := "   "
		if selected {
			cursor = StyleCyan(" > ")
		}
		key := StyleMenuKey.Render("[" + r.key + "]")
		var label string
		if selected {
			label = StyleMenuItemSelected.Render(" "+fmt.Sprintf("%-18s", r.label)+" ")
		} else {
			label = StyleMenuItem.Render(fmt.Sprintf("%-20s", r.label))
		}
		desc := StyleHelp.Render(r.desc)
		sb.WriteString(cursor + key + "  " + label + "  " + desc + "\n")
	}

	sb.WriteString("\n" + StyleHelp.Render("  ↑/↓  ·  enter  ·  press key directly  ·  esc back"))
	return sb.String()
}

func (m Model) viewTimeline() string {
	var sb strings.Builder
	sb.WriteString(m.header(""))

	title := "  Timeline"
	if m.activeEng != nil {
		title = fmt.Sprintf("  Timeline — %s", m.activeEng.Name)
	}
	sb.WriteString(StyleMenuTitle.Render(title) + "  " + fmtScroll(m.timelineScroll, len(m.timelineItems)) + "\n\n")

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

	sb.WriteString("\n\n" + StyleHelp.Render("  ↑/↓ scroll  ·  [H] home  ·  esc back"))
	return sb.String()
}

func (m Model) viewVault() string {
	var sb strings.Builder
	sb.WriteString(m.header(""))

	title := "  Credential Vault"
	if m.activeEng != nil {
		title = fmt.Sprintf("  Credential Vault — %s", m.activeEng.Name)
	}
	sb.WriteString(StyleMenuTitle.Render(title) + "  " + fmtScroll(m.vaultScroll, len(m.vaultCreds)) + "\n\n")

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

	sb.WriteString("\n\n" + StyleHelp.Render("  ↑/↓ scroll  ·  [H] home  ·  esc back"))
	return sb.String()
}

func (m Model) viewTargets() string {
	var sb strings.Builder
	sb.WriteString(m.header(""))

	title := "  Target Inventory"
	if m.activeEng != nil {
		title = fmt.Sprintf("  Target Inventory — %s", m.activeEng.Name)
	}
	sb.WriteString(StyleMenuTitle.Render(title) + "  " + fmtScroll(m.targetScroll, len(m.targetHosts)) + "\n\n")

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

	sb.WriteString("\n\n" + StyleHelp.Render("  ↑/↓ scroll  ·  [H] home  ·  esc back"))
	return sb.String()
}

func (m Model) viewNotes() string {
	var sb strings.Builder
	sb.WriteString(m.header(""))

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

	sb.WriteString(StyleHelp.Render("  [A] add note  ·  ↑/↓ scroll  ·  [H] home  ·  esc back"))
	return sb.String()
}

func (m Model) viewPlaybooks() string {
	var sb strings.Builder
	sb.WriteString(m.header("  Attack Playbooks"))
	sb.WriteString(StyleHelp.Render("  Pre-built module chains — one key launches a full kill chain") + "\n\n")
	sb.WriteString(StyleDivider.Render("  "+strings.Repeat("─", 60)) + "\n\n")

	for i, pb := range m.playbookList {
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

	sb.WriteString("\n" + StyleHelp.Render("  ↑/↓ navigate  ·  enter select  ·  [H] home  ·  esc back"))
	return sb.String()
}

func (m Model) viewPlaybookConfirm() string {
	var sb strings.Builder
	pb := m.selectedPlaybook
	sb.WriteString(m.header("  Launch Playbook"))
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
		sb.WriteString("  " + StyleWarning.Render("[!] No active engagement — findings won't be tracked.") + "\n\n")
	}

	sb.WriteString("  " + StylePrompt.Render("Launch? [y/N]  ") + StyleHelp.Render("· esc back"))
	return sb.String()
}

func (m Model) viewCampaign() string {
	var sb strings.Builder

	// Header
	sb.WriteString(m.header(""))
	title := "  CAMPAIGN MODE"
	if m.activeEng != nil {
		title += "  —  " + m.activeEng.Name
		if m.activeEng.Target != "" {
			title += "  " + StyleLabel.Render("["+m.activeEng.Target+"]")
		}
	}
	sb.WriteString(StyleMenuTitle.Render(title) + "\n")
	sb.WriteString(StyleDivider.Render("  "+strings.Repeat("─", 60)) + "\n\n")

	if m.activeEng == nil {
		sb.WriteString("  " + StyleWarning.Render("[!] No active engagement.") + "\n\n")
		sb.WriteString("  " + StyleMenuItem.Render("Campaign Mode tracks your progress across the kill chain.") + "\n")
		sb.WriteString("  " + StyleMenuItem.Render("Create an engagement to get started.") + "\n\n")
		sb.WriteString("  " + StyleMenuKey.Render("[N]") + "  " + StyleMenuItem.Render("New Engagement") + "\n")
		sb.WriteString("  " + StyleMenuKey.Render("[E]") + "  " + StyleMenuItem.Render("Engagement Hub") + "\n")
		sb.WriteString("  " + StyleMenuKey.Render("[enter]") + "  " + StyleMenuItem.Render("Quick create") + "\n\n")
		sb.WriteString("  " + StyleHelp.Render("[esc] back to menu") + "\n")
		return sb.String()
	}

	// Kill chain progress
	sb.WriteString("  " + StyleSectionHeader.Render("Kill Chain Progress") + "\n")
	sb.WriteString(StyleDivider.Render("  "+strings.Repeat("─", 40)) + "\n")
	for _, p := range m.campaignPhases {
		marker := StyleHelp.Render("[ ]")
		if p.FindingCount > 0 {
			marker = StyleSuccess.Render("[x]")
		}
		suffix := ""
		if p.FindingCount == 1 {
			suffix = StyleLabel.Render("  (1 finding)")
		} else if p.FindingCount > 1 {
			suffix = StyleLabel.Render(fmt.Sprintf("  (%d findings)", p.FindingCount))
		}
		sb.WriteString(fmt.Sprintf("  %s  %s  %s%s\n",
			marker,
			StyleMenuKey.Render(p.Icon),
			StyleMenuItem.Render(p.Name),
			suffix,
		))
	}

	// Stats bar
	if m.activeEng != nil {
		hosts, _ := targets.List(m.activeEng.ID)
		creds, _ := vault.List(m.activeEng.ID)
		stats := engagement.FindingStats(m.activeEng.ID)
		total := stats["CRITICAL"] + stats["HIGH"] + stats["MEDIUM"] + stats["INFO"]
		sb.WriteString("\n")
		sb.WriteString(StyleDivider.Render("  "+strings.Repeat("─", 40)) + "\n")
		sb.WriteString(fmt.Sprintf("  %s %s  %s %s  %s %s  %s%s%s\n",
			StyleLabel.Render("Hosts:"), StyleValue.Render(fmt.Sprintf("%d", len(hosts))),
			StyleLabel.Render("Creds:"), StyleValue.Render(fmt.Sprintf("%d", len(creds))),
			StyleLabel.Render("Findings:"), StyleValue.Render(fmt.Sprintf("%d", total)),
			StyleFindingCritical.Render(fmt.Sprintf("C:%d ", stats["CRITICAL"])),
			StyleFindingHigh.Render(fmt.Sprintf("H:%d ", stats["HIGH"])),
			StyleLabel.Render(fmt.Sprintf("M:%d", stats["MEDIUM"])),
		))
		sb.WriteString(StyleDivider.Render("  "+strings.Repeat("─", 40)) + "\n")
	}

	// Suggestions
	sb.WriteString("\n  " + StyleSectionHeader.Render("Suggested Next Steps") + "\n")
	if len(m.campaignSuggestions) == 0 {
		sb.WriteString("  " + StyleLabel.Render("Loading...") + "\n")
	} else {
		limit := m.campaignSuggestions
		if len(limit) > 6 {
			limit = m.campaignSuggestions[:6]
		}
		for i, s := range limit {
			cursor := "  "
			selected := m.campaignCursor == i
			urgency := StyleLabel.Render("·")
			switch s.Priority {
			case 0:
				urgency = StyleError.Render("!")
			case 1:
				urgency = StyleWarning.Render("→")
			}
			nameStr := StyleMenuItem.Render(fmt.Sprintf("%-20s", s.ModuleName))
			reasonStr := StyleLabel.Render(truncate(s.Reason, 42))
			if selected {
				cursor = StyleCyan("> ")
				nameStr = StyleMenuItemSelected.Render(" " + fmt.Sprintf("%-19s", s.ModuleName) + " ")
			}
			sb.WriteString(fmt.Sprintf("  %s%s  %s  %s\n",
				cursor, urgency, nameStr, reasonStr))
		}
	}

	// Footer keys
	sb.WriteString("\n")
	sb.WriteString(StyleDivider.Render("  "+strings.Repeat("─", 60)) + "\n")
	sb.WriteString("  " + StyleHelp.Render("[↑↓/1-6] navigate  [enter] launch  [M] all modules  [R] refresh  [E] engagement  [H] home  [esc] menu") + "\n")

	return sb.String()
}

func (m Model) viewOpsec() string {
	var sb strings.Builder
	sb.WriteString(m.header(""))
	title := "  OPSEC Score"
	if m.activeEng != nil {
		title = fmt.Sprintf("  OPSEC Score — %s", m.activeEng.Name)
	}
	sb.WriteString(StyleMenuTitle.Render(title) + "\n\n")

	lines := strings.Split(m.opsecContent, "\n")
	start := m.opsecScroll
	if start >= len(lines) {
		start = 0
	}
	maxLines := m.height - 10
	end := start + maxLines
	if end > len(lines) {
		end = len(lines)
	}
	for _, line := range lines[start:end] {
		switch {
		case strings.Contains(line, "─"):
			sb.WriteString(StyleDivider.Render("  "+line) + "\n")
		case strings.HasPrefix(strings.TrimSpace(line), "✦"):
			sb.WriteString(StyleSuccess.Render("  "+line) + "\n")
		case strings.HasPrefix(strings.TrimSpace(line), "◎"):
			sb.WriteString(StyleSuccess.Render("  "+line) + "\n")
		case strings.HasPrefix(strings.TrimSpace(line), "◉"):
			sb.WriteString(StyleWarning.Render("  "+line) + "\n")
		case strings.HasPrefix(strings.TrimSpace(line), "⬟"):
			sb.WriteString(StyleError.Render("  "+line) + "\n")
		case strings.Contains(line, "QUIET") || strings.Contains(line, "CLEAN"):
			sb.WriteString("  " + StyleSuccess.Render(line) + "\n")
		case strings.Contains(line, "MODERATE"):
			sb.WriteString("  " + StyleWarning.Render(line) + "\n")
		case strings.Contains(line, "LOUD") || strings.Contains(line, "CRITICAL"):
			sb.WriteString("  " + StyleError.Render(line) + "\n")
		default:
			sb.WriteString("  " + StyleMenuItem.Render(line) + "\n")
		}
	}

	sb.WriteString("\n" + StyleHelp.Render("  ↑/↓ scroll  ·  [H] home  ·  esc back"))
	return sb.String()
}

func (m Model) viewChecklist() string {
	var sb strings.Builder
	sb.WriteString(m.header(""))
	title := "  PTES Checklist"
	if m.activeEng != nil {
		title = fmt.Sprintf("  PTES Checklist — %s", m.activeEng.Name)
	}
	sb.WriteString(StyleMenuTitle.Render(title) + "\n\n")

	lines := strings.Split(m.checklistContent, "\n")
	start := m.checklistScroll
	if start >= len(lines) {
		start = 0
	}
	maxLines := m.height - 10
	end := start + maxLines
	if end > len(lines) {
		end = len(lines)
	}
	for _, line := range lines[start:end] {
		switch {
		case strings.Contains(line, "─"):
			sb.WriteString(StyleDivider.Render("  "+line) + "\n")
		case strings.Contains(line, "[✓]"):
			sb.WriteString(StyleSuccess.Render("  "+line) + "\n")
		case strings.Contains(line, "[ ]"):
			sb.WriteString(StyleHelp.Render("  "+line) + "\n")
		case strings.Contains(line, "[·]"):
			sb.WriteString(StyleLabel.Render("  "+line) + "\n")
		case strings.Contains(line, "Progress:"):
			sb.WriteString(StyleSectionHeader.Render("  "+line) + "\n")
		case len(line) > 0 && line[0] != ' ':
			sb.WriteString(StyleSectionHeader.Render("  "+line) + "\n")
		default:
			sb.WriteString(StyleMenuItem.Render("  "+line) + "\n")
		}
	}

	sb.WriteString("\n" + StyleHelp.Render("  ↑/↓ scroll  ·  [H] home  ·  esc back"))
	return sb.String()
}

func (m Model) viewGraph() string {
	var sb strings.Builder
	sb.WriteString(m.header(""))
	title := "  Attack Graph"
	if m.activeEng != nil {
		title = fmt.Sprintf("  Attack Graph — %s", m.activeEng.Name)
	}
	sb.WriteString(StyleMenuTitle.Render(title) + "\n\n")

	lines := strings.Split(m.graphContent, "\n")
	start := m.graphScroll
	if start >= len(lines) {
		start = 0
	}
	maxLines := m.height - 10
	end := start + maxLines
	if end > len(lines) {
		end = len(lines)
	}
	for _, line := range lines[start:end] {
		switch {
		case strings.Contains(line, "─"):
			sb.WriteString(StyleDivider.Render("  "+line) + "\n")
		case strings.Contains(line, "├──") || strings.Contains(line, "└──"):
			sb.WriteString(StyleMenuKey.Render("  "+line) + "\n")
		case strings.Contains(line, "target:"):
			sb.WriteString(StyleHelp.Render("  "+line) + "\n")
		case strings.Contains(line, "[OPERATOR]"):
			sb.WriteString(StyleEngagementActive.Render("  "+line) + "\n")
		default:
			sb.WriteString(StyleMenuItem.Render("  "+line) + "\n")
		}
	}

	sb.WriteString("\n" + StyleHelp.Render("  ↑/↓ scroll  ·  [H] home  ·  esc back"))
	return sb.String()
}

// --------------------------------------------------------------------------
// New views: Dashboard, Settings, Search, Compare, Module Running
// --------------------------------------------------------------------------

func (m Model) viewDashboard() string {
	var sb strings.Builder
	sb.WriteString(StyleBanner.Render(m.banner()) + "\n")
	sb.WriteString(StyleSubtitle.Render("  ghost in the net  ·  operator-grade red team engagement platform") + "\n")
	sb.WriteString(StyleDivider.Render(strings.Repeat("─", 65)) + "\n\n")

	if m.activeEng == nil {
		sb.WriteString("  " + StyleEngagementNone.Render("no active engagement") + "\n\n")
		sb.WriteString("  " + StyleMenuKey.Render("[E]") + "  " + StyleMenuItem.Render("Engagement Hub") + "\n")
		sb.WriteString("  " + StyleMenuKey.Render("[M]") + "  " + StyleMenuItem.Render("Main Menu") + "\n")
		return sb.String() + m.statusBar()
	}

	eng := m.activeEng
	// Engagement header bar
	engLine := StyleEngagementActive.Render(eng.Name)
	if eng.Target != "" {
		engLine += StyleLabel.Render("  →  ") + StyleValue.Render(eng.Target)
	}
	if eng.Scope != "" {
		engLine += StyleLabel.Render("  scope: ") + StyleHelp.Render(eng.Scope)
	}
	sb.WriteString("  " + engLine + "\n\n")

	// ── Finding severity boxes ─────────────────────────────────────────────
	stats := m.dashStats.findingStats
	if stats == nil {
		stats = map[string]int{}
	}
	total := stats["CRITICAL"] + stats["HIGH"] + stats["MEDIUM"] + stats["INFO"]

	statBox := func(label, val string, style lipgloss.Style) string {
		return lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorGray).
			Padding(0, 2).
			Render(style.Render(fmt.Sprintf("%-4s", val)) + "\n" + StyleHelp.Render(label))
	}

	critBox := statBox("CRIT", fmt.Sprintf("%d", stats["CRITICAL"]), StyleFindingCritical)
	highBox := statBox("HIGH", fmt.Sprintf("%d", stats["HIGH"]), StyleFindingHigh)
	medBox := statBox("MED", fmt.Sprintf("%d", stats["MEDIUM"]), StyleWarning)
	infoBox := statBox("INFO", fmt.Sprintf("%d", stats["INFO"]), StyleFindingInfo)
	totalBox := statBox("TOTAL", fmt.Sprintf("%d", total), StyleValue)

	sb.WriteString("  " + lipgloss.JoinHorizontal(lipgloss.Top, critBox, "  ", highBox, "  ", medBox, "  ", infoBox, "  ", totalBox) + "\n\n")

	// ── Resource counters ──────────────────────────────────────────────────
	resBox := func(label, val string) string {
		return lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorDimCyan).
			Padding(0, 3).
			Render(StyleDashboardStat.Render(fmt.Sprintf("%-4s", val)) + "\n" + StyleDashboardLabel.Render(label))
	}

	hostsB := resBox("HOSTS", fmt.Sprintf("%d", m.dashStats.hostCount))
	credsB := resBox("CREDS", fmt.Sprintf("%d", m.dashStats.credCount))
	notesB := resBox("NOTES", fmt.Sprintf("%d", m.dashStats.noteCount))

	opsecStr := ""
	if m.opsecLabel != "" {
		var opsecStyle lipgloss.Style
		switch m.opsecLabel {
		case "QUIET", "CLEAN":
			opsecStyle = StyleSuccess
		case "MODERATE":
			opsecStyle = StyleWarning
		default:
			opsecStyle = StyleError
		}
		opsecStr = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorGray).
			Padding(0, 2).
			Render(opsecStyle.Render(m.opsecLabel) + "\n" + StyleDashboardLabel.Render("OPSEC"))
	}

	row2 := hostsB + "  " + credsB + "  " + notesB
	if opsecStr != "" {
		row2 += "  " + opsecStr
	}
	sb.WriteString("  " + row2 + "\n\n")

	// ── Recent findings ────────────────────────────────────────────────────
	if len(m.dashStats.recentFindings) > 0 {
		sb.WriteString("  " + StyleSectionHeader.Render("RECENT FINDINGS") + "\n")
		sb.WriteString(StyleDivider.Render("  "+strings.Repeat("─", 55)) + "\n")
		for _, f := range m.dashStats.recentFindings {
			sev := SeverityStyle(f.Severity).Render(fmt.Sprintf("%-8s", f.Severity))
			mod := StyleLabel.Render(fmt.Sprintf("%-14s", truncate(f.Module, 13)))
			title := StyleMenuItem.Render(truncate(f.Title, 42))
			ts := StyleHelp.Render(f.CreatedAt.Format("01-02 15:04"))
			sb.WriteString(fmt.Sprintf("  %s  %s  %s  %s\n", sev, mod, title, ts))
		}
		sb.WriteString("\n")
	}

	// ── Quick actions ──────────────────────────────────────────────────────
	sb.WriteString(StyleDivider.Render("  "+strings.Repeat("─", 55)) + "\n")
	actions := []struct{ k, l string }{
		{"M", "Main Menu"}, {"C", "Campaign"}, {"F", "Findings"},
		{"E", "Engagement Hub"}, {"S", "Settings"}, {"R", "Refresh"},
	}
	for i, a := range actions {
		if i > 0 && i%3 == 0 {
			sb.WriteString("\n")
		}
		sb.WriteString("  " + StyleMenuKey.Render("["+a.k+"]") + " " + StyleMenuItem.Render(fmt.Sprintf("%-16s", a.l)))
	}
	sb.WriteString("\n")

	return sb.String()
}

func (m Model) viewSettings() string {
	var sb strings.Builder
	sb.WriteString(m.header("  Settings"))

	sb.WriteString(StyleHelp.Render("  Configure Davoid operator settings. Changes saved on [enter] or ctrl+s.\n\n"))
	sb.WriteString(StyleDivider.Render("  "+strings.Repeat("─", 55)) + "\n\n")

	labels := []string{"Webhook URL", "Webhook Events", "Ollama URL"}
	hints := []string{
		"Discord / Slack / ntfy.sh webhook",
		"shell_connect,creds_captured,finding_critical,handshake_captured,hash_cracked",
		"http://localhost:11434",
	}

	for i, f := range m.settingsFields {
		selected := i == m.settingsFieldCursor
		prefix := "  "
		if selected {
			prefix = StyleCyan("> ")
		}
		label := StyleLabel.Render(labels[i])
		var val string
		if selected {
			val = StyleSettingsField.Render(f.value + "█")
		} else {
			val = StyleValue.Render(f.value)
			if val == "" {
				val = StyleHelp.Render("("+hints[i]+")")
			}
		}
		sb.WriteString(prefix + label + "\n  " + val + "\n\n")
	}

	sb.WriteString(StyleDivider.Render("  "+strings.Repeat("─", 55)) + "\n")
	sb.WriteString(StyleHelp.Render("  tab/↑↓ switch fields  ·  ctrl+s save  ·  enter advance/save  ·  esc back"))
	return sb.String()
}

func (m Model) viewSearch() string {
	var sb strings.Builder

	// Show the underlying list with the search bar overlay at top
	searchBar := StyleSearchBar.Render(" / ") + " " + StyleValue.Render(m.searchQuery) + StyleHelp.Render("█")
	sb.WriteString(searchBar + "\n")
	sb.WriteString(StyleHelp.Render(fmt.Sprintf("  Filtering: %q   esc/enter to confirm\n\n", m.searchQuery)))

	switch m.searchState {
	case stateFindings:
		list := m.filteredFindings
		if list == nil {
			list = m.findings
		}
		if len(list) == 0 {
			sb.WriteString(StyleLabel.Render("  No matching findings.\n"))
		} else {
			for _, f := range list {
				sev := SeverityStyle(f.Severity).Render(fmt.Sprintf("%-8s", f.Severity))
				mod := StyleLabel.Render(fmt.Sprintf("%-14s", truncate(f.Module, 13)))
				title := StyleMenuItem.Render(truncate(f.Title, 50))
				sb.WriteString(fmt.Sprintf("  %s  %s  %s\n", sev, mod, title))
			}
		}
	case stateVault:
		list := m.filteredVaultCreds
		if list == nil {
			list = m.vaultCreds
		}
		if len(list) == 0 {
			sb.WriteString(StyleLabel.Render("  No matching credentials.\n"))
		} else {
			for _, c := range list {
				secret := strings.Repeat("*", min(len(c.Secret), 8))
				sb.WriteString(fmt.Sprintf("  %-12s  %-18s  %-20s  %s\n",
					truncate(c.Source, 10), truncate(c.Host, 16), truncate(c.Username, 18), secret))
			}
		}
	case stateModuleList:
		q := strings.ToLower(m.searchQuery)
		for _, item := range m.subMenuItems {
			if q == "" || strings.Contains(strings.ToLower(item.label), q) {
				sb.WriteString("  " + StyleMenuItem.Render(item.label) + "\n")
			}
		}
	}

	return sb.String()
}

func (m Model) viewCompare() string {
	var sb strings.Builder
	sb.WriteString(m.header("  Compare Engagements"))

	switch m.compareStage {
	case 0, 1:
		label := "  Select first engagement (A):"
		cursor := m.compareACursor
		if m.compareStage == 1 {
			label = fmt.Sprintf("  Select second engagement (B) to compare with %q:", m.compareEngA.Name)
			cursor = m.compareBCursor
		}
		sb.WriteString(StyleSectionHeader.Render(label) + "\n\n")
		for i, eng := range m.compareEngList {
			active := ""
			if m.activeEng != nil && eng.ID == m.activeEng.ID {
				active = StyleGreen(" [active]")
			}
			line := fmt.Sprintf("  %-30s  %-20s  %-8s%s",
				truncate(eng.Name, 28), truncate(eng.Target, 18),
				eng.CreatedAt.Format("01-02"), active)
			if i == cursor {
				sb.WriteString(StyleMenuItemSelected.Render(line) + "\n")
			} else {
				sb.WriteString(StyleTableRow.Render(line) + "\n")
			}
		}
		sb.WriteString("\n" + StyleHelp.Render("  ↑/↓ navigate  ·  enter select  ·  esc back"))

	case 2:
		engA := m.compareEngA
		engB := m.compareEngB
		if engA == nil || engB == nil {
			sb.WriteString(StyleError.Render("  missing engagement data\n"))
			return sb.String()
		}

		statsA := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}
		statsB := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}
		for _, f := range m.compareFindingsA {
			statsA[f.Severity]++
		}
		for _, f := range m.compareFindingsB {
			statsB[f.Severity]++
		}

		w := 28
		header := fmt.Sprintf("  %-*s  │  %-*s", w, truncate(engA.Name, w), w, truncate(engB.Name, w))
		sb.WriteString(StyleSectionHeader.Render(header) + "\n")
		sb.WriteString(StyleDivider.Render("  "+strings.Repeat("─", w*2+5)) + "\n")

		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "INFO"} {
			vA := fmt.Sprintf("%s: %d", sev, statsA[sev])
			vB := fmt.Sprintf("%s: %d", sev, statsB[sev])
			style := SeverityStyle(sev)
			sb.WriteString(fmt.Sprintf("  %s  │  %s\n",
				style.Render(fmt.Sprintf("%-*s", w, vA)),
				style.Render(fmt.Sprintf("%-*s", w, vB)),
			))
		}

		totalA := statsA["CRITICAL"] + statsA["HIGH"] + statsA["MEDIUM"] + statsA["INFO"]
		totalB := statsB["CRITICAL"] + statsB["HIGH"] + statsB["MEDIUM"] + statsB["INFO"]
		sb.WriteString(StyleDivider.Render("  "+strings.Repeat("─", w*2+5)) + "\n")
		sb.WriteString(fmt.Sprintf("  %s  │  %s\n",
			StyleValue.Render(fmt.Sprintf("%-*s", w, fmt.Sprintf("TOTAL: %d", totalA))),
			StyleValue.Render(fmt.Sprintf("%-*s", w, fmt.Sprintf("TOTAL: %d", totalB))),
		))

		// Unique-to-A and unique-to-B findings
		sb.WriteString("\n")
		titlesA := map[string]bool{}
		titlesB := map[string]bool{}
		for _, f := range m.compareFindingsA {
			titlesA[f.Title] = true
		}
		for _, f := range m.compareFindingsB {
			titlesB[f.Title] = true
		}

		var onlyA, onlyB []string
		for t := range titlesA {
			if !titlesB[t] {
				onlyA = append(onlyA, t)
			}
		}
		for t := range titlesB {
			if !titlesA[t] {
				onlyB = append(onlyB, t)
			}
		}

		maxLines := (m.height - 20) / 2
		start := m.compareScroll
		if len(onlyA) > 0 {
			sb.WriteString(StyleSectionHeader.Render(fmt.Sprintf("  Only in %q (%d):", truncate(engA.Name, 20), len(onlyA))) + "\n")
			for i, t := range onlyA {
				if i < start {
					continue
				}
				if i-start >= maxLines {
					break
				}
				sb.WriteString(StyleFindingHigh.Render("  + ") + StyleMenuItem.Render(truncate(t, 60)) + "\n")
			}
		}
		if len(onlyB) > 0 {
			sb.WriteString(StyleSectionHeader.Render(fmt.Sprintf("  Only in %q (%d):", truncate(engB.Name, 20), len(onlyB))) + "\n")
			for i, t := range onlyB {
				if i < start {
					continue
				}
				if i-start >= maxLines {
					break
				}
				sb.WriteString(StyleFindingCritical.Render("  + ") + StyleMenuItem.Render(truncate(t, 60)) + "\n")
			}
		}
		sb.WriteString("\n" + StyleHelp.Render("  ↑/↓ scroll  ·  [H] home  ·  esc back"))
	}

	return sb.String()
}

func (m Model) viewModuleRunning() string {
	var sb strings.Builder
	sb.WriteString(m.header(""))

	mod := m.streamingModKey
	sb.WriteString(StyleRunningHeader.Render(fmt.Sprintf("  Running: %s", mod)) + "\n")
	if !m.moduleOutputDone {
		sb.WriteString(StyleHelp.Render("  Module executing — output streaming below...\n\n"))
	} else {
		if m.moduleOutputErr != nil {
			sb.WriteString(StyleError.Render("  Error: "+m.moduleOutputErr.Error()) + "\n\n")
		} else {
			sb.WriteString(StyleSuccess.Render("  Module complete") + "\n\n")
		}
	}

	sb.WriteString(StyleDivider.Render("  "+strings.Repeat("─", 60)) + "\n")

	lines := m.moduleOutputLines
	maxLines := m.height - 14
	start := m.moduleOutputScroll
	if start >= len(lines) && len(lines) > maxLines {
		start = len(lines) - maxLines
	}
	if start < 0 {
		start = 0
	}
	end := start + maxLines
	if end > len(lines) {
		end = len(lines)
	}
	for _, line := range lines[start:end] {
		sb.WriteString("  " + StyleRunningOutput.Render(line) + "\n")
	}

	sb.WriteString("\n")
	if m.moduleOutputDone {
		sb.WriteString(StyleHelp.Render("  ↑/↓ scroll  ·  enter/esc back to menu"))
	} else {
		sb.WriteString(StyleHelp.Render("  ↑/↓ scroll  ·  waiting for module..."))
	}
	return sb.String()
}

func (m Model) activateHubKey(key string) (tea.Model, tea.Cmd) {
	noEng := func() bool { return m.activeEng == nil }
	switch strings.ToUpper(key) {
	case "N":
		m.state = stateEngagementNew
		m.engFieldCursor = 0
		for i := range m.engFields {
			m.engFields[i].value = ""
		}
		return m, nil
	case "S":
		m.state = stateEngagementList
		return m, loadEngList()
	case "F":
		if noEng() {
			m.statusMsg = "No active engagement."
			m.statusIsError = true
			return m, nil
		}
		m.state = stateFindings
		return m, loadFindings(m.activeEng.ID)
	case "L":
		if noEng() {
			m.statusMsg = "No active engagement."
			m.statusIsError = true
			return m, nil
		}
		return m, loadTimeline(m.activeEng.ID)
	case "R":
		if noEng() {
			m.statusMsg = "No active engagement."
			m.statusIsError = true
			return m, nil
		}
		return m, generateReport(m.activeEng.ID)
	case "V":
		if noEng() {
			m.statusMsg = "No active engagement."
			m.statusIsError = true
			return m, nil
		}
		return m, loadVault(m.activeEng.ID)
	case "M":
		if noEng() {
			m.statusMsg = "No active engagement."
			m.statusIsError = true
			return m, nil
		}
		return m, loadTargets(m.activeEng.ID)
	case "O":
		if noEng() {
			m.statusMsg = "No active engagement."
			m.statusIsError = true
			return m, nil
		}
		return m, loadNotes(m.activeEng.ID)
	case "I":
		if noEng() {
			m.statusMsg = "No active engagement."
			m.statusIsError = true
			return m, nil
		}
		return m, loadOpsecView(m.activeEng.ID)
	case "K":
		if noEng() {
			m.statusMsg = "No active engagement."
			m.statusIsError = true
			return m, nil
		}
		return m, loadChecklistView(m.activeEng.ID)
	case "G":
		if noEng() {
			m.statusMsg = "No active engagement."
			m.statusIsError = true
			return m, nil
		}
		return m, loadGraphView(m.activeEng.ID)
	case "X":
		if m.activeEng != nil {
			engagement.ClearActive()
			m.activeEng = nil
			m.statusMsg = "Engagement deactivated."
			m.statusIsError = false
		}
		return m, nil
	case "C":
		// Compare two engagements
		m.state = stateCompare
		m.compareStage = 0
		m.compareACursor = 0
		return m, loadEngList()
	case "T":
		// Settings
		m.state = stateSettings
		m.settingsFromHub = true
		cfg := loadConfigForSettings()
		m.settingsFields[0].value = cfg[0]
		m.settingsFields[1].value = cfg[1]
		m.settingsFields[2].value = cfg[2]
		m.settingsFieldCursor = 0
		return m, nil
	}
	return m, nil
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

type hubRow struct {
	key     string
	label   string
	desc    string
	section string // non-empty = section header row (not selectable)
}

func hubMenuRows() []hubRow {
	return []hubRow{
		{section: "ENGAGEMENTS"},
		{"N", "New Engagement", "start a new op", ""},
		{"S", "Switch / List", "pick from all engagements", ""},
		{"C", "Compare", "side-by-side finding diff", ""},
		{"X", "Deactivate", "clear active engagement", ""},
		{section: "INTEL & DATA"},
		{"F", "Findings", "all findings for active engagement", ""},
		{"L", "Timeline", "chronological activity log", ""},
		{"R", "Report", "generate Markdown / PDF report", ""},
		{section: "RESOURCES"},
		{"V", "Credential Vault", "harvested credentials", ""},
		{"M", "Target Map", "network topology + discovered hosts", ""},
		{"O", "Notes", "engagement notes", ""},
		{section: "ANALYSIS"},
		{"I", "OPSEC Score", "module noise rating for this op", ""},
		{"K", "PTES Checklist", "methodology progress tracker", ""},
		{"G", "Attack Graph", "module execution tree", ""},
		{section: "CONFIG"},
		{"T", "Settings", "webhook · Ollama URL · notifications", ""},
	}
}

func fmtScroll(current, total int) string {
	if total == 0 {
		return ""
	}
	return StyleHelp.Render(fmt.Sprintf("  %d/%d", current+1, total))
}

// statusBar returns a persistent bottom bar shown on every view.
// Format: [engagement · CRIT:N HIGH:N] [OPSEC label] [IP] [VPN] [version]
func (m Model) statusBar() string {
	var left, right strings.Builder

	if m.activeEng != nil {
		left.WriteString(StyleBottomBarEngagement.Render(" " + truncate(m.activeEng.Name, 22) + " "))
		if m.activeEng.Target != "" {
			left.WriteString(StyleBottomBar.Render(" → " + truncate(m.activeEng.Target, 18)))
		}
		if m.activeEng != nil {
			stats := engagement.FindingStats(m.activeEng.ID)
			if stats["CRITICAL"] > 0 {
				left.WriteString(StyleBottomBarAlert.Render(fmt.Sprintf(" C:%d ", stats["CRITICAL"])))
			}
			if stats["HIGH"] > 0 {
				left.WriteString(StyleBottomBarWarn.Render(fmt.Sprintf(" H:%d ", stats["HIGH"])))
			}
		}
		if m.opsecLabel != "" {
			switch m.opsecLabel {
			case "QUIET", "CLEAN":
				left.WriteString(lipgloss.NewStyle().Foreground(colorGreen).Background(lipgloss.Color("#111111")).Bold(true).Padding(0, 1).Render("OPSEC " + m.opsecLabel))
			case "MODERATE":
				left.WriteString(lipgloss.NewStyle().Foreground(colorOrange).Background(lipgloss.Color("#111111")).Bold(true).Padding(0, 1).Render("OPSEC " + m.opsecLabel))
			default:
				left.WriteString(lipgloss.NewStyle().Foreground(colorRed).Background(lipgloss.Color("#111111")).Bold(true).Padding(0, 1).Render("OPSEC " + m.opsecLabel))
			}
		}
	} else {
		left.WriteString(StyleBottomBar.Render(" no active engagement "))
	}

	if m.localIP != "" && m.localIP != "unavailable" {
		right.WriteString(StyleBottomBar.Render(" " + m.localIP))
	}
	if m.vpn != "" {
		right.WriteString(lipgloss.NewStyle().Foreground(colorGreen).Background(lipgloss.Color("#111111")).Padding(0, 1).Render("VPN " + m.vpn))
	}
	right.WriteString(StyleBottomBar.Render(" v" + m.version + " "))
	if m.latestVersion != "" {
		right.WriteString(StyleBottomBarWarn.Render(" ↑ " + m.latestVersion + " [U] "))
	}

	// Status message (errors/successes) shown in bar
	if m.statusMsg != "" {
		if m.statusIsError {
			left.WriteString(StyleBottomBarAlert.Render(" ERR " + truncate(m.statusMsg, 40) + " "))
		} else {
			left.WriteString(lipgloss.NewStyle().Foreground(colorGreen).Background(lipgloss.Color("#111111")).Bold(true).Padding(0, 1).Render("OK " + truncate(m.statusMsg, 40)))
		}
	}

	return "\n" + left.String() + right.String() + "\n"
}

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

// applySearch filters findings/vault based on m.searchQuery.
func (m *Model) applySearch() {
	q := strings.ToLower(m.searchQuery)
	switch m.searchState {
	case stateFindings:
		if q == "" {
			m.filteredFindings = m.findings
			return
		}
		var out []*engagement.Finding
		for _, f := range m.findings {
			if strings.Contains(strings.ToLower(f.Title), q) ||
				strings.Contains(strings.ToLower(f.Module), q) ||
				strings.Contains(strings.ToLower(f.Target), q) ||
				strings.Contains(strings.ToLower(f.Severity), q) {
				out = append(out, f)
			}
		}
		m.filteredFindings = out
	case stateVault:
		if q == "" {
			m.filteredVaultCreds = m.vaultCreds
			return
		}
		var out []*vault.Credential
		for _, c := range m.vaultCreds {
			if strings.Contains(strings.ToLower(c.Username), q) ||
				strings.Contains(strings.ToLower(c.Host), q) ||
				strings.Contains(strings.ToLower(c.Source), q) {
				out = append(out, c)
			}
		}
		m.filteredVaultCreds = out
	}
}

// checkModuleTools returns names of missing external tools for a module.
// Uses a lightweight mapping — full check via 'davoid doctor'.
var moduleToolDeps = map[string][]string{
	"scanner":        {"nmap"},
	"sniff":          {"tcpdump"},
	"mitm":           {"arpspoof"},
	"wifi_monitor":   {"airmon-ng"},
	"wifi_scan":      {"airodump-ng"},
	"wifi_deauth":    {"aireplay-ng"},
	"wifi_handshake": {"airodump-ng"},
	"wifi_crack":     {"aircrack-ng"},
	"wifi_eviltwin":  {"hostapd", "dnsmasq"},
	"msf_engine":     {"msfconsole"},
	"ad_ops":         {"ldapsearch"},
}

func checkModuleTools(key string) []string {
	deps, ok := moduleToolDeps[key]
	if !ok {
		return nil
	}
	var missing []string
	for _, tool := range deps {
		if _, err := exec.LookPath(tool); err != nil {
			missing = append(missing, tool)
		}
	}
	return missing
}

// loadConfigForSettings returns [webhookURL, webhookEvents, ollamaURL] from disk.
func loadConfigForSettings() [3]string {
	cfg := config.Load()
	events := strings.Join(cfg.WebhookEvents, ",")
	ollama := cfg.OllamaURL
	return [3]string{cfg.WebhookURL, events, ollama}
}

// saveSettings persists settings from the TUI fields.
func saveSettings(fields [3]inputField) {
	cfg := config.Load()
	cfg.WebhookURL = strings.TrimSpace(fields[0].value)
	if e := strings.TrimSpace(fields[1].value); e == "" {
		cfg.WebhookEvents = nil
	} else {
		cfg.WebhookEvents = strings.Split(e, ",")
	}
	cfg.OllamaURL = strings.TrimSpace(fields[2].value)
	_ = config.Save(cfg)
}

