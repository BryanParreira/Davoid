package campaign

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/ui"
	"github.com/bryanparreira/davoid/internal/targets"
	"github.com/bryanparreira/davoid/internal/vault"
)

// ModuleMeta is a minimal module descriptor — passed in to avoid import cycles with runner.
type ModuleMeta struct {
	Key         string
	Name        string
	Description string
}

// RunFunc is the module dispatcher injected from runner.
type RunFunc func(key string) error

// ─────────────────────────────────────────────────────────────────────────────
// Kill chain phase definitions
// ─────────────────────────────────────────────────────────────────────────────

type phase struct {
	name    string
	icon    string
	modules []string // runner keys
}

var killChain = []phase{
	{
		name:    "Recon & OSINT",
		icon:    "①",
		modules: []string{"scanner", "osint", "web_recon"},
	},
	{
		name:    "Network Attacks",
		icon:    "②",
		modules: []string{"mitm", "sniff", "wifi_monitor", "wifi_scan", "wifi_deauth", "wifi_handshake"},
	},
	{
		name:    "Exploitation",
		icon:    "③",
		modules: []string{"payloads", "msf_engine", "catcher", "wifi_crack", "wifi_eviltwin"},
	},
	{
		name:    "Post-Exploitation",
		icon:    "④",
		modules: []string{"looter", "cred_tester", "bruteforce", "persistence", "ad_ops"},
	},
}

func phaseForModule(key string) int {
	for i, p := range killChain {
		for _, k := range p.modules {
			if k == key {
				return i
			}
		}
	}
	return -1
}

// ─────────────────────────────────────────────────────────────────────────────
// Exported types for TUI use
// ─────────────────────────────────────────────────────────────────────────────

// Suggestion is an exported view of a suggested next module.
type Suggestion struct {
	ModuleKey  string
	ModuleName string
	Reason     string
	Priority   int // 0=urgent, 1=high, 2=normal
}

// PhaseInfo is an exported view of a kill chain phase with progress data.
type PhaseInfo struct {
	Name         string
	Icon         string
	FindingCount int
}

// GetPhaseProgress returns kill chain phases with current finding counts.
func GetPhaseProgress(engID string) []PhaseInfo {
	findings, _ := engagement.Findings(engID)
	counts := make([]int, len(killChain))
	for _, f := range findings {
		if i := phaseForModule(f.Module); i >= 0 {
			counts[i]++
		}
	}
	out := make([]PhaseInfo, len(killChain))
	for i, p := range killChain {
		out[i] = PhaseInfo{Name: p.name, Icon: p.icon, FindingCount: counts[i]}
	}
	return out
}

// GenerateSuggestions returns ranked next-step suggestions for the TUI.
func GenerateSuggestions(engID string, modules []ModuleMeta) []Suggestion {
	c := &campaign{
		modules: modules,
		eng:     &engagement.Engagement{ID: engID},
	}
	internal := c.generateSuggestions()
	out := make([]Suggestion, len(internal))
	for i, s := range internal {
		out[i] = Suggestion{
			ModuleKey:  s.moduleKey,
			ModuleName: s.moduleName,
			Reason:     s.reason,
			Priority:   s.priority,
		}
	}
	return out
}

// AllPhaseModules returns all module keys across all kill chain phases.
func AllPhaseModules() []string {
	var keys []string
	for _, p := range killChain {
		keys = append(keys, p.modules...)
	}
	return keys
}

// ─────────────────────────────────────────────────────────────────────────────
// Campaign struct — holds injected dependencies
// ─────────────────────────────────────────────────────────────────────────────

type campaign struct {
	modules []ModuleMeta
	runFn   RunFunc
	eng     *engagement.Engagement
}

func (c *campaign) moduleName(key string) string {
	for _, m := range c.modules {
		if m.Key == key {
			return m.Name
		}
	}
	return ""
}

func (c *campaign) moduleDesc(key string) string {
	for _, m := range c.modules {
		if m.Key == key {
			return m.Description
		}
	}
	return ""
}

// ─────────────────────────────────────────────────────────────────────────────
// Suggestion engine
// ─────────────────────────────────────────────────────────────────────────────

type suggestion struct {
	moduleKey  string
	moduleName string
	reason     string
	priority   int // 0 = urgent, 1 = high, 2 = normal
}

var portSuggestions = []struct {
	port      string
	moduleKey string
	reason    string
	priority  int
}{
	{"22", "cred_tester", "SSH open", 1},
	{"23", "cred_tester", "Telnet open (likely weak auth)", 0},
	{"80", "web_recon", "HTTP service discovered", 2},
	{"443", "web_recon", "HTTPS service discovered", 2},
	{"8080", "web_recon", "HTTP-alt service discovered", 2},
	{"445", "msf_engine", "SMB open — check for EternalBlue/PrintNightmare", 0},
	{"1433", "cred_tester", "MSSQL open", 1},
	{"3306", "cred_tester", "MySQL open", 1},
	{"3389", "cred_tester", "RDP open", 1},
	{"5432", "cred_tester", "PostgreSQL open", 1},
	{"6379", "msf_engine", "Redis open (often unauthenticated)", 0},
	{"389", "ad_ops", "LDAP open — likely domain controller", 0},
	{"636", "ad_ops", "LDAPS open — likely domain controller", 0},
	{"88", "ad_ops", "Kerberos open — Active Directory environment", 0},
}

func (c *campaign) generateSuggestions() []suggestion {
	findings, _ := engagement.Findings(c.eng.ID)
	hosts, _ := targets.List(c.eng.ID)
	creds, _ := vault.List(c.eng.ID)

	seen := map[string]bool{}
	var sugs []suggestion

	add := func(s suggestion) {
		if seen[s.moduleKey] {
			return
		}
		s.moduleName = c.moduleName(s.moduleKey)
		if s.moduleName == "" {
			return // module not in registry (shouldn't happen)
		}
		seen[s.moduleKey] = true
		sugs = append(sugs, s)
	}

	// ── Host/port based ──────────────────────────────────────────────────────
	openPorts := map[string]bool{}
	for _, h := range hosts {
		for _, p := range h.Ports {
			openPorts[strings.TrimSpace(p)] = true
		}
	}
	for _, ps := range portSuggestions {
		if openPorts[ps.port] {
			add(suggestion{moduleKey: ps.moduleKey, reason: ps.reason, priority: ps.priority})
		}
	}
	if len(hosts) > 0 {
		add(suggestion{
			moduleKey: "mitm",
			reason:    fmt.Sprintf("%d host(s) discovered — ARP poison + intercept", len(hosts)),
			priority:  2,
		})
	}

	// ── Finding based ────────────────────────────────────────────────────────
	for _, f := range findings {
		title := strings.ToLower(f.Title)
		desc := strings.ToLower(f.Description)

		switch f.Module {
		case "wifi_scan":
			if strings.Contains(desc, "wpa") || strings.Contains(f.Evidence, "WPA") {
				add(suggestion{moduleKey: "wifi_handshake", reason: "WPA network found: " + f.Target, priority: 1})
			} else if strings.Contains(desc, "opn") || strings.Contains(desc, "open network") {
				add(suggestion{moduleKey: "wifi_eviltwin", reason: "Open network detected: " + f.Target, priority: 0})
			}
		case "wifi_handshake":
			add(suggestion{moduleKey: "wifi_crack", reason: "Handshake captured from " + f.Target, priority: 0})
		case "mitm", "sniff":
			if strings.Contains(title, "credential") || strings.Contains(title, "password") ||
				strings.Contains(desc, "password") || strings.Contains(desc, "credential") {
				add(suggestion{moduleKey: "cred_tester", reason: "Credentials intercepted — test reuse", priority: 0})
			}
		case "scanner":
			if strings.Contains(desc, "cve") || strings.Contains(title, "vulnerable") {
				add(suggestion{moduleKey: "msf_engine", reason: "Vulnerability found: " + truncate(f.Title, 40), priority: 0})
			}
		case "catcher":
			add(suggestion{moduleKey: "looter", reason: "Shell session established — harvest loot", priority: 0})
		case "looter":
			if strings.Contains(desc, "ssh key") || strings.Contains(title, "key") {
				add(suggestion{moduleKey: "persistence", reason: "SSH key found — establish persistence", priority: 1})
			}
			add(suggestion{moduleKey: "ad_ops", reason: "Post-exploit access — enumerate AD", priority: 2})
		case "wifi_crack":
			add(suggestion{moduleKey: "wifi_eviltwin", reason: "PSK cracked — deploy evil twin", priority: 1})
		}
	}

	// ── Credential based ─────────────────────────────────────────────────────
	if len(creds) > 0 {
		add(suggestion{
			moduleKey: "cred_tester",
			reason:    fmt.Sprintf("%d credential(s) in vault — test reuse", len(creds)),
			priority:  1,
		})
	}

	// Default starting suggestion if nothing yet
	if len(sugs) == 0 {
		add(suggestion{moduleKey: "scanner", reason: "Start here — map the network", priority: 2})
		add(suggestion{moduleKey: "osint", reason: "Passive recon before active scanning", priority: 2})
		add(suggestion{moduleKey: "wifi_scan", reason: "Discover nearby wireless networks", priority: 2})
	}

	sort.SliceStable(sugs, func(i, j int) bool {
		return sugs[i].priority < sugs[j].priority
	})

	return sugs
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase progress
// ─────────────────────────────────────────────────────────────────────────────

func (c *campaign) phaseStats() []int {
	findings, _ := engagement.Findings(c.eng.ID)
	counts := make([]int, len(killChain))
	for _, f := range findings {
		if i := phaseForModule(f.Module); i >= 0 {
			counts[i]++
		}
	}
	return counts
}

// ─────────────────────────────────────────────────────────────────────────────
// Display
// ─────────────────────────────────────────────────────────────────────────────

func (c *campaign) printHeader() {
	title := "CAMPAIGN MODE — " + c.eng.Name
	if c.eng.Target != "" {
		title += "  [" + c.eng.Target + "]"
	}
	ui.Header(title)
}

func (c *campaign) printPhaseProgress() {
	stats := c.phaseStats()
	ui.Info("Kill Chain Progress")
	ui.Divider()
	for i, p := range killChain {
		count := stats[i]
		marker := ui.Dim.Render("○")
		if count > 0 {
			marker = ui.Green.Render("●")
		}
		suffix := ""
		if count == 1 {
			suffix = ui.Dim.Render("  (1 finding)")
		} else if count > 1 {
			suffix = ui.Dim.Render(fmt.Sprintf("  (%d findings)", count))
		}
		fmt.Printf("  %s  %s  %s%s\n", marker, ui.Cyan.Render(p.icon), p.name, suffix)
	}
	fmt.Println()
}

func (c *campaign) printStats() {
	hosts, _ := targets.List(c.eng.ID)
	creds, _ := vault.List(c.eng.ID)
	stats := engagement.FindingStats(c.eng.ID)
	total := stats["CRITICAL"] + stats["HIGH"] + stats["MEDIUM"] + stats["INFO"]

	ui.Divider()
	fmt.Printf("  Hosts: %s  |  Creds: %s  |  Findings: %s  (C:%s H:%s M:%s)\n",
		ui.Cyan.Render(fmt.Sprintf("%d", len(hosts))),
		ui.Cyan.Render(fmt.Sprintf("%d", len(creds))),
		ui.Cyan.Render(fmt.Sprintf("%d", total)),
		ui.Red.Render(fmt.Sprintf("%d", stats["CRITICAL"])),
		ui.Yellow.Render(fmt.Sprintf("%d", stats["HIGH"])),
		ui.Dim.Render(fmt.Sprintf("%d", stats["MEDIUM"])),
	)
	ui.Divider()
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase module browser
// ─────────────────────────────────────────────────────────────────────────────

func (c *campaign) pickModuleFromPhase() string {
	var opts []string
	var keys []string // parallel slice: "" for headers, key for modules

	for _, p := range killChain {
		opts = append(opts, ui.Bold.Render("── "+p.name+" ──"))
		keys = append(keys, "")
		for _, key := range p.modules {
			name := c.moduleName(key)
			desc := c.moduleDesc(key)
			if name == "" {
				continue
			}
			opts = append(opts, fmt.Sprintf("%-22s  %s", name, ui.Dim.Render(truncate(desc, 50))))
			keys = append(keys, key)
		}
	}

	idx := ui.Select("Pick any module", opts)
	if idx < 0 || idx >= len(keys) {
		return ""
	}
	return keys[idx]
}

// ─────────────────────────────────────────────────────────────────────────────
// Main loop
// ─────────────────────────────────────────────────────────────────────────────

func (c *campaign) run() error {
	for {
		c.printHeader()
		c.printPhaseProgress()
		c.printStats()
		fmt.Println()

		sugs := c.generateSuggestions()

		// Show suggestions
		ui.Info("Suggested Next Steps")
		ui.Divider()
		displayed := sugs
		if len(displayed) > 5 {
			displayed = sugs[:5]
		}
		for i, s := range displayed {
			urgency := ui.Dim.Render("·")
			switch s.priority {
			case 0:
				urgency = ui.Red.Render("!")
			case 1:
				urgency = ui.Yellow.Render("→")
			}
			phaseName := ""
			if pi := phaseForModule(s.moduleKey); pi >= 0 {
				phaseName = ui.Dim.Render(killChain[pi].name + " / ")
			}
			fmt.Printf("  %s %s  %s%s  %s\n",
				urgency,
				ui.Cyan.Render(fmt.Sprintf("[%d]", i+1)),
				phaseName,
				ui.Bold.Render(s.moduleName),
				ui.Dim.Render(s.reason),
			)
		}
		fmt.Println()
		fmt.Printf("  %s  Browse all modules by phase\n", ui.Cyan.Render("[M]"))
		fmt.Printf("  %s  Exit campaign mode\n", ui.Cyan.Render("[Q]"))
		fmt.Println()

		choice := strings.ToLower(strings.TrimSpace(ui.Prompt("Select")))

		if choice == "q" || choice == "0" {
			break
		}

		var moduleKey string
		if choice == "m" {
			moduleKey = c.pickModuleFromPhase()
		} else {
			var idx int
			if _, err := fmt.Sscanf(choice, "%d", &idx); err == nil && idx >= 1 && idx <= len(displayed) {
				moduleKey = displayed[idx-1].moduleKey
			}
		}

		if moduleKey == "" {
			continue
		}

		// Snapshot state before run
		beforeStats := engagement.FindingStats(c.eng.ID)
		beforeTotal := beforeStats["CRITICAL"] + beforeStats["HIGH"] + beforeStats["MEDIUM"] + beforeStats["INFO"]
		beforeHosts, _ := targets.List(c.eng.ID)
		beforeCreds, _ := vault.List(c.eng.ID)

		fmt.Println()
		if err := c.runFn(moduleKey); err != nil {
			ui.Fail(fmt.Sprintf("Module error: %v", err))
		}

		// Show delta
		afterStats := engagement.FindingStats(c.eng.ID)
		afterTotal := afterStats["CRITICAL"] + afterStats["HIGH"] + afterStats["MEDIUM"] + afterStats["INFO"]
		afterHosts, _ := targets.List(c.eng.ID)
		afterCreds, _ := vault.List(c.eng.ID)

		newFindings := afterTotal - beforeTotal
		newHosts := len(afterHosts) - len(beforeHosts)
		newCreds := len(afterCreds) - len(beforeCreds)

		if newFindings > 0 || newHosts > 0 || newCreds > 0 {
			fmt.Println()
			ui.Divider()
			ui.Success("Module complete — new intelligence captured:")
			if newFindings > 0 {
				ui.Info(fmt.Sprintf("  +%d finding(s)  (C:%+d H:%+d M:%+d)",
					newFindings,
					afterStats["CRITICAL"]-beforeStats["CRITICAL"],
					afterStats["HIGH"]-beforeStats["HIGH"],
					afterStats["MEDIUM"]-beforeStats["MEDIUM"],
				))
			}
			if newHosts > 0 {
				ui.Info(fmt.Sprintf("  +%d host(s) discovered", newHosts))
			}
			if newCreds > 0 {
				ui.Info(fmt.Sprintf("  +%d credential(s) captured", newCreds))
			}
			ui.Divider()
			ui.PressEnter()
		}
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

// Run starts campaign mode. modules is the full runner registry (passed to avoid
// import cycles). runFn is runner.RunModule.
func Run(modules []ModuleMeta, runFn RunFunc) error {
	eng, _ := engagement.Active()
	if eng == nil {
		ui.Header("Campaign Mode")
		ui.Warn("No active engagement. Create one first:")
		ui.Info("  davoid new <name>  OR  press [E] in the main menu → New Engagement")
		ui.PressEnter()
		return nil
	}

	c := &campaign{
		modules: modules,
		runFn:   runFn,
		eng:     eng,
	}
	return c.run()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
