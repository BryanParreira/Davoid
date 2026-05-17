package purpleteam

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/ui"
)

type technique struct {
	TID      string
	Name     string
	Tactic   string
	Splunk   string
	Sigma    string
	Modules  []string
}

var mitreTTPs = []technique{
	{
		TID:    "T1595.001",
		Name:   "Active Scanning: Scanning IP Blocks",
		Tactic: "Reconnaissance",
		Splunk: `index=network sourcetype=firewall | stats count by src_ip | where count > 100`,
		Sigma:  "detection:\n  keywords:\n    - 'nmap'\n    - 'masscan'",
		Modules: []string{"scanner"},
	},
	{
		TID:    "T1596.005",
		Name:   "Search Open Technical Databases",
		Tactic: "Reconnaissance",
		Splunk: `index=dns | stats count by query | sort -count`,
		Sigma:  "detection:\n  keywords:\n    - 'subdomain enumeration'",
		Modules: []string{"osint"},
	},
	{
		TID:    "T1592",
		Name:   "Gather Victim Host Information",
		Tactic: "Reconnaissance",
		Splunk: `index=web | stats count by user_agent | sort -count`,
		Sigma:  "detection:\n  keywords:\n    - 'user-agent scanner'",
		Modules: []string{"web_recon", "osint"},
	},
	{
		TID:    "T1557.002",
		Name:   "ARP Cache Poisoning",
		Tactic: "Collection",
		Splunk: `index=network sourcetype=arp | stats count by src_mac dest_mac | where src_mac != dest_mac`,
		Sigma:  "detection:\n  keywords:\n    - 'arp-reply'\n    - 'gratuitous arp'",
		Modules: []string{"mitm"},
	},
	{
		TID:    "T1040",
		Name:   "Network Sniffing",
		Tactic: "Credential Access",
		Splunk: `index=network sourcetype=zeek_conn | stats count by proto | sort -count`,
		Sigma:  "detection:\n  keywords:\n    - 'promiscuous mode'\n    - 'tcpdump'",
		Modules: []string{"sniff"},
	},
	{
		TID:    "T1566.002",
		Name:   "Phishing: Spearphishing Link",
		Tactic: "Initial Access",
		Splunk: `index=web | where uri="/login" AND method="POST" | stats count by src_ip`,
		Sigma:  "detection:\n  keywords:\n    - 'credential harvest'\n    - 'clone site'",
		Modules: []string{"phishing"},
	},
	{
		TID:    "T1105",
		Name:   "Ingress Tool Transfer",
		Tactic: "Command and Control",
		Splunk: `index=network | where bytes_out > 1000000 | stats sum(bytes_out) by dest_ip`,
		Sigma:  "detection:\n  keywords:\n    - 'wget'\n    - 'curl'\n    - 'certutil'",
		Modules: []string{"payloads"},
	},
	{
		TID:    "T1071.001",
		Name:   "C2: Web Protocols",
		Tactic: "Command and Control",
		Splunk: `index=proxy | where bytes < 1000 AND status=200 | bucket _time span=5m | stats count by dest | where count > 50`,
		Sigma:  "detection:\n  keywords:\n    - 'beacon'\n    - 'c2 callback'\n    - 'implant'",
		Modules: []string{"ghost_hub"},
	},
	{
		TID:    "T1027",
		Name:   "Obfuscated Files or Information",
		Tactic: "Defense Evasion",
		Splunk: `index=endpoint | where process_name="python*" AND cmdline="*base64*"`,
		Sigma:  "detection:\n  keywords:\n    - 'base64'\n    - 'encrypted payload'",
		Modules: []string{"crypt_keeper", "payloads"},
	},
	{
		TID:    "T1547.001",
		Name:   "Boot or Logon Autostart: Registry Run Keys",
		Tactic: "Persistence",
		Splunk: `index=windows source="WinEventLog:Security" EventCode=13 | where TargetObject LIKE "%Run%"`,
		Sigma:  "detection:\n  keywords:\n    - 'HKCU\\\\Run'\n    - 'HKLM\\\\Run'",
		Modules: []string{"persistence"},
	},
	{
		TID:    "T1110.003",
		Name:   "Password Spraying",
		Tactic: "Credential Access",
		Splunk: `index=windows source="WinEventLog:Security" EventCode=4625 | stats count by src_ip | where count > 10`,
		Sigma:  "detection:\n  keywords:\n    - 'authentication failure'\n    - 'spray'",
		Modules: []string{"cred_tester", "ad_ops"},
	},
	{
		TID:    "T1003.001",
		Name:   "OS Credential Dumping: LSASS",
		Tactic: "Credential Access",
		Splunk: `index=windows source="WinEventLog:Security" EventCode=10 TargetImage="*lsass.exe"`,
		Sigma:  "detection:\n  keywords:\n    - 'mimikatz'\n    - 'lsass'",
		Modules: []string{"looter"},
	},
	{
		TID:    "T1018",
		Name:   "Remote System Discovery",
		Tactic: "Discovery",
		Splunk: `index=network sourcetype=firewall | stats count by src_ip dest_port | where count > 50`,
		Sigma:  "detection:\n  keywords:\n    - 'port scan'\n    - 'host discovery'",
		Modules: []string{"scanner"},
	},
	{
		TID:    "T1021.004",
		Name:   "Remote Services: SSH",
		Tactic: "Lateral Movement",
		Splunk: `index=linux source="/var/log/auth.log" "Accepted password"`,
		Sigma:  "detection:\n  keywords:\n    - 'ssh login'\n    - 'paramiko'",
		Modules: []string{"looter", "cred_tester"},
	},
	{
		TID:    "T1078.002",
		Name:   "Valid Accounts: Domain Accounts",
		Tactic: "Defense Evasion",
		Splunk: `index=windows source="WinEventLog:Security" EventCode=4624 LogonType=3`,
		Sigma:  "detection:\n  keywords:\n    - 'domain login'\n    - 'ldap bind'",
		Modules: []string{"ad_ops"},
	},
}

func Run() error {
	ui.Header("Purple Team — MITRE ATT&CK Mapper & Detection Engineer")

	eng, _ := engagement.Active()
	if eng == nil {
		ui.Warn("No active engagement — showing all TTPs.")
	}

	for {
		action := ui.Select("Purple Team Operation", []string{
			"View MITRE ATT&CK Coverage",
			"Generate Detection Rules (Splunk SPL)",
			"Generate Sigma Rules",
			"Export ATT&CK Navigator JSON",
			"Generate Markdown Report",
		})
		if action < 0 {
			break
		}

		switch action {
		case 0:
			showCoverage(eng)
		case 1:
			generateSplunk(eng)
		case 2:
			generateSigma(eng)
		case 3:
			exportNavigator()
		case 4:
			generateMarkdown(eng)
		}
	}
	return nil
}

func showCoverage(_ *engagement.Engagement) {
	fmt.Println()
	ui.Divider()
	fmt.Printf("  %-12s  %-15s  %-40s  %s\n",
		ui.Bold.Render("TID"),
		ui.Bold.Render("TACTIC"),
		ui.Bold.Render("TECHNIQUE"),
		ui.Bold.Render("MODULES"),
	)
	ui.Divider()

	tactics := map[string][]technique{}
	for _, t := range mitreTTPs {
		tactics[t.Tactic] = append(tactics[t.Tactic], t)
	}

	tacticOrder := []string{
		"Reconnaissance", "Initial Access", "Execution", "Persistence",
		"Defense Evasion", "Credential Access", "Discovery",
		"Lateral Movement", "Collection", "Command and Control", "Exfiltration",
	}

	for _, tactic := range tacticOrder {
		ttps, ok := tactics[tactic]
		if !ok {
			continue
		}
		fmt.Println()
		fmt.Println(ui.Yellow.Render("  ── " + tactic + " ──"))
		for _, t := range ttps {
			fmt.Printf("  %-12s  %-15s  %-40s  %s\n",
				ui.Cyan.Render(t.TID),
				"",
				t.Name,
				ui.Dim.Render(strings.Join(t.Modules, ", ")),
			)
		}
	}
	fmt.Printf("\n  Total: %d techniques mapped.\n", len(mitreTTPs))
	ui.PressEnter()
}

func generateSplunk(_ *engagement.Engagement) {
	fmt.Println()
	ui.Divider()
	ui.Info("Splunk SPL Detection Rules")
	ui.Divider()
	for _, t := range mitreTTPs {
		fmt.Printf("\n  %s  %s\n", ui.Cyan.Render(t.TID), t.Name)
		fmt.Println(ui.Yellow.Render("  " + t.Splunk))
	}
	ui.PressEnter()
}

func generateSigma(_ *engagement.Engagement) {
	fmt.Println()
	ui.Divider()
	ui.Info("Sigma Detection Rules")
	ui.Divider()
	for _, t := range mitreTTPs {
		fmt.Printf("\n  %s  %s\n", ui.Cyan.Render(t.TID), t.Name)
		rule := fmt.Sprintf("title: Detect %s\nstatus: experimental\ndescription: Detects %s\ntags:\n  - attack.%s\n  - %s\n%s",
			t.Name, t.Name, strings.ToLower(strings.ReplaceAll(t.Tactic, " ", "_")), strings.ToLower(t.TID), t.Sigma)
		for _, line := range strings.Split(rule, "\n") {
			fmt.Println(ui.Dim.Render("  " + line))
		}
	}
	ui.PressEnter()
}

type navigatorLayer struct {
	Name        string        `json:"name"`
	Version     string        `json:"version"`
	Domain      string        `json:"domain"`
	Description string        `json:"description"`
	Techniques  []navTechnique `json:"techniques"`
}

type navTechnique struct {
	TechniqueID string `json:"techniqueID"`
	Score       int    `json:"score"`
	Comment     string `json:"comment"`
}

func exportNavigator() {
	layer := navigatorLayer{
		Name:        "Davoid Coverage",
		Version:     "4.4",
		Domain:      "enterprise-attack",
		Description: "Davoid red team framework ATT&CK coverage",
	}
	for _, t := range mitreTTPs {
		layer.Techniques = append(layer.Techniques, navTechnique{
			TechniqueID: t.TID,
			Score:       75,
			Comment:     "Covered by: " + strings.Join(t.Modules, ", "),
		})
	}
	data, _ := json.MarshalIndent(layer, "", "  ")
	fname := fmt.Sprintf("attack_navigator_%d.json", time.Now().Unix())
	os.WriteFile(fname, data, 0644)
	ui.Success(fmt.Sprintf("ATT&CK Navigator layer exported: %s", fname))
	ui.PressEnter()
}

func generateMarkdown(eng *engagement.Engagement) {
	var sb strings.Builder
	sb.WriteString("# Purple Team Report — MITRE ATT&CK Coverage\n\n")
	if eng != nil {
		sb.WriteString(fmt.Sprintf("**Engagement:** %s\n\n", eng.Name))
	}
	sb.WriteString(fmt.Sprintf("**Generated:** %s\n\n", time.Now().Format(time.RFC1123)))
	sb.WriteString("## Technique Coverage\n\n")
	sb.WriteString("| TID | Tactic | Technique | Detection |\n")
	sb.WriteString("|-----|--------|-----------|----------|\n")
	for _, t := range mitreTTPs {
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | [Splunk] |\n", t.TID, t.Tactic, t.Name))
	}

	fname := fmt.Sprintf("purple_team_report_%d.md", time.Now().Unix())
	os.WriteFile(fname, []byte(sb.String()), 0644)
	ui.Success(fmt.Sprintf("Purple team report: %s", fname))
	ui.PressEnter()
}
