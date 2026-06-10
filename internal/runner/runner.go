package runner

import (
	"fmt"
	"strings"

	"github.com/bryanparreira/davoid/internal/campaign"
	"github.com/bryanparreira/davoid/internal/modules/adops"
	"github.com/bryanparreira/davoid/internal/modules/aiassist"
	"github.com/bryanparreira/davoid/internal/modules/auditor"
	"github.com/bryanparreira/davoid/internal/modules/cloudops"
	"github.com/bryanparreira/davoid/internal/modules/credops"
	"github.com/bryanparreira/davoid/internal/modules/cryptkeeper"
	"github.com/bryanparreira/davoid/internal/modules/ghosthub"
	"github.com/bryanparreira/davoid/internal/modules/godmode"
	"github.com/bryanparreira/davoid/internal/modules/looter"
	"github.com/bryanparreira/davoid/internal/modules/payloads"
	"github.com/bryanparreira/davoid/internal/modules/mitm"
	"github.com/bryanparreira/davoid/internal/modules/msfengine"
	"github.com/bryanparreira/davoid/internal/modules/osint"
	"github.com/bryanparreira/davoid/internal/modules/persistence"
	"github.com/bryanparreira/davoid/internal/modules/phishing"
	"github.com/bryanparreira/davoid/internal/modules/purpleteam"
	"github.com/bryanparreira/davoid/internal/modules/scanner"
	"github.com/bryanparreira/davoid/internal/modules/sniff"
	"github.com/bryanparreira/davoid/internal/modules/webrecon"
	"github.com/bryanparreira/davoid/internal/modules/webscan"
	"github.com/bryanparreira/davoid/internal/modules/wifi"
)

// Module represents a Davoid module that can be invoked.
type Module struct {
	Key         string
	Name        string
	Description string
	Category    string
}

// Categories in display order (follows kill chain)
var Categories = []string{
	"Recon & OSINT",
	"Network Attacks",
	"Social Engineering",
	"Exploitation",
	"Post-Exploitation",
	"Active Directory",
	"WiFi & Wireless",
	"Advanced",
	"Web App Scanning",
}

// Registry is the full list of available modules.
var Registry = []Module{
	// ── [1] Recon & OSINT ────────────────────────────────────────────────
	{Key: "scanner", Name: "Net-Mapper", Description: "Nmap orchestration with live CVE lookup (NVD)", Category: "Recon & OSINT"},
	{Key: "osint", Name: "Holmes Engine", Description: "URL / domain / IP / username OSINT — auto-detect routing", Category: "Recon & OSINT"},
	{Key: "web_recon", Name: "Web Recon", Description: "robots.txt, domain reputation, Google Dorks, CT logs", Category: "Recon & OSINT"},

	// ── [9] Web App Scanning ──────────────────────────────────────────────
	{Key: "webscan", Name: "Full Scan", Description: "Spider → passive analysis → active injection — complete web audit", Category: "Web App Scanning"},
	{Key: "webscan_spider", Name: "Spider / Crawler", Description: "BFS crawler: map URLs, forms, and injectable parameters", Category: "Web App Scanning"},
	{Key: "webscan_passive", Name: "Passive Analyzer", Description: "Insecure cookies, missing headers, CORS wildcard, info leaks, mixed content", Category: "Web App Scanning"},
	{Key: "webscan_active", Name: "Active Scanner", Description: "SQLi, XSS, path traversal, open redirect, command injection, SSTI", Category: "Web App Scanning"},

	// ── [2] Network Attacks ───────────────────────────────────────────────
	{Key: "mitm", Name: "MITM Engine", Description: "ARP poisoning + automatic IP forwarding (Linux/macOS)", Category: "Network Attacks"},
	{Key: "sniff", Name: "Live Interceptor", Description: "Real-time traffic capture, DNS tracking, credential extraction", Category: "Network Attacks"},

	// ── [3] Social Engineering ────────────────────────────────────────────
	{Key: "phishing", Name: "Phantom Cloner", Description: "Dynamic page cloning with JS credential harvesting portal", Category: "Social Engineering"},
	{Key: "ghost_hub", Name: "GHOST-HUB C2", Description: "AES-encrypted async HTTP command & control server", Category: "Social Engineering"},

	// ── [4] Exploitation ──────────────────────────────────────────────────
	{Key: "payloads", Name: "Shell Forge", Description: "Payload generator (Bash/Python/PHP/PS/MSF) + TCP shell catcher", Category: "Exploitation"},
	{Key: "crypt_keeper", Name: "Crypt-Keeper", Description: "Payload encryption + self-decrypting AES loaders", Category: "Exploitation"},
	{Key: "msf_engine", Name: "Metasploit Bridge", Description: "MSF RPC client — auto exploit selection & execution", Category: "Exploitation"},

	// ── [5] Post-Exploitation ─────────────────────────────────────────────
	{Key: "looter", Name: "Looter", Description: "Privilege escalation discovery, SSH key harvest, loot collection", Category: "Post-Exploitation"},
	{Key: "credops", Name: "Cred Ops", Description: "Hash cracker (MD5/SHA/NTLM) + credential re-use tester (SSH/FTP/HTTP)", Category: "Post-Exploitation"},
	{Key: "persistence", Name: "Persistence Engine", Description: "systemd, crontab (Linux), LaunchAgent (macOS), registry (Windows)", Category: "Post-Exploitation"},

	// ── [6] Active Directory ──────────────────────────────────────────────
	{Key: "ad_ops", Name: "AD Ops", Description: "LDAP enum, Kerberoasting, DCSync detection, BloodHound export", Category: "Active Directory"},

	// ── [7] WiFi & Wireless ────────────────────────────────────────────────
	{Key: "wifi", Name: "WiFi Suite", Description: "Full wireless attack chain: monitor → scan → deauth → handshake → crack → evil twin", Category: "WiFi & Wireless"},

	// ── [8] Advanced ──────────────────────────────────────────────────────
	{Key: "ai_assist", Name: "AI Console", Description: "LangChain + Ollama AI-assisted attack strategy & payload mutation", Category: "Advanced"},
	{Key: "cloud_ops", Name: "Cloud Ops", Description: "Cloud-specific attack modules (AWS, GCP, Azure)", Category: "Advanced"},
	{Key: "purple_team", Name: "Purple Team", Description: "Defensive scenario simulation and blue team reporting", Category: "Advanced"},
	{Key: "god_mode", Name: "God Mode", Description: "Autonomous full-campaign orchestrator — recon → exploit chain → report", Category: "Advanced"},
}

// ByCategory returns modules filtered by category.
func ByCategory(category string) []Module {
	var out []Module
	for _, m := range Registry {
		if m.Category == category {
			out = append(out, m)
		}
	}
	return out
}

// RunModule routes the execution to the native Go module.
func RunModule(key string) error {
	switch key {
	case "scanner":
		return scanner.Run()
	case "sniff":
		return sniff.Run()
	case "osint":
		return osint.Run()
	case "web_recon":
		return webrecon.Run()
	case "webscan":
		return webscan.RunFull()
	case "webscan_spider":
		return webscan.RunSpider()
	case "webscan_passive":
		return webscan.RunPassive()
	case "webscan_active":
		return webscan.RunActive()
	case "mitm":
		return mitm.Run()
	case "phishing":
		return phishing.Run()
	case "ghost_hub":
		return ghosthub.Run()
	case "crypt_keeper":
		return cryptkeeper.Run()
	case "persistence":
		return persistence.Run()
	case "credops":
		return credops.Run()
	// legacy keys — redirect to merged modules
	case "bruteforce":
		return credops.RunHashCracker()
	case "cred_tester":
		return credops.RunCredTester()
	case "catcher":
		return payloads.RunCatch()
	case "looter":
		return looter.Run()
	case "ad_ops":
		return adops.Run()
	case "msf_engine":
		return msfengine.Run()
	case "ai_assist":
		return aiassist.Run()
	case "cloud_ops":
		return cloudops.Run()
	case "purple_team":
		return purpleteam.Run()
	case "auditor":
		return auditor.Run()
	case "god_mode":
		return godmode.Run()
	case "payloads":
		return payloads.Run()
	// Unified WiFi suite — individual keys kept for `davoid run wifi_*` CLI
	case "wifi":
		return wifi.RunSuite()
	case "wifi_monitor":
		return wifi.RunMonitor()
	case "wifi_scan":
		return wifi.RunScan()
	case "wifi_deauth":
		return wifi.RunDeauth()
	case "wifi_handshake":
		return wifi.RunHandshake()
	case "wifi_crack":
		return wifi.RunCrack()
	case "wifi_eviltwin":
		return wifi.RunEvilTwin()
	case "campaign":
		metas := make([]campaign.ModuleMeta, len(Registry))
		for i, m := range Registry {
			metas[i] = campaign.ModuleMeta{Key: m.Key, Name: m.Name, Description: m.Description}
		}
		return campaign.Run(metas, RunModule)
	default:
		return fmt.Errorf("module not found: %s", key)
	}
}

// ShortDesc truncates a description to fit the terminal.
func ShortDesc(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// ColumnPad right-pads a string to width.
func ColumnPad(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	return s + strings.Repeat(" ", width-len(s))
}
