package runner

import (
	"fmt"
	"strings"

	"github.com/bryanparreira/davoid/internal/modules/adops"
	"github.com/bryanparreira/davoid/internal/modules/aiassist"
	"github.com/bryanparreira/davoid/internal/modules/auditor"
	"github.com/bryanparreira/davoid/internal/modules/bruteforce"
	"github.com/bryanparreira/davoid/internal/modules/cloudops"
	"github.com/bryanparreira/davoid/internal/modules/credtester"
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
	"github.com/bryanparreira/davoid/internal/modules/wifi"
)

// Module represents a Davoid module that can be invoked.
type Module struct {
	Key         string
	Name        string
	Description string
	Category    string
}

// Categories in display order
var Categories = []string{
	"Intelligence & OSINT",
	"Offensive Operations",
	"Post-Exploitation",
	"Active Directory",
	"Advanced",
	"WiFi & Wireless",
	"System",
}

// Registry is the full list of available modules.
var Registry = []Module{
	{Key: "scanner", Name: "Net-Mapper", Description: "Nmap orchestration with live CVE lookup (NVD)", Category: "Intelligence & OSINT"},
	{Key: "sniff", Name: "Live Interceptor", Description: "Real-time traffic capture, DNS tracking, credential extraction", Category: "Intelligence & OSINT"},
	{Key: "osint", Name: "Holmes Engine", Description: "Username OSINT across 14 platforms, phone intel, subdomain brute", Category: "Intelligence & OSINT"},
	{Key: "web_recon", Name: "Web Recon", Description: "robots.txt scrape, domain reputation, Google Dorks, CT logs", Category: "Intelligence & OSINT"},
	{Key: "mitm", Name: "MITM Engine", Description: "ARP poisoning + automatic IP forwarding (Linux/macOS)", Category: "Offensive Operations"},
	{Key: "phishing", Name: "Phantom Cloner", Description: "Dynamic page cloning with JS credential harvesting portal", Category: "Offensive Operations"},
	{Key: "ghost_hub", Name: "GHOST-HUB C2", Description: "AES-encrypted async HTTP command & control server", Category: "Offensive Operations"},
	{Key: "payloads", Name: "Shell Forge", Description: "Multi-language payload generator (Bash, Python, PHP, PS, MSF)", Category: "Post-Exploitation"},
	{Key: "crypt_keeper", Name: "Crypt-Keeper", Description: "Payload encryption + self-decrypting AES loaders", Category: "Post-Exploitation"},
	{Key: "persistence", Name: "Persistence Engine", Description: "systemd, crontab (Linux), LaunchAgent (macOS), registry (Windows)", Category: "Post-Exploitation"},
	{Key: "bruteforce", Name: "Hash Cracker", Description: "Multi-threaded dictionary/brute MD5, SHA256, NTLM", Category: "Post-Exploitation"},
	{Key: "looter", Name: "Looter", Description: "Privilege escalation discovery, SSH key harvest, loot collection", Category: "Post-Exploitation"},
	{Key: "cred_tester", Name: "Credential Tester", Description: "Credential re-use testing across SSH, FTP, HTTP", Category: "Post-Exploitation"},
	{Key: "ad_ops", Name: "AD Ops", Description: "LDAP enum, Kerberoasting, DCSync detection, BloodHound export", Category: "Active Directory"},
	{Key: "msf_engine", Name: "Metasploit Bridge", Description: "MSF RPC client — auto exploit selection & execution", Category: "Advanced"},
	{Key: "ai_assist", Name: "AI Console", Description: "LangChain + Ollama AI-assisted attack strategy & payload mutation", Category: "Advanced"},
	{Key: "cloud_ops", Name: "Cloud Ops", Description: "Cloud-specific attack modules (AWS, GCP, Azure)", Category: "Advanced"},
	{Key: "purple_team", Name: "Purple Team", Description: "Defensive scenario simulation and blue team reporting", Category: "Advanced"},
	{Key: "auditor", Name: "Setup Auditor", Description: "Pre-flight check: dependencies, network interface capabilities", Category: "System"},
	{Key: "god_mode", Name: "God Mode", Description: "Advanced exploitation chains", Category: "System"},

	{Key: "wifi_monitor", Name: "Monitor Mode", Description: "Toggle monitor mode on wireless interfaces (airmon-ng)", Category: "WiFi & Wireless"},
	{Key: "wifi_scan", Name: "WiFi Scanner", Description: "Discover nearby networks, channels, encryption, clients (airodump-ng)", Category: "WiFi & Wireless"},
	{Key: "wifi_deauth", Name: "Deauth Attack", Description: "Broadcast or targeted 802.11 deauthentication frames (aireplay-ng)", Category: "WiFi & Wireless"},
	{Key: "wifi_handshake", Name: "Handshake Capture", Description: "Capture WPA/WPA2 4-way handshake for offline cracking", Category: "WiFi & Wireless"},
	{Key: "wifi_crack", Name: "WPA Cracker", Description: "Dictionary attack against captured handshake (aircrack-ng)", Category: "WiFi & Wireless"},
	{Key: "wifi_eviltwin", Name: "Evil Twin AP", Description: "Deploy rogue access point cloning a target SSID (hostapd + dnsmasq)", Category: "WiFi & Wireless"},
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
	case "scanner": return scanner.Run()
	case "sniff": return sniff.Run()
	case "osint": return osint.Run()
	case "web_recon": return webrecon.Run()
	case "mitm": return mitm.Run()
	case "phishing": return phishing.Run()
	case "ghost_hub": return ghosthub.Run()
	case "crypt_keeper": return cryptkeeper.Run()
	case "persistence": return persistence.Run()
	case "bruteforce": return bruteforce.Run()
	case "looter": return looter.Run()
	case "cred_tester": return credtester.Run()
	case "ad_ops": return adops.Run()
	case "msf_engine": return msfengine.Run()
	case "ai_assist": return aiassist.Run()
	case "cloud_ops": return cloudops.Run()
	case "purple_team": return purpleteam.Run()
	case "auditor": return auditor.Run()
	case "god_mode": return godmode.Run()
	case "payloads": return payloads.Run()
	case "wifi_monitor": return wifi.RunMonitor()
	case "wifi_scan": return wifi.RunScan()
	case "wifi_deauth": return wifi.RunDeauth()
	case "wifi_handshake": return wifi.RunHandshake()
	case "wifi_crack": return wifi.RunCrack()
	case "wifi_eviltwin": return wifi.RunEvilTwin()
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