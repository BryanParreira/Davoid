package playbook

import (
	"fmt"
	"strings"

	"github.com/bryanparreira/davoid/internal/modules/ui"
	"github.com/bryanparreira/davoid/internal/runner"
)

// Playbook is an ordered sequence of modules forming an attack chain.
type Playbook struct {
	Key         string
	Name        string
	Description string
	Category    string
	Modules     []string
}

var Registry = []Playbook{
	{
		Key:         "external-recon",
		Name:        "External Recon",
		Description: "Full external recon — scanner → OSINT → web audit",
		Category:    "Recon",
		Modules:     []string{"scanner", "osint", "web_recon"},
	},
	{
		Key:         "phish-to-shell",
		Name:        "Phish to Shell",
		Description: "Clone login page → harvest creds → generate payload → catch shell",
		Category:    "Social Engineering",
		Modules:     []string{"phishing", "payloads", "catcher"},
	},
	{
		Key:         "network-compromise",
		Name:        "Network Compromise",
		Description: "ARP poison → intercept traffic → crack hashes → spray creds",
		Category:    "Network",
		Modules:     []string{"mitm", "sniff", "bruteforce", "cred_tester"},
	},
	{
		Key:         "post-exploitation",
		Name:        "Post-Exploitation",
		Description: "Enumerate privesc → harvest loot → persist → spray creds across network",
		Category:    "Post-Ex",
		Modules:     []string{"looter", "persistence", "cred_tester"},
	},
	{
		Key:         "ad-attack",
		Name:        "Active Directory Attack",
		Description: "LDAP enum → AS-REP roast → Kerberoast → crack hashes → spray",
		Category:    "Active Directory",
		Modules:     []string{"ad_ops", "bruteforce", "cred_tester"},
	},
	{
		Key:         "wifi-full",
		Name:        "WiFi Full Attack",
		Description: "Enable monitor mode → scan → capture handshake → crack PSK",
		Category:    "WiFi",
		Modules:     []string{"wifi_monitor", "wifi_scan", "wifi_handshake", "wifi_crack"},
	},
	{
		Key:         "full-kill-chain",
		Name:        "Full Kill Chain",
		Description: "Recon → phishing → shell → post-ex → pivot → report",
		Category:    "Full Op",
		Modules:     []string{"scanner", "osint", "phishing", "catcher", "looter", "cred_tester", "persistence"},
	},
}

// Get returns a playbook by key or nil.
func Get(key string) *Playbook {
	for i := range Registry {
		if Registry[i].Key == key {
			return &Registry[i]
		}
	}
	return nil
}

// Run executes a playbook interactively, one module at a time.
func Run(key string) error {
	pb := Get(key)
	if pb == nil {
		return fmt.Errorf("playbook not found: %s", key)
	}

	ui.Header(fmt.Sprintf("Playbook: %s", pb.Name))
	fmt.Printf("\n  %s\n\n", pb.Description)

	width := 60
	fmt.Println("  " + strings.Repeat("─", width))
	for i, modKey := range pb.Modules {
		mod := moduleLabel(modKey)
		fmt.Printf("  %s %d. %s\n", stepIcon(i, len(pb.Modules)), i+1, mod)
	}
	fmt.Println("  " + strings.Repeat("─", width))
	fmt.Println()

	if !ui.Confirm("Start playbook?") {
		return nil
	}

	skipped := 0
	failed := 0

	for i, modKey := range pb.Modules {
		fmt.Println()
		fmt.Println("  " + strings.Repeat("═", width))
		ui.Info(fmt.Sprintf("Step %d/%d — %s", i+1, len(pb.Modules), moduleLabel(modKey)))
		fmt.Println("  " + strings.Repeat("═", width))
		fmt.Println()

		if !ui.Confirm(fmt.Sprintf("Run [%s]?", modKey)) {
			ui.Warn("Skipped.")
			skipped++
			continue
		}

		if err := runner.RunModule(modKey); err != nil {
			ui.Fail(fmt.Sprintf("Module error: %v", err))
			failed++
			if !ui.Confirm("Continue to next step?") {
				break
			}
		}
	}

	fmt.Println()
	fmt.Println("  " + strings.Repeat("─", width))
	total := len(pb.Modules)
	ran := total - skipped - failed
	ui.Success(fmt.Sprintf("Playbook complete — %d/%d modules ran  (%d skipped  %d failed)", ran, total, skipped, failed))
	fmt.Println()

	return nil
}

func moduleLabel(key string) string {
	for _, m := range runner.Registry {
		if m.Key == key {
			return fmt.Sprintf("%-18s  %s", m.Name, runner.ShortDesc(m.Description, 45))
		}
	}
	return key
}

func stepIcon(i, total int) string {
	if i == total-1 {
		return "  └──"
	}
	return "  ├──"
}
