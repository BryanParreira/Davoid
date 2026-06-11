package webintel

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/osint"
	"github.com/bryanparreira/davoid/internal/modules/ui"
	"github.com/bryanparreira/davoid/internal/modules/webrecon"
	"github.com/bryanparreira/davoid/internal/modules/webscan"
)

func Run() error {
	ui.Header("Web Intelligence Suite — OSINT → Recon → Attack Pipeline")

	fmt.Println()
	ui.Info("One target. Full pipeline: subdomain discovery → fingerprint → vulnerability scan.")
	fmt.Println()

	rawTarget := ui.Prompt("Target (domain or URL, e.g. example.com)")
	if rawTarget == "" {
		return nil
	}

	// Normalize
	if !strings.HasPrefix(rawTarget, "http") {
		rawTarget = "https://" + rawTarget
	}
	parsed, err := url.Parse(rawTarget)
	if err != nil || parsed.Hostname() == "" {
		ui.Fail("Invalid target.")
		return nil
	}
	domain := parsed.Hostname()
	// Strip www for subdomain discovery
	baseDomain := strings.TrimPrefix(domain, "www.")

	mode := ui.Select("Pipeline Mode", []string{
		"Full Pipeline    (subdomain discovery → fingerprint → active scan)",
		"Recon Only       (subdomain discovery + fingerprint, no active scan)",
		"Single Target    (skip subdomain enum, scan this URL directly)",
	})
	if mode < 0 {
		return nil
	}

	eng, _ := engagement.Active()

	// ── Phase 1: Subdomain Discovery ─────────────────────────────────────────
	var targets []string

	if mode == 2 {
		// Single target — skip enum
		targets = []string{rawTarget}
	} else {
		fmt.Println()
		ui.Divider()
		ui.Info(fmt.Sprintf("Phase 1/3 — Subdomain Discovery (%s)", baseDomain))
		ui.Divider()

		// Always include root target
		targets = append(targets, rawTarget)

		discovered := osint.DiscoverSubdomains(baseDomain)
		for _, sub := range discovered {
			subHost, _ := url.Parse(sub)
			if subHost.Hostname() != domain {
				fmt.Printf("  %s  %s\n", ui.Green.Render("FOUND"), sub)
				targets = append(targets, sub)
			}
		}

		// Also do quick DNS check for A records
		if addrs, err := net.LookupHost(baseDomain); err == nil {
			fmt.Printf("  %s  %s → %s\n",
				ui.Cyan.Render("DNS  "),
				baseDomain,
				strings.Join(addrs, ", "),
			)
		}

		fmt.Println()
		ui.Success(fmt.Sprintf("Discovered %d target(s): %s + %d subdomains",
			len(targets), domain, len(targets)-1))

		if eng != nil {
			engagement.LogFinding(eng.ID, "web_intel", baseDomain,
				fmt.Sprintf("Subdomain discovery: %d live subdomains found", len(targets)-1),
				strings.Join(targets, " | "), "INFO", "")
		}
	}

	// ── Phase 2: Web Recon (fingerprint each target) ──────────────────────────
	fmt.Println()
	ui.Divider()
	ui.Info(fmt.Sprintf("Phase 2/3 — Web Recon (%d target(s))", len(targets)))
	ui.Divider()

	liveTargets := []string{}
	for _, t := range targets {
		fmt.Println()
		ui.Info(fmt.Sprintf("Fingerprinting: %s", t))
		ui.Divider()
		if err := webrecon.RunTarget(t); err != nil {
			ui.Warn(fmt.Sprintf("Recon failed for %s: %v", t, err))
			continue
		}
		liveTargets = append(liveTargets, t)
	}

	if len(liveTargets) == 0 {
		ui.Warn("No live targets responded. Pipeline complete.")
		ui.PressEnter()
		return nil
	}

	// ── Phase 3: Web App Scanning (active attack) ─────────────────────────────
	if mode == 1 {
		// Recon only — skip attack phase
		fmt.Println()
		ui.Success(fmt.Sprintf("Recon complete. %d live target(s) fingerprinted.", len(liveTargets)))
		ui.PressEnter()
		return nil
	}

	fmt.Println()
	ui.Divider()
	ui.Info(fmt.Sprintf("Phase 3/3 — Active Web App Scan (%d live target(s))", len(liveTargets)))
	ui.Warn("Active injection testing. Authorized use only.")
	ui.Divider()

	if !ui.Confirm("Launch active scan on all live targets?") {
		ui.Info("Active scan skipped.")
		ui.PressEnter()
		return nil
	}

	for i, t := range liveTargets {
		fmt.Println()
		ui.Divider()
		ui.Info(fmt.Sprintf("[%d/%d] Scanning: %s", i+1, len(liveTargets), t))
		ui.Divider()
		webscan.RunPipeline(t, eng)
	}

	fmt.Println()
	ui.Divider()
	ui.Success(fmt.Sprintf("Web Intelligence Suite complete. %d target(s) fully audited.", len(liveTargets)))
	if eng != nil {
		ui.Info("All findings saved to engagement. Run 'davoid report' to generate report.")
	}
	ui.PressEnter()
	return nil
}
