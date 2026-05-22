package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/bryanparreira/davoid/internal/config"
	"github.com/bryanparreira/davoid/internal/cvss"
	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/auditor"
	"github.com/bryanparreira/davoid/internal/modules/playbook"
	"github.com/bryanparreira/davoid/internal/opsec"
	"github.com/bryanparreira/davoid/internal/runner"
	"github.com/bryanparreira/davoid/internal/snapshot"
	"github.com/bryanparreira/davoid/internal/targets"
	"github.com/bryanparreira/davoid/internal/templates"
	"github.com/bryanparreira/davoid/internal/tui"
	"github.com/bryanparreira/davoid/internal/vault"
)

func launchTUI() error {
	inCampaign := false
	for {
		var m tui.Model
		if inCampaign {
			m = tui.NewCampaignModel(version)
		} else {
			m = tui.NewModel(version)
		}
		p := tea.NewProgram(m, tea.WithAltScreen())
		finalModel, err := p.Run()
		if err != nil {
			return err
		}
		fm := finalModel.(tui.Model)
		pending := fm.PendingModule()
		inCampaign = fm.PendingCampaign()

		if pending == "" {
			break
		}
		if strings.HasPrefix(pending, "playbook:") {
			key := strings.TrimPrefix(pending, "playbook:")
			if err := playbook.Run(key); err != nil {
				fmt.Fprintf(os.Stderr, "\n[!] Playbook error: %v\n", err)
			}
		} else {
			if err := runner.RunModule(pending); err != nil {
				fmt.Fprintf(os.Stderr, "\n[!] Module error: %v\n", err)
			}
		}
		fmt.Print("\nPress Enter to return to Davoid...")
		bufio.NewReader(os.Stdin).ReadString('\n')
	}
	return nil
}

var version = "2.4.1" // overridden by -ldflags "-X main.version=..."

var rootCmd = &cobra.Command{
	Use:   "davoid",
	Short: "Ghost in the net — operator-grade red team engagement platform",
	Long: `
██████╗  █████╗ ██╗   ██╗ ██████╗ ██╗██████╗
██╔══██╗██╔══██╗██║   ██║██╔═══██╗██║██╔══██╗
██║  ██║███████║██║   ██║██║   ██║██║██║  ██║
██║  ██║██╔══██║╚██╗ ██╔╝██║   ██║██║██║  ██║
██████╔╝██║  ██║ ╚████╔╝ ╚██████╔╝██║██████╔╝
╚═════╝ ╚═╝  ╚═╝  ╚═══╝   ╚═════╝ ╚═╝╚═════╝

Davoid v` + version + ` — ghost in the net
Operator-grade red team engagement platform.

For authorized penetration testing and security research only.
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return launchTUI()
	},
}

var newCmd = &cobra.Command{
	Use:   "new <name>",
	Short: "Start a new engagement",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target, _ := cmd.Flags().GetString("target")
		scope, _ := cmd.Flags().GetString("scope")
		eng, err := engagement.Create(args[0], target, scope)
		if err != nil {
			return err
		}
		fmt.Printf("\n  ✓  Engagement created and set as active\n")
		fmt.Printf("     Name:   %s\n", eng.Name)
		fmt.Printf("     ID:     %s\n", eng.ID)
		if target != "" {
			fmt.Printf("     Target: %s\n", target)
		}
		if scope != "" {
			fmt.Printf("     Scope:  %s\n", scope)
		}
		fmt.Printf("\n  Run 'davoid' to open the TUI and start operating.\n\n")
		return nil
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all engagements",
	RunE: func(cmd *cobra.Command, args []string) error {
		engagements, err := engagement.All()
		if err != nil {
			return err
		}
		active, _ := engagement.Active()

		if len(engagements) == 0 {
			fmt.Println("\n  No engagements yet. Run 'davoid new <name>' to start one.")
			return nil
		}

		fmt.Println()
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(w, "  NAME\tTARGET\tSTATUS\tFINDINGS\tCREATED\tID")
		fmt.Fprintln(w, "  ────\t──────\t──────\t────────\t───────\t──")
		for _, eng := range engagements {
			marker := " "
			if active != nil && eng.ID == active.ID {
				marker = "★"
			}
			stats := engagement.FindingStats(eng.ID)
			total := stats["CRITICAL"] + stats["HIGH"] + stats["MEDIUM"] + stats["INFO"]
			fmt.Fprintf(w, "  %s %-28s\t%-18s\t%-8s\t%-8d\t%s\t%s\n",
				marker,
				truncate(eng.Name, 27),
				truncate(eng.Target, 17),
				eng.Status,
				total,
				eng.CreatedAt.Format("2006-01-02"),
				eng.ID[:8],
			)
		}
		w.Flush()
		fmt.Println()
		return nil
	},
}

var reportCmd = &cobra.Command{
	Use:   "report [engagement-id]",
	Short: "Generate a Markdown report for an engagement",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		useAI, _ := cmd.Flags().GetBool("ai")

		var engID string
		if len(args) > 0 {
			engID = args[0]
		} else {
			eng, err := engagement.Active()
			if err != nil || eng == nil {
				return fmt.Errorf("no active engagement — pass an ID or run 'davoid new <name>'")
			}
			engID = eng.ID
		}

		_, path, err := engagement.GenerateMarkdown(engID)
		if err != nil {
			return err
		}
		fmt.Printf("\n  ✓  Report saved to: %s\n", path)

		if useAI {
			fmt.Printf("\n  Generating AI executive summary via Ollama...\n")
			summary, err := generateAISummary(engID)
			if err != nil {
				fmt.Printf("  ⚠  AI summary failed: %v\n", err)
				fmt.Printf("     Make sure Ollama is running: ollama serve\n")
			} else {
				if err := engagement.PrependAISummary(path, summary); err != nil {
					fmt.Printf("  ⚠  Could not write AI summary: %v\n", err)
				} else {
					fmt.Printf("  ✓  AI executive summary added to report\n")
				}
			}
		}

		fmt.Printf("\n  Convert to PDF:  pandoc %s -o report.pdf\n\n", path)
		return nil
	},
}

var findingCmd = &cobra.Command{
	Use:   "finding",
	Short: "Log a finding to the active engagement",
	RunE: func(cmd *cobra.Command, args []string) error {
		title, _ := cmd.Flags().GetString("title")
		desc, _ := cmd.Flags().GetString("desc")
		sev, _ := cmd.Flags().GetString("severity")
		mod, _ := cmd.Flags().GetString("module")
		target, _ := cmd.Flags().GetString("target")
		evidence, _ := cmd.Flags().GetString("evidence")

		if title == "" {
			return fmt.Errorf("--title is required")
		}

		f, err := engagement.LogFinding("", mod, target, title, desc, sev, evidence)
		if err != nil {
			return err
		}
		fmt.Printf("\n  ✓  Finding logged: %s [%s]\n     ID: %s\n\n", f.Title, f.Severity, f.ID[:8])
		return nil
	},
}

var runCmd = &cobra.Command{
	Use:   "run <module>",
	Short: "Run a module directly (bypass TUI)",
	Long:  "Run any module by key without opening the TUI.\n\nExample: davoid run scanner",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		var keys []string
		for _, m := range runner.Registry {
			keys = append(keys, m.Key+"\t"+m.Name)
		}
		return keys, cobra.ShellCompDirectiveNoFileComp
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return runner.RunModule(args[0])
	},
}

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check required tool dependencies",
	Run: func(cmd *cobra.Command, args []string) {
		pm := auditor.DetectPkgMgr()
		pmLabel := string(pm)
		if pmLabel == "" {
			pmLabel = "unknown"
		}

		fmt.Println()
		fmt.Printf("  Davoid dependency check  (OS: %s  pkg manager: %s)\n", runtime.GOOS, pmLabel)
		fmt.Printf("  %s\n", strings.Repeat("─", 80))
		fmt.Printf("  %-20s  %-8s  %-30s  %s\n", "TOOL", "STATUS", "PURPOSE", "INSTALL COMMAND")
		fmt.Printf("  %s\n", strings.Repeat("─", 80))

		ok, missing := 0, 0
		for _, d := range auditor.AllDeps() {
			if d.LinuxOnly && runtime.GOOS != "linux" {
				continue
			}
			_, err := exec.LookPath(d.Cmd)
			status := "\033[32m✓ found  \033[0m"
			install := ""
			if err != nil {
				status = "\033[31m✗ missing\033[0m"
				install = auditor.InstallCmd(d, pm)
				missing++
			} else {
				ok++
			}
			fmt.Printf("  %-20s  %s  %-30s  %s\n", d.Name, status, truncate(d.Purpose, 28), install)
		}

		fmt.Println()
		fmt.Printf("  %d/%d tools available", ok, ok+missing)
		if missing > 0 {
			fmt.Printf("  —  %d missing\n", missing)
			if runtime.GOOS == "darwin" {
				fmt.Printf("  Note: WiFi attack tools (aircrack-ng suite, hostapd) require Linux.\n")
			}
		} else {
			fmt.Printf("  — all good\n")
		}
		fmt.Println()
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("davoid v%s\n", version)
	},
}

var modulesCmd = &cobra.Command{
	Use:   "modules",
	Short: "List all available modules",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println()
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(w, "  MODULE\tCATEGORY\tDESCRIPTION")
		fmt.Fprintln(w, "  ──────\t────────\t───────────")
		for _, mod := range runner.Registry {
			fmt.Fprintf(w, "  %-20s\t%-25s\t%s\n",
				mod.Name, mod.Category, truncate(mod.Description, 55))
		}
		w.Flush()
		fmt.Println()
	},
}

// ── Loot Exporter ────────────────────────────────────────────────────────────

var lootCmd = &cobra.Command{
	Use:   "loot",
	Short: "Dump all harvested loot for the active engagement",
	RunE: func(cmd *cobra.Command, args []string) error {
		reveal, _ := cmd.Flags().GetBool("reveal")
		asJSON, _ := cmd.Flags().GetBool("json")

		eng, _ := engagement.Active()
		if eng == nil {
			// fallback: pick most recent active engagement
			all, err := engagement.All()
			if err != nil || len(all) == 0 {
				return fmt.Errorf("no active engagement — run 'davoid new <name>' first")
			}
			for _, e := range all {
				if e.Status == "active" {
					eng = e
					break
				}
			}
			if eng == nil {
				eng = all[0]
			}
		}

		creds, _ := vault.List(eng.ID)
		hosts, _ := targets.List(eng.ID)
		findings, _ := engagement.Findings(eng.ID)

		if asJSON {
			return printLootJSON(eng, creds, hosts, findings, reveal)
		}
		return printLootTable(eng, creds, hosts, findings, reveal)
	},
}

func printLootTable(eng *engagement.Engagement, creds []*vault.Credential, hosts []*targets.Host, findings []*engagement.Finding, reveal bool) error {
	div := strings.Repeat("─", 70)
	fmt.Println()
	fmt.Printf("  DAVOID LOOT — %s\n", eng.Name)
	if eng.Target != "" {
		fmt.Printf("  Target: %s\n", eng.Target)
	}
	fmt.Printf("  Generated: %s\n", time.Now().Format("2006-01-02 15:04"))
	fmt.Println()

	// Credentials
	fmt.Printf("  CREDENTIALS (%d captured)\n", len(creds))
	fmt.Printf("  %s\n", div)
	if len(creds) == 0 {
		fmt.Println("  none")
	} else {
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(w, "  SOURCE\tHOST\tUSERNAME\tSECRET\tKIND")
		for _, c := range creds {
			secret := strings.Repeat("•", 8)
			if reveal {
				secret = c.Secret
			}
			fmt.Fprintf(w, "  %-12s\t%-18s\t%-20s\t%-20s\t%s\n",
				truncate(c.Source, 10),
				truncate(c.Host, 16),
				c.Username,
				secret,
				c.Kind,
			)
		}
		w.Flush()
	}
	fmt.Println()

	// Hosts
	fmt.Printf("  HOSTS (%d discovered)\n", len(hosts))
	fmt.Printf("  %s\n", div)
	if len(hosts) == 0 {
		fmt.Println("  none")
	} else {
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(w, "  IP\tHOSTNAME\tOS\tPORTS")
		for _, h := range hosts {
			ports := strings.Join(h.Ports, ",")
			if len(ports) > 40 {
				ports = ports[:37] + "..."
			}
			fmt.Fprintf(w, "  %-16s\t%-20s\t%-16s\t%s\n",
				h.IP, h.Hostname, h.OS, ports)
		}
		w.Flush()
	}
	fmt.Println()

	// Findings
	fmt.Printf("  FINDINGS (%d total)\n", len(findings))
	fmt.Printf("  %s\n", div)
	if len(findings) == 0 {
		fmt.Println("  none")
	} else {
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		for _, f := range findings {
			fmt.Fprintf(w, "  %-8s\t%-15s\t%s\n",
				f.Severity, truncate(f.Module, 14), truncate(f.Title, 55))
		}
		w.Flush()
	}
	fmt.Println()

	if !reveal && len(creds) > 0 {
		fmt.Println("  Secrets masked — run with --reveal to show plaintext")
		fmt.Println()
	}
	return nil
}

type lootJSON struct {
	Engagement  lootEngJSON    `json:"engagement"`
	Credentials []lootCredJSON `json:"credentials"`
	Hosts       []lootHostJSON `json:"hosts"`
	Findings    []lootFindJSON `json:"findings"`
}
type lootEngJSON struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Target string `json:"target"`
	Scope  string `json:"scope"`
}
type lootCredJSON struct {
	Source   string `json:"source"`
	Host     string `json:"host"`
	Username string `json:"username"`
	Secret   string `json:"secret,omitempty"`
	Kind     string `json:"kind"`
}
type lootHostJSON struct {
	IP       string   `json:"ip"`
	Hostname string   `json:"hostname"`
	OS       string   `json:"os"`
	Ports    []string `json:"ports"`
}
type lootFindJSON struct {
	Severity string `json:"severity"`
	Module   string `json:"module"`
	Target   string `json:"target"`
	Title    string `json:"title"`
}

func printLootJSON(eng *engagement.Engagement, creds []*vault.Credential, hosts []*targets.Host, findings []*engagement.Finding, reveal bool) error {
	out := lootJSON{
		Engagement: lootEngJSON{ID: eng.ID, Name: eng.Name, Target: eng.Target, Scope: eng.Scope},
	}
	for _, c := range creds {
		secret := ""
		if reveal {
			secret = c.Secret
		}
		out.Credentials = append(out.Credentials, lootCredJSON{
			Source: c.Source, Host: c.Host, Username: c.Username, Secret: secret, Kind: c.Kind,
		})
	}
	for _, h := range hosts {
		out.Hosts = append(out.Hosts, lootHostJSON{IP: h.IP, Hostname: h.Hostname, OS: h.OS, Ports: h.Ports})
	}
	for _, f := range findings {
		out.Findings = append(out.Findings, lootFindJSON{Severity: f.Severity, Module: f.Module, Target: f.Target, Title: f.Title})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// ── Playbook commands ─────────────────────────────────────────────────────────

var playbookCmd = &cobra.Command{
	Use:   "playbook",
	Short: "Run pre-built attack chain playbooks",
}

var playbookListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all available playbooks (built-in and custom YAML)",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println()
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(w, "  KEY\tNAME\tCATEGORY\tDESCRIPTION")
		fmt.Fprintln(w, "  ───\t────\t────────\t───────────")
		for _, pb := range playbook.Registry {
			fmt.Fprintf(w, "  %-22s\t%-22s\t%-18s\t%s\n",
				pb.Key, pb.Name, pb.Category, truncate(pb.Description, 55))
		}
		// Custom YAML playbooks from ~/.davoid/playbooks/
		customs := playbook.ListCustom()
		if len(customs) > 0 {
			fmt.Fprintln(w, "  ───\t────\t────────\t───────────")
			for _, pb := range customs {
				fmt.Fprintf(w, "  %-22s\t%-22s\t%-18s\t%s\n",
					pb.Key, pb.Name, pb.Category, truncate(pb.Description, 55))
			}
		}
		w.Flush()
		fmt.Println()
		fmt.Printf("  Custom playbooks: ~/.davoid/playbooks/<name>.yaml\n\n")
	},
}

var playbookRunCmd = &cobra.Command{
	Use:   "run <playbook-key>",
	Short: "Run an attack chain playbook",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		var keys []string
		for _, pb := range playbook.Registry {
			keys = append(keys, pb.Key+"\t"+pb.Name)
		}
		return keys, cobra.ShellCompDirectiveNoFileComp
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return playbook.Run(args[0])
	},
}

// ── Config command ────────────────────────────────────────────────────────────

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage Davoid operator configuration",
}

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a configuration value",
	Long: `Set a configuration value by key.

Available keys:
  webhook.url     Webhook URL for notifications (Discord, Slack, or ntfy.sh)
  webhook.events  Comma-separated events: shell_connect,creds_captured,finding_critical,handshake_captured,hash_cracked

Examples:
  davoid config set webhook.url https://discord.com/api/webhooks/...
  davoid config set webhook.events shell_connect,creds_captured
  davoid config set webhook.events ""    # clear events filter (all events)`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.Set(args[0], args[1]); err != nil {
			return err
		}
		fmt.Printf("\n  ✓  %s = %s\n\n", args[0], args[1])
		return nil
	},
}

var configGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Get a configuration value",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		val, err := config.Get(args[0])
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", val)
		return nil
	},
}

var configListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all configuration values",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println()
		for _, line := range config.All() {
			fmt.Printf("  %s\n", line)
		}
		fmt.Println()
	},
}

// ── OPSEC command ─────────────────────────────────────────────────────────────

var opsecCmd = &cobra.Command{
	Use:   "opsec",
	Short: "Show OPSEC noise score for the active engagement",
	RunE: func(cmd *cobra.Command, args []string) error {
		eng, err := engagement.Active()
		if err != nil || eng == nil {
			return fmt.Errorf("no active engagement — run 'davoid new <name>' first")
		}

		findings, err := engagement.Findings(eng.ID)
		if err != nil {
			return err
		}

		seen := map[string]bool{}
		var moduleKeys []string
		for _, f := range findings {
			if f.Module != "" && !seen[f.Module] {
				seen[f.Module] = true
				moduleKeys = append(moduleKeys, f.Module)
			}
		}

		score, label, breakdown := opsec.Score(moduleKeys)
		color := opsec.LabelColor(label)
		reset := "\033[0m"

		fmt.Println()
		fmt.Printf("  OPSEC Score — %s\n", eng.Name)
		fmt.Printf("  %s\n", strings.Repeat("─", 65))
		fmt.Printf("  Overall: %s%s%s  %s\n", color, opsec.ScoreBar(score), reset, color+label+reset)
		fmt.Println()

		if len(breakdown) == 0 {
			fmt.Println("  No modules run yet.")
		} else {
			fmt.Printf("  %-22s  %-8s  %s\n", "MODULE", "NOISE", "REASON")
			fmt.Printf("  %s\n", strings.Repeat("─", 65))
			for _, op := range breakdown {
				icon := opsec.NoiseIcon(op.Level)
				fmt.Printf("  %s %-20s  %-8s  %s\n",
					icon, op.ModuleKey, op.Level.String(), truncate(op.Reason, 38))
			}
		}
		fmt.Println()
		return nil
	},
}

// ── Checklist command ─────────────────────────────────────────────────────────

// checklistPhase maps PTES phases to module keys.
type checklistPhase struct {
	Name    string
	Modules []string
}

var phaseDefs = []checklistPhase{
	{
		Name:    "Intelligence Gathering",
		Modules: []string{"osint", "scanner", "web_recon", "cloud_ops"},
	},
	{
		Name:    "Threat Modeling / Vuln Analysis",
		Modules: []string{"scanner", "ad_ops", "msf_engine"},
	},
	{
		Name:    "Exploitation",
		Modules: []string{"payloads", "crypt_keeper", "msf_engine", "phishing", "catcher"},
	},
	{
		Name:    "Post-Exploitation",
		Modules: []string{"looter", "persistence", "cred_tester", "ghost_hub"},
	},
	{
		Name:    "Network / MITM",
		Modules: []string{"mitm", "sniff", "bruteforce"},
	},
	{
		Name:    "Lateral Movement / AD",
		Modules: []string{"ad_ops", "cred_tester", "bruteforce"},
	},
	{
		Name:    "Reporting",
		Modules: []string{"purple_team"},
	},
}

var checklistCmd = &cobra.Command{
	Use:   "checklist",
	Short: "Show methodology checklist for the active engagement (PTES phases)",
	RunE: func(cmd *cobra.Command, args []string) error {
		eng, err := engagement.Active()
		if err != nil || eng == nil {
			return fmt.Errorf("no active engagement — run 'davoid new <name>' first")
		}

		findings, _ := engagement.Findings(eng.ID)
		used := map[string]bool{}
		for _, f := range findings {
			if f.Module != "" {
				used[f.Module] = true
			}
		}

		fmt.Println()
		fmt.Printf("  Methodology Checklist — %s\n", eng.Name)
		fmt.Printf("  %s\n\n", strings.Repeat("─", 65))

		totalModules := 0
		totalDone := 0

		for _, phase := range phaseDefs {
			done := 0
			for _, m := range phase.Modules {
				if used[m] {
					done++
				}
			}
			totalModules += len(phase.Modules)
			totalDone += done

			pct := done * 100 / len(phase.Modules)
			bar := progressBar(pct, 12)

			fmt.Printf("  Phase: %s\n", phase.Name)
			fmt.Printf("  %s  %d/%d\n", bar, done, len(phase.Modules))
			for _, m := range phase.Modules {
				icon := "✗"
				color := "\033[31m"
				if used[m] {
					icon = "✓"
					color = "\033[32m"
				}
				fmt.Printf("    %s%s %-20s\033[0m\n", color, icon, m)
			}
			fmt.Println()
		}

		totalPct := 0
		if totalModules > 0 {
			totalPct = totalDone * 100 / totalModules
		}
		fmt.Printf("  Coverage: %d%%  (%d/%d modules executed)\n", totalPct, totalDone, totalModules)
		if totalPct < 50 {
			fmt.Printf("  Run 'davoid modules' to see all available modules.\n")
		}
		fmt.Println()
		return nil
	},
}

func progressBar(pct, width int) string {
	filled := pct * width / 100
	bar := ""
	for i := 0; i < width; i++ {
		if i < filled {
			bar += "█"
		} else {
			bar += "░"
		}
	}
	return "[" + bar + "]"
}

// ── Attack graph command ──────────────────────────────────────────────────────

var graphCmd = &cobra.Command{
	Use:   "graph",
	Short: "Render ASCII attack graph for the active engagement",
	RunE: func(cmd *cobra.Command, args []string) error {
		eng, err := engagement.Active()
		if err != nil || eng == nil {
			return fmt.Errorf("no active engagement — run 'davoid new <name>' first")
		}

		findings, _ := engagement.Findings(eng.ID)
		hosts, _ := targets.List(eng.ID)
		creds, _ := vault.List(eng.ID)

		fmt.Println()
		fmt.Printf("  ATTACK GRAPH — %s\n", eng.Name)
		if eng.Target != "" {
			fmt.Printf("  Target scope: %s\n", eng.Target)
		}
		fmt.Printf("  %s\n\n", strings.Repeat("─", 65))

		if len(hosts) == 0 && len(findings) == 0 {
			fmt.Println("  No data yet. Run some modules first.")
			fmt.Println()
			return nil
		}

		// Root node
		scopeLabel := eng.Target
		if scopeLabel == "" {
			scopeLabel = "Target Scope"
		}
		fmt.Printf("  [%s]\n", scopeLabel)

		// Group findings by module
		byModule := map[string][]*engagement.Finding{}
		for _, f := range findings {
			byModule[f.Module] = append(byModule[f.Module], f)
		}

		modKeys := make([]string, 0)
		seenMods := map[string]bool{}
		for _, f := range findings {
			if !seenMods[f.Module] {
				seenMods[f.Module] = true
				modKeys = append(modKeys, f.Module)
			}
		}

		for mi, mod := range modKeys {
			connector := "├──"
			if mi == len(modKeys)-1 && len(hosts) == 0 {
				connector = "└──"
			}

			modName := mod
			for _, m := range runner.Registry {
				if m.Key == mod {
					modName = m.Name
					break
				}
			}
			fmt.Printf("  │\n  %s [%s]\n", connector, modName)

			modFindings := byModule[mod]
			for fi, f := range modFindings {
				fc := "│   ├──"
				if fi == len(modFindings)-1 {
					fc = "│   └──"
				}
				sev := f.Severity
				sevColor := ""
				switch sev {
				case "CRITICAL":
					sevColor = "\033[35m"
				case "HIGH":
					sevColor = "\033[31m"
				case "MEDIUM":
					sevColor = "\033[33m"
				default:
					sevColor = "\033[34m"
				}
				fmt.Printf("  %s %s[%s]\033[0m %s\n", fc, sevColor, sev, truncate(f.Title, 45))
				if f.Target != "" {
					fmt.Printf("  │       → %s\n", f.Target)
				}
			}
		}

		// Hosts section
		if len(hosts) > 0 {
			fmt.Printf("  │\n  └── [Discovered Hosts]\n")
			for hi, h := range hosts {
				hc := "      ├──"
				if hi == len(hosts)-1 {
					hc = "      └──"
				}
				label := h.IP
				if h.Hostname != "" {
					label = h.IP + " / " + h.Hostname
				}
				if h.OS != "" {
					label += " (" + h.OS + ")"
				}
				fmt.Printf("  %s %s\n", hc, label)
				if len(h.Ports) > 0 && h.Ports[0] != "" {
					ports := h.Ports
					if len(ports) > 5 {
						ports = append(ports[:5], fmt.Sprintf("+%d", len(h.Ports)-5))
					}
					fmt.Printf("           ports: %s\n", strings.Join(ports, ", "))
				}
			}
		}

		// Credentials summary
		if len(creds) > 0 {
			fmt.Printf("\n  Captured Credentials: %d\n", len(creds))
			for _, c := range creds {
				fmt.Printf("  ● %s @ %s  [%s]\n", c.Username, c.Host, c.Kind)
			}
		}

		fmt.Println()
		return nil
	},
}

// ── Finding templates command ─────────────────────────────────────────────────

var templateCmd = &cobra.Command{
	Use:   "template",
	Short: "Manage and apply finding templates with CVSS scoring",
}

var templateListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all available finding templates",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println()
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(w, "  KEY\tNAME\tSEVERITY\tCVSS")
		fmt.Fprintln(w, "  ───\t────\t────────\t────")
		for _, t := range templates.Registry {
			score := cvss.Calculate(t.CVSS)
			fmt.Fprintf(w, "  %-20s\t%-30s\t%-10s\t%.1f\n",
				t.Key, t.Name, t.Severity, score)
		}
		w.Flush()
		fmt.Println()
	},
}

var templateShowCmd = &cobra.Command{
	Use:   "show <key>",
	Short: "Show a finding template",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return templates.Keys(), cobra.ShellCompDirectiveNoFileComp
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		t := templates.Get(args[0])
		if t == nil {
			return fmt.Errorf("template not found: %s\n\nRun 'davoid template list' to see all templates.", args[0])
		}
		target, _ := cmd.Flags().GetString("target")
		fmt.Print(templates.Render(t, target))
		return nil
	},
}

var templateApplyCmd = &cobra.Command{
	Use:   "apply <key>",
	Short: "Apply a template as a finding in the active engagement",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return templates.Keys(), cobra.ShellCompDirectiveNoFileComp
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		t := templates.Get(args[0])
		if t == nil {
			return fmt.Errorf("template not found: %s", args[0])
		}
		target, _ := cmd.Flags().GetString("target")
		mod, _ := cmd.Flags().GetString("module")
		evidence, _ := cmd.Flags().GetString("evidence")

		title := strings.ReplaceAll(t.Title, "[TARGET]", target)
		title = strings.ReplaceAll(title, "[PARAMETER]", "[parameter]")

		score := cvss.Calculate(t.CVSS)
		sev := cvss.Severity(score)

		f, err := engagement.LogFinding("", mod, target, title, t.Description, sev, evidence)
		if err != nil {
			return err
		}
		fmt.Printf("\n  ✓  Finding logged: %s\n", f.Title)
		fmt.Printf("     Severity: %s  |  CVSS: %.1f  |  ID: %s\n\n", sev, score, f.ID[:8])
		return nil
	},
}

// ── Engagement snapshot export / import ───────────────────────────────────────

var exportCmd = &cobra.Command{
	Use:   "export [engagement-id]",
	Short: "Export an engagement snapshot to a portable file",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		out, _ := cmd.Flags().GetString("out")
		password, _ := cmd.Flags().GetString("password")

		var engID string
		if len(args) > 0 {
			engID = args[0]
		} else {
			eng, err := engagement.Active()
			if err != nil || eng == nil {
				return fmt.Errorf("no active engagement — pass an ID or run 'davoid new <name>'")
			}
			engID = eng.ID
		}

		if out == "" {
			out = "davoid-" + engID[:8] + ".snap"
		}

		if err := snapshot.Export(engID, out, password); err != nil {
			return err
		}

		if password != "" {
			fmt.Printf("\n  ✓  Snapshot exported (AES-256 encrypted): %s\n", out)
		} else {
			fmt.Printf("\n  ✓  Snapshot exported: %s\n", out)
			fmt.Printf("  Tip: use --password to encrypt the archive.\n")
		}
		fmt.Printf("  Share with: davoid import %s\n\n", out)
		return nil
	},
}

var importCmd = &cobra.Command{
	Use:   "import <file>",
	Short: "Import an engagement snapshot",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		password, _ := cmd.Flags().GetString("password")

		eng, err := snapshot.Import(args[0], password)
		if err != nil {
			return err
		}

		fmt.Printf("\n  ✓  Snapshot imported\n")
		fmt.Printf("     Name:   %s\n", eng.Name)
		fmt.Printf("     ID:     %s\n", eng.ID)
		if eng.Target != "" {
			fmt.Printf("     Target: %s\n", eng.Target)
		}
		fmt.Printf("\n  Run 'davoid list' to see all engagements.\n\n")
		return nil
	},
}

// ── AI executive summary ──────────────────────────────────────────────────────

type ollamaReq struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type ollamaResp struct {
	Response string `json:"response"`
}

func generateAISummary(engID string) (string, error) {
	eng, _ := engagement.GetByID(engID)
	findings, _ := engagement.Findings(engID)
	stats := engagement.FindingStats(engID)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("You are a professional penetration tester writing an executive summary for a red team engagement report.\n\n"))
	sb.WriteString(fmt.Sprintf("Engagement: %s\n", eng.Name))
	if eng.Target != "" {
		sb.WriteString(fmt.Sprintf("Target: %s\n", eng.Target))
	}
	sb.WriteString(fmt.Sprintf("Findings: %d Critical, %d High, %d Medium, %d Info\n\n",
		stats["CRITICAL"], stats["HIGH"], stats["MEDIUM"], stats["INFO"]))
	sb.WriteString("Key findings:\n")
	for i, f := range findings {
		if i >= 10 {
			sb.WriteString(fmt.Sprintf("... and %d more findings\n", len(findings)-10))
			break
		}
		sb.WriteString(fmt.Sprintf("- [%s] %s (%s)\n", f.Severity, f.Title, f.Module))
		if f.Description != "" {
			sb.WriteString(fmt.Sprintf("  %s\n", truncate(f.Description, 120)))
		}
	}
	sb.WriteString("\nWrite a 3-4 paragraph professional executive summary suitable for a C-level audience. ")
	sb.WriteString("Include: overall risk posture, most critical issues, business impact, and top 3-5 remediation priorities. ")
	sb.WriteString("Do not use bullet points — write in flowing professional prose. Do not include any preamble or meta-commentary.")

	prompt := sb.String()

	// Try to get available models from Ollama
	model, err := pickOllamaModel()
	if err != nil {
		return "", fmt.Errorf("Ollama not available: %w", err)
	}

	reqBody, _ := json.Marshal(ollamaReq{Model: model, Prompt: prompt, Stream: false})
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Post("http://localhost:11434/api/generate", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("Ollama request failed: %w", err)
	}
	defer resp.Body.Close()

	var result ollamaResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("Ollama response parse failed: %w", err)
	}
	return strings.TrimSpace(result.Response), nil
}

func pickOllamaModel() (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://localhost:11434/api/tags")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var data struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil || len(data.Models) == 0 {
		return "llama3", nil // fallback
	}
	return data.Models[0].Name, nil
}

// ── Init / main ───────────────────────────────────────────────────────────────

func init() {
	newCmd.Flags().String("target", "", "Target IP, CIDR, or domain")
	newCmd.Flags().String("scope", "", "Engagement scope description")

	findingCmd.Flags().String("title", "", "Finding title (required)")
	findingCmd.Flags().String("desc", "", "Finding description")
	findingCmd.Flags().String("severity", "INFO", "Severity: CRITICAL, HIGH, MEDIUM, INFO")
	findingCmd.Flags().String("module", "", "Module that discovered the finding")
	findingCmd.Flags().String("target", "", "Affected target")
	findingCmd.Flags().String("evidence", "", "Supporting evidence")

	reportCmd.Flags().Bool("ai", false, "Generate AI executive summary using Ollama")

	lootCmd.Flags().Bool("reveal", false, "Show plaintext secrets (default: masked)")
	lootCmd.Flags().Bool("json", false, "Output as JSON")

	// Template sub-commands
	templateShowCmd.Flags().String("target", "", "Target to substitute in template title")
	templateApplyCmd.Flags().String("target", "", "Affected target")
	templateApplyCmd.Flags().String("module", "", "Module that discovered the finding")
	templateApplyCmd.Flags().String("evidence", "", "Supporting evidence")
	templateCmd.AddCommand(templateListCmd, templateShowCmd, templateApplyCmd)

	// Config sub-commands
	configCmd.AddCommand(configSetCmd, configGetCmd, configListCmd)

	// Playbook sub-commands
	playbookCmd.AddCommand(playbookListCmd, playbookRunCmd)

	// Export / import flags
	exportCmd.Flags().String("out", "", "Output file path (default: davoid-<id>.snap)")
	exportCmd.Flags().String("password", "", "Encrypt snapshot with AES-256 password")
	importCmd.Flags().String("password", "", "Decryption password (if snapshot was encrypted)")

	rootCmd.AddCommand(
		newCmd, listCmd, reportCmd, findingCmd,
		versionCmd, modulesCmd, runCmd, doctorCmd,
		lootCmd, playbookCmd,
		// New commands
		configCmd,
		opsecCmd,
		checklistCmd,
		graphCmd,
		templateCmd,
		exportCmd,
		importCmd,
	)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
