package main

import (
	"bufio"
	"fmt"
	"os"
	"text/tabwriter"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/runner"
	"github.com/bryanparreira/davoid/internal/tui"
)

func launchTUI() error {
	for {
		m := tui.NewModel()
		p := tea.NewProgram(m, tea.WithAltScreen())
		finalModel, err := p.Run()
		if err != nil {
			return err
		}
		pending := finalModel.(tui.Model).PendingModule()
		if pending == "" {
			break
		}
		if err := runner.RunModule(pending); err != nil {
			fmt.Fprintf(os.Stderr, "\n[!] Module error: %v\n", err)
		}
		fmt.Print("\nPress Enter to return to Davoid...")
		bufio.NewReader(os.Stdin).ReadString('\n')
	}
	return nil
}

const version = "2.0.0"

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
		fmt.Printf("\n  ✓  Report saved to: %s\n\n", path)
		fmt.Printf("  Convert to PDF:  pandoc %s -o report.pdf\n\n", path)
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

func init() {
	newCmd.Flags().String("target", "", "Target IP, CIDR, or domain")
	newCmd.Flags().String("scope", "", "Engagement scope description")

	findingCmd.Flags().String("title", "", "Finding title (required)")
	findingCmd.Flags().String("desc", "", "Finding description")
	findingCmd.Flags().String("severity", "INFO", "Severity: CRITICAL, HIGH, MEDIUM, INFO")
	findingCmd.Flags().String("module", "", "Module that discovered the finding")
	findingCmd.Flags().String("target", "", "Affected target")
	findingCmd.Flags().String("evidence", "", "Supporting evidence")

	rootCmd.AddCommand(newCmd, listCmd, reportCmd, findingCmd, versionCmd, modulesCmd)
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
