package ui

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	Cyan   = lipgloss.NewStyle().Foreground(lipgloss.Color("#00d7ff")).Bold(true)
	Green  = lipgloss.NewStyle().Foreground(lipgloss.Color("#00ff87")).Bold(true)
	Red    = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff5f5f")).Bold(true)
	Yellow = lipgloss.NewStyle().Foreground(lipgloss.Color("#ffd700")).Bold(true)
	Dim    = lipgloss.NewStyle().Faint(true)
	Bold   = lipgloss.NewStyle().Bold(true)
	White  = lipgloss.NewStyle().Foreground(lipgloss.Color("#ffffff"))
)

var reader = bufio.NewReader(os.Stdin)

func Header(title string) {
	bar := strings.Repeat("═", len(title)+6)
	fmt.Println()
	fmt.Println(Cyan.Render("╔" + bar + "╗"))
	fmt.Println(Cyan.Render("║") + "   " + Bold.Render(title) + "   " + Cyan.Render("║"))
	fmt.Println(Cyan.Render("╚" + bar + "╝"))
	fmt.Println()
}

func Prompt(label string) string {
	fmt.Print(Cyan.Render("  » ") + label + ": ")
	s, _ := reader.ReadString('\n')
	return strings.TrimSpace(s)
}

func PromptDefault(label, def string) string {
	fmt.Printf(Cyan.Render("  » ")+"%s [%s]: ", label, Dim.Render(def))
	s, _ := reader.ReadString('\n')
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	return s
}

// Select shows a numbered menu and returns the 0-based index, or -1 for back/quit.
func Select(label string, options []string) int {
	fmt.Println()
	fmt.Println(Bold.Render("  " + label))
	for i, opt := range options {
		fmt.Printf("  %s  %s\n", Cyan.Render(fmt.Sprintf("[%d]", i+1)), opt)
	}
	fmt.Println(Dim.Render("  [0] Back"))
	for {
		choice := Prompt("Select")
		var idx int
		if _, err := fmt.Sscanf(choice, "%d", &idx); err == nil {
			if idx == 0 {
				return -1
			}
			if idx >= 1 && idx <= len(options) {
				return idx - 1
			}
		}
		fmt.Println(Red.Render("  Invalid choice."))
	}
}

func Confirm(label string) bool {
	for {
		s := Prompt(label + " [y/N]")
		switch strings.ToLower(s) {
		case "y", "yes":
			return true
		case "n", "no", "":
			return false
		}
	}
}

func Success(msg string) { fmt.Println(Green.Render("  ✓ " + msg)) }
func Fail(msg string)    { fmt.Println(Red.Render("  ✗ " + msg)) }
func Info(msg string)    { fmt.Println(Cyan.Render("  ℹ ") + msg) }
func Warn(msg string)    { fmt.Println(Yellow.Render("  ⚠ " + msg)) }

func Divider() {
	fmt.Println(Dim.Render("  " + strings.Repeat("─", 60)))
}

func PressEnter() {
	fmt.Print(Dim.Render("\n  Press Enter to continue..."))
	reader.ReadString('\n')
}
