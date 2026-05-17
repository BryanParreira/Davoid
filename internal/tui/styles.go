package tui

import "github.com/charmbracelet/lipgloss"

// Davoid color palette — ghost-in-the-net identity
var (
	colorBG       = lipgloss.Color("#0d0d0d")
	colorCyan     = lipgloss.Color("#00e5ff")
	colorDimCyan  = lipgloss.Color("#007a8a")
	colorRed      = lipgloss.Color("#ff3d3d")
	colorOrange   = lipgloss.Color("#ff8c00")
	colorGreen    = lipgloss.Color("#39ff14")
	colorGray     = lipgloss.Color("#444444")
	colorLightGray = lipgloss.Color("#888888")
	colorWhite    = lipgloss.Color("#e0e0e0")
	colorPurple   = lipgloss.Color("#b469ff")
)

var (
	StyleBanner = lipgloss.NewStyle().
		Foreground(colorCyan).
		Bold(true)

	StyleSubtitle = lipgloss.NewStyle().
		Foreground(colorDimCyan).
		Italic(true)

	StyleBorder = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorDimCyan).
		Padding(0, 1)

	StyleMenuTitle = lipgloss.NewStyle().
		Foreground(colorCyan).
		Bold(true).
		Underline(true)

	StyleMenuKey = lipgloss.NewStyle().
		Foreground(colorCyan).
		Bold(true)

	StyleMenuItem = lipgloss.NewStyle().
		Foreground(colorWhite)

	StyleMenuItemSelected = lipgloss.NewStyle().
		Foreground(colorBG).
		Background(colorCyan).
		Bold(true).
		Padding(0, 1)

	StyleMenuItemDisabled = lipgloss.NewStyle().
		Foreground(colorGray)

	StyleSectionHeader = lipgloss.NewStyle().
		Foreground(colorPurple).
		Bold(true)

	StyleLabel = lipgloss.NewStyle().
		Foreground(colorLightGray)

	StyleValue = lipgloss.NewStyle().
		Foreground(colorWhite)

	StyleEngagementActive = lipgloss.NewStyle().
		Foreground(colorGreen).
		Bold(true)

	StyleEngagementNone = lipgloss.NewStyle().
		Foreground(colorGray).
		Italic(true)

	StyleFindingCritical = lipgloss.NewStyle().
		Foreground(colorRed).
		Bold(true)

	StyleFindingHigh = lipgloss.NewStyle().
		Foreground(colorOrange).
		Bold(true)

	StyleFindingInfo = lipgloss.NewStyle().
		Foreground(colorLightGray)

	StyleSuccess = lipgloss.NewStyle().
		Foreground(colorGreen).
		Bold(true)

	StyleError = lipgloss.NewStyle().
		Foreground(colorRed).
		Bold(true)

	StyleWarning = lipgloss.NewStyle().
		Foreground(colorOrange)

	StylePrompt = lipgloss.NewStyle().
		Foreground(colorCyan).
		Bold(true)

	StyleInput = lipgloss.NewStyle().
		Foreground(colorWhite).
		Border(lipgloss.NormalBorder(), false, false, true, false).
		BorderForeground(colorDimCyan).
		Padding(0, 1)

	StyleStatusBar = lipgloss.NewStyle().
		Foreground(colorLightGray).
		Background(lipgloss.Color("#111111")).
		Padding(0, 1)

	StyleHelp = lipgloss.NewStyle().
		Foreground(colorGray).
		Italic(true)

	StyleTable = lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(colorGray)

	StyleTableHeader = lipgloss.NewStyle().
		Foreground(colorCyan).
		Bold(true)

	StyleTableRow = lipgloss.NewStyle().
		Foreground(colorWhite)

	StyleTableRowAlt = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#cccccc"))

	StyleDivider = lipgloss.NewStyle().
		Foreground(colorGray)

	StyleVersion = lipgloss.NewStyle().
		Foreground(colorDimCyan)
)

func SeverityStyle(severity string) lipgloss.Style {
	switch severity {
	case "CRITICAL":
		return StyleFindingCritical
	case "HIGH":
		return StyleFindingHigh
	case "MEDIUM":
		return StyleWarning
	default:
		return StyleFindingInfo
	}
}
