package tui

import "github.com/charmbracelet/lipgloss"

var (
	surfaceGraphite = lipgloss.Color("#1A1B26")
	surfaceAlt      = lipgloss.Color("#24283B")
	surfaceBorder   = lipgloss.Color("#2F3346")

	textPrimary = lipgloss.Color("#C0CAF5")
	textMuted   = lipgloss.Color("#565F89")
	textDim     = lipgloss.Color("#3B4261")

	accentCyan  = lipgloss.Color("#7DCFFF")
	accentAmber = lipgloss.Color("#FFB347")
	accentCoral = lipgloss.Color("#F7768E")
	accentGreen = lipgloss.Color("#9ECE6A")

	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(surfaceBorder).
			Padding(0, 1)

	labelStyle = lipgloss.NewStyle().
			Foreground(textMuted).
			Width(10)

	valueStyle = lipgloss.NewStyle().
			Foreground(textPrimary)

	titleStyle = lipgloss.NewStyle().
			Foreground(accentCyan).
			Bold(true)

	mutedStyle = lipgloss.NewStyle().
			Foreground(textMuted)

	dimStyle = lipgloss.NewStyle().
			Foreground(textDim)

	progressFull = lipgloss.NewStyle().
			Foreground(accentCyan)

	progressEmpty = lipgloss.NewStyle().
			Foreground(surfaceBorder)
)

func severityColor(severity string) lipgloss.Color {
	switch severity {
	case "critical", "high":
		return accentCoral
	case "medium":
		return accentAmber
	case "low":
		return accentCyan
	default:
		return textMuted
	}
}
