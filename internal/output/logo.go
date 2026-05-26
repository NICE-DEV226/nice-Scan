package output

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	logoAccent = lipgloss.Color("#7DCFFF")
	logoMuted  = lipgloss.Color("#565F89")
	logoDim    = lipgloss.Color("#3B4261")
	logoBorder = lipgloss.Color("#2F3346")
)

func RenderLogoCompact() string {
	top := lipgloss.NewStyle().
		Foreground(logoAccent).
		Bold(true).
		Render("  NICE_SCAN")

	version := lipgloss.NewStyle().
		Foreground(logoMuted).
		Render("v0.1.0")

	tagline := lipgloss.NewStyle().
		Foreground(logoMuted).
		Render("  Fast. Precise. Intelligent.")

	header := lipgloss.JoinHorizontal(lipgloss.Left,
		top,
		lipgloss.NewStyle().Width(2).Render(""),
		version,
	)

	block := lipgloss.JoinVertical(lipgloss.Left,
		header,
		tagline,
	)

	panel := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(logoBorder).
		Padding(0, 2).
		Render(block)

	return panel
}

func RenderLogoOneLine() string {
	return lipgloss.NewStyle().
		Foreground(logoAccent).
		Bold(true).
		Render("NICE_SCAN")
}

func SetTabTitle(title string) {
	fmt.Print("\x1b]0;" + title + " \x07")
}

func SetTab() {
	SetTabTitle("NICE_SCAN — Fast. Precise. Intelligent.")
}

func RenderSeparator() string {
	return lipgloss.NewStyle().
		Foreground(logoBorder).
		Render(strings.Repeat("─", 40))
}
