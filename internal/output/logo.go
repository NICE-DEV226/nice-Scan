package output

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	loMark  = lipgloss.Color("#7DCFFF")
	loName  = lipgloss.Color("#C0CAF5")
	loMuted = lipgloss.Color("#565F89")
)

func RenderLogoCompact() string {
	mark := lipgloss.NewStyle().Foreground(loMark).Bold(true)

	top := mark.Render("  █████")
	mid1 := mark.Render(" █     █")
	mid2 := mark.Render(" █  ◉  █")
	mid3 := mark.Render(" █     █")
	bot := mark.Render("  █████")

	name := lipgloss.NewStyle().Foreground(loName).Bold(true).Render("NICE_SCAN")
	tagline := lipgloss.NewStyle().Foreground(loMuted).Render("Fast. Precise. Intelligent.")

	icon := strings.Join([]string{top, mid1, mid2, mid3, bot}, "\n")
	text := lipgloss.JoinVertical(lipgloss.Left, name, tagline)

	logo := lipgloss.JoinHorizontal(lipgloss.Center,
		icon,
		"  ",
		text,
	)

	return logo
}

func RenderLogoOneLine() string {
	return lipgloss.NewStyle().Foreground(loMark).Bold(true).Render("◉")
}

func SetTabTitle(title string) {
	fmt.Print("\x1b]0;" + title + " \x07")
}

func SetTab() {
	SetTabTitle("NICE_SCAN — Fast. Precise. Intelligent.")
}
