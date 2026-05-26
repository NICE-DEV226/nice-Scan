package output

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	loBorder = lipgloss.Color("#2F3346")
	loMark   = lipgloss.Color("#7DCFFF")
	loName   = lipgloss.Color("#C0CAF5")
	loMuted  = lipgloss.Color("#565F89")
)

func RenderLogoCompact() string {
	n := lipgloss.NewStyle().Foreground(loMark).Bold(true).Render("N")
	s := lipgloss.NewStyle().Foreground(loMark).Bold(true).Render("S")
	pipe := lipgloss.NewStyle().Foreground(loBorder).Render("│")
	top := lipgloss.NewStyle().Foreground(loBorder).Render("┌───┐")
	bot := lipgloss.NewStyle().Foreground(loBorder).Render("└───┘")

	name := lipgloss.NewStyle().Foreground(loName).Bold(true).Render("NICE_SCAN")
	ver := lipgloss.NewStyle().Foreground(loMuted).Render("v0.1.0")
	tag := lipgloss.NewStyle().Foreground(loMuted).Render("Fast. Precise. Intelligent.")

	line1 := top + "  " + name + "  " + ver
	line2 := pipe + " " + n + " " + pipe
	line3 := pipe + " " + s + " " + pipe + "  " + tag
	line4 := bot

	return strings.Join([]string{line1, line2, line3, line4}, "\n")
}

func RenderLogoOneLine() string {
	n := lipgloss.NewStyle().Foreground(loMark).Bold(true).Render("N")
	s := lipgloss.NewStyle().Foreground(loMark).Bold(true).Render("S")
	return n + s
}

func SetTabTitle(title string) {
	fmt.Print("\x1b]0;" + title + " \x07")
}

func SetTab() {
	SetTabTitle("NICE_SCAN — Fast. Precise. Intelligent.")
}
