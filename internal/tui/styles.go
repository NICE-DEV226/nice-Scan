package tui

import (
	"github.com/NICE-DEV226/nice-Scan/internal/output"
	"github.com/charmbracelet/lipgloss"
)

// All surfaces draw from the shared design system (internal/output);
// this file only wires the few styles the dashboard adds on top.
var (
	textPrimary = output.Ink
	textMuted   = output.Muted
	accentCyan  = output.Accent

	panelStyle = output.PanelStyle

	labelStyle = output.LabelStyle
	valueStyle = output.ValueStyle
	mutedStyle = output.MutedStyle
	dimStyle   = output.FaintStyle

	titleStyle = lipgloss.NewStyle().Foreground(textPrimary).Bold(true)
)

func severityColor(severity string) lipgloss.Color {
	return output.SeverityColor(severity)
}
