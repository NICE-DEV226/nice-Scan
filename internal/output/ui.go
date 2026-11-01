package output

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Design system for every terminal surface (CLI, TUI, shell, brain).
//
// Principles: color carries meaning only. Structural chrome is neutral
// grays; the single accent marks identity and focus; semantic tones mark
// outcomes (Good/Warning/Failure). Severity is the dominant color signal
// in a security report, so no decorative element competes with it.
var (
	Ink    = lipgloss.Color("#D3D6E0") // primary text
	Muted  = lipgloss.Color("#828A9C") // secondary text
	Faint  = lipgloss.Color("#515769") // meta: hints, timestamps, rules
	Line   = lipgloss.Color("#303541") // borders and dividers
	Accent = lipgloss.Color("#7AA6DC") // identity, focus — used sparingly

	// Semantic tones, desaturated so they read calmly side by side.
	Good = lipgloss.Color("#8FBC8F") // verified / valid / up-to-date
	Warn = lipgloss.Color("#D2A56C") // caution / notable / medium
	Fail = lipgloss.Color("#E06B6B") // confirmed finding / failure / high+
)

var (
	TitleStyle   = lipgloss.NewStyle().Foreground(Ink).Bold(true)
	SectionStyle = lipgloss.NewStyle().Foreground(Ink).Bold(true)
	LabelStyle   = lipgloss.NewStyle().Foreground(Muted)
	ValueStyle   = lipgloss.NewStyle().Foreground(Ink)
	MutedStyle   = lipgloss.NewStyle().Foreground(Muted)
	FaintStyle   = lipgloss.NewStyle().Foreground(Faint)
	AccentStyle  = lipgloss.NewStyle().Foreground(Accent)
	GoodStyle    = lipgloss.NewStyle().Foreground(Good)
	WarnStyle    = lipgloss.NewStyle().Foreground(Warn)
	FailStyle    = lipgloss.NewStyle().Foreground(Fail)
	PanelStyle   = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(Line).
			Padding(0, 1)
)

// Section renders a plain bold header line — the only structural marker
// a CLI report needs. Indent is included so call sites stay bare.
func Section(title string) string {
	return "  " + SectionStyle.Render(title)
}

// Note renders the narrative "—" verdict line used across modules.
func Note(s string) string {
	return MutedStyle.Render("  — " + s)
}

// Detail indents a supporting line under a result row. The caller owns
// the style (Faint for meta, Muted for evidence); Detail only aligns.
func Detail(s string) string {
	return "    " + s
}

// Rule renders a hairline divider at the given width.
func Rule(width int) string {
	if width < 1 {
		width = 1
	}
	return FaintStyle.Render(strings.Repeat("─", width))
}

// KV renders an aligned label/value pair.
func KV(label, value string, labelWidth int) string {
	lbl := LabelStyle.Width(labelWidth).Render(label)
	return "  " + lbl + ValueStyle.Render(value)
}

// SeverityColor maps a severity name to its semantic tone. Critical and
// High share the failure red (both demand action); Low and Info carry no
// color at all — the absence of tone is itself the signal "nothing to
// act on". Keyed by string so every package shares one source of truth.
func SeverityColor(sev string) lipgloss.Color {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return Fail
	case "medium":
		return Warn
	default:
		return Muted
	}
}

// SeverityStyle renders text in its severity tone.
func SeverityStyle(sev string) lipgloss.Style {
	return lipgloss.NewStyle().Foreground(SeverityColor(sev))
}
