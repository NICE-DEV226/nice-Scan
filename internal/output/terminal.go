package output

import (
	"fmt"
	"os"
	"strings"
	"time"

	"nice_scan/internal/engine"
	"nice_scan/internal/transport"
	"nice_scan/internal/types"

	"github.com/charmbracelet/lipgloss"
)

var (
	appStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("39")).
			MarginBottom(1)

	subtitleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("243"))

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("39")).
			Padding(0, 2, 0, 2)

	labelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("243")).
			Width(14)

	valueStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("255"))

	severityColors = map[types.Severity]lipgloss.Color{
		types.SeverityInfo:     "243",
		types.SeverityLow:      "220",
		types.SeverityMedium:   "208",
		types.SeverityHigh:     "196",
		types.SeverityCritical: "198",
	}

	severityLabels = map[types.Severity]string{
		types.SeverityInfo:     "INFO",
		types.SeverityLow:      "LOW",
		types.SeverityMedium:   "MEDIUM",
		types.SeverityHigh:     "HIGH",
		types.SeverityCritical: "CRITICAL",
	}
)

type TerminalRenderer struct {
	width int
}

func NewTerminal() *TerminalRenderer {
	return &TerminalRenderer{
		width: 72,
	}
}

func (r *TerminalRenderer) RenderBanner() {
	banner := appStyle.Render("╭──────────────────────────────────────────────╮")
	banner += "\n"
	banner += appStyle.Render("│              NICE_SCAN v0.1.0               │")
	banner += "\n"
	banner += appStyle.Render("│      Fast. Precise. Intelligent.            │")
	banner += "\n"
	banner += appStyle.Render("╰──────────────────────────────────────────────╯")

	fmt.Fprintln(os.Stdout, banner)
	fmt.Fprintln(os.Stdout)
}

func (r *TerminalRenderer) RenderResult(res *engine.ScanResult) {
	r.renderDashboard(res.Stats)
	fmt.Fprintln(os.Stdout)

	severityOrder := []types.Severity{
		types.SeverityCritical,
		types.SeverityHigh,
		types.SeverityMedium,
		types.SeverityLow,
		types.SeverityInfo,
	}

	for _, sev := range severityOrder {
		severityFindings := filterBySeverity(res.Findings, sev)
		if len(severityFindings) > 0 {
			r.renderFindingsGroup(sev, severityFindings)
		}
	}

	if len(res.Findings) == 0 {
		r.renderEmpty()
	}
}

func (r *TerminalRenderer) renderDashboard(stats engine.ScanStats) {
	targetLabel := labelStyle.Render("Target")
	targetVal := valueStyle.Render(stats.Target)

	statLine := strings.Builder{}
	statLine.WriteString(boxStyle.Render(
		lipgloss.JoinVertical(lipgloss.Left,
			targetLabel+" "+targetVal,
			"",
			r.statLine("Requests", fmt.Sprintf("%d/%d", stats.Completed, stats.Total)),
			r.statLine("Failed", fmt.Sprintf("%d", stats.Failed)),
			r.statLine("Findings", fmt.Sprintf("%d", stats.Findings)),
			r.statLine("Duration", stats.Duration.Round(time.Millisecond).String()),
			r.statLine("Workers", fmt.Sprintf("%d", 64)),
		),
	))

	fmt.Fprintln(os.Stdout, statLine)
}

func (r *TerminalRenderer) statLine(label, value string) string {
	return labelStyle.Render(label) + " " + valueStyle.Render(value)
}

func (r *TerminalRenderer) renderFindingsGroup(severity types.Severity, findings []types.Finding) {
	color := severityColors[severity]
	label := severityLabels[severity]

	header := lipgloss.NewStyle().
		Bold(true).
		Foreground(color).
		Render(fmt.Sprintf("  %s: %d finding(s)", label, len(findings)))

	fmt.Fprintln(os.Stdout, header)

	for _, f := range findings {
		r.renderFinding(f, color)
	}

	fmt.Fprintln(os.Stdout)
}

func (r *TerminalRenderer) renderFinding(f types.Finding, color lipgloss.Color) {
	nameStyle := lipgloss.NewStyle().Bold(true).Foreground(color)

	name := nameStyle.Render("  " + f.Name)

	desc := ""
	if f.Evidence != "" {
		desc = "  " + lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(f.Evidence)
	}

	confidence := lipgloss.NewStyle().
		Foreground(lipgloss.Color("243")).
		Render(fmt.Sprintf("  [%.0f%% confidence]", f.Confidence*100))

	fmt.Fprintln(os.Stdout, name)
	if desc != "" {
		fmt.Fprintln(os.Stdout, desc)
	}
	fmt.Fprintln(os.Stdout, confidence)
	fmt.Fprintln(os.Stdout)
}

func (r *TerminalRenderer) renderEmpty() {
	fmt.Fprintln(os.Stdout, lipgloss.NewStyle().
		Foreground(lipgloss.Color("243")).
		Render("  No findings detected."))
}

func filterBySeverity(findings []types.Finding, sev types.Severity) []types.Finding {
	var filtered []types.Finding
	for _, f := range findings {
		if f.Severity == sev {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func (r *TerminalRenderer) RenderJSON(res *engine.ScanResult) {
	jr := NewJSON()
	jr.RenderResult(res)
}

func (r *TerminalRenderer) RenderTransportStats(stats transport.RequestStats) {
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, boxStyle.Render(
		lipgloss.JoinVertical(lipgloss.Left,
			labelStyle.Render("Total Reqs")+" "+valueStyle.Render(fmt.Sprintf("%d", stats.Total)),
			labelStyle.Render("Successful")+" "+valueStyle.Render(fmt.Sprintf("%d", stats.Success)),
			labelStyle.Render("Failed")+" "+valueStyle.Render(fmt.Sprintf("%d", stats.Failed)),
			labelStyle.Render("Retried")+" "+valueStyle.Render(fmt.Sprintf("%d", stats.Retried)),
			labelStyle.Render("Rate Limited")+" "+valueStyle.Render(fmt.Sprintf("%d", stats.RateLimited)),
			labelStyle.Render("Total Time")+" "+valueStyle.Render(stats.TotalTime.Round(time.Millisecond).String()),
		),
	))
}
