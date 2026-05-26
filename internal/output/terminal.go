package output

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nice-scan/nice_scan/internal/engine"
	"github.com/nice-scan/nice_scan/internal/transport"
	"github.com/nice-scan/nice_scan/internal/types"

	"github.com/charmbracelet/lipgloss"
)

var (
	// Surfaces
	surfaceGraphite = lipgloss.Color("#1A1B26")
	surfaceAlt      = lipgloss.Color("#24283B")
	surfaceBorder   = lipgloss.Color("#2F3346")
	surfaceHover    = lipgloss.Color("#363B54")

	// Text
	textPrimary = lipgloss.Color("#C0CAF5")
	textMuted   = lipgloss.Color("#565F89")
	textDim     = lipgloss.Color("#3B4261")

	// Accents - restrained, elegant
	accentCyan  = lipgloss.Color("#7DCFFF")
	accentBlue  = lipgloss.Color("#87C7FF")
	accentViolet  = lipgloss.Color("#BB9AF7")
	accentAmber = lipgloss.Color("#FFB347")
	accentCoral = lipgloss.Color("#F7768E")
	accentGreen   = lipgloss.Color("#9ECE6A")

	// Severity - subtle, no neon
	severityColors = map[types.Severity]lipgloss.Color{
		types.SeverityCritical: accentCoral,
		types.SeverityHigh:     accentCoral,
		types.SeverityMedium:   accentAmber,
		types.SeverityLow:      accentCyan,
		types.SeverityInfo:     textMuted,
	}

	severitySymbols = map[types.Severity]string{
		types.SeverityCritical: "■",
		types.SeverityHigh:     "■",
		types.SeverityMedium:   "◧",
		types.SeverityLow:      "◇",
		types.SeverityInfo:     "○",
	}

	severityLabels = map[types.Severity]string{
		types.SeverityCritical: "CRITICAL",
		types.SeverityHigh:     "HIGH",
		types.SeverityMedium:   "MEDIUM",
		types.SeverityLow:      "LOW",
		types.SeverityInfo:     "INFO",
	}
)

type TerminalRenderer struct {
	width  int
	styles *Styles
}

type Styles struct {
	header   lipgloss.Style
	panel    lipgloss.Style
	title    lipgloss.Style
	label    lipgloss.Style
	value    lipgloss.Style
	muted    lipgloss.Style
	divider  lipgloss.Style
	severity func(types.Severity) lipgloss.Style
}

func NewTerminal() *TerminalRenderer {
	r := &TerminalRenderer{
		width: 78,
	}

	r.styles = &Styles{
		header: lipgloss.NewStyle().
			Foreground(accentCyan).
			Bold(true).
			Padding(0, 0, 0, 0),

		panel: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(surfaceBorder).
			Padding(1, 2).
			Width(r.width - 4),

		title: lipgloss.NewStyle().
			Foreground(textPrimary).
			Bold(true),

		label: lipgloss.NewStyle().
			Foreground(textMuted).
			Width(11),

		value: lipgloss.NewStyle().
			Foreground(textPrimary),

		muted: lipgloss.NewStyle().
			Foreground(textMuted),

		divider: lipgloss.NewStyle().
			Foreground(surfaceBorder),

		severity: func(sev types.Severity) lipgloss.Style {
			c := severityColors[sev]
			if c == "" {
				c = textMuted
			}
			return lipgloss.NewStyle().
				Foreground(c).
				Bold(true).
				Width(8).
				Align(lipgloss.Right)
		},
	}

	return r
}

func (r *TerminalRenderer) RenderBanner() {
	SetTab()

	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, RenderLogoCompact())
	fmt.Fprintln(os.Stdout)
}

func (r *TerminalRenderer) RenderResult(res *engine.ScanResult) {
	r.renderDashboard(res.Stats)
	fmt.Fprintln(os.Stdout)

	r.renderFindingsOverview(res.Findings)
	fmt.Fprintln(os.Stdout)

	r.renderEmptyState(res.Findings)
}

func (r *TerminalRenderer) RenderTransportStats(s transport.RequestStats) {
	r.renderTransportStats(s)
}

func (r *TerminalRenderer) renderDashboard(stats engine.ScanStats) {
	rows := []string{}

	rows = append(rows, lipgloss.JoinHorizontal(lipgloss.Left,
		r.styles.label.Render("Target"),
		r.styles.value.Render(stats.Target),
	))

	rows = append(rows, "")

	requestsLabel := r.styles.label.Render("Requests")
	requestsVal := r.styles.value.Render(fmt.Sprintf("%d/%d", stats.Completed, stats.Total))

	latency := stats.Duration
	var rate float64
	if latency > 0 {
		rate = float64(stats.Total) / latency.Seconds()
	}

	rateLabel := r.styles.label.Render("Rate")
	rateVal := r.styles.value.Render(fmt.Sprintf("%.0f/s", rate))

	rows = append(rows, lipgloss.JoinHorizontal(lipgloss.Left,
		requestsLabel, requestsVal,
	))

	rows = append(rows, lipgloss.JoinHorizontal(lipgloss.Left,
		rateLabel, rateVal,
	))

	workersLabel := r.styles.label.Render("Workers")
	workersVal := r.styles.value.Render(fmt.Sprintf("%d", stats.Workers))
	failedLabel := r.styles.label.Render("Failed")
	failedVal := r.styles.value.Render(fmt.Sprintf("%d", stats.Failed))
	if stats.Failed > 0 {
		failedVal = lipgloss.NewStyle().Foreground(accentCoral).Render(fmt.Sprintf("%d", stats.Failed))
	}

	duration := stats.Duration.Round(time.Millisecond).String()
	durationLabel := r.styles.label.Render("Duration")
	durationVal := r.styles.value.Render(duration)

	panel := r.styles.panel.Render(
		lipgloss.JoinVertical(lipgloss.Left,
			rows[0],
			rows[1],
			rows[2],
			rows[3],
			"",
			lipgloss.JoinHorizontal(lipgloss.Left,
				workersLabel, workersVal,
			),
			lipgloss.JoinHorizontal(lipgloss.Left,
				failedLabel, failedVal,
			),
			lipgloss.JoinHorizontal(lipgloss.Left,
				durationLabel, durationVal,
			),
			"",
			r.progressBar(stats.Completed, stats.Total),
		),
	)

	fmt.Fprintln(os.Stdout, panel)
}

func (r *TerminalRenderer) renderFindingsOverview(findings []types.Finding) {
	if len(findings) == 0 {
		return
	}

	order := []types.Severity{
		types.SeverityCritical,
		types.SeverityHigh,
		types.SeverityMedium,
		types.SeverityLow,
		types.SeverityInfo,
	}

	severityCounts := map[types.Severity]int{}
	for _, sev := range order {
		severityCounts[sev] = 0
	}
	for _, f := range findings {
		severityCounts[f.Severity]++
	}

	countParts := []string{}
	for _, sev := range order {
		count := severityCounts[sev]
		if count == 0 {
			continue
		}
		color := severityColors[sev]
		if color == "" {
			color = textMuted
		}
		style := lipgloss.NewStyle().Foreground(color).Bold(true)
		label := lipgloss.NewStyle().Foreground(textMuted).Render(strings.ToLower(string(sev)))
		countParts = append(countParts, fmt.Sprintf("%s %s %d", style.Render(severitySymbols[sev]), label, count))
	}

	summary := strings.Join(countParts, "  ·  ")

	header := lipgloss.NewStyle().Foreground(textMuted).Padding(0, 2).Render("Findings")

	fmt.Fprintln(os.Stdout, lipgloss.JoinVertical(lipgloss.Left,
		header,
		lipgloss.NewStyle().Padding(0, 2, 1, 2).Render(summary),
	))

	for _, sev := range order {
		count := severityCounts[sev]
		if count == 0 {
			continue
		}
		r.renderSeverityGroup(sev, findings)
	}
}

func (r *TerminalRenderer) renderSeverityGroup(sev types.Severity, findings []types.Finding) {
	sym := severitySymbols[sev]
	color := severityColors[sev]
	label := severityLabels[sev]

	header := lipgloss.NewStyle().
		Foreground(color).
		Bold(true).
		Padding(0, 2, 0, 2).
		Render(fmt.Sprintf("%s  %s", sym, label))

	fmt.Fprintln(os.Stdout, header)

	for _, f := range findings {
		if f.Severity != sev {
			continue
		}
		r.renderFinding(f, color)
	}

	fmt.Fprintln(os.Stdout)
}

func (r *TerminalRenderer) renderFinding(f types.Finding, color lipgloss.Color) {
	name := lipgloss.NewStyle().
		Foreground(textPrimary).
		Padding(0, 0, 0, 4).
		Render(f.Name)

	var desc string
	if f.Evidence != "" {
		desc = lipgloss.NewStyle().
			Foreground(textMuted).
			Padding(0, 0, 0, 4).
			Render(r.truncate(f.Evidence, r.width-20))
	}

	confidence := lipgloss.NewStyle().
		Foreground(textDim).
		Padding(0, 0, 0, 4).
		Render(fmt.Sprintf("%.0f%% confidence", f.Confidence*100))

	fmt.Fprintln(os.Stdout, name)
	if desc != "" {
		fmt.Fprintln(os.Stdout, desc)
	}
	fmt.Fprintln(os.Stdout, confidence)
	fmt.Fprintln(os.Stdout)
}

func (r *TerminalRenderer) renderEmptyState(findings []types.Finding) {
	if len(findings) > 0 {
		return
	}

	msg := lipgloss.NewStyle().
		Foreground(textMuted).
		Padding(0, 2).
		Render("No issues detected. Target appears clean.")

	fmt.Fprintln(os.Stdout, msg)
}

func (r *TerminalRenderer) renderTransportStats(s transport.RequestStats) {
	if s.Total == 0 {
		return
	}

	items := []string{}
	addStat := func(l, v string) {
		lbl := lipgloss.NewStyle().Foreground(textMuted).Width(13).Render(l)
		val := lipgloss.NewStyle().Foreground(textPrimary).Render(v)
		items = append(items, lbl+val)
	}

	addStat("Total Requests", fmt.Sprintf("%d", s.Total))
	addStat("Successful", fmt.Sprintf("%d", s.Success))
	addStat("Failed", fmt.Sprintf("%d", s.Failed))
	if s.Retried > 0 {
		addStat("Retried", fmt.Sprintf("%d", s.Retried))
	}
	if s.RateLimited > 0 {
		addStat("Rate Limited", fmt.Sprintf("%d", s.RateLimited))
	}
	addStat("Elapsed", s.TotalTime.Round(time.Millisecond).String())

	content := lipgloss.JoinVertical(lipgloss.Left, items...)

	panel := r.styles.panel.Render(content)

	fmt.Fprintln(os.Stdout, panel)
}

func (r *TerminalRenderer) progressBar(current, total int) string {
	if total == 0 {
		return ""
	}

	barWidth := r.width - 16
	if barWidth < 10 {
		barWidth = 10
	}

	pct := float64(current) / float64(total)
	filled := int(float64(barWidth) * pct)
	if filled > barWidth {
		filled = barWidth
	}
	if current >= total && total > 0 {
		filled = barWidth
	}

	fill := strings.Repeat("━", filled)
	empty := strings.Repeat("─", barWidth-filled)

	bar := lipgloss.NewStyle().Foreground(accentCyan).Render(fill) +
		lipgloss.NewStyle().Foreground(surfaceBorder).Render(empty)

	pctStr := lipgloss.NewStyle().
		Foreground(textMuted).
		Width(5).
		Align(lipgloss.Right).
		Render(fmt.Sprintf("%3.0f%%", pct*100))

	return lipgloss.JoinHorizontal(lipgloss.Center, bar, " ", pctStr)
}

func (r *TerminalRenderer) truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}

func (r *TerminalRenderer) RenderJSON(res *engine.ScanResult) {
	jr := NewJSON()
	jr.RenderResult(res)
}
