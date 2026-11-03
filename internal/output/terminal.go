package output

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/engine"
	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"

	"github.com/charmbracelet/lipgloss"
)

// Severity presentation is keyed off the shared SeverityColor mapping;
// glyphs give color-free redundancy for terminals without color.
var severitySymbols = map[types.Severity]string{
	types.SeverityCritical: "■",
	types.SeverityHigh:     "■",
	types.SeverityMedium:   "◆",
	types.SeverityLow:      "◇",
	types.SeverityInfo:     "○",
}

var severityLabels = map[types.Severity]string{
	types.SeverityCritical: "CRITICAL",
	types.SeverityHigh:     "HIGH",
	types.SeverityMedium:   "MEDIUM",
	types.SeverityLow:      "LOW",
	types.SeverityInfo:     "INFO",
}

type TerminalRenderer struct {
	width int
}

func NewTerminal() *TerminalRenderer {
	return &TerminalRenderer{width: 78}
}

func (r *TerminalRenderer) RenderBanner() {
	SetTab()

	_, _ = fmt.Fprintln(os.Stdout)
	_, _ = fmt.Fprintln(os.Stdout, RenderLogoCompact())
	_, _ = fmt.Fprintln(os.Stdout, "  "+Rule(r.width-4))
	_, _ = fmt.Fprintln(os.Stdout)
}

func (r *TerminalRenderer) RenderResult(res *engine.ScanResult) {
	r.renderDashboard(res.Stats)
	_, _ = fmt.Fprintln(os.Stdout)

	r.renderStacks(res.Stacks)

	r.renderCheckGrid(res)
	_, _ = fmt.Fprintln(os.Stdout)

	r.renderFindingsOverview(res.Findings)

	r.renderEmptyState(res.Findings)
}

// renderStacks shows what the target said it runs — the fingerprint-first
// detail the probes were conditioned on. Honest fallback: when no signal
// came back, it says the full probe set was kept instead of pretending a
// stack was read.
func (r *TerminalRenderer) renderStacks(stacks []engine.StackReport) {
	if len(stacks) == 0 {
		return
	}
	_, _ = fmt.Fprintln(os.Stdout, Section("Stack"))
	for _, st := range stacks {
		line := "  " + LabelStyle.Width(10).Render("Server") + ValueStyle.Render(st.Detail)
		_, _ = fmt.Fprintln(os.Stdout, line)
		note := "  " + LabelStyle.Width(10).Render("Probes")
		if st.Conditioned {
			note += MutedStyle.Render("stack-conditioned — family-specific paths limited to the detected stack")
		} else {
			note += MutedStyle.Render("full set kept — no stack signal to condition on")
		}
		_, _ = fmt.Fprintln(os.Stdout, note)
		if len(stacks) > 1 {
			_, _ = fmt.Fprintln(os.Stdout, "  "+MutedStyle.Render(st.Target))
		}
	}
	_, _ = fmt.Fprintln(os.Stdout)
}

func (r *TerminalRenderer) renderCheckGrid(res *engine.ScanResult) {
	if len(res.AnalyzerNames) == 0 {
		return
	}

	_, _ = fmt.Fprintln(os.Stdout, Section("Modules"))

	colCount := 2
	perCol := (len(res.AnalyzerNames) + colCount - 1) / colCount

	for row := 0; row < perCol; row++ {
		var cells []string
		for col := 0; col < colCount; col++ {
			idx := row + col*perCol
			if idx >= len(res.AnalyzerNames) {
				break
			}
			cell := MutedStyle.Width(22).Render("· " + res.AnalyzerNames[idx])
			cells = append(cells, cell)
		}
		_, _ = fmt.Fprintln(os.Stdout, "  "+strings.Join(cells, ""))
	}
}

func (r *TerminalRenderer) RenderTransportStats(s transport.RequestStats) {
	r.renderTransportStats(s)
}

func (r *TerminalRenderer) renderDashboard(stats engine.ScanStats) {
	_, _ = fmt.Fprintln(os.Stdout, Section("Scan"))

	_, _ = fmt.Fprintln(os.Stdout, KV("Target", stats.Target, 10))

	requests := fmt.Sprintf("%d/%d", stats.Completed, stats.Total)
	var rate string
	if stats.Duration > 0 {
		rate = fmt.Sprintf("  ·  %.0f req/s", float64(stats.Total)/stats.Duration.Seconds())
	}
	_, _ = fmt.Fprintln(os.Stdout, KV("Requests", fmt.Sprintf("%s  ·  %d workers%s", requests, stats.Workers, rate), 10))

	failedLine := "  " + LabelStyle.Width(10).Render("Failed")
	if stats.Failed > 0 {
		failedLine += FailStyle.Render(fmt.Sprintf("%d", stats.Failed))
	} else {
		failedLine += ValueStyle.Render("0")
	}
	_, _ = fmt.Fprintln(os.Stdout, failedLine)

	_, _ = fmt.Fprintln(os.Stdout, KV("Duration", stats.Duration.Round(time.Millisecond).String(), 10))
	_, _ = fmt.Fprintln(os.Stdout)
	_, _ = fmt.Fprintln(os.Stdout, "  "+r.progressBar(stats.Completed, stats.Total))
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
		countStyle := SeverityStyle(string(sev))
		if sev == types.SeverityCritical || sev == types.SeverityHigh || sev == types.SeverityMedium {
			countStyle = countStyle.Bold(true)
		}
		countParts = append(countParts, fmt.Sprintf("%s %s",
			countStyle.Render(fmt.Sprintf("%d", count)),
			MutedStyle.Render(severityLabels[sev]),
		))
	}

	_, _ = fmt.Fprintln(os.Stdout, Section("Findings"))
	_, _ = fmt.Fprintln(os.Stdout, "  "+strings.Join(countParts, "   "))
	_, _ = fmt.Fprintln(os.Stdout)

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
	color := SeverityColor(string(sev))
	label := severityLabels[sev]

	_, _ = fmt.Fprintln(os.Stdout, "  "+lipgloss.NewStyle().Foreground(color).Render(
		fmt.Sprintf("%s %s", sym, label),
	))

	for _, f := range findings {
		// A finding renders under its OWN severity marker: grouping is by
		// header, and a mis-stamped severity must not inherit the group
		// hue (a Critical row in the Medium block reads as Medium).
		if f.Severity != sev {
			continue
		}
		r.renderFinding(f)
	}

	_, _ = fmt.Fprintln(os.Stdout)
}

func (r *TerminalRenderer) renderFinding(f types.Finding) {
	// The severity glyph carries the color; the finding name stays neutral
	// ink — coloring whole finding text would dilute the one signal
	// that matters.
	glyph := SeverityStyle(string(f.Severity)).Render(severitySymbols[f.Severity])
	_, _ = fmt.Fprintln(os.Stdout, "    "+glyph+"  "+ValueStyle.Render(types.Sanitize(f.Name)))

	if f.Metadata != nil {
		if version := types.Sanitize(f.Metadata["version"]); version != "" {
			_, _ = fmt.Fprintln(os.Stdout, Detail("  "+FaintStyle.Render(version)))
		}
	}

	if f.Evidence != "" {
		_, _ = fmt.Fprintln(os.Stdout, Detail(MutedStyle.Render(r.truncate(types.Sanitize(f.Evidence), r.width-24))))
	}

	confidence := FaintStyle.Render(fmt.Sprintf("%.0f%% confidence", f.Confidence*100))
	_, _ = fmt.Fprintln(os.Stdout, Detail(confidence))
}

func (r *TerminalRenderer) renderEmptyState(findings []types.Finding) {
	if len(findings) > 0 {
		return
	}

	_, _ = fmt.Fprintln(os.Stdout)
	_, _ = fmt.Fprintln(os.Stdout, MutedStyle.Render("  No findings. Target appears clean against the checks run."))
}

func (r *TerminalRenderer) renderTransportStats(s transport.RequestStats) {
	if s.Total == 0 {
		return
	}

	_, _ = fmt.Fprintln(os.Stdout)
	_, _ = fmt.Fprintln(os.Stdout, Section("Transport"))
	addStat := func(l, v string) {
		_, _ = fmt.Fprintln(os.Stdout, KV(l, v, 15))
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

	fill := strings.Repeat("─", filled)
	empty := strings.Repeat("─", barWidth-filled)

	bar := AccentStyle.Render(fill) + FaintStyle.Render(empty)

	pctStr := MutedStyle.Width(5).Align(lipgloss.Right).Render(fmt.Sprintf("%3.0f%%", pct*100))

	return bar + " " + pctStr
}

func (r *TerminalRenderer) truncate(s string, maxLen int) string {
	// Render sink: rune-aligned truncation (byte slicing of multibyte
	// evidence renders a corrupted glyph) and a guard for degenerate
	// widths (byte slicing to a negative index would panic).
	//
	// Evidence overflows as a head + tail problem: a finding's meaning is
	// carried by BOTH the start (which surface) and the end (the reflected
	// snippet the old cut-to-length deleted, reading as an arbitrary mid-URL
	// severance). Center-cut — keep the front and the back, elide the middle.
	if maxLen <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	if maxLen < 8 {
		return string(runes[:maxLen-1]) + "…"
	}
	head := (maxLen - 1) * 2 / 3
	tail := maxLen - 1 - head
	return string(runes[:head]) + "…" + string(runes[len(runes)-tail:])
}

func (r *TerminalRenderer) RenderJSON(res *engine.ScanResult) {
	jr := NewJSON()
	jr.RenderResult(res)
}
