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

	r.renderEmptyState(res.Findings, res.Stats)
}

// RenderFindings prints a standalone findings block for a command that produced
// findings directly rather than through a full engine.ScanResult (e.g. the
// subdomain recon). It reuses the same overview + empty-state rendering as a
// scan but skips the scan-shaped dashboard/stacks/check-grid.
func (r *TerminalRenderer) RenderFindings(target string, findings []types.Finding) {
	if target != "" {
		_, _ = fmt.Fprintln(os.Stdout, Section("Target"))
		_, _ = fmt.Fprintln(os.Stdout, KV("Domain", target, 10))
		_, _ = fmt.Fprintln(os.Stdout)
	}
	r.renderFindingsOverview(findings)
	r.renderEmptyState(findings, engine.ScanStats{})
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

	if stats.Refused > 0 {
		refusedLine := "  " + LabelStyle.Width(10).Render("Refused")
		refusedLine += FailStyle.Render(fmt.Sprintf("%d  ·  never sent", stats.Refused))
		_, _ = fmt.Fprintln(os.Stdout, refusedLine)
	}

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
		_, _ = fmt.Fprintln(os.Stdout, Detail(MutedStyle.Render(r.renderEvidence(types.Sanitize(f.Evidence)))))
	}

	confidence := FaintStyle.Render(fmt.Sprintf("%.0f%% confidence", f.Confidence*100))
	_, _ = fmt.Fprintln(os.Stdout, Detail(confidence))
}

func (r *TerminalRenderer) renderEmptyState(findings []types.Finding, stats engine.ScanStats) {
	if len(findings) > 0 {
		return
	}

	_, _ = fmt.Fprintln(os.Stdout)
	if stats.Refused > 0 {
		// The absence of findings here says nothing about the target: the
		// checks never ran. Saying "appears clean" would turn a refusal into
		// a guarantee.
		_, _ = fmt.Fprintln(os.Stdout, FailStyle.Render(fmt.Sprintf(
			"  Nothing was concluded: %d of %d requests were refused by the scope boundary or the internal-address guard.",
			stats.Refused, stats.Total)))
		_, _ = fmt.Fprintln(os.Stdout, MutedStyle.Render("  Re-run without --block-internal, or with --allow-out-of-scope, if that target is intended."))
		return
	}
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

func (r *TerminalRenderer) renderEvidence(ev string) string {
	// Evidence IS the verdict: "Access-Control-Allow-Origin: https://real-origin"
	// is the whole argument. The old width-derived cut (r.width-24) shrank to a
	// handful of runes on a narrow/non-TTY terminal and mangled the decisive
	// value to "h…ue"; even a center-cut destroyed it, because the carried value
	// (the echoed origin) sits in the MIDDLE of a longer evidence line.
	//
	// There is no finding where hiding part of the evidence beats showing it: a
	// truncated HIGH the operator cannot verify is worse than a wrapped line.
	// So evidence is ALWAYS rendered whole and folded onto indented
	// continuation lines instead of being cut away.
	return wrapText(ev, evidenceWrapWidth(r.width))
}

// evidenceWrapWidth picks a soft wrap column: the terminal width minus the
// finding indent, floored so a very narrow terminal still gets readable chunks
// rather than a one-word-per-line cascade.
func evidenceWrapWidth(termWidth int) int {
	w := termWidth - 24
	if w < 48 {
		w = 48
	}
	return w
}

// wrapText folds long single-line evidence onto indented continuation lines so
// it stays readable on narrow terminals instead of being truncated away.
func wrapText(s string, width int) string {
	if width < 12 {
		width = 12
	}
	words := strings.Fields(s)
	if len(words) == 0 {
		return s
	}
	var lines []string
	var cur strings.Builder
	for _, w := range words {
		if cur.Len() > 0 && cur.Len()+1+len([]rune(w)) > width {
			lines = append(lines, cur.String())
			cur.Reset()
		}
		if cur.Len() > 0 {
			cur.WriteString(" ")
		}
		cur.WriteString(w)
	}
	if cur.Len() > 0 {
		lines = append(lines, cur.String())
	}
	return strings.Join(lines, "\n                        ")
}

func (r *TerminalRenderer) RenderJSON(res *engine.ScanResult) {
	jr := NewJSON()
	jr.RenderResult(res)
}
