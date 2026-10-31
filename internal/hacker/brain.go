package hacker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
	"github.com/charmbracelet/lipgloss"
)

var (
	clCyan   = lipgloss.Color("#7DCFFF")
	clMuted  = lipgloss.Color("#565F89")
	clRed    = lipgloss.Color("#F7768E")
	clGreen  = lipgloss.Color("#9ECE6A")
	clYellow = lipgloss.Color("#E0AF68")
	clOrange = lipgloss.Color("#FF9E64")
	clDim    = lipgloss.Color("#3B4261")

	styleHeader = lipgloss.NewStyle().Bold(true).Foreground(clCyan)
	styleMuted  = lipgloss.NewStyle().Foreground(clMuted)
	styleRed    = lipgloss.NewStyle().Foreground(clRed).Bold(true)
	styleGreen  = lipgloss.NewStyle().Foreground(clGreen)
	styleYellow = lipgloss.NewStyle().Foreground(clYellow)
	styleLabel  = lipgloss.NewStyle().Foreground(clMuted).Width(12).Align(lipgloss.Right)
	styleValue  = lipgloss.NewStyle().Foreground(clCyan)
	styleCyan   = lipgloss.NewStyle().Foreground(clCyan)
)

type Brain struct {
	target  string
	kb      *Knowledge
	planner *Planner
	chainer *Chainer
	client  *transport.Client
	actions []Action
	startAt time.Time
}

func NewBrain(target string, client *transport.Client, actions ...Action) *Brain {
	return &Brain{
		target:  target,
		kb:      NewKnowledge(target),
		client:  client,
		actions: actions,
		planner: NewPlanner(actions...),
		chainer: NewChainer(),
	}
}

// AppendAction registers additional actions before the run — the only
// sanctioned way for the CLI to add destructive modules after NewBrain
// (they stay absent entirely without operator consent).
func (b *Brain) AppendAction(as ...Action) {
	for _, a := range as {
		b.actions = append(b.actions, a)
		b.planner.AddAction(a)
	}
}

func (b *Brain) Run(ctx context.Context) *Report {
	b.startAt = time.Now()
	step := 0

	fmt.Println(styleHeader.Render("  NICE HACKER — DECISION ENGINE"))
	fmt.Println(styleMuted.Render(fmt.Sprintf("  Target: %s", b.target)))
	fmt.Println(styleValue.Render(fmt.Sprintf("  Actions loaded: %d", len(b.actions))))
	fmt.Println()
	fmt.Println(styleMuted.Render(fmt.Sprintf("  %s", strings.Repeat("─", 56))))
	fmt.Println()

	for {
		select {
		case <-ctx.Done():
			fmt.Println(styleYellow.Render("\n  Interrupted by user"))
			return b.buildReport(step)
		default:
		}

		chainActions := b.chainer.DetectAndExecute(ctx, b.target, b.kb, b.client)
		for _, ca := range chainActions {
			step++
			meta := ca.Metadata()
			b.renderProgress(step, meta.Name, meta.Description, 0)
			result := ca.Execute(ctx, b.target, b.kb, b.client)
			for _, f := range result.Findings {
				b.kb.AddFinding(f)
				b.renderFinding(f)
			}
			fmt.Println()
		}

		if !b.planner.HasRemaining(b.kb) {
			break
		}

		action := b.planner.NextAction(b.kb)
		if action == nil {
			break
		}

		step++
		meta := action.Metadata()
		b.renderProgress(step, meta.Name, meta.Description, 0)

		select {
		case <-ctx.Done():
			fmt.Println(styleYellow.Render("\n  Interrupted by user"))
			return b.buildReport(step)
		default:
		}

		result := action.Execute(ctx, b.target, b.kb, b.client)

		for _, f := range result.Findings {
			b.kb.AddFinding(f)
			b.renderFinding(f)
		}

		for _, newAction := range result.Actions {
			b.planner.AddAction(newAction)
			fmt.Printf("  %s %s\n",
				styleGreen.Render("◈"),
				styleGreen.Render(fmt.Sprintf("Spawned: %s", newAction.Metadata().Name)),
			)
		}

		b.renderKBSummary()
	}

	return b.buildReport(step)
}

func (b *Brain) renderKBSummary() {
	caps := b.kb.GetCapabilities()
	if len(caps) > 0 {
		var capStrs []string
		for _, c := range caps {
			switch c.Origin {
			case OriginHint:
				// Remote-text hints render as suspected, never as facts.
				capStrs = append(capStrs, lipgloss.NewStyle().Foreground(clYellow).Render("?"+c.Name))
			case OriginObserved:
				// Page-derived semantics: real fetch, unproven capability.
				capStrs = append(capStrs, lipgloss.NewStyle().Foreground(clCyan).Render("≈"+c.Name))
			default:
				capStrs = append(capStrs, lipgloss.NewStyle().Foreground(clGreen).Render(c.Name))
			}
		}
		fmt.Printf("  %s %s  %s\n",
			lipgloss.NewStyle().Foreground(clDim).Render("└"),
			strings.Join(capStrs, " "),
			lipgloss.NewStyle().Foreground(clDim).Render(fmt.Sprintf("(? = hint from remote text, ≈ = observed on fetched page, %d verified)", countVerified(caps))),
		)
	}
	fmt.Println()
}

func countVerified(caps []Capability) int {
	n := 0
	for _, c := range caps {
		if c.Origin == OriginVerified {
			n++
		}
	}
	return n
}

func (b *Brain) buildReport(steps int) *Report {
	dur := time.Since(b.startAt)
	chains := b.chainer.DetectChains(b.kb)
	impact := "No significant vulnerabilities discovered"
	riskScore := 0.0

	// Executed findings drive the floor of the score. The previous version
	// ignored Findings entirely — a run with a wire-confirmed XSS (and no
	// chain pattern) reported risk 0/10 while a single keyword in a page
	// minted verified-origin chains worth 10/10. Severity of a finding is
	// itself established truth here: only actions with wire-verified
	// verdicts emit the high severities (the raw keyword classes emit
	// info/low-medium).
	maxRisk := 0.0
	for _, c := range chains {
		if c.RiskScore > maxRisk {
			maxRisk = c.RiskScore
		}
	}
	if maxRisk > 0 {
		riskScore = maxRisk
		impact = "Attack chains derived from verified capabilities"
		for _, c := range chains {
			impact += fmt.Sprintf("; %s", c.Name)
		}
	}

	for _, f := range b.kb.GetFindings() {
		sevRisk := severityRiskFloor(f.Severity)
		if sevRisk > riskScore {
			riskScore = sevRisk
			impact = fmt.Sprintf("Confirmed finding (%s): %s", f.Severity, f.Name)
		}
	}

	creds := b.kb.GetCredentials()
	// Only accepted credentials count as compromise evidence. Records kept
	// because a login attempt *failed* (Valid=false) say nothing about the
	// account other than that the password was wrong.
	credsValid := false
	for _, c := range creds {
		if c.Valid {
			credsValid = true
			break
		}
	}
	if credsValid && riskScore < 9.0 {
		riskScore = 9.0
		impact = "Valid credentials obtained — account compromise confirmed"
	}

	// kb.GetSecrets() only holds content actually captured by executed
	// actions (AddSecret); scanner bookkeeping lives in AddScannerState and
	// can no longer trigger this tier.
	secrets := b.kb.GetSecrets()
	if len(secrets) > 0 && riskScore < 10.0 {
		riskScore = 10.0
		impact = "Secrets exposed — critical data breach imminent"
	}

	endpoints := b.kb.GetEndpoints()
	if len(endpoints) > 0 && riskScore < 5.0 {
		riskScore = 5.0
		impact = "Exposed endpoints discovered"
	}

	// An alg=none forgery only counts when the forged token was validated by
	// the scanner (Valid=true). JWTForgeNoneAction currently stores forged
	// payloads with Valid=false: claiming "full account takeover" over a
	// token that was computed but never accepted fabricated critical risk.
	jwts := b.kb.GetJWTs()
	for _, j := range jwts {
		if j.Algorithm == "none" && j.Valid {
			riskScore = 10.0
			impact = "JWT with alg=none accepted — full account takeover confirmed"
		}
	}

	return &Report{
		Target:       b.target,
		Duration:     dur,
		Steps:        steps,
		Impact:       impact,
		RiskScore:    riskScore,
		AttackChains: chains,
		Findings:     b.kb.GetFindings(),
		Capabilities: b.kb.GetCapabilities(),
		Credentials:  b.kb.GetCredentials(),
		Endpoints:    b.kb.GetEndpoints(),
		Pages:        b.kb.GetPages(),
	}
}

// severityRiskFloor maps a confirmed finding's severity to the risk floor
// it justifies in the final report. Conservative by design: a single high
// finding cannot outrank multi-step verified chains (7.5 caps below the
// chain ceiling), while criticals carry near-chain weight.
func severityRiskFloor(s Severity) float64 {
	switch s {
	case SevCritical:
		return 9.5
	case SevHigh:
		return 7.5
	case SevMedium:
		return 4.5
	case SevLow:
		return 2.0
	}
	return 0
}

func severityColor(s Severity) lipgloss.Color {
	switch s {
	case SevCritical:
		return clRed
	case SevHigh:
		return clOrange
	case SevMedium:
		return clYellow
	case SevLow:
		return clCyan
	default:
		return clMuted
	}
}

func (b *Brain) renderProgress(step int, name, desc string, remaining int) {
	elapsed := time.Since(b.startAt).Round(time.Second)

	stepHeader := fmt.Sprintf("  Step %d/%d", step, step+remaining)
	if remaining == 0 {
		stepHeader = fmt.Sprintf("  Step %d", step)
	}

	fmt.Println(styleMuted.Render(fmt.Sprintf("  %s  [%s]  %s",
		stepHeader,
		elapsed.String(),
		lipgloss.NewStyle().Foreground(clDim).Render("─"),
	)))

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(clDim).
		Padding(0, 1)

	content := fmt.Sprintf("  %s  %s",
		styleCyan.Bold(true).Render(name),
		styleMuted.Render(desc),
	)

	fmt.Println(box.Render(content))
}

func (b *Brain) renderFinding(f Finding) {
	sevStyle := lipgloss.NewStyle().Foreground(severityColor(f.Severity)).Bold(true)
	sym := "•"
	switch f.Severity {
	case SevCritical:
		sym = "!!"
	case SevHigh:
		sym = "▸"
	case SevMedium:
		sym = "›"
	}
	label := strings.ToUpper(string(f.Severity))
	if label == "" {
		label = "INFO"
	}
	// Sanity at the render sink: finding text carries remote content.
	fmt.Printf("  %s %s %s\n",
		sevStyle.Render(sym),
		lipgloss.NewStyle().Foreground(severityColor(f.Severity)).Width(8).Render(label),
		lipgloss.NewStyle().Foreground(severityColor(f.Severity)).Render(types.Sanitize(f.Name)),
	)
	if f.Evidence != "" {
		ev := f.Evidence
		if len(ev) > 120 {
			ev = ev[:117] + "..."
		}
		fmt.Println(styleMuted.Render(fmt.Sprintf("         %s", types.Sanitize(ev))))
	}
}

func (b *Brain) RenderReport(report *Report) {
	fmt.Println()
	fmt.Println(strings.Repeat("═", 56))
	fmt.Println(styleHeader.Render("  NICE HACKER — ATTACK REPORT"))
	fmt.Println(strings.Repeat("═", 56))
	fmt.Println()

	rows := [][2]string{
		{"Target", report.Target},
		{"Duration", fmt.Sprintf("%.0fs", report.Duration.Seconds())},
		{"Steps", fmt.Sprintf("%d", report.Steps)},
		{"Risk Score", fmt.Sprintf("%.1f/10", report.RiskScore)},
	}
	for _, r := range rows {
		fmt.Printf("  %s %s\n", styleLabel.Render(r[0]+":"), styleValue.Render(r[1]))
	}
	fmt.Println()

	fmt.Println(styleHeader.Render("  Impact Summary"))
	fmt.Println(styleMuted.Render(fmt.Sprintf("  %s", types.Sanitize(report.Impact))))
	fmt.Println()

	if len(report.AttackChains) > 0 {
		fmt.Println(styleHeader.Render("  Attack Chains Discovered"))
		fmt.Println()
		for _, chain := range report.AttackChains {
			fmt.Printf("  %s %s\n",
				styleRed.Render("⚡"),
				styleRed.Bold(true).Render(types.Sanitize(chain.Name)),
			)
			fmt.Printf("  %s Risk: %.0f/10\n", styleMuted.Render("  "), chain.RiskScore)
			fmt.Printf("  %s %s\n", styleMuted.Render("  →"), types.Sanitize(chain.Impact))
			fmt.Println()
		}
	}

	findings := report.Findings
	if len(findings) > 0 {
		fmt.Println(styleHeader.Render("  Findings"))
		fmt.Println()
		for _, f := range findings {
			b.renderFinding(f)
		}
		fmt.Println()
	}

	if len(report.Credentials) > 0 {
		fmt.Println(styleHeader.Render("  Credentials Obtained"))
		fmt.Println()
		for _, c := range report.Credentials {
			if c.Valid {
				fmt.Printf("  %s %s:%s %s\n", styleRed.Render("◈"), types.Sanitize(c.Username), types.Sanitize(c.Password), styleGreen.Render("✓ valid"))
			} else {
				fmt.Printf("  %s %s:%s %s\n", styleMuted.Render("·"), types.Sanitize(c.Username), types.Sanitize(c.Password), styleMuted.Render("tested"))
			}
		}
		fmt.Println()
	}

	if len(report.Endpoints) > 0 {
		fmt.Println(styleHeader.Render("  Endpoints Discovered"))
		fmt.Println()
		for _, e := range report.Endpoints {
			method := styleYellow.Render(e.Method)
			statusStr := ""
			if e.Status > 0 {
				statusStr = fmt.Sprintf(" [%d]", e.Status)
			}
			fmt.Printf("  %s %s%s\n", method, styleCyan.Render(types.Sanitize(e.Path)), styleMuted.Render(statusStr))
		}
		fmt.Println()
	}

	if len(report.Pages) > 0 {
		fmt.Println(styleHeader.Render(fmt.Sprintf("  Pages Crawled (%d)", len(report.Pages))))
		fmt.Println()
		for _, p := range report.Pages {
			detail := fmt.Sprintf("%d bytes", p.BodyLen)
			if p.Forms > 0 {
				detail += fmt.Sprintf(" · %d forms", p.Forms)
			}
			if len(p.Links) > 0 {
				detail += fmt.Sprintf(" · %d links", len(p.Links))
			}
			if len(p.JSFiles) > 0 {
				detail += fmt.Sprintf(" · %d JS", len(p.JSFiles))
			}
			fmt.Printf("  %s %s %s\n",
				styleGreen.Render("●"),
				styleCyan.Render(types.Sanitize(p.URL)),
				styleMuted.Render(detail),
			)
		}
		fmt.Println()
	}

	// The capability board is engine bookkeeping, not evidence: it now
	// sits after the observed surface (pages/endpoints) so the report
	// leads with what was actually seen. The origin markers stay visible
	// because the whole point is that a hint is not an observation.
	if len(report.Capabilities) > 0 {
		fmt.Println(styleHeader.Render("  Engine Knowledge (✓ verified · ≈ observed · ? hint)"))
		fmt.Println()
		for _, c := range report.Capabilities {
			label := c.Name
			style := styleGreen
			switch c.Origin {
			case OriginHint:
				label = "?" + c.Name
				style = styleYellow
			case OriginObserved:
				label = "≈" + c.Name
				style = styleCyan
			}
			fmt.Printf("  %s %s\n", style.Render("●"), styleCyan.Render(types.Sanitize(label)))
		}
		fmt.Println()
	}

	summary := b.kb.ReportDir.GenerateSummary()
	fmt.Println(styleHeader.Render("  Extracted Data"))
	fmt.Println(styleMuted.Render(fmt.Sprintf("  %s", summary)))
	fmt.Println()

	fmt.Println(strings.Repeat("─", 56))
	fmt.Println(styleMuted.Render("  NICE HACKER — Attack Complete"))
}
