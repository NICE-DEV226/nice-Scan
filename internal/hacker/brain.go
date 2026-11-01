package hacker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/output"
	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
	"github.com/charmbracelet/lipgloss"
)

var (
	clCyan   = output.Accent
	clMuted  = output.Muted
	clRed    = output.Fail
	clGreen  = output.Good
	clYellow = output.Warn
	clDim    = output.Faint

	styleMuted  = output.MutedStyle
	styleRed    = lipgloss.NewStyle().Foreground(clRed)
	styleYellow = output.WarnStyle
	styleLabel  = lipgloss.NewStyle().Foreground(clMuted).Width(12)
	styleValue  = output.ValueStyle
)

type Brain struct {
	target      string
	kb          *Knowledge
	planner     *Planner
	chainer     *Chainer
	client      *transport.Client
	actions     []Action
	startAt     time.Time
	destructive bool
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

// AppendAction registers additional actions before the run. Destructive
// actions may be registered freely — consent is enforced at dispatch time
// (see SetDestructive), so a spawned or pre-registered module can never
// execute on its own.
func (b *Brain) AppendAction(as ...Action) {
	for _, a := range as {
		b.actions = append(b.actions, a)
		b.planner.AddAction(a)
	}
}

// SetDestructive records the operator's --destructive consent for the run.
// Without it, every action flagged Destructive — registered or spawned at
// runtime — is withheld and listed in the report.
func (b *Brain) SetDestructive(allowed bool) {
	b.destructive = allowed
	b.planner.AllowDestructive(allowed)
}

func (b *Brain) Run(ctx context.Context) *Report {
	b.startAt = time.Now()
	step := 0

	fmt.Println(output.Section("Decision Engine"))
	fmt.Println(output.KV("Target", b.target, 9))
	mode := "safe — destructive actions withheld"
	if b.destructive {
		mode = "destructive — operator consent granted"
	}
	fmt.Println(output.KV("Mode", mode, 9))
	fmt.Println(output.KV("Actions", fmt.Sprintf("%d", len(b.actions)), 9))
	fmt.Println()
	fmt.Println("  " + output.Rule(56))
	fmt.Println()

	for {
		select {
		case <-ctx.Done():
			fmt.Println(styleYellow.Render("\n  interrupted by operator"))
			return b.buildReport(step)
		default:
		}

		chainActions := b.chainer.DetectAndExecute(ctx, b.target, b.kb, b.client)
		for _, ca := range chainActions {
			// Chains execute outside the planner, so the consent gate has
			// to be re-checked here — no dispatch path bypasses it.
			if ca.Metadata().Destructive && !b.destructive {
				continue
			}
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
			note := ""
			if newAction.Metadata().Destructive && !b.destructive {
				note = " · withheld: run with --destructive"
			}
			fmt.Printf("  %s %s%s\n",
				output.FaintStyle.Render("└"),
				output.MutedStyle.Render("spawned: "+newAction.Metadata().Name),
				output.FaintStyle.Render(note),
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

	// A chain whose every required capability is verified is still a
	// HYPOTHESIS: every chain action above emits PoC/hypothesis output and
	// contacts nothing. Its score is therefore weighted as a lead and
	// capped below the confirmed-high finding floor (7.5) — an unexecuted
	// pattern can never outscore executed evidence. The per-chain
	// "risk if executed" stays visible in the report.
	const chainHypothesisCap = 7.0

	maxRisk := 0.0
	for _, c := range chains {
		if c.RiskScore > maxRisk {
			maxRisk = c.RiskScore
		}
	}
	if maxRisk > 0 {
		riskScore = maxRisk
		if riskScore > chainHypothesisCap {
			riskScore = chainHypothesisCap
		}
		impact = "Attack-chain hypotheses from verified capabilities (compound attack not executed)"
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
		Target:             b.target,
		Duration:           dur,
		Steps:              steps,
		Impact:             impact,
		RiskScore:          riskScore,
		AttackChains:       chains,
		Findings:           b.kb.GetFindings(),
		Capabilities:       b.kb.GetCapabilities(),
		Credentials:        b.kb.GetCredentials(),
		Endpoints:          b.kb.GetEndpoints(),
		Pages:              b.kb.GetPages(),
		PendingDestructive: b.planner.PendingDestructive(b.kb),
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
	return output.SeverityColor(string(s))
}

func (b *Brain) renderProgress(step int, name, desc string, remaining int) {
	elapsed := time.Since(b.startAt).Round(time.Second)

	stepHeader := fmt.Sprintf("Step %d/%d", step, step+remaining)
	if remaining == 0 {
		stepHeader = fmt.Sprintf("Step %d", step)
	}

	// One line per step: position, elapsed, action, intent. No boxes —
	// the action name carries the emphasis, the rest stays quiet.
	line := "  " + styleMuted.Render(stepHeader) + "  " +
		output.ValueStyle.Render(name)
	if desc != "" {
		line += "  " + output.MutedStyle.Render(desc)
	}
	line += "  " + output.FaintStyle.Render("· "+elapsed.String())
	fmt.Println(line)
}

func (b *Brain) renderFinding(f Finding) {
	sym := "·"
	switch f.Severity {
	case SevCritical, SevHigh:
		sym = "■"
	case SevMedium:
		sym = "◆"
	case SevLow:
		sym = "◇"
	}
	label := strings.ToUpper(string(f.Severity))
	if label == "" {
		label = "INFO"
	}
	sev := output.SeverityStyle(string(f.Severity))
	// Sanity at the render sink: finding text carries remote content.
	fmt.Printf("  %s %s %s\n",
		sev.Render(sym),
		lipgloss.NewStyle().Foreground(severityColor(f.Severity)).Width(8).Render(label),
		output.ValueStyle.Render(types.Sanitize(f.Name)),
	)
	if f.Evidence != "" {
		// Rune-safe truncation: evidence is remote unicode; byte slicing
		// would emit a corrupted partial rune into the terminal.
		ev := []rune(types.Sanitize(f.Evidence))
		if len(ev) > 120 {
			ev = append(ev[:117], []rune("…")...)
		}
		fmt.Println(output.MutedStyle.Padding(0, 0, 0, 10).Render(string(ev)))
	}
}

func (b *Brain) RenderReport(report *Report) {
	fmt.Println()
	fmt.Println("  " + output.Rule(56))
	fmt.Println(output.Section("Attack Report"))
	fmt.Println("  " + output.Rule(56))
	fmt.Println()

	rows := [][2]string{
		{"Target", report.Target},
		{"Duration", fmt.Sprintf("%.0fs", report.Duration.Seconds())},
		{"Steps", fmt.Sprintf("%d", report.Steps)},
		{"Risk Score", fmt.Sprintf("%.1f/10", report.RiskScore)},
	}
	for _, r := range rows {
		fmt.Printf("  %s %s\n", styleLabel.Render(r[0]), styleValue.Render(r[1]))
	}
	fmt.Println()

	fmt.Println(output.Section("Impact Summary"))
	fmt.Println(output.MutedStyle.Render("  " + types.Sanitize(report.Impact)))
	fmt.Println()

	if len(report.AttackChains) > 0 {
		fmt.Println(output.Section("Attack Chains  (hypotheses — compound attack not executed)"))
		fmt.Println()
		for _, chain := range report.AttackChains {
			fmt.Printf("  %s %s\n",
				styleRed.Render("■"),
				output.ValueStyle.Render(types.Sanitize(chain.Name)),
			)
			fmt.Printf("  %s\n", output.MutedStyle.Render(fmt.Sprintf("    risk %.0f/10 if executed  ·  %s", chain.RiskScore, types.Sanitize(chain.Impact))))
			fmt.Println()
		}
	}

	findings := report.Findings
	if len(findings) > 0 {
		fmt.Println(output.Section("Findings"))
		fmt.Println()
		for _, f := range findings {
			b.renderFinding(f)
		}
		fmt.Println()
	}

	if len(report.Credentials) > 0 {
		fmt.Println(output.Section("Credentials"))
		fmt.Println()
		for _, c := range report.Credentials {
			if c.Valid {
				fmt.Printf("  %s %s\n", styleRed.Render("■"),
					output.ValueStyle.Render(types.Sanitize(c.Username)+":"+types.Sanitize(c.Password))+" "+styleRed.Render("valid"))
			} else {
				fmt.Printf("  %s %s\n", output.FaintStyle.Render("·"),
					output.MutedStyle.Render(types.Sanitize(c.Username)+":"+types.Sanitize(c.Password))+" "+output.FaintStyle.Render("tested"))
			}
		}
		fmt.Println()
	}

	if len(report.Endpoints) > 0 {
		fmt.Println(output.Section("Endpoints Discovered"))
		fmt.Println()
		for _, e := range report.Endpoints {
			method := output.FaintStyle.Render(e.Method)
			statusStr := ""
			if e.Status > 0 {
				statusStr = fmt.Sprintf(" [%d]", e.Status)
			}
			fmt.Printf("  %s %s%s\n", method, output.ValueStyle.Render(types.Sanitize(e.Path)), output.MutedStyle.Render(statusStr))
		}
		fmt.Println()
	}

	if len(report.Pages) > 0 {
		fmt.Println(output.Section(fmt.Sprintf("Pages Crawled (%d)", len(report.Pages))))
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
			fmt.Printf("  %s %s\n",
				output.ValueStyle.Render(types.Sanitize(p.URL)),
				output.MutedStyle.Render(detail),
			)
		}
		fmt.Println()
	}

	// The capability board is engine bookkeeping, not evidence: it now
	// sits after the observed surface (pages/endpoints) so the report
	// leads with what was actually seen. The origin markers stay visible
	// because the whole point is that a hint is not an observation.
	if len(report.Capabilities) > 0 {
		fmt.Println(output.Section("Engine Knowledge  (✓ verified · ≈ observed · ? hint)"))
		fmt.Println()
		for _, c := range report.Capabilities {
			label := "✓ " + c.Name
			style := output.GoodStyle
			switch c.Origin {
			case OriginHint:
				label = "? " + c.Name
				style = output.FaintStyle
			case OriginObserved:
				label = "≈ " + c.Name
				style = output.MutedStyle
			}
			fmt.Printf("  %s\n", style.Render(types.Sanitize(label)))
		}
		fmt.Println()
	}

	summary := b.kb.ReportDir.GenerateSummary()
	fmt.Println(output.Section("Extracted Data"))
	fmt.Println(output.MutedStyle.Render("  " + summary))
	fmt.Println()

	if len(report.PendingDestructive) > 0 {
		fmt.Println(output.Section("Withheld — consent required"))
		fmt.Println(output.MutedStyle.Render("  " + strings.Join(report.PendingDestructive, ", ")))
		fmt.Println(output.FaintStyle.Render("  These actions met their evidence requirements but write to or bulk-read the target; run with --destructive to execute them."))
		fmt.Println()
	}

	fmt.Println("  " + output.Rule(56))
	fmt.Println(output.MutedStyle.Render("  Attack complete."))
}
