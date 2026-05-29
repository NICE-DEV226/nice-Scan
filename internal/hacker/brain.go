package hacker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/NICE-DEV226/nice-Scan/internal/transport"
)

var (
	clCyan   = lipgloss.Color("#7DCFFF")
	clMuted  = lipgloss.Color("#565F89")
	clRed    = lipgloss.Color("#F7768E")
	clGreen  = lipgloss.Color("#9ECE6A")
	clYellow = lipgloss.Color("#E0AF68")
	clPurple = lipgloss.Color("#BB9AF7")
	clOrange = lipgloss.Color("#FF9E64")
	clDim    = lipgloss.Color("#3B4261")

	styleHeader = lipgloss.NewStyle().Bold(true).Foreground(clCyan)
	styleMuted  = lipgloss.NewStyle().Foreground(clMuted)
	styleRed    = lipgloss.NewStyle().Foreground(clRed).Bold(true)
	styleGreen  = lipgloss.NewStyle().Foreground(clGreen)
	styleYellow = lipgloss.NewStyle().Foreground(clYellow)
	stylePurple = lipgloss.NewStyle().Foreground(clPurple)
	styleOrange = lipgloss.NewStyle().Foreground(clOrange)
	styleLabel  = lipgloss.NewStyle().Foreground(clMuted).Width(12).Align(lipgloss.Right)
	styleValue  = lipgloss.NewStyle().Foreground(clCyan)
	styleCyan   = lipgloss.NewStyle().Foreground(clCyan)

	severitySymbol = map[Severity]string{
		SevCritical: "!!",
		SevHigh:     "▸",
		SevMedium:   "›",
		SevLow:      "·",
		SevInfo:     "•",
	}
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
			capStrs = append(capStrs, lipgloss.NewStyle().Foreground(clGreen).Render(c.Name))
		}
		fmt.Printf("  %s %s\n",
			lipgloss.NewStyle().Foreground(clDim).Render("└"),
			strings.Join(capStrs, " "),
		)
	}
	fmt.Println()
}

func (b *Brain) buildReport(steps int) *Report {
	dur := time.Since(b.startAt)
	chains := b.chainer.DetectChains(b.kb)
	impact := "No significant vulnerabilities discovered"
	riskScore := 0.0

	maxRisk := 0.0
	for _, c := range chains {
		if c.RiskScore > maxRisk {
			maxRisk = c.RiskScore
		}
	}
	if maxRisk > 0 {
		riskScore = maxRisk
		impact = "Multiple attack chains detected"
		for _, c := range chains {
			impact += fmt.Sprintf("; %s", c.Name)
		}
	}

	creds := b.kb.GetCredentials()
	if len(creds) > 0 && riskScore < 9.0 {
		riskScore = 9.0
		impact = "Valid credentials obtained — account compromise confirmed"
	}

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

	jwts := b.kb.GetJWTs()
	for _, j := range jwts {
		if j.Algorithm == "none" {
			riskScore = 10.0
			impact = "JWT forged with alg=none — full account takeover possible"
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
	fmt.Printf("  %s %s %s\n",
		sevStyle.Render(sym),
		lipgloss.NewStyle().Foreground(severityColor(f.Severity)).Width(8).Render(label),
		lipgloss.NewStyle().Foreground(severityColor(f.Severity)).Render(f.Name),
	)
	if f.Evidence != "" {
		ev := f.Evidence
		if len(ev) > 120 {
			ev = ev[:117] + "..."
		}
		fmt.Println(styleMuted.Render(fmt.Sprintf("         %s", ev)))
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
	fmt.Println(styleMuted.Render(fmt.Sprintf("  %s", report.Impact)))
	fmt.Println()

	if len(report.AttackChains) > 0 {
		fmt.Println(styleHeader.Render("  Attack Chains Discovered"))
		fmt.Println()
		for _, chain := range report.AttackChains {
			fmt.Printf("  %s %s\n",
				styleRed.Render("⚡"),
				styleRed.Bold(true).Render(chain.Name),
			)
			fmt.Printf("  %s Risk: %.0f/10\n", styleMuted.Render("  "), chain.RiskScore)
			fmt.Printf("  %s %s\n", styleMuted.Render("  →"), chain.Impact)
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

	if len(report.Capabilities) > 0 {
		fmt.Println(styleHeader.Render("  Capabilities Acquired"))
		fmt.Println()
		for _, c := range report.Capabilities {
			fmt.Printf("  %s %s\n", styleGreen.Render("✓"), styleCyan.Render(c.Name))
		}
		fmt.Println()
	}

	if len(report.Credentials) > 0 {
		fmt.Println(styleHeader.Render("  Credentials Obtained"))
		fmt.Println()
		for _, c := range report.Credentials {
			if c.Valid {
				fmt.Printf("  %s %s:%s %s\n", styleRed.Render("◈"), c.Username, c.Password, styleGreen.Render("✓ valid"))
			} else {
				fmt.Printf("  %s %s:%s %s\n", styleMuted.Render("·"), c.Username, c.Password, styleMuted.Render("tested"))
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
			fmt.Printf("  %s %s%s\n", method, styleCyan.Render(e.Path), styleMuted.Render(statusStr))
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
				styleCyan.Render(p.URL),
				styleMuted.Render(detail),
			)
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
