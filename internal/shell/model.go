package shell

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/engine"
	"github.com/NICE-DEV226/nice-Scan/internal/exploit"
	"github.com/NICE-DEV226/nice-Scan/internal/fingerprint"
	"github.com/NICE-DEV226/nice-Scan/internal/output"
	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	// Surfaces — sourced from the shared design system.
	clBorder = output.Line
	clPrompt = output.Accent
	clName   = output.Ink
	clMuted  = output.Muted
	clDim    = output.Faint
	clCoral  = output.Fail

	// Styles
	promptStyle = lipgloss.NewStyle().Foreground(clPrompt).Bold(true)

	panelSep = lipgloss.NewStyle().Foreground(clBorder).Render(strings.Repeat("─", 72))

	severityLabel = map[types.Severity]string{
		types.SeverityCritical: "CRITICAL",
		types.SeverityHigh:     "HIGH",
		types.SeverityMedium:   "MEDIUM",
		types.SeverityLow:      "LOW",
		types.SeverityInfo:     "INFO",
	}

	severitySym = map[types.Severity]string{
		types.SeverityCritical: "■",
		types.SeverityHigh:     "■",
		types.SeverityMedium:   "◆",
		types.SeverityLow:      "◇",
		types.SeverityInfo:     "○",
	}

	commands = []struct {
		name string
		desc string
		args string
	}{
		{"scan", "Full security scan (passive + active)", "<url>"},
		{"audit", "Deep audit with ALL checks + verbose", "<url>"},
		{"exploit", "Active exploitation (state-writing modules need consent)", "<url>"},
		{"tech", "Technology detection (165 signatures)", "<url>"},
		{"tls", "TLS/SSL configuration analysis", "<url>"},
		{"consent", "Grant/revoke state-modifying consent", "[on|off]"},
		{"clear", "Clear output", ""},
		{"list", "Show session targets and findings", ""},
		{"help", "Show available commands", ""},
		{"exit", "Exit the shell", ""},
	}
)

type session struct {
	targets  []string
	findings []types.Finding
	requests int
	duration time.Duration
	mu       sync.Mutex
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func (s *session) add(target string, findings []types.Finding, reqs int, dur time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.targets = append(s.targets, target)
	s.findings = append(s.findings, findings...)
	s.requests += reqs
	s.duration += dur
}

func (s *session) display() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	parts := []string{}
	if len(s.targets) > 0 {
		parts = append(parts, fmt.Sprintf("%d target(s)", len(s.targets)))
	}
	if len(s.findings) > 0 {
		parts = append(parts, fmt.Sprintf("%d finding(s)", len(s.findings)))
	}
	if s.requests > 0 {
		parts = append(parts, fmt.Sprintf("%d requests", s.requests))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " · ")
}

type Model struct {
	input textinput.Model

	output  []string
	session session
	cfg     *types.Config
	client  *transport.Client
	// stacks caches the classified server-side profile per target for the
	// whole shell session: the fingerprint is read once, then every later
	// scan/fuzz command conditions on it without re-fetching the homepage.
	stacks       map[string]fingerprint.Stack
	ready        bool
	quitting     bool
	width        int
	height       int
	scrollOffset int
}

func NewModel(cfg *types.Config) (*Model, error) {
	ti := textinput.New()
	ti.Placeholder = "Type a command (help for list)"
	ti.PromptStyle = promptStyle
	ti.Cursor.Style = lipgloss.NewStyle().Foreground(clPrompt)
	ti.CharLimit = 256
	ti.Width = 60
	ti.Focus()

	shellClientOpts := []transport.ClientOption{
		transport.WithTimeout(cfg.Timeout),
		transport.WithRetries(cfg.Retries),
		transport.WithFollowRedirects(cfg.FollowRedirects),
		transport.WithMaxRedirects(cfg.MaxRedirects),
		// Parity with the CLI paths: the shell previously dropped the
		// operator's proxy, cookie and header credentials, so scans run
		// from the interactive session on an authenticated app looked
		// like an unauthenticated client (missed findings / different
		// server behavior).
		transport.WithProxy(cfg.Proxy),
	}
	if cfg.Cookie != "" {
		shellClientOpts = append(shellClientOpts, transport.WithCookie(cfg.Cookie))
	}
	if len(cfg.Headers) > 0 {
		shellClientOpts = append(shellClientOpts, transport.WithHeaders(cfg.Headers))
	}
	if cfg.RateLimit > 0 {
		shellClientOpts = append(shellClientOpts, transport.WithRateLimit(cfg.RateLimit))
	}
	client := transport.NewClient(shellClientOpts...)

	welcome := []string{
		"",
		output.Section("nice-scan shell"),
		"",
		lipgloss.NewStyle().Foreground(clMuted).Padding(0, 2).Render("  scan <url>   Full security scan (all modules)"),
		lipgloss.NewStyle().Foreground(clMuted).Padding(0, 2).Render("  audit <url>  Deep audit, verbose, HTML report"),
		lipgloss.NewStyle().Foreground(clMuted).Padding(0, 2).Render("  exploit <url>  Active exploitation modules"),
		lipgloss.NewStyle().Foreground(clMuted).Padding(0, 2).Render("  tech <url>   Technology fingerprinting"),
		lipgloss.NewStyle().Foreground(clMuted).Padding(0, 2).Render("  tls <url>    TLS/SSL configuration analysis"),
		lipgloss.NewStyle().Foreground(clMuted).Padding(0, 2).Render("  help         Full command list  ·  exit  Quit"),
		"",
		lipgloss.NewStyle().Foreground(clDim).Padding(0, 2).Render("  Tab: autocomplete  ·  PgUp/PgDn: scroll  ·  Ctrl+C: quit"),
		"",
	}
	m := &Model{
		input:        ti,
		cfg:          cfg,
		client:       client,
		stacks:       map[string]fingerprint.Stack{},
		output:       welcome,
		scrollOffset: 0,
	}

	return m, nil
}

func (m *Model) Init() tea.Cmd {
	return tea.Batch(
		textinput.Blink,
		tea.SetWindowTitle("NICE_SCAN — Interactive Shell"),
	)
}

type cmdResultMsg []string

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.ready = true
		return m, nil

	case tea.MouseMsg:
		if msg.Action == tea.MouseActionPress {
			switch msg.Button {
			case tea.MouseButtonWheelUp:
				m.scrollOffset += 2
				m.clampScroll()
				return m, nil
			case tea.MouseButtonWheelDown:
				m.scrollOffset -= 2
				m.clampScroll()
				return m, nil
			}
		}
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			m.quitting = true
			return m, tea.Quit

		case "tab":
			m.autocomplete()
			return m, nil

		case "shift+up", "pgup":
			m.scrollOffset += 3
			m.clampScroll()
			return m, nil

		case "shift+down", "pgdown":
			m.scrollOffset -= 3
			m.clampScroll()
			return m, nil

		case "home":
			m.scrollOffset = m.maxScrollOffset()
			m.clampScroll()
			return m, nil

		case "end":
			m.scrollOffset = 0
			return m, nil

		case "enter":
			line := strings.TrimSpace(m.input.Value())
			if line == "" {
				return m, nil
			}

			m.output = append(m.output, promptStyle.Render("❯ "+line))
			m.input.Reset()
			m.scrollOffset = 0

			cmd, args := parseLine(line)
			switch cmd {
			case "exit", "quit", "q":
				m.quitting = true
				return m, tea.Quit
			case "clear", "cls":
				m.output = nil
				return m, nil
			case "help", "?":
				m.output = append(m.output, m.helpText()...)
				return m, nil
			case "list", "ls":
				m.output = append(m.output, m.listSession()...)
				return m, nil
			case "consent":
				state := "off"
				if m.cfg.Destructive {
					state = "on"
				}
				arg := ""
				if len(args) > 0 {
					arg = strings.ToLower(args[0])
				}
				switch arg {
				case "on":
					m.cfg.Destructive = true
					m.output = append(m.output,
						output.WarnStyle.Render(`  ⚠ consent granted — state-modifying modules (login spray, role tampering) may now POST to targets.`),
						output.FaintStyle.Render("  Revoke with 'consent off'. Authorized targets only."),
					)
				case "off":
					m.cfg.Destructive = false
					m.output = append(m.output,
						output.MutedStyle.Render("  consent revoked — state-modifying modules withheld again."),
					)
				default:
					m.output = append(m.output,
						output.MutedStyle.Render("  destructive consent: "+state),
						output.FaintStyle.Render("  usage: consent on | consent off"),
					)
				}
				return m, nil
			case "scan", "audit", "exploit", "tech", "tls":
				if len(args) == 0 {
					m.output = append(m.output, lipgloss.NewStyle().Foreground(clCoral).Render("  Missing URL. Usage: "+cmd+" <url>"))
					return m, nil
				}
				return m, m.exec(cmd, args[0])
			default:
				m.output = append(m.output, lipgloss.NewStyle().Foreground(clCoral).Render("  Unknown command: "+cmd))
				m.output = append(m.output, lipgloss.NewStyle().Foreground(clMuted).Render("  Type 'help' for available commands."))
				return m, nil
			}
		}

	case cmdResultMsg:
		m.output = append(m.output, msg...)
		m.scrollOffset = 0
		return m, nil
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m *Model) View() string {
	if !m.ready {
		return output.RenderLogoCompact() + "\n\n" + lipgloss.NewStyle().Foreground(clMuted).Render("  Initializing...")
	}

	var b strings.Builder

	b.WriteString(output.RenderLogoCompact())
	b.WriteString("\n")

	sessionInfo := m.session.display()
	if sessionInfo != "" {
		b.WriteString(lipgloss.NewStyle().Foreground(clMuted).Padding(0, 2).Render(sessionInfo))
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Foreground(clDim).Padding(0, 2).Render(panelSep))
		b.WriteString("\n")
	}

	visible := m.output
	pageSize := m.scrollPageSize()
	if len(visible) > pageSize {
		start := len(visible) - pageSize - m.scrollOffset
		if start < 0 {
			start = 0
		}
		end := start + pageSize
		if end > len(visible) {
			end = len(visible)
		}
		visible = visible[start:end]
	}

	for _, line := range visible {
		b.WriteString(line)
		b.WriteString("\n")
	}

	b.WriteString("\n")
	scrollInfo := ""
	total := len(m.output)
	showing := len(visible)
	if total > showing {
		scrollInfo = fmt.Sprintf("  (pg↑↓ scroll · %d/%d lines)", showing, total)
	}
	b.WriteString(lipgloss.NewStyle().Foreground(clDim).Padding(0, 2).Render(panelSep + scrollInfo))
	b.WriteString("\n")
	b.WriteString("\n")
	b.WriteString(m.input.View())

	return lipgloss.NewStyle().Padding(0, 2).Render(b.String())
}

// shellTargetScope normalizes a user-typed interactive target and derives
// the credential scope to bind for the shell's shared client for that one
// command. Normalized target is always returned; scope is empty when the
// input is degenerate (scheme-detection is case-insensitive, pseudo-hosts
// like "https" or colon artifacts must never become a credential scope).
func shellTargetScope(target string) (normalized, scope string) {
	lower := strings.ToLower(target)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		target = "https://" + target
	}
	normalized = strings.TrimRight(target, "/")
	scope = transport.HostDomain(normalized)
	// Degenerate inputs must fail closed: an empty or colon-artifact host
	// (":", "::", ...) would otherwise become the credential scope — and a
	// single-label name like "https" is resolvable inside corporate search
	// domains, so operator cookies must never bind to it.
	if parsed, err := url.Parse(normalized); err != nil || parsed.Host == "" || strings.HasPrefix(parsed.Host, ":") {
		return normalized, ""
	}
	return normalized, scope
}

func (m *Model) exec(cmd string, target string) tea.Cmd {
	return func() tea.Msg {
		// Interactive targets are user-typed. Bind operator credentials to
		// that host for this command: the shared shell client must not send
		// them to other origins the scan may touch (redirects, crawl).
		target, scope := shellTargetScope(target)
		if scope != "" {
			m.client.SetCredScope(scope)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		var lines []string
		var findings []types.Finding
		var stats engine.ScanStats

		switch cmd {
		case "scan":
			scanner := engine.NewScanner(m.cfg, m.client)
			scanner.RegisterAnalyzers(
				fingerprint.New(),
				engine.NewHeaderAnalyzer(),
				engine.NewTLSAnalyzer(),
				engine.NewExposureAnalyzer(),
				engine.NewSQLiAnalyzer(),
				engine.NewXSSAnalyzer(scanner.XSSCanary()),
				engine.NewCORSAnalyzer(),
				engine.NewHTTPMethodsAnalyzer(),
				engine.NewTokenExtractor(),
				engine.NewAuthAnalyzer(),
				engine.NewPrivilegeEscalationAnalyzer(),
				engine.NewDataExtractionAnalyzer(),
			)
			m.seedStack(scanner, target)
			result := scanner.Scan(ctx, []string{target})
			m.cacheStacks(scanner)
			findings = result.Findings
			stats = result.Stats
			lines = append(m.renderStacks(result.Stacks), m.renderFindings(result.Findings, result.Stats)...)

		case "tech":
			scanner := engine.NewScanner(m.cfg, m.client)
			scanner.RegisterAnalyzer(fingerprint.New())
			m.seedStack(scanner, target)
			result := scanner.Scan(ctx, []string{target})
			m.cacheStacks(scanner)
			findings = result.Findings
			stats = result.Stats
			lines = append(m.renderStacks(result.Stacks), m.renderFindings(result.Findings, result.Stats)...)

		case "tls":
			scanner := engine.NewScanner(m.cfg, m.client)
			scanner.RegisterAnalyzer(engine.NewTLSAnalyzer())
			result := scanner.Scan(ctx, []string{target})
			findings = result.Findings
			stats = result.Stats
			lines = m.renderFindings(result.Findings, result.Stats)

		case "audit":
			m.cfg.Verbose = true
			scanner := engine.NewScanner(m.cfg, m.client)
			scanner.RegisterAnalyzers(
				fingerprint.New(),
				engine.NewHeaderAnalyzer(),
				engine.NewTLSAnalyzer(),
				engine.NewExposureAnalyzer(),
				engine.NewSQLiAnalyzer(),
				engine.NewXSSAnalyzer(scanner.XSSCanary()),
				engine.NewCORSAnalyzer(),
				engine.NewHTTPMethodsAnalyzer(),
				engine.NewTokenExtractor(),
				engine.NewAuthAnalyzer(),
				engine.NewPrivilegeEscalationAnalyzer(),
				engine.NewDataExtractionAnalyzer(),
			)
			m.seedStack(scanner, target)
			result := scanner.Scan(ctx, []string{target})
			m.cacheStacks(scanner)
			findings = result.Findings
			stats = result.Stats
			lines = append(m.renderStacks(result.Stacks), m.renderFindings(result.Findings, result.Stats)...)

		case "exploit":
			opts := exploit.Options{
				Target:  target,
				Verbose: m.cfg.Verbose,
			}
			exp := exploit.New(m.client, opts)

			var expLines []string
			expLines = append(expLines, "")

			// Same consent model as the CLI: credential spraying and
			// tampered role POSTs write to the target. Grant it in-session
			// with "consent on" (or start the shell with --destructive).
			var sprayReqs int
			if m.cfg.Destructive {
				expLines = append(expLines, output.Section("Login Bruteforce"))
				loginResults := exp.BruteforceLogin(ctx, target, exploit.CommonCredentials)
				sprayReqs += len(loginResults)
				for _, r := range loginResults[:min(len(loginResults), 5)] {
					cl := clMuted
					sym := "✗"
					if r.Success {
						cl = clCoral
						sym = "✓"
					}
					// The password NEVER rides the terminal in plaintext, not
					// even on a verified hit — a working credential is what
					// most needs keeping out of scrollback and logs. The
					// operator uses the captured session (--access) to act
					// on it; the mask proves which pair the differential
					// accepted without disclosing the secret itself.
					shown := r.Username
					if r.Success {
						shown = r.Username + ":" + types.MaskSecret(r.Password)
					}
					expLines = append(expLines, lipgloss.NewStyle().Foreground(cl).Padding(0, 4).Render(
						fmt.Sprintf("  %s %s → %d", sym, shown, r.StatusCode),
					))
				}

				expLines = append(expLines, "")
				expLines = append(expLines, output.Section("Role / Privilege Escalation"))
				roleResults := exp.RoleTampering(ctx, target)
				sprayReqs += len(roleResults)
				found := false
				for _, r := range roleResults {
					if !r.Success {
						continue
					}
					found = true
					expLines = append(expLines, lipgloss.NewStyle().Foreground(clCoral).Padding(0, 4).Render(
						fmt.Sprintf("  ✓ %s=%s %s → %d", r.Parameter, r.Value, r.Method, r.StatusCode),
					))
					if len(expLines) > 20 {
						break
					}
				}
				if !found {
					expLines = append(expLines, lipgloss.NewStyle().Foreground(clMuted).Padding(0, 4).Render("  — No privilege escalation found"))
				}
			} else {
				expLines = append(expLines, output.MutedStyle.Render(
					`  Login bruteforce and role tampering withheld — state-modifying. Type "consent on" to grant them for this session.`,
				))
			}

			expLines = append(expLines, "")
			expLines = append(expLines, output.Section("IDOR Enumeration"))
			idorResults := exp.IDOREnumeration(ctx, target, "", 1, 5)
			// Per-surface modal baseline (mirrors the exploit command): an
			// absolute "BodySize > 500" heuristic painted ordinary pages coral
			// as if they were hits. A referent is interesting only when it
			// differs from the OTHER ids of the SAME endpoint.
			surfaceMode := map[string]int{}
			{
				type hist struct {
					counts map[int]int
				}
				hists := map[string]*hist{}
				for _, r := range idorResults {
					h := hists[r.Surface]
					if h == nil {
						h = &hist{counts: map[int]int{}}
						hists[r.Surface] = h
					}
					h.counts[r.BodySize]++
				}
				for surf, h := range hists {
					best, mode := -1, 0
					for size, c := range h.counts {
						if c > best {
							mode, best = size, c
						}
					}
					surfaceMode[surf] = mode
				}
			}
			notable := 0
			for _, r := range idorResults[:min(len(idorResults), 10)] {
				cl := clMuted
				if base, ok := surfaceMode[r.Surface]; ok && absInt(r.BodySize-base) > 100 {
					cl = clCoral
					notable++
				}
				expLines = append(expLines, lipgloss.NewStyle().Foreground(cl).Padding(0, 4).Render(
					fmt.Sprintf("  %s=%d → %d (%d bytes)", r.ParamType, r.ID, r.StatusCode, r.BodySize),
				))
			}
			if notable == 0 {
				expLines = append(expLines, output.MutedStyle.Render(
					"  — every id within each endpoint returned the same size: identifier ignored or consistently authorized",
				))
			}
			expLines = append(expLines, "")
			expLines = append(expLines, lipgloss.NewStyle().Foreground(clMuted).Padding(0, 2).Render(
				fmt.Sprintf("  Exploit completed — %d total requests", sprayReqs+len(idorResults)),
			))

			lines = expLines
		}

		m.session.add(target, findings, stats.Completed, stats.Duration)

		return cmdResultMsg(lines)
	}
}

// seedStack hands the session-cached fingerprint to a fresh scanner (known
// stacks skip phase-1 entirely), and cacheStacks stores what the scan just
// classified — one stack read per target for the whole shell session.
func (m *Model) seedStack(s *engine.Scanner, target string) {
	if st, ok := m.stacks[target]; ok {
		s.SeedStack(target, st)
	}
}

func (m *Model) cacheStacks(s *engine.Scanner) {
	for t, st := range s.Stacks() {
		if st.Known() {
			m.stacks[t] = st
		}
	}
}

// renderStacks puts the fingerprint-first detail on screen before the
// findings: the stack read from the homepage, and whether family-specific
// probes were conditioned on it.
func (m *Model) renderStacks(stacks []engine.StackReport) []string {
	var lines []string
	muted := lipgloss.NewStyle().Foreground(clMuted).Padding(0, 2)
	value := lipgloss.NewStyle().Foreground(output.Ink).Padding(0, 2)
	for _, st := range stacks {
		lines = append(lines, value.Render("  stack: "+st.Detail))
		if st.Conditioned {
			lines = append(lines, muted.Render("  probes: stack-conditioned (foreign-family paths skipped)"))
		} else {
			lines = append(lines, muted.Render("  probes: full set kept — no stack signal"))
		}
	}
	return lines
}

func (m *Model) renderFindings(findings []types.Finding, stats engine.ScanStats) []string {
	var lines []string

	if len(findings) == 0 {
		lines = append(lines, lipgloss.NewStyle().Foreground(clMuted).Padding(0, 2).Render("  No issues detected."))
		return lines
	}

	order := []types.Severity{
		types.SeverityCritical,
		types.SeverityHigh,
		types.SeverityMedium,
		types.SeverityLow,
		types.SeverityInfo,
	}

	for _, sev := range order {
		var group []types.Finding
		for _, f := range findings {
			if f.Severity == sev {
				group = append(group, f)
			}
		}
		if len(group) == 0 {
			continue
		}

		sym := severitySym[sev]
		label := severityLabel[sev]
		color := output.SeverityColor(string(sev))

		header := lipgloss.NewStyle().Foreground(color).Bold(true).Padding(0, 2).Render(fmt.Sprintf("  %s  %s  (%d)", sym, label, len(group)))
		lines = append(lines, "", header)

		for _, f := range group {
			name := lipgloss.NewStyle().Foreground(clName).Padding(0, 4).Render(f.Name)
			lines = append(lines, name)
			if f.Metadata != nil {
				if v, ok := f.Metadata["version"]; ok && v != "" {
					ver := lipgloss.NewStyle().Foreground(clDim).Padding(0, 6).Render(v)
					lines = append(lines, ver)
				}
			}
			if f.Evidence != "" {
				ev := truncate(f.Evidence, 68)
				lines = append(lines, lipgloss.NewStyle().Foreground(clMuted).Padding(0, 4).Render(ev))
			}
		}
	}

	summary := lipgloss.NewStyle().Foreground(clMuted).Padding(0, 2).Render(
		fmt.Sprintf("  %d/%d requests · %v", stats.Completed, stats.Total, stats.Duration.Round(time.Millisecond)),
	)
	lines = append(lines, "", summary)

	return lines
}

func (m *Model) autocomplete() {
	val := m.input.Value()
	parts := strings.Fields(val)
	current := strings.ToLower(val)

	if len(parts) <= 1 {
		for _, c := range commands {
			if strings.HasPrefix(c.name, current) && c.name != current {
				m.input.SetValue(c.name + " ")
				return
			}
		}
	}
}

func (m *Model) listSession() []string {
	m.session.mu.Lock()
	defer m.session.mu.Unlock()

	if len(m.session.targets) == 0 {
		return []string{lipgloss.NewStyle().Foreground(clMuted).Padding(0, 2).Render("  No targets scanned yet.")}
	}

	var lines []string
	lines = append(lines, "")
	lines = append(lines, lipgloss.NewStyle().Foreground(clName).Bold(true).Padding(0, 2).Render("  Session Summary"))
	lines = append(lines, "")
	lines = append(lines, lipgloss.NewStyle().Foreground(clMuted).Padding(0, 2).Render(fmt.Sprintf("  %d targets  ·  %d findings  ·  %d requests  ·  %s",
		len(m.session.targets), len(m.session.findings), m.session.requests, m.session.duration.Round(time.Second))))

	lines = append(lines, "")
	lines = append(lines, lipgloss.NewStyle().Foreground(clDim).Padding(0, 2).Render("  Targets:"))
	for _, t := range m.session.targets {
		lines = append(lines, lipgloss.NewStyle().Foreground(clMuted).Padding(0, 4).Render("  · "+t))
	}

	if len(m.session.findings) > 0 {
		lines = append(lines, "")
		lines = append(lines, lipgloss.NewStyle().Foreground(clDim).Padding(0, 2).Render("  Findings by Severity:"))
		bySev := map[types.Severity][]string{}
		order := []types.Severity{types.SeverityCritical, types.SeverityHigh, types.SeverityMedium, types.SeverityLow, types.SeverityInfo}
		for _, f := range m.session.findings {
			bySev[f.Severity] = append(bySev[f.Severity], f.Name)
		}
		for _, sev := range order {
			items := bySev[sev]
			if len(items) == 0 {
				continue
			}
			label := severityLabel[sev]
			sym := severitySym[sev]
			cl := output.SeverityColor(string(sev))
			lines = append(lines, lipgloss.NewStyle().Foreground(cl).Padding(0, 4).Render(fmt.Sprintf("  %s %s  (%d)", sym, label, len(items))))
			for _, item := range items {
				lines = append(lines, lipgloss.NewStyle().Foreground(clMuted).Padding(0, 6).Render("  · "+item))
			}
		}
	}

	lines = append(lines, "")
	return lines
}

func (m *Model) scrollPageSize() int {
	available := m.height - 7
	if available < 10 {
		available = 10
	}
	return available
}

func (m *Model) maxScrollOffset() int {
	pageSize := m.scrollPageSize()
	total := len(m.output)
	if total <= pageSize {
		return 0
	}
	return total - pageSize
}

func (m *Model) clampScroll() {
	max := m.maxScrollOffset()
	if m.scrollOffset > max {
		m.scrollOffset = max
	}
	if m.scrollOffset < 0 {
		m.scrollOffset = 0
	}
}

func (m *Model) helpText() []string {
	var lines []string
	lines = append(lines, "")
	lines = append(lines, lipgloss.NewStyle().Foreground(clName).Bold(true).Padding(0, 2).Render("  Commands:"))
	lines = append(lines, "")
	for _, c := range commands {
		name := lipgloss.NewStyle().Foreground(clName).Bold(true).Render("    " + c.name)
		args := lipgloss.NewStyle().Foreground(clMuted).Render(c.args)
		desc := lipgloss.NewStyle().Foreground(clMuted).Render(c.desc)
		line := fmt.Sprintf("%s %s  %s", name, args, desc)
		lines = append(lines, line)
	}
	lines = append(lines, "")
	lines = append(lines, lipgloss.NewStyle().Foreground(clDim).Padding(0, 2).Render("  Navigation:  ↑↓ history  ·  Tab complete  ·  PgUp/PgDn scroll  ·  Ctrl+C quit"))
	lines = append(lines, "")
	return lines
}

func (m *Model) Close() {
	if m.client != nil {
		// Close frees transport resources shared with the session; a
		// close error at this point has no interactive recovery path.
		_ = m.client.Close()
	}
}

func parseLine(line string) (string, []string) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return "", nil
	}
	return strings.ToLower(parts[0]), parts[1:]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
