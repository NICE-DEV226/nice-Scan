package shell

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"regexp"
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
		{"exploit", "Active exploitation chain (login, privesc, IDOR, token, discovered creds, access)", "<url> [--creds u:p] [--all]"},
		{"tech", "Technology detection (165 signatures)", "<url>"},
		{"tls", "TLS/SSL configuration analysis", "<url>"},
		{"consent", "Grant/revoke state-modifying consent", "[on|off]"},
		{"copy", "Copy last command output to clipboard (OSC 52)", "[all]"},
		{"history", "Show entered commands", ""},
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
	history      []string
	histIdx      int
	lastOutput   []string
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
		// --block-internal is baked into the dialer at construction: the
		// shell previously dropped it, so the guard the flag promises was
		// silently disarmed for every interactive scan.
		transport.WithPrivateNetworkAllowed(!cfg.BlockInternal),
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
		lipgloss.NewStyle().Foreground(clMuted).Padding(0, 2).Render("  exploit <url>  Login · privesc · IDOR · token · discovered creds · access"),
		lipgloss.NewStyle().Foreground(clMuted).Padding(0, 2).Render("  tech <url>   Technology fingerprinting"),
		lipgloss.NewStyle().Foreground(clMuted).Padding(0, 2).Render("  tls <url>    TLS/SSL configuration analysis"),
		lipgloss.NewStyle().Foreground(clMuted).Padding(0, 2).Render("  help         Full command list  ·  exit  Quit"),
		"",
		lipgloss.NewStyle().Foreground(clDim).Padding(0, 2).Render("  ↑/↓: command history  ·  Tab: autocomplete  ·  PgUp/PgDn: scroll  ·  Ctrl+Y / copy: clipboard  ·  Ctrl+C: quit"),
		"",
	}
	m := &Model{
		input:        ti,
		cfg:          cfg,
		client:       client,
		stacks:       map[string]fingerprint.Stack{},
		output:       welcome,
		histIdx:      0,
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

// cmdNoticeMsg appends lines to the scrollback WITHOUT replacing the copy
// buffer: a `copy` confirmation must not become the thing the next Ctrl+Y
// copies over the command output the operator actually wanted.
type cmdNoticeMsg []string

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

		case "up":
			m.recallHistory(-1)
			return m, nil

		case "down":
			m.recallHistory(1)
			return m, nil

		case "ctrl+y":
			return m, m.copyOutput(m.lastOutput, "last output")

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

			m.pushHistory(line)
			m.input.Reset()
			m.scrollOffset = 0

			m.output = append(m.output, promptStyle.Render("❯ "+line))

			cmd, args := parseLine(line)
			switch cmd {
			case "exit", "quit", "q":
				m.quitting = true
				return m, tea.Quit
			case "clear", "cls":
				m.output = nil
				return m, nil
			case "help", "?":
				lines := m.helpText()
				m.output = append(m.output, lines...)
				m.lastOutput = lines
				return m, nil
			case "list", "ls":
				lines := m.listSession()
				m.output = append(m.output, lines...)
				m.lastOutput = lines
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
			case "copy":
				scope, src := "last output", m.lastOutput
				if len(args) > 0 && strings.EqualFold(args[0], "all") {
					scope, src = "full scrollback", m.output
				}
				return m, m.copyOutput(src, scope)
			case "history":
				lines := m.historyText()
				m.output = append(m.output, lines...)
				m.lastOutput = lines
				return m, nil
			case "scan", "audit", "tech", "tls":
				if len(args) == 0 || strings.HasPrefix(args[0], "-") {
					m.output = append(m.output, lipgloss.NewStyle().Foreground(clCoral).Render("  Missing URL. Usage: "+cmd+" <url>"))
					return m, nil
				}
				return m, m.exec(cmd, args[0], runOpts{})
			case "exploit":
				target, o := parseRunArgs(args)
				if target == "" {
					m.output = append(m.output, lipgloss.NewStyle().Foreground(clCoral).Render("  Missing URL. Usage: exploit <url> [--creds u:p] [--cookie n=v] [--idor 1-50] [--all]"))
					return m, nil
				}
				return m, m.exec("exploit", target, o)
			default:
				m.output = append(m.output, lipgloss.NewStyle().Foreground(clCoral).Render("  Unknown command: "+cmd))
				m.output = append(m.output, lipgloss.NewStyle().Foreground(clMuted).Render("  Type 'help' for available commands."))
				return m, nil
			}
		}

	case cmdResultMsg:
		m.output = append(m.output, msg...)
		m.lastOutput = []string(msg)
		m.scrollOffset = 0
		return m, nil

	case cmdNoticeMsg:
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

func (m *Model) exec(cmd string, target string, o runOpts) tea.Cmd {
	return func() tea.Msg {
		// Interactive targets are user-typed. Bind operator credentials to
		// that host for this command: the shared shell client must not send
		// them to other origins the scan may touch (redirects, crawl).
		target, scope := shellTargetScope(target)
		// The interactive scan commands share one client across targets, so
		// the destination boundary is re-armed per command exactly like the
		// credential scope. Without this the shell silently ran with no
		// target allow-list: redirects could carry probes to any host even
		// though the CLI defaults EnforceScope on.
		if m.cfg.EnforceScope {
			if scope == "" {
				return cmdResultMsg{
					output.WarnStyle.Render("  refused: target has no usable host for the scope boundary — not scanned"),
				}
			}
			m.client.SetTargetScope(scope)
		}
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
			// The exploit service owns the boundary: scope and consent from
			// the operator's config, a client of its own. A target the shell
			// could not turn into a scope is refused before any module runs.
			exp, err := exploit.NewService(exploit.ServiceOptions{
				Config: m.cfg,
				Scope:  []string{scope},
				Target: target,
			})
			if err != nil {
				lines = append(lines, output.WarnStyle.Render("  exploit refused: "+err.Error()))
				break
			}
			defer func() { _ = exp.Close() }()
			if o.cookie != "" {
				exp.SetAuthCookie(o.cookie, "shell --cookie")
			}

			var expLines []string
			expLines = append(expLines, "")
			reqs := 0

			// Login: --creds is one explicit operator-owned attempt; otherwise
			// the 40-pair spray. Both POST to the target, so they need
			// in-session consent ("consent on" or start with --destructive).
			if m.cfg.Destructive {
				expLines = append(expLines, output.Section("Login Bruteforce"))
				switch {
				case o.creds != "":
					user, pass, ok := strings.Cut(o.creds, ":")
					if !ok || user == "" || pass == "" {
						expLines = append(expLines, output.MutedStyle.Render("  --creds wants user:pass — login skipped"))
					} else {
						a := exp.TryLogin(ctx, target, exploit.Credential{User: user, Pass: pass, Desc: "operator-supplied"})
						if a != nil {
							reqs++
							expLines = append(expLines, loginRow(*a))
							if a.Success && a.SetCookie != "" && exp.AttachHarvestedSession(a.SetCookie, "login "+a.Username) {
								expLines = append(expLines, output.MutedStyle.Render("  ✓ valid credential — session captured, --access will use it"))
							}
						}
					}
				default:
					loginResults, loginErr := exp.BruteforceLogin(ctx, target, exploit.CommonCredentials)
					if loginErr != nil {
						expLines = append(expLines, output.WarnStyle.Render("  login refused: "+loginErr.Error()))
					} else {
						reqs += len(loginResults)
						valid := 0
						for _, r := range loginResults {
							if r.Success {
								valid++
								expLines = append(expLines, loginRow(r))
								if r.SetCookie != "" && exp.AttachHarvestedSession(r.SetCookie, "login "+r.Username) {
									expLines = append(expLines, output.MutedStyle.Render("  ✓ valid credential — session captured (cookie "+exploit.ShortCookie(r.SetCookie)+"), --access will use it"))
								}
							}
						}
						expLines = append(expLines, output.MutedStyle.Render(fmt.Sprintf("  %d credential pair(s) tested — %d valid", len(loginResults), valid)))
					}
				}
				expLines = append(expLines, "")
			} else {
				expLines = append(expLines, output.MutedStyle.Render(
					`  login withheld — state-modifying. Type "consent on" to grant it (then retry, or pass --creds u:p).`,
				))
				expLines = append(expLines, "")
			}

			// Discovered Credential Access: a pair the target itself leaked
			// (JSON / form / base64 Basic on its login + admin pages), aimed at
			// its own form through the same differential verdict. Consent-gated.
			if m.cfg.Destructive {
				disc := exp.DiscoverCredentialPairs(ctx, target)
				if len(disc) > 0 {
					expLines = append(expLines, output.Section("Discovered Credential Access"))
					proven := 0
					for _, c := range disc {
						a := exp.TryLogin(ctx, target, c)
						shown := types.Sanitize(c.User) + " " + types.MaskSecret(c.Pass)
						if a != nil && a.Success {
							proven++
							expLines = append(expLines, output.MutedStyle.Render(fmt.Sprintf("  ✓ leaked pair VERIFIED (%s → %d): session captured — --access shows what it reaches", shown, a.StatusCode)))
						} else {
							expLines = append(expLines, output.MutedStyle.Render(fmt.Sprintf("  ! leaked pair (%s) exposed but not accepted on login — still a reportable leak", shown)))
						}
					}
					if proven == 0 {
						expLines = append(expLines, output.MutedStyle.Render(fmt.Sprintf("  %d pair(s) discovered; none verified as login-capable", len(disc))))
					}
					expLines = append(expLines, "")
				}
			}

			// Role / Privilege Escalation (differential, consent-gated).
			if m.cfg.Destructive {
				expLines = append(expLines, output.Section("Role / Privilege Escalation"))
				roleResults, roleErr := exp.RoleTampering(ctx, target)
				if roleErr != nil {
					expLines = append(expLines, output.WarnStyle.Render("  role module refused: "+roleErr.Error()))
				} else {
					reqs += len(roleResults)
					found := false
					for _, r := range roleResults {
						if !r.Success {
							continue
						}
						found = true
						expLines = append(expLines, lipgloss.NewStyle().Foreground(clCoral).Padding(0, 4).Render(
							fmt.Sprintf("  ✓ %s=%s %s → %d", types.Sanitize(r.Parameter), types.Sanitize(r.Value), r.Method, r.StatusCode),
						))
						if len(expLines) > 20 {
							break
						}
					}
					if !found {
						expLines = append(expLines, output.MutedStyle.Render("  — no role parameter affected privilege over the control round"))
					}
				}
				expLines = append(expLines, "")
			}

			// IDOR Enumeration (read-only): per-endpoint modal baseline, same
			// as the exploit command — an absolute size heuristic painted
			// ordinary pages as hits; a referent matters only vs its OWN endpoint.
			idorStart, idorEnd := 1, 5
			if o.all && o.idor == "" {
				idorEnd = 20
			}
			if o.idor != "" {
				if _, err := fmt.Sscanf(o.idor, "%d-%d", &idorStart, &idorEnd); err != nil {
					idorStart, idorEnd = 1, 5
				}
			}
			if idorStart <= 0 || idorEnd < idorStart {
				idorStart, idorEnd = 1, 5
			}
			if idorEnd-idorStart+1 > exploit.MaxIDORSpan {
				idorEnd = idorStart + exploit.MaxIDORSpan - 1
			}
			expLines = append(expLines, output.Section(fmt.Sprintf("IDOR Enumeration (%d-%d)", idorStart, idorEnd)))
			idorResults := exp.IDOREnumeration(ctx, target, "", idorStart, idorEnd)
			reqs += len(idorResults)
			surfaceMode := map[string]int{}
			{
				hists := map[string]map[int]int{}
				for _, r := range idorResults {
					if hists[r.Surface] == nil {
						hists[r.Surface] = map[int]int{}
					}
					hists[r.Surface][r.BodySize]++
				}
				for surf, counts := range hists {
					best, mode := -1, 0
					for size, c := range counts {
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

			// Token / Session Reuse (read-only): harvest real JWTs and session
			// cookies, replay them on protected endpoints. An empty harvest is
			// an honest skip — no placeholder is ever probed.
			expLines = append(expLines, output.Section("Token / Session Reuse"))
			tokens, discoveredCookies := exp.DiscoverTokens(ctx, target)
			if o.cookie != "" {
				discoveredCookies = append(discoveredCookies, o.cookie)
			}
			reuseShown := 0
			reuseHits := 0
			for _, r := range exp.TryTokenReuse(ctx, tokens, target) {
				if reuseShown >= 4 {
					break
				}
				if r.Success {
					reuseHits++
				}
				reuseShown++
				expLines = append(expLines, renderReuseRow(r))
			}
			for _, r := range exp.TrySessionReuse(ctx, discoveredCookies, target) {
				if reuseShown >= 4 {
					break
				}
				if r.Success {
					reuseHits++
				}
				reuseShown++
				expLines = append(expLines, renderReuseRow(r))
			}
			if reuseShown == 0 {
				expLines = append(expLines, output.MutedStyle.Render("  — no reusable token or session discovered: nothing to test"))
			} else {
				expLines = append(expLines, output.MutedStyle.Render(fmt.Sprintf("  %d token/session replay(s) tested — %d granted access", reuseShown, reuseHits)))
			}
			expLines = append(expLines, "")

			// Admin Access Verification (differential): the module that actually
			// answers "what does this session reach" — replays admin paths anon
			// vs with the harvested session and reports only REAL gains.
			expLines = append(expLines, output.Section("Admin Access Verification (differential)"))
			accessResults := exp.VerifiedAdminAccess(ctx, target)
			verified := 0
			sawNoSession := false
			for _, r := range accessResults {
				if r.Path == "(no session)" {
					sawNoSession = true
					expLines = append(expLines, output.MutedStyle.Render("  ○ "+truncate(r.Evidence, 92)))
					continue
				}
				cl := clMuted
				status := "○"
				if r.Success {
					cl = clCoral
					status = "✓"
					verified++
				}
				expLines = append(expLines, lipgloss.NewStyle().Foreground(cl).Padding(0, 4).Render(
					fmt.Sprintf("  %s %s → anon %d / session %d (%s)", status, r.Path, r.Anonymous, r.WithSess, truncate(r.Evidence, 64)),
				))
			}
			if cookie, source := exp.AuthCookie(); cookie != "" {
				expLines = append(expLines, output.MutedStyle.Render(
					fmt.Sprintf("  session in use: %s (source: %s)", exploit.ShortCookie(cookie), types.Sanitize(source)),
				))
			}
			if verified == 0 && !sawNoSession {
				expLines = append(expLines, output.MutedStyle.Render("  — no admin path answered differently with the session: no verified access gain"))
			}

			expLines = append(expLines, "")
			expLines = append(expLines, lipgloss.NewStyle().Foreground(clMuted).Padding(0, 2).Render(
				fmt.Sprintf("  Exploit completed — %d request(s)", reqs),
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
	lines = append(lines, lipgloss.NewStyle().Foreground(clDim).Padding(0, 2).Render("  Navigation:  ↑↓ history  ·  Tab complete  ·  PgUp/PgDn scroll  ·  Ctrl+Y / copy: clipboard  ·  Ctrl+C quit"))
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

// ── Command history ───────────────────────────────────────────────────────

const maxHistory = 200

// pushHistory records an entered command (deduping an immediate repeat) and
// parks the recall pointer at the fresh line, so the first ↑ yields the
// command just run.
func (m *Model) pushHistory(line string) {
	if line == "" {
		return
	}
	if n := len(m.history); n > 0 && m.history[n-1] == line {
		m.histIdx = n
		return
	}
	m.history = append(m.history, line)
	if len(m.history) > maxHistory {
		m.history = m.history[len(m.history)-maxHistory:]
	}
	m.histIdx = len(m.history)
}

// recallHistory walks the buffer: dir<0 → older (↑), dir>0 → newer (↓).
// histIdx==len(history) is the fresh, empty line.
func (m *Model) recallHistory(dir int) {
	n := len(m.history)
	if n == 0 {
		return
	}
	if m.histIdx > n {
		m.histIdx = n
	}
	ni := m.histIdx + dir
	if ni < 0 {
		ni = 0
	}
	if ni > n {
		ni = n
	}
	m.histIdx = ni
	if m.histIdx == n {
		m.input.SetValue("")
		m.input.SetCursor(0)
		return
	}
	v := m.history[m.histIdx]
	m.input.SetValue(v)
	m.input.SetCursor(len(v))
}

func (m *Model) historyText() []string {
	if len(m.history) == 0 {
		return []string{output.MutedStyle.Render("  No commands entered yet.")}
	}
	lines := []string{
		"",
		lipgloss.NewStyle().Foreground(clName).Bold(true).Padding(0, 2).Render("  Command history (oldest first)"),
	}
	for i, h := range m.history {
		lines = append(lines, lipgloss.NewStyle().Foreground(clMuted).Padding(0, 2).Render(
			fmt.Sprintf("  %3d  %s", i+1, types.Sanitize(h)),
		))
	}
	lines = append(lines, "")
	return lines
}

// ── Clipboard (OSC 52) ────────────────────────────────────────────────────

var rxANSI = regexp.MustCompile("\x1b\\[[0-9;]*[a-zA-Z]|\x1b\\][^\x07]*\x07")

func stripANSI(s string) string { return rxANSI.ReplaceAllString(s, "") }

// writeClipboard emits an OSC 52 copy sequence. The payload is base64 of the
// text, so no ESC/BEL from the content can break out of the sequence — this is
// an operator-initiated copy, not remote-influenced text smuggled to the
// terminal (the attack types Sanitize defends against).
func writeClipboard(s string) {
	enc := base64.StdEncoding.EncodeToString([]byte(s))
	_, _ = os.Stdout.WriteString("\x1b]52;c;" + enc + "\x07")
}

// copyOutput strips styling from the given block and copies the plain text,
// reporting how much landed (a terminal without OSC 52 support simply no-ops,
// so the line count is the honest signal).
func (m *Model) copyOutput(lines []string, scope string) tea.Cmd {
	plain := make([]string, 0, len(lines))
	for _, l := range lines {
		plain = append(plain, stripANSI(l))
	}
	text := strings.TrimRight(strings.Join(plain, "\n"), "\n ")
	return func() tea.Msg {
		if strings.TrimSpace(text) == "" {
			return cmdNoticeMsg([]string{output.MutedStyle.Render("  Nothing to copy yet.")})
		}
		writeClipboard(text)
		return cmdNoticeMsg([]string{output.MutedStyle.Render(
			fmt.Sprintf("  Copied %s to clipboard (%d line(s), %d bytes).", scope, len(plain), len(text)),
		)})
	}
}

// ── Inline flags + exploit row renderers ──────────────────────────────────

// runOpts carries per-command options parsed from a typed command line so the
// shell matches the CLI instead of silently dropping everything after the URL.
type runOpts struct {
	creds  string
	cookie string
	idor   string
	all    bool
}

func parseRunArgs(args []string) (string, runOpts) {
	var target string
	var o runOpts
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, bool) {
			if i+1 < len(args) {
				v := args[i+1]
				i++
				return v, true
			}
			return "", false
		}
		switch {
		case a == "--creds":
			if v, ok := next(); ok {
				o.creds = v
			}
		case strings.HasPrefix(a, "--creds="):
			o.creds = strings.TrimPrefix(a, "--creds=")
		case a == "--cookie":
			if v, ok := next(); ok {
				o.cookie = v
			}
		case strings.HasPrefix(a, "--cookie="):
			o.cookie = strings.TrimPrefix(a, "--cookie=")
		case a == "--idor":
			if v, ok := next(); ok {
				o.idor = v
			}
		case strings.HasPrefix(a, "--idor="):
			o.idor = strings.TrimPrefix(a, "--idor=")
		case a == "--all":
			o.all = true
		case strings.HasPrefix(a, "-"):
			// Unknown flag: ignore it rather than mistake it for the target.
		default:
			if target == "" {
				target = a
			}
		}
	}
	return target, o
}

func loginRow(r exploit.LoginAttempt) string {
	cl, sym := clMuted, "✗"
	if r.Success {
		cl, sym = clCoral, "✓"
	}
	shown := types.Sanitize(r.Username)
	if r.Success {
		shown += ":" + types.MaskSecret(r.Password)
	}
	return lipgloss.NewStyle().Foreground(cl).Padding(0, 4).Render(
		fmt.Sprintf("  %s %s → %d", sym, shown, r.StatusCode),
	)
}

func renderReuseRow(r exploit.TokenReuseAttempt) string {
	cl := clMuted
	if r.Success {
		cl = clCoral
	}
	return lipgloss.NewStyle().Foreground(cl).Padding(0, 4).Render(
		fmt.Sprintf("  %s %s → %d", types.Sanitize(truncate(r.Token, 40)), types.Sanitize(r.Endpoint), r.StatusCode),
	)
}
