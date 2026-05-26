package shell

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/nice-scan/nice_scan/internal/engine"
	"github.com/nice-scan/nice_scan/internal/fingerprint"
	"github.com/nice-scan/nice_scan/internal/output"
	"github.com/nice-scan/nice_scan/internal/transport"
	"github.com/nice-scan/nice_scan/internal/types"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	// Surfaces
	clBorder = lipgloss.Color("#2F3346")
	clPrompt = lipgloss.Color("#7DCFFF")
	clName   = lipgloss.Color("#C0CAF5")
	clMuted  = lipgloss.Color("#565F89")
	clDim    = lipgloss.Color("#3B4261")
	clCoral  = lipgloss.Color("#F7768E")
	clAmber  = lipgloss.Color("#FFB347")
	clCyan   = lipgloss.Color("#7DCFFF")

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

	severityColor = map[types.Severity]lipgloss.Color{
		types.SeverityCritical: clCoral,
		types.SeverityHigh:     clCoral,
		types.SeverityMedium:   clAmber,
		types.SeverityLow:      clCyan,
		types.SeverityInfo:     clMuted,
	}

	severitySym = map[types.Severity]string{
		types.SeverityCritical: "■",
		types.SeverityHigh:     "■",
		types.SeverityMedium:   "◧",
		types.SeverityLow:      "◇",
		types.SeverityInfo:     "○",
	}

	commands = []struct {
		name string
		desc string
		args string
	}{
		{"scan", "Full security scan", "<url>"},
		{"tech", "Technology detection", "<url>"},
		{"tls", "TLS configuration analysis", "<url>"},
		{"clear", "Clear output", ""},
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

func severity(sev string) types.Severity {
	switch sev {
	case "critical":
		return types.SeverityCritical
	case "high":
		return types.SeverityHigh
	case "medium":
		return types.SeverityMedium
	case "low":
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}

func colorForSev(sev string) lipgloss.Color {
	switch sev {
	case "critical", "high":
		return clCoral
	case "medium":
		return clAmber
	case "low":
		return clCyan
	default:
		return clMuted
	}
}

type Model struct {
	input textinput.Model

	output []string
	session session
	cfg     *types.Config
	client  *transport.Client
	ready   bool
	quitting bool
	width   int
}

func NewModel(cfg *types.Config) (*Model, error) {
	ti := textinput.New()
	ti.Placeholder = "Type a command (help for list)"
	ti.PromptStyle = promptStyle
	ti.Cursor.Style = lipgloss.NewStyle().Foreground(clPrompt)
	ti.CharLimit = 256
	ti.Width = 60
	ti.Focus()

	client := transport.NewClient(
		transport.WithTimeout(cfg.Timeout),
		transport.WithRetries(cfg.Retries),
		transport.WithFollowRedirects(cfg.FollowRedirects),
		transport.WithMaxRedirects(cfg.MaxRedirects),
	)

	return &Model{
		input:  ti,
		cfg:    cfg,
		client: client,
	}, nil
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
		m.ready = true
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			m.quitting = true
			return m, tea.Quit

		case "tab":
			m.autocomplete()
			return m, nil

		case "enter":
			line := strings.TrimSpace(m.input.Value())
			if line == "" {
				return m, nil
			}

			m.output = append(m.output, promptStyle.Render("❯ "+line))
			m.input.Reset()

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
			case "scan", "tech", "tls":
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
	if len(visible) > 80 {
		visible = visible[len(visible)-80:]
	}

	for _, line := range visible {
		b.WriteString(line)
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(clDim).Padding(0, 2).Render(panelSep))
	b.WriteString("\n")
	b.WriteString("\n")
	b.WriteString(m.input.View())

	return lipgloss.NewStyle().Padding(0, 2).Render(b.String())
}

func (m *Model) exec(cmd string, target string) tea.Cmd {
	return func() tea.Msg {
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "https://" + target
		}
		target = strings.TrimRight(target, "/")

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
			)
			result := scanner.Scan(ctx, []string{target})
			findings = result.Findings
			stats = result.Stats
			lines = m.renderFindings(result.Findings, result.Stats)

		case "tech":
			scanner := engine.NewScanner(m.cfg, m.client)
			scanner.RegisterAnalyzer(fingerprint.New())
			result := scanner.Scan(ctx, []string{target})
			findings = result.Findings
			stats = result.Stats
			lines = m.renderFindings(result.Findings, result.Stats)

		case "tls":
			scanner := engine.NewScanner(m.cfg, m.client)
			scanner.RegisterAnalyzer(engine.NewTLSAnalyzer())
			result := scanner.Scan(ctx, []string{target})
			findings = result.Findings
			stats = result.Stats
			lines = m.renderFindings(result.Findings, result.Stats)
		}

		m.session.add(target, findings, stats.Completed, stats.Duration)

		return cmdResultMsg(lines)
	}
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
		color := severityColor[sev]

		header := lipgloss.NewStyle().Foreground(color).Bold(true).Padding(0, 2).Render(fmt.Sprintf("  %s  %s  (%d)", sym, label, len(group)))
		lines = append(lines, "", header)

		for _, f := range group {
			name := lipgloss.NewStyle().Foreground(clName).Padding(0, 4).Render(f.Name)
			lines = append(lines, name)
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

func (m *Model) helpText() []string {
	var lines []string
	lines = append(lines, "")
	lines = append(lines, lipgloss.NewStyle().Foreground(clName).Bold(true).Padding(0, 2).Render("  Commands:"))
	lines = append(lines, "")
	for _, c := range commands {
		name := lipgloss.NewStyle().Foreground(clPrompt).Bold(true).Render("    " + c.name)
		args := lipgloss.NewStyle().Foreground(clMuted).Render(c.args)
		desc := lipgloss.NewStyle().Foreground(clMuted).Render(c.desc)
		line := fmt.Sprintf("%s %s  %s", name, args, desc)
		lines = append(lines, line)
	}
	lines = append(lines, "")
	lines = append(lines, lipgloss.NewStyle().Foreground(clDim).Padding(0, 2).Render("  Navigation:  ↑↓ history  ·  Tab complete  ·  Ctrl+C quit"))
	lines = append(lines, "")
	return lines
}

func (m *Model) Close() {
	if m.client != nil {
		m.client.Close()
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
