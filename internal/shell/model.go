package shell

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nice-scan/nice_scan/internal/engine"
	"github.com/nice-scan/nice_scan/internal/fingerprint"
	"github.com/nice-scan/nice_scan/internal/output"
	"github.com/nice-scan/nice_scan/internal/transport"
	"github.com/nice-scan/nice_scan/internal/types"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	prompt    = lipgloss.NewStyle().Foreground(lipgloss.Color("#7DCFFF")).Bold(true).Render("nice_scan> ")
	styleOut  = lipgloss.NewStyle().Foreground(lipgloss.Color("#C0CAF5"))
	styleMute = lipgloss.NewStyle().Foreground(lipgloss.Color("#565F89"))
	styleErr  = lipgloss.NewStyle().Foreground(lipgloss.Color("#F7768E"))
	styleCyan = lipgloss.NewStyle().Foreground(lipgloss.Color("#7DCFFF"))
	styleName = lipgloss.NewStyle().Foreground(lipgloss.Color("#C0CAF5")).Bold(true)

	banner = strings.Join([]string{
		styleCyan.Render("  █████"),
		styleCyan.Render(" █     █"),
		styleCyan.Render(" █  ◉  █") + "  " + styleName.Render("NICE_SCAN"),
		styleCyan.Render(" █     █") + "  " + styleMute.Render("Fast. Precise. Intelligent."),
		styleCyan.Render("  █████"),
	}, "\n")
)

type Model struct {
	output   []string
	input    string
	history  []string
	histIdx  int
	width    int
	height   int
	ready    bool
	quitting bool

	cfg    *types.Config
	client *transport.Client
}

func NewModel(cfg *types.Config) (*Model, error) {
	return &Model{
		cfg: cfg,
	}, nil
}

func (m *Model) Init() tea.Cmd {
	return nil
}

type cmdResultMsg struct {
	lines []string
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.ready = true
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "ctrl+d":
			m.quitting = true
			return m, tea.Quit

		case "enter":
			line := strings.TrimSpace(m.input)
			if line == "" {
				return m, nil
			}
			m.history = append(m.history, line)
			m.histIdx = len(m.history)

			if cmd, args := parseLine(line); cmd != "" {
				promptLine := styleMute.Render(fmt.Sprintf("❯ %s %s", cmd, strings.Join(args, " ")))
				m.output = append(m.output, "", promptLine)

				if cmd == "exit" || cmd == "quit" || cmd == "q" {
					m.output = append(m.output, styleMute.Render("Goodbye."))
					m.quitting = true
					return m, tea.Quit
				}
				if cmd == "clear" || cmd == "cls" {
					m.output = nil
					m.input = ""
					return m, nil
				}
				if cmd == "help" || cmd == "?" {
					m.showHelp()
					m.input = ""
					return m, nil
				}
				if cmd == "banner" {
					m.output = append(m.output, banner)
					m.input = ""
					return m, nil
				}
				return m, m.execCommand(cmd, args)
			}

		case "up":
			if len(m.history) > 0 && m.histIdx > 0 {
				m.histIdx--
				m.input = m.history[m.histIdx]
			}

		case "down":
			if m.histIdx < len(m.history)-1 {
				m.histIdx++
				m.input = m.history[m.histIdx]
			} else {
				m.histIdx = len(m.history)
				m.input = ""
			}

		case "backspace":
			if len(m.input) > 0 {
				m.input = m.input[:len(m.input)-1]
			}

		default:
			if len(msg.String()) == 1 {
				m.input += msg.String()
			}
		}

	case cmdResultMsg:
		m.output = append(m.output, msg.lines...)
		m.output = append(m.output, "")
		m.input = ""
	}

	return m, nil
}

func (m *Model) View() string {
	if !m.ready {
		return banner + "\n\n" + styleMute.Render("  Initializing...")
	}

	var b strings.Builder

	b.WriteString(banner)
	b.WriteString("\n\n")

	for _, line := range m.output {
		b.WriteString(line)
		b.WriteString("\n")
	}

	return b.String() + "\n" + prompt + m.input
}

func parseLine(line string) (string, []string) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return "", nil
	}
	return strings.ToLower(parts[0]), parts[1:]
}

func (m *Model) execCommand(cmd string, args []string) tea.Cmd {
	return func() tea.Msg {
		if len(args) == 0 {
			return cmdResultMsg{lines: []string{styleErr.Render("Missing argument. Usage: " + cmd + " <url>")}}
		}

		target := args[0]
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "https://" + target
		}
		target = strings.TrimRight(target, "/")

		client := m.buildClient()
		defer client.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		output.RenderLogoCompact()

		var sb strings.Builder

		switch cmd {
		case "scan":
			scanner := engine.NewScanner(m.cfg, client)
			scanner.RegisterAnalyzers(
				fingerprint.New(),
				engine.NewHeaderAnalyzer(),
				engine.NewTLSAnalyzer(),
				engine.NewExposureAnalyzer(),
			)
			result := scanner.Scan(ctx, []string{target})

			for _, f := range result.Findings {
				color := severityColor(string(f.Severity))
				sb.WriteString(fmt.Sprintf("  %s  %s\n",
					lipgloss.NewStyle().Foreground(color).Bold(true).Render(strings.ToUpper(string(f.Severity[0]))),
					lipgloss.NewStyle().Foreground(lipgloss.Color("#C0CAF5")).Render(f.Name),
				))
				if f.Evidence != "" {
					sb.WriteString(styleMute.Render("       " + truncate(f.Evidence, 70)) + "\n")
				}
			}
			sb.WriteString(styleMute.Render(fmt.Sprintf("\n  %d requests in %v — %d findings\n",
				result.Stats.Completed, result.Stats.Duration.Round(time.Millisecond), len(result.Findings))))

		case "tech":
			scanner := engine.NewScanner(m.cfg, client)
			scanner.RegisterAnalyzer(fingerprint.New())
			result := scanner.Scan(ctx, []string{target})
			for _, f := range result.Findings {
				sb.WriteString(fmt.Sprintf("  %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#7DCFFF")).Render(f.Name)))
			}
			sb.WriteString(styleMute.Render(fmt.Sprintf("\n  %d technologies detected\n", len(result.Findings))))

		case "tls":
			scanner := engine.NewScanner(m.cfg, client)
			scanner.RegisterAnalyzer(engine.NewTLSAnalyzer())
			result := scanner.Scan(ctx, []string{target})
			for _, f := range result.Findings {
				sb.WriteString(fmt.Sprintf("  %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#C0CAF5")).Render(f.Name)))
				sb.WriteString(styleMute.Render("  " + f.Description + "\n"))
			}
			if len(result.Findings) == 0 {
				sb.WriteString(styleMute.Render("  No TLS issues found.\n"))
			}

		default:
			return cmdResultMsg{lines: []string{styleErr.Render("Unknown command: " + cmd + ". Type 'help'.")}}
		}

		lines := strings.Split(sb.String(), "\n")
		return cmdResultMsg{lines: lines}
	}
}

func (m *Model) buildClient() *transport.Client {
	opts := []transport.ClientOption{
		transport.WithTimeout(m.cfg.Timeout),
		transport.WithRetries(m.cfg.Retries),
		transport.WithFollowRedirects(m.cfg.FollowRedirects),
		transport.WithMaxRedirects(m.cfg.MaxRedirects),
	}
	if m.cfg.RateLimit > 0 {
		opts = append(opts, transport.WithRateLimit(m.cfg.RateLimit))
	}
	if m.cfg.Proxy != "" {
		opts = append(opts, transport.WithProxy(m.cfg.Proxy))
	}
	return transport.NewClient(opts...)
}

func (m *Model) showHelp() {
	help := []string{
		"",
		styleOut.Render("  Commands:"),
		styleOut.Render("    scan <url>     Full reconnaissance scan"),
		styleOut.Render("    tech <url>     Technology detection"),
		styleOut.Render("    tls <url>      TLS analysis"),
		"",
		styleOut.Render("    banner         Show logo"),
		styleOut.Render("    clear          Clear screen"),
		styleOut.Render("    help, ?        This help"),
		styleOut.Render("    exit, quit     Exit shell"),
		"",
		styleMute.Render("  Navigation:"),
		styleMute.Render("    ↑↓  history    Tab  complete"),
		"",
	}
	m.output = append(m.output, help...)
}

func severityColor(severity string) lipgloss.Color {
	switch severity {
	case "critical", "high":
		return lipgloss.Color("#F7768E")
	case "medium":
		return lipgloss.Color("#FFB347")
	case "low":
		return lipgloss.Color("#7DCFFF")
	default:
		return lipgloss.Color("#565F89")
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func filterBySeverity(findings []types.Finding, sev types.Severity) []types.Finding {
	var f []types.Finding
	for _, fi := range findings {
		if fi.Severity == sev {
			f = append(f, fi)
		}
	}
	return f
}
