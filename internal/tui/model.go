package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/engine"
	"github.com/NICE-DEV226/nice-Scan/internal/output"
	"github.com/NICE-DEV226/nice-Scan/internal/types"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type sessionState int

const (
	stateIdle    sessionState = iota
	stateRunning
	stateDone
)

type Model struct {
	ctx    context.Context
	cancel context.CancelFunc

	scanner *engine.Scanner
	targets []string
	events  chan engine.ScanEvent

	state      sessionState
	spinner    spinner.Model
	progress   progress.Model
	err        error

	stats     engine.ScanStats
	findings  []types.Finding
	allFindings []types.Finding
	requestLog []string

	width  int
	height int

	quitting bool
}

func NewModel(scanner *engine.Scanner, targets []string) *Model {
	ctx, cancel := context.WithCancel(context.Background())

	s := spinner.New()
	s.Style = spinnerStyle()
	s.Spinner = spinner.Dot

	p := progress.New(
		progress.WithDefaultGradient(),
		progress.WithWidth(40),
		progress.WithoutPercentage(),
	)

	return &Model{
		ctx:      ctx,
		cancel:   cancel,
		scanner:  scanner,
		targets:  targets,
		events:   make(chan engine.ScanEvent, 200),
		state:    stateIdle,
		spinner:  s,
		progress: p,
	}
}

func spinnerStyle() lipgloss.Style {
	return lipgloss.NewStyle().Foreground(accentCyan)
}

func (m *Model) Init() tea.Cmd {
	return tea.Batch(
		tea.SetWindowTitle("NICE_SCAN — Fast. Precise. Intelligent."),
		m.spinner.Tick,
		m.waitForScan(),
	)
}

func (m *Model) waitForScan() tea.Cmd {
	return func() tea.Msg {
		go m.scanner.ScanStream(m.ctx, m.targets, m.events)
		m.state = stateRunning
		return scanStartedMsg{}
	}
}

type scanStartedMsg struct{}
type scanEventMsg engine.ScanEvent

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.progress.Width = msg.Width - 20
		if m.progress.Width < 10 {
			m.progress.Width = 10
		}
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			m.cancel()
			m.quitting = true
			return m, tea.Quit
		}
		return m, nil

	case scanStartedMsg:
		return m, m.pollEvents()

	case scanEventMsg:
		evt := engine.ScanEvent(msg)
		m.stats = evt.Stats

		if evt.Result != nil {
			entry := fmt.Sprintf("%s %s (%d)",
				evt.Result.Duration.Round(time.Millisecond),
				evt.Result.Target,
				evt.Result.Response.StatusCode,
			)
			m.requestLog = append(m.requestLog, entry)
			if len(m.requestLog) > 50 {
				m.requestLog = m.requestLog[len(m.requestLog)-50:]
			}
		}

		if evt.Findings != nil {
			m.findings = append(m.findings, evt.Findings...)
			m.allFindings = append(m.allFindings, evt.Findings...)
		}

		if evt.Done {
			m.state = stateDone
			m.findings = evt.Findings
			m.stats = evt.Stats
			return m, tea.Sequence(
				tea.Printf("Scan complete: %d findings", len(evt.Findings)),
				tea.Quit,
			)
		}

		return m, m.pollEvents()

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case progress.FrameMsg:
		pm, cmd := m.progress.Update(msg)
		m.progress = pm.(progress.Model)
		return m, cmd

	case error:
		m.err = msg
		m.state = stateDone
		return m, tea.Quit
	}

	return m, nil
}

func (m *Model) pollEvents() tea.Cmd {
	return func() tea.Msg {
		evt, ok := <-m.events
		if !ok {
			return nil
		}
		return scanEventMsg(evt)
	}
}

func (m *Model) View() string {
	if m.quitting {
		return m.renderSummary()
	}

	switch m.state {
	case stateIdle:
		return m.renderIdle()
	case stateRunning:
		return m.renderRunning()
	case stateDone:
		return m.renderSummary()
	default:
		return ""
	}
}

func (m *Model) renderIdle() string {
	return "Preparing scan..."
}

func (m *Model) renderRunning() string {
	var b strings.Builder

	b.WriteString(m.renderHeader())
	b.WriteString("\n\n")

	stats := m.renderStats()
	events := m.renderEventLog()

	split := lipgloss.JoinHorizontal(lipgloss.Top, stats, "  ", events)
	b.WriteString(split)
	b.WriteString("\n\n")

	b.WriteString(m.renderProgress())
	b.WriteString("\n")

	b.WriteString(mutedStyle.Render("  q: quit"))

	return lipgloss.NewStyle().Padding(1, 2).Render(b.String())
}

func (m *Model) renderHeader() string {
	logo := output.RenderLogoOneLine()
	title := titleStyle.Render(logo)
	spinner := m.spinner.View()
	target := mutedStyle.Render(m.targets[0])

	var elapsed string
	if m.stats.StartTime.IsZero() {
		elapsed = "0s"
	} else {
		elapsed = time.Since(m.stats.StartTime).Round(time.Second).String()
	}
	duration := dimStyle.Render(elapsed)

	return lipgloss.JoinHorizontal(lipgloss.Left,
		title, " ",
		spinner, " ",
		target, "  ",
		duration,
	)
}

func (m *Model) renderStats() string {
	var b strings.Builder

	stats := []struct {
		label string
		value string
	}{
		{"Requests", fmt.Sprintf("%d/%d", m.stats.Completed, m.stats.Total)},
		{"Failed", fmt.Sprintf("%d", m.stats.Failed)},
		{"Findings", fmt.Sprintf("%d", len(m.allFindings))},
		{"Workers", fmt.Sprintf("%d", m.stats.Workers)},
	}

	if m.stats.Duration > 0 {
		rate := float64(m.stats.Completed) / m.stats.Duration.Seconds()
		stats = append(stats, struct{ label, value string }{"Rate", fmt.Sprintf("%.0f/s", rate)})
	}

	for _, s := range stats {
		l := labelStyle.Render(s.label)
		v := valueStyle.Render(s.value)
		b.WriteString(lipgloss.JoinHorizontal(lipgloss.Left, l, v))
		b.WriteString("\n")
	}

	return panelStyle.Width(24).Render(b.String())
}

func (m *Model) renderEventLog() string {
	var b strings.Builder

	for _, entry := range m.requestLog {
		b.WriteString(dimStyle.Render(entry))
		b.WriteString("\n")
	}

	maxHeight := 10
	lines := strings.Split(b.String(), "\n")
	if len(lines) > maxHeight {
		lines = lines[len(lines)-maxHeight:]
	}

	return panelStyle.
		Width(48).
		Render(strings.Join(lines, "\n"))
}

func (m *Model) renderProgress() string {
	if m.stats.Total == 0 {
		return ""
	}

	pct := float64(m.stats.Completed) / float64(m.stats.Total)
	if pct > 1.0 {
		pct = 1.0
	}

	bar := m.progress.ViewAs(pct)

	pctStr := dimStyle.Render(fmt.Sprintf("%3.0f%%", pct*100))

	return lipgloss.JoinHorizontal(lipgloss.Center,
		progressFull.Render("Progress"),
		"  ",
		bar,
		"  ",
		pctStr,
	)
}

func (m *Model) renderSummary() string {
	var b strings.Builder

	b.WriteString(m.renderFindingsSummary())
	b.WriteString("\n")

	return b.String()
}

func (m *Model) renderFindingsSummary() string {
	if len(m.findings) == 0 {
		return mutedStyle.Render("No findings detected.")
	}

	types := []string{"critical", "high", "medium", "low", "info"}
	counts := map[string]int{}
	for _, f := range m.findings {
		counts[string(f.Severity)]++
	}

	var parts []string
	for _, t := range types {
		if counts[t] > 0 {
			c := severityColor(t)
			style := lipgloss.NewStyle().Foreground(c).Bold(true)
			label := mutedStyle.Render(t)
			parts = append(parts, fmt.Sprintf("%s %s %d", style.Render("■"), label, counts[t]))
		}
	}

	summary := strings.Join(parts, "  ")
	b := strings.Builder{}
	b.WriteString(lipgloss.NewStyle().Padding(0, 2).Render(summary))
	b.WriteString("\n\n")

	for _, f := range m.findings {
		color := severityColor(string(f.Severity))
		name := lipgloss.NewStyle().Foreground(textPrimary).Padding(0, 2).Render(f.Name)
		sev := lipgloss.NewStyle().Foreground(color).Render(strings.ToUpper(string(f.Severity[0])))
		desc := mutedStyle.Padding(0, 4).Render(f.Description)

		b.WriteString(fmt.Sprintf("  %s  %s\n", sev, name))
		b.WriteString(fmt.Sprintf("%s\n", desc))
		b.WriteString("\n")
	}

	return b.String()
}
