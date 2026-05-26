package main

	import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/nice-scan/nice_scan/internal/engine"
	"github.com/nice-scan/nice_scan/internal/fingerprint"
	"github.com/nice-scan/nice_scan/internal/output"
	"github.com/nice-scan/nice_scan/internal/shell"
	"github.com/nice-scan/nice_scan/internal/transport"
	"github.com/nice-scan/nice_scan/internal/tui"
	"github.com/nice-scan/nice_scan/internal/types"

	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

var (
	cfg         = types.DefaultConfig()
	jsonOutput  bool
	interactive bool
)

func main() {
	root := &cobra.Command{
		Use:   "nice_scan",
		Short: "Fast. Precise. Intelligent. — Modern Security Reconnaissance Engine",
		Long: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).Render(`
  ╭──────────────────────────────────────────────╮
  │              NICE_SCAN v0.1.0               │
  │      Fast. Precise. Intelligent.            │
  │      Modern Security Reconnaissance Engine   │
  ╰──────────────────────────────────────────────╯`),
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if jsonOutput {
				cfg.OutputFormat = "json"
			}
		},
	}

	root.PersistentFlags().IntVarP(&cfg.Workers, "workers", "w", 64, "number of concurrent workers")
	root.PersistentFlags().DurationVar(&cfg.Timeout, "timeout", types.DefaultConfig().Timeout, "request timeout")
	root.PersistentFlags().IntVar(&cfg.Retries, "retries", types.DefaultConfig().Retries, "max retries per request")
	root.PersistentFlags().IntVar(&cfg.RateLimit, "rate-limit", 0, "requests per second (0 = unlimited)")
	root.PersistentFlags().StringVar(&cfg.Proxy, "proxy", "", "HTTP proxy URL")
	root.PersistentFlags().BoolVarP(&jsonOutput, "json", "j", false, "output as JSON")
	root.PersistentFlags().BoolVarP(&interactive, "interactive", "i", false, "interactive live dashboard")
	root.PersistentFlags().BoolVarP(&cfg.Verbose, "verbose", "v", false, "verbose output")
	root.PersistentFlags().StringVar(&cfg.Cookie, "cookie", "", "cookie header to include")
	root.PersistentFlags().StringSliceVar(&headers, "header", nil, "custom headers (key:value)")
	root.PersistentFlags().BoolVar(&cfg.FollowRedirects, "follow-redirects", true, "follow redirects")
	root.PersistentFlags().IntVar(&cfg.MaxRedirects, "max-redirects", 5, "max redirects to follow")

	root.AddCommand(scanCmd())
	root.AddCommand(techCmd())
	root.AddCommand(tlsCmd())
	root.AddCommand(shellCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var headers []string

func buildClient() *transport.Client {
	opts := []transport.ClientOption{
		transport.WithTimeout(cfg.Timeout),
		transport.WithRetries(cfg.Retries),
		transport.WithFollowRedirects(cfg.FollowRedirects),
		transport.WithMaxRedirects(cfg.MaxRedirects),
		transport.WithVerbose(cfg.Verbose),
	}

	if cfg.RateLimit > 0 {
		opts = append(opts, transport.WithRateLimit(cfg.RateLimit))
	}
	if cfg.Proxy != "" {
		opts = append(opts, transport.WithProxy(cfg.Proxy))
	}
	if cfg.Cookie != "" {
		opts = append(opts, transport.WithCookie(cfg.Cookie))
	}

	headerMap := make(map[string]string)
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headerMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	if len(headerMap) > 0 {
		opts = append(opts, transport.WithHeaders(headerMap))
	}

	return transport.NewClient(opts...)
}

func scanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scan [target]",
		Short: "Run a full reconnaissance scan",
		Long:  "Full scan including tech fingerprinting, header analysis, TLS checks, and exposure detection",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := normalizeTarget(args[0])

			client := buildClient()
			defer client.Close()

			scanner := engine.NewScanner(cfg, client)
			scanner.RegisterAnalyzers(
				fingerprint.New(),
				engine.NewHeaderAnalyzer(),
				engine.NewTLSAnalyzer(),
				engine.NewExposureAnalyzer(),
			)

			if interactive {
				model := tui.NewModel(scanner, []string{target})
				p := tea.NewProgram(model, tea.WithAltScreen())
				if _, err := p.Run(); err != nil {
					return err
				}
				return nil
			}

			renderer := output.NewTerminal()
			renderer.RenderBanner()

			ctx, cancel := signalContext()
			defer cancel()

			result := scanner.Scan(ctx, []string{target})

			if jsonOutput {
				renderer.RenderJSON(result)
			} else {
				renderer.RenderResult(result)
				renderer.RenderTransportStats(client.Stats())
			}

			return nil
		},
	}
}

func techCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tech [target]",
		Short: "Detect technologies only",
		Long:  "Identify frameworks, CDNs, WAFs, and other technologies",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := normalizeTarget(args[0])

			renderer := output.NewTerminal()
			renderer.RenderBanner()

			client := buildClient()
			defer client.Close()

			scanner := engine.NewScanner(cfg, client)
			scanner.RegisterAnalyzer(fingerprint.New())

			ctx, cancel := signalContext()
			defer cancel()

			result := scanner.Scan(ctx, []string{target})

			if jsonOutput {
				renderer.RenderJSON(result)
			} else {
				renderer.RenderResult(result)
			}

			return nil
		},
	}
}

func tlsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tls [target]",
		Short: "Analyze TLS configuration",
		Long:  "Check TLS version, cipher suites, and certificate validity",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := normalizeTarget(args[0])

			renderer := output.NewTerminal()
			renderer.RenderBanner()

			client := buildClient()
			defer client.Close()

			scanner := engine.NewScanner(cfg, client)
			scanner.RegisterAnalyzer(engine.NewTLSAnalyzer())

			ctx, cancel := signalContext()
			defer cancel()

			result := scanner.Scan(ctx, []string{target})

			if jsonOutput {
				renderer.RenderJSON(result)
			} else {
				renderer.RenderResult(result)
			}

			return nil
		},
	}
}

func shellCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "shell",
		Short: "Start an interactive reconnaissance shell",
		Long:  "Persistent interactive shell — type commands like scan, tech, tls without restarting",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			model, err := shell.NewModel(cfg)
			if err != nil {
				return err
			}
			defer model.Close()
			p := tea.NewProgram(model, tea.WithAltScreen())
			if _, err := p.Run(); err != nil {
				return err
			}
			return nil
		},
	}
}

func normalizeTarget(target string) string {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}
	target = strings.TrimRight(target, "/")
	return target
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()
	return ctx, cancel
}
