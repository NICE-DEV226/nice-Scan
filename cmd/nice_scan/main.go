package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/NICE-DEV226/nice-Scan/internal/engine"
	"github.com/NICE-DEV226/nice-Scan/internal/exploit"
	"github.com/NICE-DEV226/nice-Scan/internal/fingerprint"
	"github.com/NICE-DEV226/nice-Scan/internal/hacker"
	"github.com/NICE-DEV226/nice-Scan/internal/output"
	"github.com/NICE-DEV226/nice-Scan/internal/shell"
	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/tui"
	"github.com/NICE-DEV226/nice-Scan/internal/types"

	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

var (
	cfg         = types.DefaultConfig()
	jsonOutput  bool
	interactive bool
	reportFile  string
	showVersion bool
)

var version = "dev"

var clCyan = lipgloss.Color("#7DCFFF")
var clMuted = lipgloss.Color("#565F89")
var clPrimary = lipgloss.Color("#C0CAF5")

func main() {
	root := &cobra.Command{
		Use:   "nice_scan",
		Short: "Fast. Precise. Intelligent. — Modern Security Reconnaissance Engine",
		Long: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).Render(`
  ╭──────────────────────────────────────────────╮
  │              NICE_SCAN v` + version + `               │
  │      Fast. Precise. Intelligent.            │
  │      Modern Security Reconnaissance Engine   │
  ╰──────────────────────────────────────────────╯`),
		SilenceUsage: true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if jsonOutput {
				cfg.OutputFormat = "json"
			}
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if showVersion {
				fmt.Printf("nice_scan v%s\n", version)
				return nil
			}
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Foreground(clCyan).Bold(true).Render("  NICE_SCAN v" + version))
			fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Render("  Fast. Precise. Intelligent."))
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Render("  Quick Start:"))
			fmt.Println()
			fmt.Printf("  %s  %s\n",
				lipgloss.NewStyle().Foreground(clPrimary).Render("nice_scan hack example.com"),
				lipgloss.NewStyle().Foreground(clMuted).Render("— Autonomous hack agent (try this first!)"),
			)
			fmt.Printf("  %s  %s\n",
				lipgloss.NewStyle().Foreground(clPrimary).Render("nice_scan scan example.com --json"),
				lipgloss.NewStyle().Foreground(clMuted).Render("— Full recon scan with JSON output"),
			)
			fmt.Printf("  %s  %s\n",
				lipgloss.NewStyle().Foreground(clPrimary).Render("nice_scan hack example.com -R report.html"),
				lipgloss.NewStyle().Foreground(clMuted).Render("— Hack + HTML report"),
			)
			fmt.Printf("  %s  %s\n",
				lipgloss.NewStyle().Foreground(clPrimary).Render("nice_scan --help"),
				lipgloss.NewStyle().Foreground(clMuted).Render("— All commands and flags"),
			)
			fmt.Println()
			return cmd.Help()
		},
	}

	root.Flags().BoolVarP(&showVersion, "version", "", false, "show version")

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
	root.PersistentFlags().StringVarP(&reportFile, "report", "R", "", "save detailed HTML report to file")

	root.AddCommand(scanCmd())
	root.AddCommand(auditCmd())
	root.AddCommand(techCmd())
	root.AddCommand(tlsCmd())
	root.AddCommand(exploitCmd())
	root.AddCommand(hackCmd())
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
		Short: "Full reconnaissance scan (passive + active checks)",
		Long:  "Complete scan: fingerprinting, header analysis, TLS, exposures, SQLi, XSS, CORS, HTTP methods, token extraction, auth detection, privilege escalation, data extraction. Generates ~50 requests. Use -R for HTML report.",
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
				engine.NewSQLiAnalyzer(),
				engine.NewXSSAnalyzer(),
				engine.NewCORSAnalyzer(),
				engine.NewHTTPMethodsAnalyzer(),
				engine.NewTokenExtractor(),
				engine.NewAuthAnalyzer(),
				engine.NewPrivilegeEscalationAnalyzer(),
				engine.NewDataExtractionAnalyzer(),
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

			if reportFile != "" {
				report := engine.GenerateReport(result)
				html := report.RenderHTML()
				if err := os.WriteFile(reportFile, []byte(html), 0644); err != nil {
					return fmt.Errorf("failed to write report: %w", err)
				}
				fmt.Println()
				fmt.Println(lipgloss.NewStyle().Foreground(clCyan).Render("  Report saved: " + reportFile))
			}

			return nil
		},
	}
}

func auditCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "audit [target]",
		Short: "Deep audit with ALL checks and verbose output",
		Long:  "Same as scan but forces verbose output, shows every module's findings in detail, and generates HTML report by default. Use for comprehensive assessment.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := normalizeTarget(args[0])

			cfg.Verbose = true
			if reportFile == "" {
				reportFile = "audit_report.html"
			}

			client := buildClient()
			defer client.Close()

			scanner := engine.NewScanner(cfg, client)
			scanner.RegisterAnalyzers(
				fingerprint.New(),
				engine.NewHeaderAnalyzer(),
				engine.NewTLSAnalyzer(),
				engine.NewExposureAnalyzer(),
				engine.NewSQLiAnalyzer(),
				engine.NewXSSAnalyzer(),
				engine.NewCORSAnalyzer(),
				engine.NewHTTPMethodsAnalyzer(),
				engine.NewTokenExtractor(),
				engine.NewAuthAnalyzer(),
				engine.NewPrivilegeEscalationAnalyzer(),
				engine.NewDataExtractionAnalyzer(),
			)

			renderer := output.NewTerminal()
			renderer.RenderBanner()

			ctx, cancel := signalContext()
			defer cancel()

			result := scanner.Scan(ctx, []string{target})

			renderer.RenderResult(result)
			renderer.RenderTransportStats(client.Stats())

			if reportFile != "" {
				report := engine.GenerateReport(result)
				html := report.RenderHTML()
				if err := os.WriteFile(reportFile, []byte(html), 0644); err != nil {
					return fmt.Errorf("failed to write report: %w", err)
				}
				fmt.Println()
				fmt.Println(lipgloss.NewStyle().Foreground(clCyan).Render("  Full audit report: " + reportFile))
			}

			return nil
		},
	}
}

func exploitCmd() *cobra.Command {
	var (
		loginBrute   bool
		idorRange    string
		roleTamper   bool
		tokenReuse   bool
		registerAcc  bool
		resetPass    bool
		sessionFix   bool
		allModules   bool
	)

	cmd := &cobra.Command{
		Use:   "exploit [target]",
		Short: "Active exploitation: login brute, IDOR, privesc, token, register, reset, session",
		Long: lipgloss.NewStyle().Foreground(clMuted).Render(`
  Active exploitation module — tests credentials, enumerates IDs, escalates privileges,
  reuses tokens, registers accounts, exploits password reset, and tests session fixation.
  Only use on authorized targets.

  Modules:
    --login       Bruteforce common credentials against login forms
    --idor 1-100  Numeric ID enumeration range (query + path-based)
    --role        Role/privilege tampering (params, headers, cookies)
    --token       Reuse discovered JWT/session tokens on protected endpoints
    --register    Attempt account registration with various privilege levels
    --reset       Test password reset for user enumeration + token leaks
    --session     Test session fixation and session hijacking
    --all         Run all exploitation modules
`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := normalizeTarget(args[0])

			if !loginBrute && !roleTamper && !tokenReuse && !registerAcc && !resetPass && !sessionFix && idorRange == "" && !allModules {
				return cmd.Help()
			}

			client := buildClient()
			defer client.Close()

			opts := exploit.Options{
				Target:  target,
				Verbose: cfg.Verbose,
			}
			exp := exploit.New(client, opts)

			renderer := output.NewTerminal()
			renderer.RenderBanner()

			ctx, cancel := signalContext()
			defer cancel()

			fmt.Println(lipgloss.NewStyle().Foreground(clCyan).Bold(true).Padding(0, 2).Render("  Exploitation Results"))
			fmt.Println()

			runLogin := loginBrute || allModules
			runRole := roleTamper || allModules
			runToken := tokenReuse || allModules
			runIdor := idorRange != "" || allModules
			runRegister := registerAcc || allModules
			runReset := resetPass || allModules
			runSession := sessionFix || allModules

			if runLogin {
				fmt.Println(lipgloss.NewStyle().Foreground(clPrimary).Padding(0, 2).Render("  🔑 Login Bruteforce"))
				results := exp.BruteforceLogin(ctx, target, exploit.CommonCredentials)
				displayCount := 0
				for _, r := range results {
					if displayCount >= 15 {
						fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Padding(0, 4).Render(fmt.Sprintf("  … and %d more", len(results)-displayCount)))
						break
					}
					cl := lipgloss.Color("#565F89")
					status := "✗"
					if r.Success {
						cl = lipgloss.Color("#F7768E")
						status = "✓"
					}
					fmt.Println(lipgloss.NewStyle().Foreground(cl).Padding(0, 4).Render(
						fmt.Sprintf("  %s %s:%s → %d (%s)", status, r.Username, r.Password, r.StatusCode, truncateStr(r.Evidence, 50)),
					))
					displayCount++
				}
				if len(results) == 0 {
					fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Padding(0, 4).Render("  — No login forms found or all failed"))
				}
				fmt.Println()
			}

			if runRole {
				fmt.Println(lipgloss.NewStyle().Foreground(clPrimary).Padding(0, 2).Render("  ⬆️  Role / Privilege Escalation"))
				results := exp.RoleTampering(ctx, target)
				found := false
				displayCount := 0
				for _, r := range results {
					if !r.Success && displayCount >= 10 {
						continue
					}
					if displayCount >= 20 {
						break
					}
					cl := lipgloss.Color("#565F89")
					status := "✗"
					if r.Success {
						cl = lipgloss.Color("#F7768E")
						status = "✓"
						found = true
					}
					fmt.Println(lipgloss.NewStyle().Foreground(cl).Padding(0, 4).Render(
						fmt.Sprintf("  %s %s=%s %s → %d (%s)", status, r.Parameter, r.Value, r.Method, r.StatusCode, truncateStr(r.Evidence, 50)),
					))
					displayCount++
				}
				if !found {
					fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Padding(0, 4).Render("  — No privilege escalation found"))
				}
				fmt.Println()
			}

			if runToken {
				fmt.Println(lipgloss.NewStyle().Foreground(clPrimary).Padding(0, 2).Render("  🎫 Token / Session Reuse"))
				tokens := []string{"test-token-placeholder"}
				results := exp.TryTokenReuse(ctx, tokens, target)
				displayCount := 0
				for _, r := range results {
					if displayCount >= 8 {
						break
					}
					cl := lipgloss.Color("#565F89")
					if r.Success {
						cl = lipgloss.Color("#F7768E")
					}
					fmt.Println(lipgloss.NewStyle().Foreground(cl).Padding(0, 4).Render(
						fmt.Sprintf("  %s %s → %d (%s)", r.Token, r.Endpoint, r.StatusCode, truncateStr(r.Evidence, 50)),
					))
					displayCount++
				}
				if len(results) == 0 {
					fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Padding(0, 4).Render("  — No endpoints tested"))
				}
				fmt.Println()
			}

			if runIdor {
				var startID, endID int
				fmt.Sscanf(idorRange, "%d-%d", &startID, &endID)
				if startID <= 0 || endID <= 0 {
					startID, endID = 1, 10
				}
				fmt.Println(lipgloss.NewStyle().Foreground(clPrimary).Padding(0, 2).Render(fmt.Sprintf("  🔢 IDOR Enumeration (%d-%d)", startID, endID)))
				results := exp.IDOREnumeration(ctx, target, "", startID, endID)
				baseline := 0
				if len(results) > 0 {
					baseline = results[0].BodySize
				}
				displayCount := 0
				for _, r := range results {
					if displayCount >= 25 {
						fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Padding(0, 4).Render(fmt.Sprintf("  … and %d more", len(results)-displayCount)))
						break
					}
					cl := lipgloss.Color("#565F89")
					diff := ""
					if baseline > 0 && abs(r.BodySize-baseline) > 100 {
						cl = lipgloss.Color("#F7768E")
						diff = fmt.Sprintf(" ← DIFF: %d bytes", abs(r.BodySize-baseline))
					}
					fmt.Println(lipgloss.NewStyle().Foreground(cl).Padding(0, 4).Render(
						fmt.Sprintf("  %s %s=%d → %d (%d bytes%s)", r.ParamType, extractIDORParam(r.URL), r.ID, r.StatusCode, r.BodySize, diff),
					))
					displayCount++
				}
				if len(results) == 0 {
					fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Padding(0, 4).Render("  — No IDOR results"))
				}
				fmt.Println()
			}

			if runRegister {
				fmt.Println(lipgloss.NewStyle().Foreground(clPrimary).Padding(0, 2).Render("  📝 Account Registration"))
				results := exp.RegisterAccount(ctx, target)
				for _, r := range results {
					cl := lipgloss.Color("#565F89")
					status := "✗"
					if r.Success {
						cl = lipgloss.Color("#F7768E")
						status = "✓"
					}
					fmt.Println(lipgloss.NewStyle().Foreground(cl).Padding(0, 4).Render(
						fmt.Sprintf("  %s %s → %d (%s)", status, r.Payload, r.StatusCode, truncateStr(r.Evidence, 50)),
					))
				}
				if len(results) == 0 {
					fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Padding(0, 4).Render("  — No registration forms found"))
				}
				fmt.Println()
			}

			if runReset {
				fmt.Println(lipgloss.NewStyle().Foreground(clPrimary).Padding(0, 2).Render("  🔐 Password Reset"))
				results := exp.ExploitPasswordReset(ctx, target)
				for _, r := range results {
					cl := lipgloss.Color("#565F89")
					status := "○"
					if r.Vulnerable {
						cl = lipgloss.Color("#F7768E")
						status = "⚠"
					}
					fmt.Println(lipgloss.NewStyle().Foreground(cl).Padding(0, 4).Render(
						fmt.Sprintf("  %s %s → %d (%s)", status, r.Identifier, r.StatusCode, truncateStr(r.Evidence, 50)),
					))
				}
				if len(results) == 0 {
					fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Padding(0, 4).Render("  — No reset forms found"))
				}
				fmt.Println()
			}

			if runSession {
				fmt.Println(lipgloss.NewStyle().Foreground(clPrimary).Padding(0, 2).Render("  🍪 Session Fixation"))
				results := exp.TestSessionFixation(ctx, target)
				for _, r := range results {
					cl := lipgloss.Color("#565F89")
					status := "○"
					if r.Vulnerable {
						cl = lipgloss.Color("#F7768E")
						status = "⚠"
					}
					fmt.Println(lipgloss.NewStyle().Foreground(cl).Padding(0, 4).Render(
						fmt.Sprintf("  %s %s → %d (%s)", status, r.Endpoint, r.StatusCode, truncateStr(r.Evidence, 50)),
					))
				}
				if len(results) == 0 {
					fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Padding(0, 4).Render("  — No login forms found for session testing"))
				}
				fmt.Println()
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&loginBrute, "login", false, "Bruteforce common credentials against login forms")
	cmd.Flags().StringVar(&idorRange, "idor", "", "IDOR enumeration range (e.g. 1-100)")
	cmd.Flags().BoolVar(&roleTamper, "role", false, "Test role/privilege escalation via params + headers")
	cmd.Flags().BoolVar(&tokenReuse, "token", false, "Reuse JWT/session tokens on protected endpoints")
	cmd.Flags().BoolVar(&registerAcc, "register", false, "Attempt account registration with various payloads")
	cmd.Flags().BoolVar(&resetPass, "reset", false, "Test password reset for user enumeration + token leaks")
	cmd.Flags().BoolVar(&sessionFix, "session", false, "Test session fixation and cookie security")
	cmd.Flags().BoolVar(&allModules, "all", false, "Run all exploitation modules")

	return cmd
}

func hackCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "hack [target]",
		Short: "Autonomous hacker — Decision Engine chains attacks automatically",
		Long: lipgloss.NewStyle().Foreground(lipgloss.Color("#565F89")).Render(`
  NICE HACKER — fully autonomous attack agent. The Decision Engine:
  1. Passive recon (crt.sh, Wayback) — discover subdomains
  2. Crawl — discover pages, forms, endpoints, JS files
  3. Fuzz — hidden endpoints and parameter discovery
  4. Port scan — TCP connect on top 100 ports
  5. Attack modules — JWT forge, SQLi, XSS, LFI, CMD injection, upload
  6. Login bruteforce — 40 common credentials against discovered forms
  7. GraphQL introspection + mutation fuzzing
  8. S3 bucket enumeration
  9. OOB callback server for blind detection
  10. Attack chain detection + execution
  11. Complete attack report (terminal + HTML with -R)

  This is an offensive tool — only use on authorized targets.

  Examples:
    nice_scan hack example.com
    nice_scan hack https://example.com -R report.html
    nice_scan hack example.com --timeout 10s
`),
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				fmt.Println()
				fmt.Println(lipgloss.NewStyle().Foreground(clCyan).Bold(true).Render("  NICE HACKER"))
				fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Render("  Autonomous attack agent — Decision Engine"))
				fmt.Println()
				fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Render("  Usage:  nice_scan hack <target> [flags]"))
				fmt.Println()
				fmt.Printf("  %s\n", lipgloss.NewStyle().Foreground(clPrimary).Render("  nice_scan hack example.com"))
				fmt.Printf("  %s\n", lipgloss.NewStyle().Foreground(clPrimary).Render("  nice_scan hack https://example.com --timeout 10s -R report.html"))
				fmt.Println()
				return fmt.Errorf("target argument required")
			}
			if len(args) > 1 {
				return fmt.Errorf("too many arguments: expected 1 target, got %d", len(args))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			target := normalizeTarget(args[0])

			client := buildClient()
			defer client.Close()

			renderer := output.NewTerminal()
			renderer.RenderBanner()

			brain := hacker.NewBrain(target, client,
				&hacker.PassiveReconAction{},
				&hacker.CrawlAction{},
				&hacker.FuzzAction{},
				&hacker.PortScanAction{},
				&hacker.LoginBruteAction{},
				&hacker.XSSAction{},
				&hacker.SQLiAction{},
				&hacker.JWTForgeAction{},
				&hacker.LFIAction{},
				&hacker.CMDInjectAction{},
				&hacker.UploadAction{},
				&hacker.GraphQLAction{},
				&hacker.S3Action{},
				hacker.NewOOBAction(),
			)

			ctx, cancel := signalContext()
			defer cancel()

			report := brain.Run(ctx)
			brain.RenderReport(report)

			if reportFile != "" {
				html := hacker.RenderHTMLReport(report)
				if err := os.WriteFile(reportFile, []byte(html), 0644); err != nil {
					return fmt.Errorf("failed to write HTML report: %w", err)
				}
				fmt.Println()
				fmt.Println(lipgloss.NewStyle().Foreground(clCyan).Render("  HTML Report saved: " + reportFile))
			}

			return nil
		},
	}
}

func extractIDORParam(urlStr string) string {
	idx := strings.LastIndexByte(urlStr, '=')
	if idx > 0 && idx < len(urlStr)-1 {
		return urlStr[strings.LastIndexByte(urlStr[:idx], '?')+1 : idx]
	}
	parts := strings.Split(urlStr, "/")
	if len(parts) > 0 {
		return parts[len(parts)-2]
	}
	return "id"
}

func techCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tech [target]",
		Short: "Detect technologies only (165 signatures)",
		Long:  "Identify frameworks, CDNs, WAFs, CMS, clouds, databases, analytics and other technologies with version extraction.",
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
		Short: "Analyze TLS/SSL configuration",
		Long:  "Check TLS version, cipher suites, certificate validity, and security of the TLS configuration.",
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
		Short: "Start the interactive reconnaissance shell",
		Long:  "Persistent interactive shell — type scan, audit, tech, tls, exploit commands without restarting. Full session context with scrollback.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			model, err := shell.NewModel(cfg)
			if err != nil {
				return err
			}
			defer model.Close()
			p := tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseCellMotion())
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

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
