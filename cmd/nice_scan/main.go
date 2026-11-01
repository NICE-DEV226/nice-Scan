package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/engine"
	"github.com/NICE-DEV226/nice-Scan/internal/exploit"
	"github.com/NICE-DEV226/nice-Scan/internal/fingerprint"
	"github.com/NICE-DEV226/nice-Scan/internal/hacker"
	"github.com/NICE-DEV226/nice-Scan/internal/output"
	"github.com/NICE-DEV226/nice-Scan/internal/shell"
	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/tui"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
	"github.com/NICE-DEV226/nice-Scan/internal/update"

	tea "github.com/charmbracelet/bubbletea"
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

// version is the ldflags stamp set by the release workflow; source
// builds fall back to the Go toolchain's own module version record
// (go install @vX.Y.Z stamps it) and finally to "dev" for plain
// working-tree builds. displayV prefixes the "v" exactly once — the
// module record arrives already prefixed ("v0.2.1").
var version = "dev"

func displayVersion() string {
	if version != "" && version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return strings.TrimPrefix(bi.Main.Version, "v")
	}
	return version
}

func displayV() string {
	return "v" + displayVersion()
}

func init() {
	version = displayVersion()
	output.Version = version
}

// Chrome styles are the shared design system (internal/output); these
// aliases keep the local call sites readable.
var (
	clMuted = output.Muted
	clFail  = output.Fail
	clWarn  = output.Warn
)

func main() {
	root := &cobra.Command{
		Use:   "nice_scan",
		Short: "Fast. Precise. Intelligent. — Modern Security Reconnaissance Engine",
		Long: `
  nice-scan ` + version + `
  Fast. Precise. Intelligent. — Modern Security Reconnaissance Engine`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if jsonOutput {
				cfg.OutputFormat = "json"
			}
			// Single source of truth for --header values: populate cfg.Headers
			// so the CLI client and the interactive shell client both honor
			// them (the shell previously dropped cookie/proxy/headers).
			headerMap := parseHeaderFlags(headers)
			if len(headerMap) > 0 {
				cfg.Headers = headerMap
			}
			// Fail fast on an unusable proxy: silently ignoring a configured
			// proxy broke the operator's OPSEC assumption (traffic would
			// leave without the configured tunnel).
			if err := validateProxy(cfg.Proxy); err != nil {
				slog.Error("invalid --proxy", "error", err)
				os.Exit(2)
			}
			notifyNewRelease(cmd)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if showVersion {
				fmt.Printf("nice_scan v%s\n", version)
				return nil
			}
			fmt.Println()
			fmt.Println(output.RenderLogoCompact())
			fmt.Println("  " + output.Rule(52))
			fmt.Println()
			fmt.Println(output.Section("Quick start"))
			fmt.Println()
			quickStart := [][2]string{
				{"nice_scan hack example.com", "autonomous recon + exploitation agent"},
				{"nice_scan scan example.com --json", "full scan, JSON for pipelines"},
				{"nice_scan hack example.com -R report.html", "agent + HTML report"},
				{"nice_scan --help", "all commands and flags"},
			}
			for _, q := range quickStart {
				fmt.Printf("  %s\n      %s\n", output.ValueStyle.Render(q[0]), output.MutedStyle.Render(q[1]))
			}
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
	root.PersistentFlags().BoolVar(&cfg.Destructive, "destructive", false, "consent to state-modifying actions (command upload/registration spawns) — modifies target state, authorized targets only")
	root.PersistentFlags().BoolVar(&noUpdateCheck, "no-update-check", false, "disable the automatic new-release check (also honored via NICE_SCAN_NO_UPDATE_CHECK=1)")

	root.AddCommand(scanCmd())
	root.AddCommand(auditCmd())
	root.AddCommand(techCmd())
	root.AddCommand(tlsCmd())
	root.AddCommand(exploitCmd())
	root.AddCommand(hackCmd())
	root.AddCommand(shellCmd())
	root.AddCommand(updateCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var headers []string

var noUpdateCheck bool

// notifyNewRelease tells the operator the running binary is behind the
// latest published release. One network call per day (cache), 3 s
// budget, silent fail-open: the CLI must never break or slow a session
// over an advisory. Dev builds (source trees) never get compared —
// their version carries no registry meaning.
func notifyNewRelease(cmd *cobra.Command) {
	if showVersion || noUpdateCheck || os.Getenv("NICE_SCAN_NO_UPDATE_CHECK") == "1" {
		return
	}
	if cmd != nil && cmd.Name() == "update" {
		return // the update command performs its own, fresher check
	}
	current := displayVersion()
	if !update.IsComparable(current) {
		return // dev trees: pseudo-versions carry no registry meaning
	}

	latest, fresh, _ := update.CachedLatest()
	if !fresh {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		tag, err := update.DefaultClient().Latest(ctx)
		if err != nil {
			return // offline / rate-limited: silent, fail-open
		}
		latest = tag
		update.StoreCheck(tag)
	}
	if !update.IsNewer(latest, current) {
		return
	}

	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Render(
		"  Update available: " + latest + " (running v" + current + ") — run \"nice_scan update\" (--no-update-check disables)"))
}

func updateCmd() *cobra.Command {
	var checkOnly bool
	var force bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Self-update to the latest release (checksum-verified)",
		Long: `Resolve the latest GitHub release, download the asset for this
platform, verify it against the release's published sha256 checksums
(fail-closed on any mismatch) and atomically replace the running
binary. The previous binary is kept as nice_scan.old next to it for
rollback.

The full GPG-verified supply chain (pinned fingerprint, builder
attestations) remains on the installer path: this in-place update is
checksum-verified only, and says so.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			current := displayVersion()

			ctx, cancel := signalContext()
			defer cancel()

			client := update.DefaultClient()
			rel, err := client.FetchRelease(ctx)
			if err != nil {
				return err
			}

			if checkOnly {
				if !update.IsComparable(current) {
					fmt.Printf("  Latest release: %s — running %q (non-release build, no comparison)\n", rel.TagName, current)
					return nil
				}
				if update.IsNewer(rel.TagName, current) {
					fmt.Printf("  Update available: %s (running v%s)\n", rel.TagName, current)
				} else {
					fmt.Printf("  Up to date: v%s\n", current)
				}
				update.StoreCheck(rel.TagName)
				return nil
			}

			if !update.IsComparable(current) && !force {
				return fmt.Errorf("running %q (non-release build): version comparison is meaningless here — use --force to replace it with %s", current, rel.TagName)
			}
			if update.IsComparable(current) && !update.IsNewer(rel.TagName, current) {
				fmt.Printf("  Up to date: v%s (latest release %s)\n", current, rel.TagName)
				update.StoreCheck(rel.TagName)
				return nil
			}
			if !update.IsComparable(current) {
				fmt.Printf("  Installing %s over the non-release build %q\n", rel.TagName, current)
			}

			assets, err := client.Assets(ctx, rel, runtime.GOOS, runtime.GOARCH)
			if err != nil {
				return err
			}

			fmt.Printf("  Downloading %s…\n", assets[0].Name)
			archivePath, err := client.Download(ctx, assets[0])
			if err != nil {
				return err
			}
			defer func() { _ = os.Remove(archivePath) }()

			binPath, err := update.Extract(archivePath, runtime.GOOS)
			if err != nil {
				return err
			}
			defer func() { _ = os.RemoveAll(filepath.Dir(binPath)) }()

			installed, backup, err := update.ReplaceSelf(binPath)
			if err != nil {
				return err
			}

			fmt.Printf("  Updated nice_scan → %s\n", rel.TagName)
			fmt.Printf("  Installed at %s (previous binary kept as %s for rollback)\n", installed, backup)
			fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Render("  Verified: sha256 against the release's published checksums. The GPG-signed chain (pinned fingerprint) remains on the installer path."))
			fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Render("  Restart nice_scan to run the new version."))
			return nil
		},
	}
	cmd.Flags().BoolVar(&checkOnly, "check", false, "only report the comparison with the latest release, no download")
	cmd.Flags().BoolVar(&force, "force", false, "download and install even when the running version is a dev build")
	return cmd
}

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
	if len(cfg.Headers) > 0 {
		opts = append(opts, transport.WithHeaders(cfg.Headers))
	}

	return transport.NewClient(opts...)
}

// parseHeaderFlags converts "Key: value" flag repeats into a header map,
// placing everything before the first colon as the key.
func parseHeaderFlags(headerLines []string) map[string]string {
	out := make(map[string]string, len(headerLines))
	for _, h := range headerLines {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			out[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return out
}

// buildClientForTarget builds the shared client bound to the command's
// target: operator credentials (cookie/headers) only attach to the target's
// host and its subdomains, never to third-party hosts the scan might touch.
func buildClientForTarget(target string) *transport.Client {
	client := buildClient()
	if scope := transport.HostDomain(target); scope != "" {
		client.SetCredScope(scope)
	}
	return client
}

// validateProxy rejects malformed --proxy values up front. The transport
// used to log-and-ignore them, silently sending direct traffic while the
// operator believed a tunnel was active.
func validateProxy(proxy string) error {
	if proxy == "" {
		return nil
	}
	parsed, err := url.Parse(proxy)
	if err != nil {
		return fmt.Errorf("could not parse proxy URL: %w", err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "socks5":
	default:
		return fmt.Errorf("unsupported proxy scheme %q (want http, https or socks5)", parsed.Scheme)
	}
	if parsed.Hostname() == "" {
		return fmt.Errorf("proxy URL is missing a host")
	}
	return nil
}

func scanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scan [target]",
		Short: "Full reconnaissance scan (passive + active checks)",
		Long:  "Complete scan: reads the target stack from its homepage FIRST, then fires only probes that stack makes sense for (a Python server never gets /phpinfo.php or /wp-login.php), plus header analysis, TLS, exposures, SQLi, XSS, CORS, HTTP methods, token extraction, auth detection, privilege escalation, data extraction. Generates ~50 requests. Use -R for HTML report.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := normalizeTarget(args[0])

			client := buildClientForTarget(target)
			defer func() { _ = client.Close() }()

			scanner := engine.NewScanner(cfg, client)
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

			if interactive {
				model := tui.NewModel(scanner, []string{target})
				p := tea.NewProgram(model, tea.WithAltScreen())
				fm, err := p.Run()
				if err != nil {
					return err
				}
				// The alt-screen dashboard closes with the program; the
				// final model carries the outcome — print it on the
				// regular screen or a finished (and a fully-failed) scan
				// leaves the terminal empty.
				if final, ok := fm.(*tui.Model); ok {
					fmt.Print(final.PostRunSummary())
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
				// Reports embed scan evidence (URLs, tokens, responses):
				// operator-private, 0600 regardless of umask.
				if err := os.WriteFile(reportFile, []byte(html), 0600); err != nil {
					return fmt.Errorf("failed to write report: %w", err)
				}
				fmt.Println()
				fmt.Println(output.MutedStyle.Render("  Report saved: ") + output.ValueStyle.Render(reportFile))
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

			client := buildClientForTarget(target)
			defer func() { _ = client.Close() }()

			scanner := engine.NewScanner(cfg, client)
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
				// Reports embed scan evidence (URLs, tokens, responses):
				// operator-private, 0600 regardless of umask.
				if err := os.WriteFile(reportFile, []byte(html), 0600); err != nil {
					return fmt.Errorf("failed to write report: %w", err)
				}
				fmt.Println()
				fmt.Println(output.MutedStyle.Render("  Full audit report: ") + output.ValueStyle.Render(reportFile))
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
		accessVerify bool
		credsFeed    string
		allModules   bool
	)

	cmd := &cobra.Command{
		Use:   "exploit [target]",
		Short: "Active exploitation: login brute, IDOR, privesc, token, register, reset, session",
		Long: `
  Active exploitation. With NO module flag, the safe chain runs,
  in the order a real attack would:

    token/session reuse on protected endpoints → admin access
    verification (anonymous vs session).

  State-writing modules are consent-gated: the 40-pair login spray and
  differential role tampering POST to the target (a spray can lock real
  accounts) and run only under --destructive — or, for the login, with
  --creds user:pass as one explicit operator-owned attempt.

  Verification rule everywhere: differential evidence or nothing — a row
  with ✓ means the server actually served something the anonymous round
  did not. No session captured? The access block says so and tells you
  the one action that would produce one.

  Extras (opt-in, the default chain already covers the common run):
    --login            40-pair credential spray (requires --destructive)
    --role             differential role tampering (requires --destructive)
    --register         create an account, log in with it, harvest the session
                       (state-modifying: requires --destructive consent)
    --idor 1-100       numeric ID enumeration (query + path)
    --reset            password-reset probing (user enumeration / token leaks)
    --session          session fixation checks
    --token/--access   force a single read-only module alone
    --all              every module this command can run safely
                       (--login/--role/--register still need --destructive)
    --cookie "n=v"     feed your own session instead of finding one
    --creds "u:p"      feed your own credential: one login attempt, one
                       differential verdict, then the session feeds the
                       access verification automatically

  Only use on authorized targets.
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := normalizeTarget(args[0])

			// No module flag selected: run the default chain (the plain
			// "tell me everything honest" run) instead of dumping help.
			selected := cmd.Flags().Changed("login") || cmd.Flags().Changed("role") ||
				cmd.Flags().Changed("token") || cmd.Flags().Changed("idor") ||
				cmd.Flags().Changed("register") || cmd.Flags().Changed("reset") ||
				cmd.Flags().Changed("session") || cmd.Flags().Changed("access") ||
				cmd.Flags().Changed("all")
			if !selected {
				loginBrute = true
				roleTamper = true
				tokenReuse = true
				accessVerify = true
			}

			client := buildClientForTarget(target)
			defer func() { _ = client.Close() }()

			opts := exploit.Options{
				Target:  target,
				Verbose: cfg.Verbose,
			}
			exp := exploit.New(client, opts)

			// A session the operator already holds (from their own browser,
			// burp, previous run) makes every authenticated differential in this
			// command real instead of unauthenticated guessing.
			if cfg.Cookie != "" {
				exp.SetAuthCookie(cfg.Cookie, "operator --cookie")
			}

			renderer := output.NewTerminal()
			renderer.RenderBanner()

			ctx, cancel := signalContext()
			defer cancel()

			fmt.Println(output.Section("Exploitation"))
			fmt.Println()

			runLogin := loginBrute || allModules
			runRole := roleTamper || allModules
			runToken := tokenReuse || allModules
			runIdor := idorRange != "" || allModules
			// Credential spraying and role tampering POST state to the
			// target (a spray can lock real accounts; tampered rounds hit
			// register/update forms as admin). The default chain no longer
			// fires them silently — they require --destructive consent.
			// An operator-fed --creds is explicit single-attempt consent.
			if runLogin && !cfg.Destructive && credsFeed == "" {
				fmt.Println(lipgloss.NewStyle().Foreground(clWarn).Render(
					"  ⚠ login spray skipped: 40-pair brute force can lock real accounts. Re-run with --destructive, or --creds user:pass for one explicit attempt.",
				))
				runLogin = false
			}
			if runRole && !cfg.Destructive {
				fmt.Println(lipgloss.NewStyle().Foreground(clWarn).Render(
					"  ⚠ role tampering skipped: tampered POSTs write to the target. Re-run with --destructive to consent.",
				))
				runRole = false
			}
			// Account registration and password-reset testing write state
			// to the target (accounts created, reset flows exercised).
			// They ship ONLY under --destructive consent — --all does not
			// silently include them.
			runRegister := registerAcc && cfg.Destructive
			if registerAcc && !cfg.Destructive {
				fmt.Println(lipgloss.NewStyle().Foreground(clWarn).Render(
					"  ⚠ --register refused: creating accounts is state-modifying. Re-run with --destructive to consent.",
				))
			}
			runReset := resetPass && cfg.Destructive
			if resetPass && !cfg.Destructive {
				fmt.Println(lipgloss.NewStyle().Foreground(clWarn).Render(
					"  ⚠ --reset refused: password-reset flows send live emails and mint state on the target. Re-run with --destructive to consent.",
				))
			}
			runSession := sessionFix || allModules

			// Operator-supplied credential: when the operator already
			// owns an account, the 40-pair spray is pure noise — one
			// attempt, one differential verdict, one session.
			var creds = exploit.CommonCredentials
			if credsFeed != "" {
				user, pass, _ := strings.Cut(credsFeed, ":")
				if user != "" && pass != "" {
					creds = []exploit.Credential{{User: user, Pass: pass, Desc: "operator-supplied"}}
				} else {
					return fmt.Errorf("--creds expects user:pass form, got %q", credsFeed)
				}
			}

			if runLogin {
				fmt.Println(output.Section("Login Bruteforce"))
				results := exp.BruteforceLogin(ctx, target, creds)

				var valid []exploit.LoginAttempt
				var notable []exploit.LoginAttempt
				for _, r := range results {
					if r.Success {
						valid = append(valid, r)
						continue
					}
					// Operationally interesting failures: the spray never
					// ran or no verdict was possible — the operator needs
					// to see those; per-pair « invalid » rows add nothing.
					if strings.Contains(r.Evidence, "skipped") ||
						strings.Contains(r.Evidence, "baseline could not be established") ||
						strings.Contains(r.Evidence, "verdict withheld") ||
						strings.Contains(r.Evidence, "no failure baseline") {
						notable = append(notable, r)
					}
				}

				for _, r := range valid {
					fmt.Println(lipgloss.NewStyle().Foreground(clFail).Padding(0, 4).Render(
						fmt.Sprintf("  ✓ %s:%s → %d (%s)", types.Sanitize(r.Username), types.Sanitize(r.Password), r.StatusCode, truncateStr(r.Evidence, 60)),
					))
				}
				for _, r := range notable {
					fmt.Println(lipgloss.NewStyle().Foreground(clWarn).Padding(0, 4).Render(
						fmt.Sprintf("  ! %s (%s)", truncateStr(r.Evidence, 78), truncateStr(r.FormURL, 40)),
					))
				}

				switch {
				case len(valid) > 0:
					fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Padding(0, 4).Render(
						fmt.Sprintf("  %d credential pair(s) tested — %d valid", len(results), len(valid)),
					))
				case len(notable) > 0:
					fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Padding(0, 4).Render(
						fmt.Sprintf("  %d pair(s) considered — none verified valid (details above)", len(results)),
					))
				default:
					fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Padding(0, 4).Render(
						fmt.Sprintf("  %d invalid", len(results)),
					))
				}
				// A differential-verified credential is worth its session:
				// the harvested cookie feeds the access modules so they
				// compare real, authenticated rounds.
				for _, r := range results {
					if r.Success && r.SetCookie != "" {
						if exp.AttachHarvestedSession(r.SetCookie, "login "+r.Username) {
							fmt.Println(lipgloss.NewStyle().Foreground(clFail).Padding(0, 4).Render(
								fmt.Sprintf("  ✓ valid credential — session captured (cookie %s), re-run --access to verify admin access with it", types.Sanitize(exploit.ShortCookie(r.SetCookie))),
							))
						}
						break
					}
				}
				fmt.Println()
			}

			if runRole {
				fmt.Println(output.Section("Role / Privilege Escalation"))
				results := exp.RoleTampering(ctx, target)

				var lifts []exploit.RoleResult
				for _, r := range results {
					if r.Success {
						lifts = append(lifts, r)
					}
				}

				for _, r := range lifts {
					fmt.Println(lipgloss.NewStyle().Foreground(clFail).Padding(0, 4).Render(
						fmt.Sprintf("  ✓ %s=%s %s → %d (%s)", types.Sanitize(r.Parameter), types.Sanitize(r.Value), r.Method, r.StatusCode, truncateStr(r.Evidence, 66)),
					))
				}

				if len(lifts) > 0 {
					fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Padding(0, 4).Render(
						fmt.Sprintf("  %d tamper round(s) — %d lifted privileges over the control round", len(results), len(lifts)),
					))
				} else {
					fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Padding(0, 4).Render(
						fmt.Sprintf("  — %d tamper rounds tested against a control round: no response differed — no role parameter affected privilege on this target", len(results)),
					))
				}
				fmt.Println()
			}

			if runToken {
				fmt.Println(output.Section("Token / Session Reuse"))

				// Real discovery first: JWTs harvested from reachable
				// pages and session cookies from Set-Cookie headers.
				// No placeholder is probed: an empty harvest is an
				// honest skip, never a fake attempt.
				tokens, discoveredCookies := exp.DiscoverTokens(ctx, target)
				if cfg.Cookie != "" {
					discoveredCookies = append(discoveredCookies, cfg.Cookie)
				}

				results := exp.TryTokenReuse(ctx, tokens, target)
				displayCount := 0
				for _, r := range results {
					if displayCount >= 8 {
						break
					}
					cl := clMuted
					if r.Success {
						cl = clFail
					}
					fmt.Println(lipgloss.NewStyle().Foreground(cl).Padding(0, 4).Render(
						fmt.Sprintf("  %s %s → %d (%s)", types.Sanitize(r.Token), types.Sanitize(r.Endpoint), r.StatusCode, truncateStr(r.Evidence, 50)),
					))
					displayCount++
				}
				for _, r := range exp.TrySessionReuse(ctx, discoveredCookies, target) {
					if displayCount >= 8 {
						break
					}
					cl := clMuted
					if r.Success {
						cl = clFail
					}
					fmt.Println(lipgloss.NewStyle().Foreground(cl).Padding(0, 4).Render(
						fmt.Sprintf("  %s %s → %d (%s)", types.Sanitize(r.Token), types.Sanitize(r.Endpoint), r.StatusCode, truncateStr(r.Evidence, 50)),
					))
					displayCount++
				}
				if displayCount == 0 {
					fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Padding(0, 4).Render(
						"  — No reusable token or session discovered: nothing to test (no fake attempt made)",
					))
				}
				fmt.Println()
			}

			if runIdor {
				var startID, endID int
				if _, err := fmt.Sscanf(idorRange, "%d-%d", &startID, &endID); err != nil {
					// An empty range means IDOR ran as part of --all, not a
					// malformed operator flag — say so instead of scolding
					// about an "" the operator never typed.
					if idorRange == "" {
						startID, endID = 1, 10
					} else {
						fmt.Printf("  invalid --idor range %q (want N-M integers), using 1-10\n", idorRange)
						startID, endID = 1, 10
					}
				}
				if startID <= 0 || endID <= 0 {
					startID, endID = 1, 10
				}
				if endID < startID {
					startID, endID = endID, startID
				}
				if endID-startID+1 > exploit.MaxIDORSpan {
					fmt.Printf("  range clamped to %d IDs (MaxIDORSpan): %d-%d\n",
						exploit.MaxIDORSpan, startID, startID+exploit.MaxIDORSpan-1)
					endID = startID + exploit.MaxIDORSpan - 1
				}
				fmt.Println(output.Section(fmt.Sprintf("IDOR Enumeration (%d-%d)", startID, endID)))
				results := exp.IDOREnumeration(ctx, target, "", startID, endID)

				// Per-surface differential, not one global baseline. The old
				// code compared every row — "/users/?id=2" AND "/order/?id=1"
				// alike — against results[0], so two different endpoints with
				// naturally different page sizes screamed "divergent". Group
				// by Surface, take each surface's MOST COMMON size as its
				// reference (an IDOR leak is a minority row, so the mode is
				// the honest baseline), and flag only rows that differ from
				// their OWN endpoint's mode.
				type surfaceStat struct {
					counts map[int]int
					refs   []exploit.IDORResult
				}
				surfaces := map[string]*surfaceStat{}
				var order []string
				for _, r := range results {
					s := r.Surface
					if s == "" {
						s = r.ParamType + ":" + fmt.Sprintf("%d", r.ID)
					}
					st := surfaces[s]
					if st == nil {
						st = &surfaceStat{counts: map[int]int{}}
						surfaces[s] = st
						order = append(order, s)
					}
					st.counts[r.BodySize]++
					st.refs = append(st.refs, r)
				}

				totalDivergent := 0
				totalSurfaces := len(order)
				for _, s := range order {
					st := surfaces[s]
					if len(st.refs) < 2 {
						continue
					}
					baseline, best := 0, -1
					for size, c := range st.counts {
						if c > best {
							baseline, best = size, c
						}
					}
					for _, r := range st.refs {
						if abs(r.BodySize-baseline) > 100 {
							totalDivergent++
							fmt.Println(lipgloss.NewStyle().Foreground(clFail).Padding(0, 4).Render(
								fmt.Sprintf("  ? %s id=%d → %d (%d bytes, mode %d, diff %d) — this referent answers differently from its own endpoint; follow it",
									types.Sanitize(r.Surface), r.ID, r.StatusCode, r.BodySize, baseline, abs(r.BodySize-baseline)),
							))
						}
					}
				}

				if totalSurfaces == 0 || len(results) == 0 {
					fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Padding(0, 4).Render(
						"  — enumeration produced no responses to compare (target unreachable for every probed referent)"))
				} else if totalDivergent == 0 {
					fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Padding(0, 4).Render(
						fmt.Sprintf("  — %d request(s) across %d endpoint(s): within every endpoint all referents returned the same size — the identifier is ignored or consistently authorized; no IDOR candidate",
							len(results), totalSurfaces)))
				} else {
					fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Padding(0, 4).Render(
						fmt.Sprintf("  — %d referent(s) diverged from their own endpoint's modal size — listed above as candidates (compare the bodies before trusting a hit)", totalDivergent)))
				}
				fmt.Println()
			}

			if runRegister {
				fmt.Println(output.Section("Account Registration"))
				results := exp.RegisterAccount(ctx, target)
				for _, r := range results {
					cl := clMuted
					status := "✗"
					if r.Success {
						cl = clFail
						status = "✓"
					}
					fmt.Println(lipgloss.NewStyle().Foreground(cl).Padding(0, 4).Render(
						fmt.Sprintf("  %s %s → %d (%s)", status, types.Sanitize(r.Payload), r.StatusCode, truncateStr(r.Evidence, 50)),
					))
				}
				if len(results) == 0 {
					fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Padding(0, 4).Render(
						"  — " + exp.RegisterProbeReport()))
				}
				// A created account is logged in automatically (same
				// differential verdict as the bruteforce) and its session
				// feeds --access. Say what happened, never silently.
				if cookie, source := exp.AuthCookie(); cookie != "" && strings.HasPrefix(source, "login ") {
					fmt.Println(lipgloss.NewStyle().Foreground(clFail).Padding(0, 4).Render(
						fmt.Sprintf("  ✓ registered account logged in — session captured (cookie %s)", types.Sanitize(exploit.ShortCookie(cookie))),
					))
				}
				fmt.Println()
			}

			if runReset {
				fmt.Println(output.Section("Password Reset"))
				results := exp.ExploitPasswordReset(ctx, target)
				vuln := 0
				for _, r := range results {
					if !r.Vulnerable {
						continue
					}
					vuln++
					fmt.Println(lipgloss.NewStyle().Foreground(clFail).Padding(0, 4).Render(
						fmt.Sprintf("  ⚠ %s → %d (%s)", types.Sanitize(r.Identifier), r.StatusCode, truncateStr(r.Evidence, 66)),
					))
				}
				summary := clMuted
				switch {
				case len(results) == 0:
					fmt.Println(lipgloss.NewStyle().Foreground(summary).Padding(0, 4).Render("  — " + exp.ResetProbeReport()))
				case vuln > 0:
					fmt.Println(lipgloss.NewStyle().Foreground(summary).Padding(0, 4).Render(
						fmt.Sprintf("  — %d probe(s) sent — %d showed a reset-surface vulnerability (enumeration split or token leak)", len(results), vuln)))
				default:
					fmt.Println(lipgloss.NewStyle().Foreground(summary).Padding(0, 4).Render(
						fmt.Sprintf("  — %d probe(s) sent — none showed an enumeration split, token leak or vulnerable response", len(results))))
				}
				fmt.Println()
			}

			if runSession {
				fmt.Println(output.Section("Session Hardening (fixation needs a credentialed login — not tested)"))
				results := exp.TestSessionHardening(ctx, target)
				for _, r := range results {
					cl := clMuted
					status := "○"
					if r.Vulnerable {
						cl = clFail
						status = "⚠"
					}
					fmt.Println(lipgloss.NewStyle().Foreground(cl).Padding(0, 4).Render(
						fmt.Sprintf("  %s %s → %d (%s)", status, types.Sanitize(r.Endpoint), r.StatusCode, truncateStr(r.Evidence, 50)),
					))
				}
				if len(results) == 0 {
					fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Padding(0, 4).Render("  — No login forms found for session testing"))
				}
				fmt.Println()
			}

			// ── Verified access chain ────────────────────────────────
			// Every module above only makes sense if access actually
			// changes with a session. This module replays admin paths
			// anonymously vs with the session and reports REAL gains —
			// or states plainly that nothing was verified.
			runAccess := accessVerify || allModules
			if runAccess {
				fmt.Println(output.Section("Admin Access Verification (differential)"))
				results := exp.VerifiedAdminAccess(ctx, target)
				verified := 0
				sawNoSession := false
				for _, r := range results {
					if r.Path == "(no session)" {
						sawNoSession = true
						// The one honest verdict available without a
						// session: say what would fix it, once.
						fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Padding(0, 4).Render(
							fmt.Sprintf("  ○ %s", truncateStr(r.Evidence, 96)),
						))
						continue
					}
					cl := clMuted
					status := "○"
					if r.Success {
						cl = clFail
						status = "✓"
						verified++
					}
					fmt.Println(lipgloss.NewStyle().Foreground(cl).Padding(0, 4).Render(
						fmt.Sprintf("  %s %s → anon %d / session %d (%s)", status, r.Path, r.Anonymous, r.WithSess, truncateStr(r.Evidence, 72)),
					))
				}
				if cookie, source := exp.AuthCookie(); cookie != "" {
					fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Padding(0, 4).Render(
						fmt.Sprintf("  session in use: %s (source: %s)", types.Sanitize(exploit.ShortCookie(cookie)), types.Sanitize(source)),
					))
				}
				if verified == 0 && !sawNoSession {
					fmt.Println(lipgloss.NewStyle().Foreground(clMuted).Padding(0, 4).Render(
						"  — No admin path answered differently with the session: no verified access gain",
					))
				}
				fmt.Println()
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&loginBrute, "login", false, "Bruteforce common credentials against login forms (--destructive required; spray can lock accounts)")
	cmd.Flags().StringVar(&idorRange, "idor", "", "IDOR enumeration range (e.g. 1-100)")
	cmd.Flags().BoolVar(&roleTamper, "role", false, "Test role/privilege escalation via params + headers (--destructive required; tampered POSTs)")
	cmd.Flags().BoolVar(&tokenReuse, "token", false, "Reuse JWT/session tokens on protected endpoints")
	cmd.Flags().BoolVar(&registerAcc, "register", false, "Attempt account registration with various payloads (--destructive required; successful accounts are logged in to harvest a session)")
	cmd.Flags().BoolVar(&resetPass, "reset", false, "Test password reset for user enumeration + token leaks")
	cmd.Flags().BoolVar(&sessionFix, "session", false, "Inspect session cookie issuance on login surfaces (flags, ID entropy) — fixation itself needs --creds")
	cmd.Flags().BoolVar(&accessVerify, "access", false, "Replay admin paths anonymously vs with the session — differential access verification")
	cmd.Flags().StringVar(&credsFeed, "creds", "", "Log in with one known credential instead of the 40-pair spray (user:pass); its harvested session feeds --access")
	cmd.Flags().BoolVar(&allModules, "all", false, "Run all exploitation modules")

	return cmd
}

func hackCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "hack [target]",
		Short: "Autonomous hacker — Decision Engine chains attacks automatically",
		Long: `
  Autonomous attack agent — the Decision Engine:
  1. Passive recon (crt.sh, Wayback) — discover subdomains
  2. Crawl — discover pages, forms, endpoints, JS files
  3. Fuzz — hidden endpoints and parameter discovery
  4. Port scan — TCP connect on top 100 ports
  5. Attack modules — JWT forge, SQLi, XSS, LFI detection
  6. GraphQL introspection, S3 bucket enumeration, OOB callbacks
  7. Attack chain detection + execution
  8. Complete attack report (terminal + HTML with -R)

  State-writing modules — login bruteforce, cmd injection, uploads,
  webshell, SQLi/LFI/S3 data dumps, GraphQL mutation fuzzing — are
  withheld unless you grant --destructive consent. The report lists
  exactly what was withheld; nothing vanishes silently.

  This is an offensive tool — only use on authorized targets.

  Examples:
    nice_scan hack example.com
    nice_scan hack https://example.com -R report.html
    nice_scan hack example.com --timeout 10s
    nice_scan hack example.com --destructive   # consent to state-writing
`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				fmt.Println()
				fmt.Println(output.Section("Autonomous attack agent — Decision Engine"))
				fmt.Println(output.MutedStyle.Render("  Usage:  nice_scan hack <target> [flags]"))
				fmt.Println()
				fmt.Printf("  %s\n", output.ValueStyle.Render("nice_scan hack example.com"))
				fmt.Printf("  %s\n", output.ValueStyle.Render("nice_scan hack https://example.com --timeout 10s -R report.html"))
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

			client := buildClientForTarget(target)
			defer func() { _ = client.Close() }()

			renderer := output.NewTerminal()
			renderer.RenderBanner()

			if cfg.Destructive {
				fmt.Println(lipgloss.NewStyle().Foreground(clFail).Render(
					"  ⚠ destructive mode — state-modifying actions enabled (cmd injection, shell upload, credential spray, data dumps)",
				))
			}

			brain := hacker.NewBrain(target, client, defaultHackActions(cfg)...)
			// Destructive modules are always registered; consent is enforced
			// at dispatch, so runtime-spawned ones are covered too.
			brain.AppendAction(&hacker.CMDInjectAction{}, &hacker.UploadAction{})
			brain.SetDestructive(cfg.Destructive)
			brain.AppendAction(&hacker.GraphQLAction{},
				&hacker.S3Action{Proxy: cfg.Proxy},
				hacker.NewOOBAction(),
			)

			ctx, cancel := signalContext()
			defer cancel()

			report := brain.Run(ctx)
			brain.RenderReport(report)

			if reportFile != "" {
				html := hacker.RenderHTMLReport(report)
				// Reports embed scan evidence (URLs, tokens, responses):
				// operator-private, 0600 regardless of umask.
				if err := os.WriteFile(reportFile, []byte(html), 0600); err != nil {
					return fmt.Errorf("failed to write HTML report: %w", err)
				}
				fmt.Println()
				fmt.Println(output.MutedStyle.Render("  HTML report saved: ") + output.ValueStyle.Render(reportFile))
			}

			return nil
		},
	}
}

// defaultHackActions is the registry every `hack` run loads. It is a
// separate function so a test can assert the modules are actually wired:
// three read-only modules (headers, JS secrets, source maps) existed with
// full implementations and were registered nowhere, so they never ran. A
// registry that silently omits an action is indistinguishable from one that
// works — hence the assertion in TestDefaultHackActionsIncludePassiveModules.
//
// Consent is enforced at dispatch (planner), not here: actions flagged
// Destructive — LoginBrute included — stay in the registry but are
// withheld and reported unless the operator granted --destructive.
func defaultHackActions(cfg *types.Config) []hacker.Action {
	return []hacker.Action{
		&hacker.PassiveReconAction{Proxy: cfg.Proxy},
		&hacker.CrawlAction{},
		&hacker.FuzzAction{},
		&hacker.SmartHeadersAction{},
		&hacker.TLSInspectorAction{},
		&hacker.FormIntegrityAction{},
		&hacker.PortScanAction{},
		&hacker.LoginBruteAction{},
		&hacker.JSSecretsAction{},
		&hacker.SourceMapAction{},
		&hacker.XSSAction{},
		&hacker.SQLiAction{},
		&hacker.JWTForgeAction{},
		&hacker.LFIAction{},
	}
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

			client := buildClientForTarget(target)
			defer func() { _ = client.Close() }()

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

			client := buildClientForTarget(target)
			defer func() { _ = client.Close() }()

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
	lower := strings.ToLower(target)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
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
	// Print sink: remote-derived result fields (evidence, payloads) may
	// carry terminal control sequences. Sanitize before truncation.
	s = types.Sanitize(s)
	if n <= 0 {
		return ""
	}
	// Truncate on rune boundaries: byte slicing of remote unicode
	// evidence would emit a corrupted partial rune into the terminal.
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n-1]) + "…"
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
