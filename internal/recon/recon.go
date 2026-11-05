// Package recon is the evidence service: it builds a target-scoped transport,
// registers the analyzers, and returns graded findings. It renders nothing and
// writes nothing to stdout.
//
// The engine underneath it was already the deterministic part; what lived one
// layer up in cmd/nice_scan was not reusable — the analyzer roster and the
// scoped-client construction were pasted into each command, so the CLI was the
// only possible consumer. A model, a script, a future MCP server and the TUI
// drive the same calls — Baseline, Scan, VerifyAccess — and a service that
// prints is a service a model cannot call.
package recon

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/engine"
	"github.com/NICE-DEV226/nice-Scan/internal/fingerprint"
	"github.com/NICE-DEV226/nice-Scan/internal/subdomain"
	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// ErrNoScope is returned when a Service is asked to exist without a target
// allow-list. It is an error rather than a default-open client because this is
// the machine-facing gate: the caller that is not a human reading the output
// must state where it is allowed to go.
var ErrNoScope = errors.New("recon: a non-empty target scope is required")

// Options configures a Service. Operator policy (timeout, retries, proxy,
// credentials, whether the scope is a hard boundary, whether internal
// addresses are dialable) comes from Config; the scope itself is the service's
// contract with its caller and is therefore explicit here.
type Options struct {
	// Config is the operator's policy. Nil means types.DefaultConfig().
	Config *types.Config
	// Scope lists the hosts requests may be aimed at: the target host and,
	// for a multi-host scan, each of them. Entries are matched as
	// registrable hosts, so a host and its subdomains are in scope.
	Scope []string
	// Analyzers overrides the default roster. A caller that wants one
	// capability — technology only, or a TLS read — passes a shorter list
	// rather than filtering a full scan's findings afterwards.
	Analyzers []engine.Analyzer
}

// Service holds one scoped client and one scanner, so a session's stack cache
// and its credential scope persist across calls the way they do in the shell.
type Service struct {
	client  *transport.Client
	scanner *engine.Scanner
	verbose bool
}

// Baseline is the cheapest true read of a target: one GET, what it served,
// what stack it declared, and what the analyzers make of that single response.
type Baseline struct {
	URL         string
	Status      int
	ContentType string
	Size        int64
	Sig         string
	Stack       fingerprint.Stack
	Findings    []types.Finding
	Response    *types.Response
}

// New builds the scoped client and the scanner, and registers the roster
// against the scanner's own XSS canary — the probes and the analyzer that
// judges them must share one token, which is why the roster cannot be a
// package-level table.
func New(o Options) (*Service, error) {
	scope := transport.NormalizeScope(o.Scope)
	if len(scope) == 0 {
		return nil, fmt.Errorf("%w: got %v", ErrNoScope, o.Scope)
	}

	cfg := o.Config
	if cfg == nil {
		cfg = types.DefaultConfig()
	}

	opts := transport.OptionsFromConfig(cfg)
	opts = append(opts, transport.WithCredScope(scope))
	if cfg.EnforceScope {
		opts = append(opts, transport.WithTargetScope(scope...))
	}
	if cfg.BlockInternal {
		opts = append(opts, transport.WithPrivateNetworkAllowed(false))
	}

	client := transport.NewClient(opts...)
	scanner := engine.NewScanner(cfg, client)

	analyzers := o.Analyzers
	if len(analyzers) == 0 {
		analyzers = DefaultAnalyzers(scanner.XSSCanary())
	}
	scanner.RegisterAnalyzers(analyzers...)

	return &Service{client: client, scanner: scanner, verbose: cfg.Verbose}, nil
}

// Scanner hands out the scanner this service is configured to run. The
// interactive dashboard needs it because it consumes ScanStream events rather
// than a finished result; everything else goes through the methods below.
func (s *Service) Scanner() *engine.Scanner { return s.scanner }

// Scan runs the roster over the target set and returns the engine's result
// unchanged — findings already carry the provenance the engine stamped.
func (s *Service) Scan(ctx context.Context, targets []string) (*engine.ScanResult, error) {
	if len(targets) == 0 {
		return nil, errors.New("recon: no target to scan")
	}
	return s.scanner.Scan(ctx, targets), nil
}

// Baseline fetches the homepage once and analyzes that single response. No
// path probe is generated: this is the read a caller uses to decide what to
// aim at next.
func (s *Service) Baseline(ctx context.Context, target string) (*Baseline, error) {
	res, findings := s.scanner.Baseline(ctx, target)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.Response == nil {
		return nil, fmt.Errorf("recon: %s returned no response", target)
	}

	stack := s.scanner.Stacks()[target]

	return &Baseline{
		URL:         target,
		Status:      res.Response.StatusCode,
		ContentType: res.Response.ContentType,
		Size:        int64(len(res.Response.Body)),
		Sig:         engine.ResponseSig(res.Response),
		Stack:       stack,
		Findings:    findings,
		Response:    res.Response,
	}, nil
}

// DiscoverSubdomains enumerates a domain through two independent families.
//
// It is a package function rather than a Service method because it puts
// nothing through the scoped client: the sources are a public
// certificate-transparency log and the recursive resolver. Hanging it off the
// service would tell a caller that the scan's target scope governs requests it
// does not govern.
func DiscoverSubdomains(ctx context.Context, domain string) (*subdomain.Result, error) {
	return subdomain.Discover(ctx, domain, subdomain.Options{
		Resolver: subdomain.NewDNSResolver(),
		CT:       subdomain.NewCTLogSource(nil),
	})
}

// Close releases the client's connections. The scanner shares that client, so
// closing the service closes the scan.
func (s *Service) Close() error { return s.client.Close() }

// Stats reports what the scoped client actually put on the wire: the caller's
// check that a scan cost what its report claims it cost.
func (s *Service) Stats() transport.RequestStats { return s.client.Stats() }

// DefaultAnalyzers is the roster a full reconnaissance run registers. It lives
// here because there is exactly one honest answer to "what does a scan do", and
// it was previously written twice in cmd/nice_scan — where a change to one copy
// would have made `audit` and `scan` disagree.
func DefaultAnalyzers(canary string) []engine.Analyzer {
	return []engine.Analyzer{
		fingerprint.New(),
		engine.NewHeaderAnalyzer(),
		engine.NewTLSAnalyzer(),
		engine.NewExposureAnalyzer(),
		engine.NewSQLiAnalyzer(),
		engine.NewXSSAnalyzer(canary),
		engine.NewCORSAnalyzer(),
		engine.NewHTTPMethodsAnalyzer(),
		engine.NewTokenExtractor(),
		engine.NewAuthAnalyzer(),
		engine.NewPrivilegeEscalationAnalyzer(),
		engine.NewDataExtractionAnalyzer(),
	}
}

// SubdomainFindings turns a discovery Result into reportable findings.
// Confirmed names (both families agree on a live host) become Info findings
// carrying their addresses and corroborating sources as evidence; unconfirmed
// names are folded into the summary count so the caller sees the honest
// denominator without a wall of single-source noise.
func SubdomainFindings(res *subdomain.Result) []types.Finding {
	findings := make([]types.Finding, 0, len(res.Confirmed)+1)

	wildcard := "no"
	if res.Wildcard {
		wildcard = "yes"
	}
	findings = append(findings, types.Finding{
		Type:        types.FindingSubdomain,
		Name:        fmt.Sprintf("Subdomain recon: %d confirmed", len(res.Confirmed)),
		Severity:    types.SeverityInfo,
		Description: fmt.Sprintf("%d candidates checked, %d resolved, wildcard DNS: %s", res.Candidates, res.Resolved, wildcard),
		Confidence:  1.0, // a factual run summary, not a probabilistic claim
		Metadata: map[string]string{
			"domain":     res.Domain,
			"candidates": strconv.Itoa(res.Candidates),
			"resolved":   strconv.Itoa(res.Resolved),
			"confirmed":  strconv.Itoa(len(res.Confirmed)),
			"wildcard":   wildcard,
		},
	})

	for _, rec := range res.Confirmed {
		srcs := make([]string, 0, len(rec.Sources))
		for _, s := range rec.Sources {
			srcs = append(srcs, string(s))
		}
		findings = append(findings, types.Finding{
			Type:        types.FindingSubdomain,
			Name:        rec.Host,
			Severity:    types.SeverityInfo,
			Description: "Corroborated by CT log and a live DNS resolution",
			Evidence:    fmt.Sprintf("%s  [%s]", strings.Join(rec.Addrs, ", "), strings.Join(srcs, "+")),
			Confidence:  1.0,
			Metadata: map[string]string{
				"sources": strings.Join(srcs, ","),
				"addrs":   strings.Join(rec.Addrs, ","),
			},
			Prov: &types.Provenance{
				PathOrigin: types.PathObserved,
				// Two independent families had to agree, and the DNS
				// half only counts when the address differs from the
				// wildcard catch-all. Recording which exclusion made
				// the corroboration possible is the point: on a
				// wildcarded namespace "it resolved" is worthless.
				Methods:     []types.EvidenceMethod{types.MethodCrossSourceCorroboration},
				BaselineRef: "wildcard-dns:" + wildcard,
				Grade:       types.GradeCorroborated,
			},
		})
	}
	return findings
}
