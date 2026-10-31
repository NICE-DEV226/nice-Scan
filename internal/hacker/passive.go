package hacker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

type PassiveReconAction struct {
	// Proxy carries the operator's proxy config into the dedicated
	// recon client below (third-party services must still honor the
	// configured exit route).
	Proxy string
}

func (a *PassiveReconAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "Passive Recon",
		Description: "GitHub dorking, crt.sh, Wayback Machine — no requests to target",
		Priority:    5,
		Requires:    nil,
		Provides:    []string{"has_subdomain"},
	}
}

// Test seam: source bases are overridable so unit tests can exercise
// the full failed/empty/hit matrix without third-party traffic.
var (
	crtShBase   = "https://crt.sh"
	waybackBase = "https://web.archive.org"
)

// reconSource carries one third-party recon source's state. Failed
// exists because a failed source can never justify "no public recon
// data" — the only honest phrase for unreachable sources is
// "inconclusive".
type reconSource struct {
	Name   string
	Data   []string
	Failed bool
	Detail string
}

func (s reconSource) ran() bool {
	return !s.Failed
}

func (s reconSource) empty() bool {
	return !s.Failed && len(s.Data) == 0
}

type crtShEntry struct {
	IssuerCaID     int    `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	ID             int    `json:"id"`
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	SerialNumber   string `json:"serial_number"`
}

func (a *PassiveReconAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	domain := extractDomain(target)
	if domain == "" {
		return ActionResult{}
	}

	var findings []Finding

	reconCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// Dedicated recon client for third-party services: deliberately bare
	// (no operator cookie, no configured auth headers). Attaching the
	// operator's credentials to crt.sh / web.archive.org burned them to
	// third parties on every scan. Proxy is honored when configured.
	reconOpts := []transport.ClientOption{
		transport.WithTimeout(15 * time.Second),
		transport.WithRetries(1),
	}
	if a.Proxy != "" {
		reconOpts = append(reconOpts, transport.WithProxy(a.Proxy))
	}
	reconClient := transport.NewClient(reconOpts...)
	defer func() { _ = reconClient.Close() }()

	crtCh := make(chan reconSource, 1)
	wbCh := make(chan reconSource, 1)

	go func() {
		crtCh <- queryCRTSh(reconCtx, reconClient, domain)
	}()
	go func() {
		wbCh <- queryWayback(reconCtx, reconClient, domain)
	}()

	var subdomains []string
	var waybackURLs []string
	var crtState, wbState reconSource
	crtState.Name = "crt.sh"
	wbState.Name = "Wayback"

collect:
	for i := 0; i < 2; i++ {
		select {
		case r := <-crtCh:
			crtState = r
			subdomains = r.Data
		case r := <-wbCh:
			wbState = r
			waybackURLs = r.Data
		case <-reconCtx.Done():
			// Cancellation: keep whatever arrived, stop waiting for
			// the rest. A bare `break` would only exit the select and
			// spin the remaining loop iterations.
			break collect
		}
	}

	if len(subdomains) > 0 {
		findings = append(findings, Finding{
			Type:        "subdomain",
			Name:        fmt.Sprintf("Subdomains discovered via crt.sh (%d)", len(subdomains)),
			Severity:    SevMedium,
			Description: fmt.Sprintf("Certificate Transparency logs reveal %d subdomains", len(subdomains)),
			Evidence:    strings.Join(subdomains[:min(10, len(subdomains))], ", "),
			Details:     map[string]string{"count": fmt.Sprintf("%d", len(subdomains))},
		})

		kb.AddCapability(Capability{
			Name:   "has_subdomain",
			Origin: OriginHint, // third-party CT data: unverified until the scanner resolves/checks them
			Target: target,
			Details: map[string]string{
				"count":  fmt.Sprintf("%d", len(subdomains)),
				"list":   strings.Join(subdomains, ", "),
				"source": "crt.sh certificate transparency logs",
			},
		})

		potentiallyInteresting := []string{"admin", "dev", "staging", "api", "test", "internal", "vpn", "jenkins", "jira", "confluence", "gitlab"}
		for _, sd := range subdomains {
			sdLow := strings.ToLower(sd)
			for _, keyword := range potentiallyInteresting {
				if strings.Contains(sdLow, keyword) {
					findings = append(findings, Finding{
						Type:        "interesting_subdomain",
						Name:        fmt.Sprintf("Interesting subdomain: %s", sd),
						Severity:    SevHigh,
						Description: fmt.Sprintf("Subdomain '%s' suggests a potentially sensitive service", sd),
						Evidence:    sd,
					})
					break
				}
			}
		}

		kb.AddCapability(Capability{
			Name:   "has_recon",
			Origin: OriginHint, // third-party CT data
			Target: target,
			Details: map[string]string{
				"subdomains": fmt.Sprintf("%d", len(subdomains)),
			},
		})
	}

	if len(waybackURLs) > 0 {
		findings = append(findings, Finding{
			Type:        "wayback_urls",
			Name:        fmt.Sprintf("Historical URLs via Wayback Machine (%d)", len(waybackURLs)),
			Severity:    SevLow,
			Description: "Wayback Machine reveals historical endpoints that may not be indexed anymore",
			Evidence:    strings.Join(waybackURLs[:min(10, len(waybackURLs))], ", "),
			Details:     map[string]string{"count": fmt.Sprintf("%d", len(waybackURLs))},
		})

		for _, wu := range waybackURLs {
			wLow := strings.ToLower(wu)
			if strings.Contains(wLow, "api") || strings.Contains(wLow, "admin") || strings.Contains(wLow, "graphql") || strings.Contains(wLow, "swagger") {
				ep := Endpoint{
					Path:   wu,
					Method: "GET",
					Status: 0,
				}
				kb.AddEndpoint(ep)
			}
		}
	}

	if len(subdomains) == 0 && len(waybackURLs) == 0 {
		// Honest verdict matrix: a failed source can never justify
		// "no data". Both sources failed → inconclusive; one failed
		// → partial verification only; both ran and returned nothing
		// → the plain "no public recon data" claim.
		var failed []reconSource
		if crtState.Failed {
			failed = append(failed, crtState)
		}
		if wbState.Failed {
			failed = append(failed, wbState)
		}
		switch {
		case len(failed) == 2:
			findings = append(findings, Finding{
				Type:     "recon_inconclusive",
				Name:     "Recon inconclusive: all public sources unreachable",
				Severity: SevInfo,
				Description: fmt.Sprintf("%s and %s could not be queried — the ABSENCE of subdomains/historical URLs is NOT verified",
					crtState.Name, wbState.Name),
				Evidence: fmt.Sprintf("%s (%s), %s (%s)", crtState.Name, crtState.Detail, wbState.Name, wbState.Detail),
			})
		case len(failed) == 1 && (crtState.empty() || wbState.empty()):
			findings = append(findings, Finding{
				Type:     "recon_partial",
				Name:     "Recon partially verified — one source unreachable",
				Severity: SevInfo,
				Description: fmt.Sprintf("The reachable source returned no data. %s failed (%s) — its absence claim is NOT verified",
					failed[0].Name, failed[0].Detail),
				Evidence: fmt.Sprintf("%s: %s", failed[0].Name, failed[0].Detail),
			})
		default:
			findings = append(findings, Finding{
				Type:        "recon_complete",
				Name:        "No public recon data found",
				Severity:    SevInfo,
				Description: "No subdomains or historical URLs discovered for " + domain,
			})
		}
	}

	return ActionResult{Findings: findings}
}
func extractDomain(target string) string {
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimRight(target, "/")
	parts := strings.Split(target, "/")
	if len(parts) > 0 {
		host := parts[0]
		host = strings.Split(host, ":")[0]
		return host
	}
	return target
}

func queryCRTSh(ctx context.Context, client *transport.Client, domain string) reconSource {
	u := fmt.Sprintf("%s/?q=%%.%s&output=json", crtShBase, domain)
	resp, err := client.Do(ctx, &types.Request{
		Method: "GET",
		URL:    u,
	})
	if err != nil {
		return reconSource{Name: "crt.sh", Failed: true, Detail: fmt.Sprintf("request failed: %v", err)}
	}
	if resp.StatusCode != 200 {
		return reconSource{Name: "crt.sh", Failed: true, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
	var entries []crtShEntry
	if err := json.Unmarshal(resp.Body, &entries); err != nil {
		// crt.sh answers errors as HTML rate-limit/queue pages; the
		// non-JSON payload is a source failure, not "no certificates".
		return reconSource{Name: "crt.sh", Failed: true, Detail: "non-JSON response (rate-limit or error page)"}
	}
	return reconSource{Name: "crt.sh", Data: filterCrtShNames(entries, domain)}
}

// filterCrtShNames reduces crt.sh certificate-transparency results to hosts
// strictly scoped to the scanned domain. Extracted pure for tests.
func filterCrtShNames(entries []crtShEntry, domain string) []string {
	seen := make(map[string]bool)
	var subdomains []string
	for _, entry := range entries {
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			if name == "" || name == domain {
				continue
			}
			name = strings.TrimPrefix(name, "*.")
			// Strict suffix match on the scoped domain only. The old
			// fallback accepted any name sharing the last two labels
			// ("sibling TLD"), so `target.com` results could include
			// attacker-owned `victim-target.co` lookalikes and steer the
			// scanner at third-party hosts.
			if !strings.HasSuffix(name, "."+domain) {
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			subdomains = append(subdomains, name)
		}
	}
	if len(subdomains) > 100 {
		subdomains = subdomains[:100]
	}
	return subdomains
}

// isDomainScopedURL reports whether a raw URL belongs to the scanned domain
// itself (host == domain or a subdomain of it). Wayback intake uses this to
// re-bind historical URLs to the target: entries recorded with foreign
// hosts (CDX rows for other origins) previously flowed into the KB endpoint
// list, where credentialed probe modules executed payloads against those
// third-party hosts.
func isDomainScopedURL(raw, domain string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func queryWayback(ctx context.Context, client *transport.Client, domain string) reconSource {
	u := fmt.Sprintf("%s/cdx/search/cdx?url=%s/*&output=json&fl=original&limit=200", waybackBase, domain)
	resp, err := client.Do(ctx, &types.Request{
		Method: "GET",
		URL:    u,
	})
	if err != nil {
		return reconSource{Name: "Wayback", Failed: true, Detail: fmt.Sprintf("request failed: %v", err)}
	}
	if resp.StatusCode != 200 {
		return reconSource{Name: "Wayback", Failed: true, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}

	var raw []json.RawMessage
	if err := json.Unmarshal(resp.Body, &raw); err != nil {
		return reconSource{Name: "Wayback", Failed: true, Detail: "non-JSON response"}
	}

	var urls []string
	seen := make(map[string]bool)
	for _, r := range raw {
		var urlStr string
		if err := json.Unmarshal(r, &urlStr); err != nil {
			continue
		}
		// Drop rows whose original URL is recorded on a foreign host before
		// they can enter the endpoint KB.
		if !isDomainScopedURL(urlStr, domain) {
			continue
		}
		parsed, err := url.Parse(urlStr)
		if err != nil {
			continue
		}
		cleaned := parsed.Scheme + "://" + parsed.Host + parsed.Path
		if cleaned == "" || seen[cleaned] {
			continue
		}
		seen[cleaned] = true
		urls = append(urls, cleaned)
		if len(urls) >= 100 {
			break
		}
	}
	return reconSource{Name: "Wayback", Data: urls}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
