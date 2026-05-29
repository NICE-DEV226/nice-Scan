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

type PassiveReconAction struct{}

func (a *PassiveReconAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "Passive Recon",
		Description: "GitHub dorking, crt.sh, Wayback Machine — no requests to target",
		Priority:    5,
		Requires:    nil,
		Provides:    []string{"has_subdomain"},
	}
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

	type crtResult struct {
		subs []string
		err  error
	}
	type wbResult struct {
		urls []string
		err  error
	}

	crtCh := make(chan crtResult, 1)
	wbCh := make(chan wbResult, 1)

	go func() {
		subs := queryCRTSh(reconCtx, client, domain)
		crtCh <- crtResult{subs: subs}
	}()
	go func() {
		urls := queryWayback(reconCtx, client, domain)
		wbCh <- wbResult{urls: urls}
	}()

	var subdomains []string
	var waybackURLs []string

	for i := 0; i < 2; i++ {
		select {
		case r := <-crtCh:
			subdomains = r.subs
		case r := <-wbCh:
			waybackURLs = r.urls
		case <-reconCtx.Done():
			break
		}
	}

	if len(subdomains) > 0 {
		findings = append(findings, Finding{
			Type:        "subdomain",
			Name:        fmt.Sprintf("Subdomains discovered via crt.sh (%d)", len(subdomains)),
			Severity:    SevMedium,
			Description: fmt.Sprintf("Certificate Transparency logs reveal %d subdomains", len(subdomains)),
			Evidence:    strings.Join(subdomains[:minInt(10, len(subdomains))], ", "),
			Details:     map[string]string{"count": fmt.Sprintf("%d", len(subdomains))},
		})

		kb.AddCapability(Capability{
			Name:   "has_subdomain",
			Target: target,
			Details: map[string]string{
				"count": fmt.Sprintf("%d", len(subdomains)),
				"list":  strings.Join(subdomains, ", "),
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
			Evidence:    strings.Join(waybackURLs[:minInt(10, len(waybackURLs))], ", "),
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
		findings = append(findings, Finding{
			Type:        "recon_complete",
			Name:        "No public recon data found",
			Severity:    SevInfo,
			Description: "No subdomains or historical URLs discovered for " + domain,
		})
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

func queryCRTSh(ctx context.Context, client *transport.Client, domain string) []string {
	u := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	resp, err := client.Do(ctx, &types.Request{
		Method: "GET",
		URL:    u,
	})
	if err != nil {
		return nil
	}

	if resp.StatusCode != 200 {
		return nil
	}

	var entries []crtShEntry
	if err := json.Unmarshal(resp.Body, &entries); err != nil {
		return nil
	}

	seen := make(map[string]bool)
	domainParts := strings.Split(domain, ".")
	if len(domainParts) < 2 {
		return nil
	}
	tld := domainParts[len(domainParts)-2] + "." + domainParts[len(domainParts)-1]

	var subdomains []string
	for _, entry := range entries {
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			if name == "" || name == domain {
				continue
			}
			if strings.HasPrefix(name, "*.") {
				name = name[2:]
			}
			if !strings.HasSuffix(name, "."+domain) && name != domain {
				if !strings.HasSuffix(name, "."+tld) {
					continue
				}
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

func queryWayback(ctx context.Context, client *transport.Client, domain string) []string {
	u := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original&limit=200", domain)
	resp, err := client.Do(ctx, &types.Request{
		Method: "GET",
		URL:    u,
	})
	if err != nil {
		return nil
	}
	if resp.StatusCode != 200 {
		return nil
	}

	var raw []json.RawMessage
	if err := json.Unmarshal(resp.Body, &raw); err != nil {
		return nil
	}

	var urls []string
	seen := make(map[string]bool)
	for _, r := range raw {
		var urlStr string
		if err := json.Unmarshal(r, &urlStr); err != nil {
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
	return urls
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
