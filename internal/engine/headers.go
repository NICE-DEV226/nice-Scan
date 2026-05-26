package engine

import (
	"context"
	"fmt"
	"strings"

	"nice_scan/internal/types"
)

type HeaderAnalyzer struct{}

func NewHeaderAnalyzer() *HeaderAnalyzer {
	return &HeaderAnalyzer{}
}

func (a *HeaderAnalyzer) Name() string {
	return "headers"
}

func (a *HeaderAnalyzer) Analyze(ctx context.Context, resp *types.Response) []types.Finding {
	if resp == nil {
		return nil
	}

	var findings []types.Finding

	checks := []struct {
		header      string
		name        string
		severity    types.Severity
		description string
		missing     bool
		checkValue  func(string) (bool, string)
	}{
		{
			header: "Content-Security-Policy",
			name: "Missing CSP Header",
			severity: types.SeverityMedium,
			description: "Content-Security-Policy header is missing, increasing risk of XSS and data injection attacks",
			missing: true,
		},
		{
			header: "Strict-Transport-Security",
			name: "Missing HSTS Header",
			severity: types.SeverityMedium,
			description: "HTTP Strict-Transport-Security header is missing, allowing MITM downgrade attacks",
			missing: true,
		},
		{
			header: "X-Frame-Options",
			name: "Missing X-Frame-Options",
			severity: types.SeverityLow,
			description: "X-Frame-Options header is missing, clickjacking may be possible",
			missing: true,
		},
		{
			header: "X-Content-Type-Options",
			name: "Missing X-Content-Type-Options",
			severity: types.SeverityLow,
			description: "X-Content-Type-Options: nosniff is missing, MIME sniffing may be possible",
			missing: true,
		},
		{
			header: "Referrer-Policy",
			name: "Missing Referrer-Policy",
			severity: types.SeverityInfo,
			description: "Referrer-Policy header is missing, referrer information may leak",
			missing: true,
		},
		{
			header: "Server",
			name: "Server Version Disclosure",
			severity: types.SeverityLow,
			description: "Server header reveals server version information to attackers",
			missing: false,
			checkValue: func(val string) (bool, string) {
				if val == "" || strings.Contains(strings.ToLower(val), "nginx") || strings.Contains(strings.ToLower(val), "apache") {
					return false, ""
				}
				return true, fmt.Sprintf("Server: %s", val)
			},
		},
		{
			header: "X-Powered-By",
			name: "Technology Disclosure",
			severity: types.SeverityInfo,
			description: "X-Powered-By header reveals technology stack",
			missing: false,
			checkValue: func(val string) (bool, string) {
				if val == "" {
					return false, ""
				}
				return true, fmt.Sprintf("X-Powered-By: %s", val)
			},
		},
	}

	for _, check := range checks {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		val := resp.Headers.Get(check.header)

		if check.missing {
			if val == "" {
				findings = append(findings, types.Finding{
					Type:        types.FindingHeader,
					Name:        check.name,
					Severity:    check.severity,
					Description: check.description,
					Evidence:    fmt.Sprintf("%s header not set", check.header),
					Confidence:  1.0,
				})
			}
		} else if check.checkValue != nil {
			if found, evidence := check.checkValue(val); found {
				findings = append(findings, types.Finding{
					Type:        types.FindingHeader,
					Name:        check.name,
					Severity:    check.severity,
					Description: check.description,
					Evidence:    evidence,
					Confidence:  0.8,
				})
			}
		}
	}

	findings = append(findings, a.checkCookies(resp)...)

	return findings
}

func (a *HeaderAnalyzer) checkCookies(resp *types.Response) []types.Finding {
	var findings []types.Finding

	for _, cookie := range resp.Headers.Values("Set-Cookie") {
		parts := strings.SplitN(cookie, ";", 2)
		name := strings.TrimSpace(parts[0])

		if !strings.Contains(strings.ToLower(cookie), "secure") && strings.HasPrefix(resp.FinalURL, "https") {
			findings = append(findings, types.Finding{
				Type:        types.FindingMisconfig,
				Name:        "Cookie Missing Secure Flag",
				Severity:    types.SeverityMedium,
				Description: fmt.Sprintf("Cookie %q is missing the Secure flag over HTTPS", name),
				Evidence:    fmt.Sprintf("Set-Cookie: %s", cookie),
				Confidence:  1.0,
			})
		}

		if !strings.Contains(strings.ToLower(cookie), "httponly") {
			findings = append(findings, types.Finding{
				Type:        types.FindingMisconfig,
				Name:        "Cookie Missing HttpOnly Flag",
				Severity:    types.SeverityLow,
				Description: fmt.Sprintf("Cookie %q is missing the HttpOnly flag", name),
				Evidence:    fmt.Sprintf("Set-Cookie: %s", cookie),
				Confidence:  1.0,
			})
		}

		if !strings.Contains(strings.ToLower(cookie), "samesite") {
			findings = append(findings, types.Finding{
				Type:        types.FindingMisconfig,
				Name:        "Cookie Missing SameSite Attribute",
				Severity:    types.SeverityLow,
				Description: fmt.Sprintf("Cookie %q is missing SameSite attribute", name),
				Evidence:    fmt.Sprintf("Set-Cookie: %s", cookie),
				Confidence:  0.8,
			})
		}
	}

	return findings
}
