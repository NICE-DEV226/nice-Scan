package engine

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

type HeaderAnalyzer struct{}

func NewHeaderAnalyzer() *HeaderAnalyzer {
	return &HeaderAnalyzer{}
}

// rxServerVersion flags a version-like numeric sequence inside a Server
// value: NNN.NNN with optional build suffix ("nginx/1.24.2",
// "Apache/2.4.41 (Unix)"). A bare technology name ("nginx", "cloudflare")
// discloses no version and is not flagged.
var rxServerVersion = regexp.MustCompile(`\d+\.\d+`)

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
		httpsOnly   bool
		checkValue  func(string) (bool, string)
	}{
		{
			header:      "Content-Security-Policy",
			name:        "Missing CSP Header",
			severity:    types.SeverityLow,
			description: "Content-Security-Policy header is missing, increasing risk of XSS and data injection attacks",
			missing:     true,
			// Absent CSP is a defense-in-depth gap, not an exploitable finding
			// on its own — it only raises the blast radius of an XSS that must
			// already exist. Many correctly-secured sites ship without it, so
			// MEDIUM over-weighted an unproven risk; Low is the honest call.
		},
		{
			header:      "Strict-Transport-Security",
			name:        "Missing HSTS Header",
			severity:    types.SeverityMedium,
			description: "HTTP Strict-Transport-Security header is missing, allowing MITM downgrade attacks",
			missing:     true,
			// HSTS is only meaningful over HTTPS — the browser ignores it on an
			// http:// origin and there is nothing to downgrade on one. Firing
			// "Missing HSTS" on a plain-HTTP target was pure noise (and every
			// http:// scan produced it). Only report it when the response came
			// back over TLS.
			httpsOnly: true,
		},
		{
			header:      "X-Frame-Options",
			name:        "Missing X-Frame-Options",
			severity:    types.SeverityLow,
			description: "X-Frame-Options header is missing, clickjacking may be possible",
			missing:     true,
		},
		{
			header:      "X-Content-Type-Options",
			name:        "Missing X-Content-Type-Options",
			severity:    types.SeverityLow,
			description: "X-Content-Type-Options: nosniff is missing, MIME sniffing may be possible",
			missing:     true,
		},
		{
			header:      "Referrer-Policy",
			name:        "Missing Referrer-Policy",
			severity:    types.SeverityInfo,
			description: "Referrer-Policy header is missing, referrer information may leak",
			missing:     true,
		},
		{
			header:      "Server",
			name:        "Server Version Disclosure",
			severity:    types.SeverityLow,
			description: "Server header reveals server version information to attackers",
			missing:     false,
			checkValue: func(val string) (bool, string) {
				// The logic was INVERTED: it skipped nginx/apache (the
				// headers actually carrying versions) and only flagged
				// version-less names. A disclosure needs a version-like
				// number in the value: "nginx/1.24.2" flags, "nginx" does
				// not.
				if val == "" || !rxServerVersion.MatchString(val) {
					return false, ""
				}
				return true, fmt.Sprintf("Server: %s", val)
			},
		},
		{
			header:      "X-Powered-By",
			name:        "Technology Disclosure",
			severity:    types.SeverityInfo,
			description: "X-Powered-By header reveals technology stack",
			missing:     false,
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

		isHTTPS := strings.HasPrefix(strings.ToLower(resp.FinalURL), "https://") ||
			strings.HasPrefix(strings.ToLower(resp.RequestURL), "https://")

		if check.missing {
			if check.httpsOnly && !isHTTPS {
				continue
			}
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

	isHTTPS := strings.HasPrefix(strings.ToLower(resp.FinalURL), "https://") ||
		strings.HasPrefix(strings.ToLower(resp.RequestURL), "https://")

	for _, cookie := range resp.Headers.Values("Set-Cookie") {
		nameValue := strings.TrimSpace(strings.SplitN(cookie, ";", 2)[0])
		// Report the cookie NAME only. The leading pair is "name=value" and a
		// session VALUE is a credential — echoing it into the finding (and
		// thus the saved HTML/JSON report) leaked live session tokens.
		cookieName := nameValue
		if eq := strings.IndexByte(cookieName, '='); eq >= 0 {
			cookieName = strings.TrimSpace(cookieName[:eq])
		}

		attrs := cookieAttrSet(cookie)
		if isHTTPS && !attrs["secure"] {
			findings = append(findings, types.Finding{
				Type:        types.FindingMisconfig,
				Name:        "Cookie Missing Secure Flag",
				Severity:    types.SeverityMedium,
				Description: fmt.Sprintf("Cookie %q is missing the Secure flag over HTTPS", cookieName),
				Evidence:    fmt.Sprintf("Set-Cookie name: %s", cookieName),
				Confidence:  1.0,
			})
		}

		if !attrs["httponly"] {
			findings = append(findings, types.Finding{
				Type:        types.FindingMisconfig,
				Name:        "Cookie Missing HttpOnly Flag",
				Severity:    types.SeverityLow,
				Description: fmt.Sprintf("Cookie %q is missing the HttpOnly flag", cookieName),
				Evidence:    fmt.Sprintf("Set-Cookie name: %s", cookieName),
				Confidence:  1.0,
			})
		}

		if !attrs["samesite"] {
			findings = append(findings, types.Finding{
				Type:        types.FindingMisconfig,
				Name:        "Cookie Missing SameSite Attribute",
				Severity:    types.SeverityLow,
				Description: fmt.Sprintf("Cookie %q is missing SameSite attribute", cookieName),
				Evidence:    fmt.Sprintf("Set-Cookie name: %s", cookieName),
				Confidence:  0.8,
			})
		}
	}

	return findings
}
