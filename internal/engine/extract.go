package engine

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

var (
	rxEmail = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

	rxPhone = regexp.MustCompile(`(?:\+\d{1,3}[-.\s])?\(?\d{3}\)?[-.\s]\d{3}[-.\s]?\d{4}`)

	rxSSN = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)

	rxCreditCard = regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`)

	rxAPIKeyGeneric = regexp.MustCompile(`(?i)(?:api[_-]?key|api[_-]?secret|app[_-]?secret|client[_-]?secret|consumer[_-]?key|consumer[_-]?secret)\s*[=:]\s*['"]?([A-Za-z0-9_\-]{16,64})['"]?`)

	rxAWSKey = regexp.MustCompile(`(?:AKIA|ASIA)[A-Z0-9]{16}`)

	rxPrivateKey = regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)

	rxGitHubToken = regexp.MustCompile(`(?i)github[_-]?token['"]?\s*[:=]\s*["']?([A-Za-z0-9_\-]{35,40})["']?`)

	rxSlackToken = regexp.MustCompile(`(?i)(xox[baprs]-[A-Za-z0-9\-]{10,})`)

	rxGoogleAPI = regexp.MustCompile(`(?i)AIza[0-9A-Za-z\-_]{35}`)

	rxJWTClaim = regexp.MustCompile(`(?i)(sub|name|email|preferred_username|given_name|family_name)["']?\s*:\s*"([^"]+)"`)

	rxDBConnection = regexp.MustCompile(`(?i)(mysql|postgres|mongodb|redis|sqlite|oracle)://[^\s"']+`)

	rxUserDump = regexp.MustCompile(`(?i)(users|accounts|customers|members|employees)\s*(?:table|list|collection|database)?\s*:?`)

	rxInternalIP = regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`)
)

type DataExtractionAnalyzer struct{}

func NewDataExtractionAnalyzer() *DataExtractionAnalyzer {
	return &DataExtractionAnalyzer{}
}

func (a *DataExtractionAnalyzer) Name() string {
	return "extract"
}

func (a *DataExtractionAnalyzer) Analyze(ctx context.Context, resp *types.Response) []types.Finding {
	if resp == nil || len(resp.Body) == 0 {
		return nil
	}

	var findings []types.Finding
	body := string(resp.Body)

	emails := uniqueStrings(rxEmail.FindAllString(body, -1))
	if len(emails) > 0 {
		findings = append(findings, types.Finding{
			Type:        types.FindingSecret,
			Name:        fmt.Sprintf("Email Addresses Found (%d)", len(emails)),
			Severity:    types.SeverityLow,
			Description: "Email addresses discovered in response body — may expose users, staff, or contacts",
			Evidence:    fmt.Sprintf("Emails: %s", truncate(strings.Join(emails, ", "), 120)),
			Confidence:  0.9,
			Metadata: map[string]string{
				"count": fmt.Sprintf("%d", len(emails)),
				"emails": strings.Join(emails, ","),
			},
		})
	}

	phones := uniqueStrings(rxPhone.FindAllString(body, -1))
	if len(phones) > 0 {
		findings = append(findings, types.Finding{
			Type:        types.FindingSecret,
			Name:        fmt.Sprintf("Phone Numbers Found (%d)", len(phones)),
			Severity:    types.SeverityMedium,
			Description: "Phone numbers discovered in response body — PII leak",
			Evidence:    fmt.Sprintf("Phones: %s", truncate(strings.Join(phones, ", "), 120)),
			Confidence:  0.8,
		})
	}

	ips := uniqueStrings(rxInternalIP.FindAllString(body, -1))
	if len(ips) > 0 {
		findings = append(findings, types.Finding{
			Type:        types.FindingExposure,
			Name:        fmt.Sprintf("Internal IP Addresses Leaked (%d)", len(ips)),
			Severity:    types.SeverityHigh,
			Description: "Internal/private IP addresses exposed in response — network reconnaissance vector",
			Evidence:    fmt.Sprintf("IPs: %s", strings.Join(ips, ", ")),
			Confidence:  0.85,
		})
	}

	if rxPrivateKey.MatchString(body) {
		findings = append(findings, types.Finding{
			Type:        types.FindingSecret,
			Name:        "Private Key Leaked",
			Severity:    types.SeverityCritical,
			Description: "Private cryptographic key found in response body — complete compromise of TLS/SSH/authentication",
			Evidence:    extractSnippet(body, rxPrivateKey.String(), 80),
			Confidence:  0.95,
		})
	}

	apiKeys := uniqueStrings(rxAPIKeyGeneric.FindAllString(body, -1))
	for _, k := range apiKeys {
		findings = append(findings, types.Finding{
			Type:        types.FindingSecret,
			Name:        "API Key/Secret Found",
			Severity:    types.SeverityCritical,
			Description: "API key or client secret exposed in response body — third-party service compromise possible",
			Evidence:    truncate(k, 60),
			Confidence:  0.85,
		})
	}

	if m := rxAWSKey.FindString(body); m != "" {
		findings = append(findings, types.Finding{
			Type:        types.FindingSecret,
			Name:        "AWS Access Key ID Leaked",
			Severity:    types.SeverityCritical,
			Description: "Amazon Web Services Access Key ID exposed — potential cloud account compromise",
			Evidence:    fmt.Sprintf("AWS Key: %s", m),
			Confidence:  0.9,
		})
	}

	if m := rxGitHubToken.FindString(body); m != "" {
		findings = append(findings, types.Finding{
			Type:        types.FindingSecret,
			Name:        "GitHub Token Leaked",
			Severity:    types.SeverityCritical,
			Description: "GitHub authentication token exposed — repository and code access",
			Evidence:    truncate(m, 40),
			Confidence:  0.9,
		})
	}

	if m := rxSlackToken.FindString(body); m != "" {
		findings = append(findings, types.Finding{
			Type:        types.FindingSecret,
			Name:        "Slack Token Leaked",
			Severity:    types.SeverityCritical,
			Description: "Slack API token exposed — team communication compromise",
			Evidence:    truncate(m, 30),
			Confidence:  0.9,
		})
	}

	if m := rxGoogleAPI.FindString(body); m != "" {
		findings = append(findings, types.Finding{
			Type:        types.FindingSecret,
			Name:        "Google API Key Leaked",
			Severity:    types.SeverityCritical,
			Description: "Google API key exposed — may allow unauthorized Google Cloud/API usage",
			Evidence:    fmt.Sprintf("Key: %s...", truncate(m, 10)),
			Confidence:  0.85,
		})
	}

	ssns := uniqueStrings(rxSSN.FindAllString(body, -1))
	if len(ssns) > 0 {
		findings = append(findings, types.Finding{
			Type:        types.FindingSecret,
			Name:        fmt.Sprintf("SSN/PII Found (%d)", len(ssns)),
			Severity:    types.SeverityCritical,
			Description: "Social Security Numbers or national ID numbers exposed — severe PII breach",
			Evidence:    truncate(strings.Join(ssns, ", "), 60),
			Confidence:  0.9,
		})
	}

	ccs := uniqueStrings(rxCreditCard.FindAllString(body, -1))
	if len(ccs) > 0 {
		findings = append(findings, types.Finding{
			Type:        types.FindingSecret,
			Name:        fmt.Sprintf("Credit Card Numbers Found (%d)", len(ccs)),
			Severity:    types.SeverityCritical,
			Description: "Credit card numbers exposed in response body — PCI DSS compliance violation, financial fraud risk",
			Evidence:    truncate(strings.Join(ccs, ", "), 60),
			Confidence:  0.85,
		})
	}

	jwtClaims := uniqueStrings(rxJWTClaim.FindAllString(body, -1))
	if len(jwtClaims) > 0 {
		findings = append(findings, types.Finding{
			Type:        types.FindingSecret,
			Name:        "JWT Claim Data Found",
			Severity:    types.SeverityMedium,
			Description: "User identity claims (sub, name, email) found in response — potential user data exposure",
			Evidence:    truncate(strings.Join(jwtClaims, " | "), 100),
			Confidence:  0.7,
		})
	}

	dbConns := uniqueStrings(rxDBConnection.FindAllString(body, -1))
	if len(dbConns) > 0 {
		findings = append(findings, types.Finding{
			Type:        types.FindingSecret,
			Name:        "Database Connection String Leaked",
			Severity:    types.SeverityCritical,
			Description: "Database connection string exposed — direct database access possible",
			Evidence:    truncate(strings.Join(dbConns, ", "), 80),
			Confidence:  0.9,
		})
	}

	if rxUserDump.MatchString(body) {
		findings = append(findings, types.Finding{
			Type:        types.FindingExposure,
			Name:        "User Data Reference Found",
			Severity:    types.SeverityHigh,
			Description: "Response references user data table/collection — potential mass data extraction endpoint",
			Evidence:    extractSnippet(body, rxUserDump.String(), 80),
			Confidence:  0.6,
		})
	}

	return findings
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func uniqueStrings(s []string) []string {
	seen := make(map[string]struct{}, len(s))
	r := make([]string, 0, len(s))
	for _, v := range s {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			r = append(r, v)
		}
	}
	return r
}
