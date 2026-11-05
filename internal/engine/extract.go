package engine

import (
	"context"
	"encoding/base64"
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

	// The old pattern matched the bare prose word ("our valued members",
	// "registered users") as a HIGH "User Data Reference Found" — that is a
	// marketing sentence, not a dump endpoint. Require the term to be a
	// STRUCTURED collection key bound to actual records: a JSON key whose value
	// opens with [ or {, or a "<word> table/collection dump" style marker
	// followed by row-looking text.
	rxUserDump = regexp.MustCompile(`(?i)(?:["']?(?:users|accounts|customers|members|employees)["']?\s*[:=]\s*[\[{])|(?:(?:users|accounts|customers|members|employees)_?(?:table|collection|dump|list)\b[\s\S]{0,40}?\{)`)

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

	emails := emailCandidates(body, rxDBConnection.FindAllStringIndex(body, -1))
	emails = filterDocEmails(emails)
	if len(emails) > 0 {
		findings = append(findings, types.Finding{
			Type:        types.FindingSecret,
			Name:        fmt.Sprintf("Email Addresses Found (%d)", len(emails)),
			Severity:    types.SeverityLow,
			Description: "Email addresses discovered in response body — may expose users, staff, or contacts",
			Evidence:    fmt.Sprintf("Emails: %s", truncate(strings.Join(emails, ", "), 120)),
			Confidence:  0.9,
			Metadata: map[string]string{
				"count":  fmt.Sprintf("%d", len(emails)),
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
			Evidence:    types.RedactSecretValue(k),
			Confidence:  0.85,
		})
	}

	if m := rxAWSKey.FindString(body); m != "" {
		findings = append(findings, types.Finding{
			Type:        types.FindingSecret,
			Name:        "AWS Access Key ID Leaked",
			Severity:    types.SeverityCritical,
			Description: "Amazon Web Services Access Key ID exposed — potential cloud account compromise",
			Evidence:    fmt.Sprintf("AWS Key: %s", types.RedactSecretValue(m)),
			Confidence:  0.9,
		})
	}

	if m := rxGitHubToken.FindString(body); m != "" {
		findings = append(findings, types.Finding{
			Type:        types.FindingSecret,
			Name:        "GitHub Token Leaked",
			Severity:    types.SeverityCritical,
			Description: "GitHub authentication token exposed — repository and code access",
			Evidence:    types.RedactSecretValue(m),
			Confidence:  0.9,
		})
	}

	if m := rxSlackToken.FindString(body); m != "" {
		findings = append(findings, types.Finding{
			Type:        types.FindingSecret,
			Name:        "Slack Token Leaked",
			Severity:    types.SeverityCritical,
			Description: "Slack API token exposed — team communication compromise",
			Evidence:    types.RedactSecretValue(m),
			Confidence:  0.9,
		})
	}

	if m := rxGoogleAPI.FindString(body); m != "" {
		findings = append(findings, types.Finding{
			Type:        types.FindingSecret,
			Name:        "Google API Key Leaked",
			Severity:    types.SeverityCritical,
			Description: "Google API key exposed — may allow unauthorized Google Cloud/API usage",
			Evidence:    fmt.Sprintf("Key: %s", types.RedactSecretValue(m)),
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

	ccCandidates := uniqueStrings(rxCreditCard.FindAllString(body, -1))
	var ccs []string
	for _, c := range ccCandidates {
		// A bare 16-digit run is overwhelmingly an order id, timestamp,
		// tracking number, or log line — NOT a card. Flagging those as a
		// CRITICAL PCI breach was a pure false positive. Keep a candidate
		// only when it passes the Luhn checksum AND carries a real
		// major-industry prefix (Visa/Mastercard/Amex/Discover), the two
		// signals that actually distinguish a PAN from arbitrary digits.
		if isLikelyCardNumber(c) {
			ccs = append(ccs, c)
		}
	}
	if len(ccs) > 0 {
		findings = append(findings, types.Finding{
			Type:        types.FindingSecret,
			Name:        fmt.Sprintf("Credit Card Numbers Found (%d)", len(ccs)),
			Severity:    types.SeverityCritical,
			Description: "Luhn-valid card numbers with a major issuer prefix exposed in response body — PCI DSS violation, financial fraud risk",
			Evidence:    truncate(strings.Join(maskCardNumbers(ccs), ", "), 60),
			Confidence:  0.85,
		})
	}

	// A JWT's payload is base64url, NOT encrypted — sub/name/email are the
	// standard, client-visible OIDC claims. Seeing them in a token is by-design
	// and is not itself an exposure; it only matters if the token carries data
	// the client should not hold, or if it belongs to another principal and
	// surfaces in an unauthenticated response (reported by the token-leak /
	// IDOR checks, not here). So this is an informational note, and it is only
	// emitted when a real three-segment JWT is present AND decoded — the old
	// matcher called any plain `{"email":"…"}` JSON a "JWT claim", which was
	// simply wrong.
	if payload := jwtPayload(rxJWT.FindString(body)); payload != "" {
		jwtClaims := uniqueStrings(rxJWTClaim.FindAllString(payload, -1))
		if len(jwtClaims) > 0 {
			findings = append(findings, types.Finding{
				Type:        types.FindingExposure,
				Name:        "JWT Carries Identity Claims",
				Severity:    types.SeverityInfo,
				Description: "A JWT in the response carries identity claims (sub/name/email). A JWT payload is base64url, not encrypted, so these are client-visible by design and not an exposure on their own — confirm they are meant to be client-side, and escalate only if another principal's token appears here without authentication.",
				Evidence:    truncate(strings.Join(jwtClaims, " | "), 100),
				Confidence:  0.6,
			})
		}
	}

	dbConns := uniqueStrings(rxDBConnection.FindAllString(body, -1))
	if len(dbConns) > 0 {
		// The scheme, host and database name are the actionable part; the
		// userinfo in front of them is a live database password.
		shapes := make([]string, 0, len(dbConns))
		for _, c := range dbConns {
			shapes = append(shapes, truncate(types.RedactText(c), 120))
		}
		findings = append(findings, types.Finding{
			Type:        types.FindingSecret,
			Name:        "Database Connection String Leaked",
			Severity:    types.SeverityCritical,
			Description: "Database connection string exposed — direct database access possible",
			Evidence:    strings.Join(shapes, ", "),
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

// isLikelyCardNumber reports whether a raw match is plausibly a payment card
// PAN: only digits are kept, length is 13-19, the leading digits map to a real
// major-industry prefix (Visa/Mastercard/Amex/Discover/JCB), and the run
// satisfies the Luhn mod-10 checksum. Arbitrary 16-digit ids fail one of these
// far more often than not, which is exactly what prunes the false positives.
func isLikelyCardNumber(raw string) bool {
	digits := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		if c := raw[i]; c >= '0' && c <= '9' {
			digits = append(digits, c)
		}
	}
	n := len(digits)
	if n < 13 || n > 19 {
		return false
	}
	if !hasCardPrefix(string(digits)) {
		return false
	}
	// Luhn: from the right, double every second digit; fold >9 by -9; sum.
	sum := 0
	double := false
	for i := n - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

func hasCardPrefix(d string) bool {
	switch {
	case strings.HasPrefix(d, "4"): // Visa
		return true
	case len(d) >= 2 && d[0] == '5' && d[1] >= '1' && d[1] <= '5': // Mastercard 51-55
		return true
	case len(d) >= 4 && d[:4] >= "2221" && d[:4] <= "2720": // Mastercard 2-series
		return true
	case len(d) >= 2 && d[0] == '3' && (d[1] == '4' || d[1] == '7'): // Amex
		return true
	case len(d) >= 4 && d[:4] == "6011": // Discover
		return true
	case len(d) >= 2 && d[0] == '6' && d[1] == '5': // Discover
		return true
	case len(d) >= 4 && d[:4] >= "3528" && d[:4] <= "3589": // JCB
		return true
	}
	return false
}

// maskCardNumbers keeps only the first 6 and last 4 digits of a confirmed PAN.
// A scanner report that copies full card numbers into HTML/JSON output would
// itself be a PCI violation — the finding is the EXPOSURE, not the value.
func maskCardNumbers(cards []string) []string {
	out := make([]string, 0, len(cards))
	for _, c := range cards {
		var b strings.Builder
		for i := 0; i < len(c); i++ {
			if ch := c[i]; ch >= '0' && ch <= '9' {
				b.WriteByte(ch)
			}
		}
		digits := b.String()
		if len(digits) >= 11 {
			digits = digits[:6] + strings.Repeat("*", len(digits)-10) + digits[len(digits)-4:]
		}
		out = append(out, digits)
	}
	return out
}

// docEmailDomains are reserved by RFC 2606/6761 or are documentation
// placeholders. A "real PII" finding built from them is noise: they appear in
// templates, comments and example copy, never as an actual contact to report.
var docEmailDomains = map[string]struct{}{
	"example.com": {}, "example.net": {}, "example.org": {},
	"invalid": {}, "test": {}, "localhost": {},
	"email.com": {}, "email.tld": {}, "domain.com": {},
	"sdomain.ink": {}, "sub.example.com": {},
}

// placeholderEmailLocals are template/documentation stub words used as the
// local-part ("utilisateur@mail.com", "exemple@…", "vous@…"). They are French
// and English placeholder text shipped in copy, never a real contact — a PII
// finding counting them overstates an exposure that does not exist.
var placeholderEmailLocals = map[string]struct{}{
	"user": {}, "users": {}, "admin": {}, "example": {}, "test": {},
	"name": {}, "email": {}, "mail": {}, "info": {}, "you": {}, "someone": {},
	"utilisateur": {}, "exemple": {}, "vous": {}, "nom": {}, "pseudo": {},
	"monnom": {}, "mon_nom": {}, "toto": {}, "machin": {}, "bidule": {},
}

// filterDocEmails drops addresses on reserved/placeholder domains and stub
// local-parts so the PII finding counts real contacts, not template text.
// emailCandidates harvests address-shaped strings, dropping any match that
// begins inside one of the excluded byte spans. A connection string is one
// credential from scheme to database name, and its userinfo reads perfectly
// well as an address: reporting "r00tpass@db.internal" as a contact puts a live
// database password into the report under a PII label.
func emailCandidates(body string, excluded [][]int) []string {
	var out []string
	for _, m := range rxEmail.FindAllStringIndex(body, -1) {
		if insideAnySpan(m, excluded) {
			continue
		}
		out = append(out, body[m[0]:m[1]])
	}
	return uniqueStrings(out)
}

func insideAnySpan(match []int, spans [][]int) bool {
	for _, s := range spans {
		if match[0] >= s[0] && match[0] < s[1] {
			return true
		}
	}
	return false
}

func filterDocEmails(in []string) []string {
	out := make([]string, 0, len(in))
	for _, e := range in {
		at := strings.LastIndexByte(e, '@')
		if at < 0 {
			continue
		}
		local := strings.ToLower(strings.TrimSpace(e[:at]))
		domain := strings.ToLower(strings.TrimSpace(e[at+1:]))
		if _, ok := docEmailDomains[domain]; ok {
			continue
		}
		// any subdomain of example.* is reserved too
		if strings.HasSuffix(domain, ".example.com") || strings.HasSuffix(domain, ".example.org") || strings.HasSuffix(domain, ".example.net") {
			continue
		}
		if _, ok := placeholderEmailLocals[local]; ok {
			continue
		}
		out = append(out, e)
	}
	return out
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

// jwtPayload base64url-decodes the payload segment of a three-part JWT so the
// claim matcher reads the token's own claims rather than any `{"email":…}` in
// the surrounding body. Returns "" when tok is not a decodable JWT.
func jwtPayload(tok string) string {
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		if raw, err = base64.URLEncoding.DecodeString(parts[1]); err != nil {
			return ""
		}
	}
	return string(raw)
}
