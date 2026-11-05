package engine

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// credPattern is one credential/secret detector applied to the raw response
// body and (since the buried-credential work) to decoded views of that body.
// It was hoisted out of TokenExtractor.Analyze so the decode/unquoted passes in
// this file reuse exactly the same shapes instead of duplicating them.
type credPattern struct {
	rx   *regexp.Regexp
	name string
	sev  types.Severity
	desc string
	conf float64
}

// credPatterns are the labelled `key: "value"` / `key=value` credential shapes.
// Every one demands a captured VALUE (m[1]); a match whose value group is empty
// is the bare keyword, not a leak, and is withheld by the caller.
var credPatterns = []credPattern{
	{rxAccessToken, "Access Token Leaked", types.SeverityCritical, "Access token exposed in response body", 0.85},
	{rxAPIToken, "API Key / Token Leaked", types.SeverityCritical, "API key or token exposed in response body", 0.85},
	{rxSecret, "Secret Key Leaked", types.SeverityCritical, "Secret key exposed in response body", 0.8},
	{rxPassword, "Password Leaked", types.SeverityCritical, "Password or credential exposed in response body", 0.85},
	{rxAuth, "Authorization Credential Leaked", types.SeverityHigh, "Authorization credential exposed in response", 0.75},
}

var (
	// An unquoted credential assignment: a secret-bearing key followed by ":" or
	// "=" and a bare token value. The credPatterns require surrounding quotes,
	// so `PASSWORD=hunter2`, `.env`/`wp-config` style lines and minified-JS
	// ternaries (`pass=abc123,`) were invisible to them.
	rxUnquotedCred = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_])(?:password|passwd|pwd|db_?pass(?:word)?|database_?password|secret_?key|access_?key|auth_?token|api_?key)\s*[=:]\s*([^\s"'<>;&|,{}()\[\]\\]{6,})`)

	// A run of >=16 base64 characters (optionally padded). Capped when scanned
	// so a whole minified bundle isn't exploded; a false hit is bounded because
	// we only emit when a full credPattern matches the DECODED text.
	rxBase64Run = regexp.MustCompile(`[A-Za-z0-9+/]{16,}={0,2}`)

	// >=3 consecutive percent-encoded octets — a URL-encoded credential.
	rxPercentRun = regexp.MustCompile(`(?:%[0-9A-Fa-f]{2}){3,}`)

	// Values that are obviously not a real credential.
	credPlaceholders = map[string]struct{}{
		"changeme": {}, "changeit": {}, "password": {}, "passwd": {}, "secret": {},
		"yourpassword": {}, "your_password": {}, "yourpasswordhere": {}, "xxxxxx": {},
		"xxxxxxx": {}, "xxxxxxxx": {}, "todo": {}, "tbd": {}, "example": {},
		"placeholder": {}, "none": {}, "null": {}, "undefined": {},
	}
)

// maskSecret keeps a credential's length without reproducing the value; it
// delegates to the one project-wide masking helper so every surface masks
// identically. A decoded Basic password must never enter a report in plaintext.
func maskSecret(v string) string { return types.MaskSecret(v) }

// mostlyPrintable guards base64 decoding: a real encoded credential decodes to
// text, whereas random base64 in a bundle decodes to binary and would only
// generate noise. >=90% of runes must be printable/whitespace.
func mostlyPrintable(s string) bool {
	if s == "" {
		return false
	}
	runes := []rune(s)
	ok := 0
	for _, r := range runes {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			ok++
		case r >= 0x20 && r < 0x7f:
			ok++
		case r > 0xa0 && r < 0x2500:
			ok++
		}
	}
	return float64(ok)/float64(len(runes)) >= 0.9
}

// decodedViews returns plaintext views of s produced by decoding URL-escaped
// and base64 runs, each tagged with the encoding that revealed it. Only views
// that yield printable text longer than a few bytes are kept.
func decodedViews(s string) []struct {
	text   string
	origin string
} {
	var views []struct {
		text   string
		origin string
	}
	add := func(text, origin string) {
		if len(text) >= 8 && mostlyPrintable(text) {
			views = append(views, struct {
				text   string
				origin string
			}{text, origin})
		}
	}

	for _, run := range rxPercentRun.FindAllString(s, 40) {
		if dec, err := url.PathUnescape(run); err == nil {
			add(dec, "URL encoding")
		}
	}

	for _, run := range rxBase64Run.FindAllString(s, 40) {
		for _, enc := range []*base64.Encoding{
			base64.StdEncoding, base64.URLEncoding,
			base64.RawStdEncoding, base64.RawURLEncoding,
		} {
			if raw, err := enc.DecodeString(run); err == nil && len(raw) >= 8 {
				add(string(raw), "base64 encoding")
				break
			}
		}
	}
	return views
}

// looksLikeRealValue rejects template fragments, placeholders, and single-char
// repetitions so an unquoted `key=var` or `token=xxxx` is not reported.
func looksLikeRealValue(v string) bool {
	v = strings.TrimSpace(v)
	if len(v) < 6 {
		return false
	}
	if _, ph := credPlaceholders[strings.ToLower(v)]; ph {
		return false
	}
	// Reject ${...} / <%= ... %> / mustache style templates and pure repeats.
	if strings.ContainsAny(v, "{}<>%$") {
		return false
	}
	first := v[0]
	allSame := true
	for i := 1; i < len(v); i++ {
		if v[i] != first {
			allSame = false
			break
		}
	}
	if allSame {
		return false
	}
	// A credential worth reporting mixes case or carries a non-letter.
	return strings.IndexFunc(v, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z')
	}) >= 0
}

// decodeBasicAuth turns `Basic <b64>` into user + masked-password evidence so a
// Basic credential is actionable, not just a base64 blob. Returns nil when the
// blob is not a decodable user:pass pair.
func decodeBasicAuth(b64 string) *types.Finding {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		if raw, err = base64.URLEncoding.DecodeString(b64); err != nil {
			return nil
		}
	}
	user, pass, found := strings.Cut(string(raw), ":")
	if !found || user == "" || pass == "" {
		return nil
	}
	return &types.Finding{
		Type:        types.FindingSecret,
		Name:        "Basic Auth Credential (decoded)",
		Severity:    types.SeverityCritical,
		Description: fmt.Sprintf("Basic-Auth payload decodes to a live credential for user %q — treat as an exposed login credential and verify it is not accepted anywhere.", user),
		Evidence:    fmt.Sprintf("user: %s | password: %s", user, maskSecret(pass)),
		Confidence:  0.9,
		Metadata:    map[string]string{"auth_user": user},
	}
}

// findBuriedCreds scans decoded views + unquoted assignments for credentials the
// raw-body, quote-shaped patterns cannot see. `reported` is the set of evidence
// values already emitted; it is seeded with the raw-body findings and updated in
// place, so a value visible both raw and decoded is reported only once.
func findBuriedCreds(body string, reported map[string]bool) []types.Finding {
	var findings []types.Finding

	for _, view := range decodedViews(body) {
		for _, p := range credPatterns {
			for _, m := range p.rx.FindAllStringSubmatch(view.text, -1) {
				if len(m) < 2 || strings.TrimSpace(m[1]) == "" {
					continue
				}
				ev := truncate(m[1], 30)
				if reported[ev] {
					continue
				}
				reported[ev] = true
				findings = append(findings, types.Finding{
					Type:        types.FindingSecret,
					Name:        p.name + " (revealed by " + view.origin + ")",
					Severity:    p.sev,
					Description: p.desc + " — the value only appears after decoding; it was buried in the response.",
					// The dedup key above is the matched value; the report
					// is not: a credential scanner whose own output is a
					// credential store has moved the problem, not solved it.
					Evidence:   types.RedactSecretValue(m[1]),
					Confidence: p.conf,
				})
			}
		}
	}

	for _, m := range rxUnquotedCred.FindAllStringSubmatch(body, -1) {
		if len(m) < 2 || !looksLikeRealValue(m[1]) {
			continue
		}
		ev := truncate(m[1], 30)
		if reported[ev] {
			continue
		}
		reported[ev] = true
		findings = append(findings, types.Finding{
			Type:        types.FindingSecret,
			Name:        "Credential Assigned (unquoted value)",
			Severity:    types.SeverityHigh,
			Description: "A secret-bearing key is bound to a literal value in unquoted form (env/config/minified-JS style) — the quoted-only matcher would have missed it.",
			Evidence:    types.RedactSecretValue(m[1]),
			Confidence:  0.6,
		})
	}

	return findings
}
