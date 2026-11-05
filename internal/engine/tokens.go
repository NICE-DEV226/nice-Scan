package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

var (
	rxBearer      = regexp.MustCompile(`(?i)Bearer\s+([A-Za-z0-9\-_.]+(?:\.[A-Za-z0-9\-_.]+)+)`)
	rxBasicAuth   = regexp.MustCompile(`(?i)Basic\s+([A-Za-z0-9+/=]+)`)
	rxAccessToken = regexp.MustCompile(`(?i)access[_\-]token["']?\s*[:=]\s*["']([A-Za-z0-9\-_.]{8,})["']`)
	// The label alternation must be grouped: the old
	// `api[_\-]key|api[_\-]token|app[_\-]token["']?\s*[:=]...` bound the
	// `:= value` clause ONLY to the last alternative, so the bare words
	// "api_key"/"api-token" (every JS variable, every doc) matched with NO
	// value captured — the loop then fell back to m[0] and printed a CRITICAL
	// "API Key Leaked" whose evidence was the word "api_key" itself. Group the
	// labels and demand a real ≥8-char value after ":" or "=".
	rxAPIToken = regexp.MustCompile(`(?i)(?:api[_\-]key|api[_\-]token|app[_\-]token)["']?\s*[:=]\s*["']?([A-Za-z0-9\-_.@]{8,})["']?`)
	rxSecret   = regexp.MustCompile(`(?i)secret["']?\s*[:=]\s*["']?([A-Za-z0-9\-_.@!]{8,})["']?`)
	rxPassword = regexp.MustCompile(`(?i)password["']?\s*[:=]\s*["']([^"']{6,})["']`)
	rxAuth     = regexp.MustCompile(`(?i)authorization["']?\s*[:=]\s*["']([^"']+)["']`)

	sessionCookies = []string{
		"sessionid", "session_id", "sessid", "sid", "PHPSESSID", "JSESSIONID",
		"ASP.NET_SessionId", "connect.sid", "laravel_session", "_session",
		"ci_session", "symfony", "PHPSESSID",
	}

	rxJWT = regexp.MustCompile(`eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+(\.[A-Za-z0-9\-_]+)?`)
)

type TokenExtractor struct{}

func NewTokenExtractor() *TokenExtractor {
	return &TokenExtractor{}
}

func (t *TokenExtractor) Name() string {
	return "tokens"
}

func (t *TokenExtractor) Analyze(ctx context.Context, resp *types.Response) []types.Finding {
	if resp == nil {
		return nil
	}

	var findings []types.Finding

	headerAuth := resp.Headers.Get("Authorization")
	body := string(resp.Body)
	combined := headerAuth + "\n" + body

	if m := rxJWT.FindString(combined); m != "" {
		findings = append(findings, t.analyzeJWT(m))
	}

	if m := rxBearer.FindStringSubmatch(combined); len(m) > 1 {
		if !rxJWT.MatchString(m[1]) {
			findings = append(findings, types.Finding{
				Type:        types.FindingSecret,
				Name:        "Bearer Token Found",
				Severity:    types.SeverityHigh,
				Description: "Bearer authentication token found in response",
				Evidence:    fmt.Sprintf("Bearer token %s", types.RedactSecretValue(m[1])),
				Confidence:  0.8,
			})
		}
	}

	for _, name := range sessionCookies {
		for _, c := range resp.Headers.Values("Set-Cookie") {
			if strings.HasPrefix(strings.TrimSpace(c), name+"=") {
				val := extractCookieValue(c)
				findings = append(findings, types.Finding{
					Type:        types.FindingSecret,
					Name:        fmt.Sprintf("Session Cookie: %s", name),
					Severity:    types.SeverityInfo,
					Description: "Session cookie set by application",
					Evidence:    fmt.Sprintf("%s=%s", name, types.RedactSecretValue(val)),
					Confidence:  0.9,
					Metadata: map[string]string{
						"cookie": name,
						"raw":    cookieShape(c),
					},
				})

				attrs := cookieAttrSet(c)
				if !attrs["secure"] && strings.HasPrefix(resp.RequestURL, "https") {
					findings = append(findings, types.Finding{
						Type:        types.FindingMisconfig,
						Name:        fmt.Sprintf("Session Cookie Missing Secure Flag: %s", name),
						Severity:    types.SeverityMedium,
						Description: "Session cookie transmitted over HTTPS without Secure flag — possible session hijacking via man-in-the-middle",
						Evidence:    fmt.Sprintf("Cookie: %s (missing Secure flag on HTTPS)", cookieShape(c)),
						Confidence:  0.9,
					})
				}
				if !attrs["httponly"] {
					findings = append(findings, types.Finding{
						Type:        types.FindingMisconfig,
						Name:        fmt.Sprintf("Session Cookie Missing HttpOnly Flag: %s", name),
						Severity:    types.SeverityLow,
						Description: "Session cookie accessible via JavaScript — possible XSS-based session theft",
						Evidence:    fmt.Sprintf("Cookie: %s (missing HttpOnly)", cookieShape(c)),
						Confidence:  0.9,
					})
				}
			}
		}
	}

	// reported seeds the buried/decoded pass so a value already found raw is not
	// re-reported when the same bytes also appear inside a decoded view.
	reported := map[string]bool{}

	for _, p := range credPatterns {
		select {
		case <-ctx.Done():
			return findings
		default:
		}
		for _, m := range p.rx.FindAllStringSubmatch(body, -1) {
			// Every credential pattern must expose a captured VALUE (m[1]).
			// A match whose value group is empty is the bare keyword, not a
			// leak — emitting it produced Critical findings whose "evidence"
			// was the word "api_key". Withhold those.
			if len(m) < 2 || strings.TrimSpace(m[1]) == "" {
				continue
			}
			val := truncate(m[1], 30)
			reported[val] = true
			findings = append(findings, types.Finding{
				Type:        types.FindingSecret,
				Name:        p.name,
				Severity:    p.sev,
				Description: p.desc,
				// The dedup key above is the matched value; the report is not.
				Evidence:   types.RedactSecretValue(m[1]),
				Confidence: p.conf,
			})
		}
	}

	// Basic-Auth: report the base64 blob only when it does NOT decode; when it
	// does, replace the blob with the actionable user + masked-password pair
	// (the password never leaves in plaintext in the report).
	for _, m := range rxBasicAuth.FindAllStringSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		if dec := decodeBasicAuth(m[1]); dec != nil {
			findings = append(findings, *dec)
		} else {
			findings = append(findings, types.Finding{
				Type:        types.FindingSecret,
				Name:        "Basic Auth Credential",
				Severity:    types.SeverityHigh,
				Description: "Base64-encoded Basic Authentication credentials found",
				// 30 base64 characters decode to ~22 bytes — the whole
				// user:password pair. A prefix of a credential is the
				// credential.
				Evidence:   types.RedactSecretValue(m[1]),
				Confidence: 0.8,
			})
		}
	}

	findings = append(findings, findBuriedCreds(body, reported)...)

	return findings
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type jwtClaims struct {
	Sub   string   `json:"sub"`
	Iss   string   `json:"iss"`
	Aud   any      `json:"aud"`
	Exp   float64  `json:"exp"`
	Nbf   float64  `json:"nbf"`
	Iat   float64  `json:"iat"`
	Role  string   `json:"role"`
	Roles []string `json:"roles"`
	Admin bool     `json:"admin"`
	Email string   `json:"email"`
	User  string   `json:"user"`
	Name  string   `json:"name"`
	Scp   string   `json:"scope"`
}

func (t *TokenExtractor) analyzeJWT(raw string) types.Finding {
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return types.Finding{}
	}

	var hdr jwtHeader
	var cls jwtClaims
	hdrStr := decodeBase64URL(parts[0])
	clsStr := decodeBase64URL(parts[1])
	_ = json.Unmarshal([]byte(hdrStr), &hdr)
	_ = json.Unmarshal([]byte(clsStr), &cls)

	var details []string
	details = append(details, fmt.Sprintf("Alg: %s", hdr.Alg))

	if cls.Iss != "" {
		details = append(details, fmt.Sprintf("Issuer: %s", cls.Iss))
	}
	if cls.Sub != "" {
		details = append(details, fmt.Sprintf("Subject: %s", cls.Sub))
	}
	if cls.Email != "" {
		details = append(details, fmt.Sprintf("Email: %s", cls.Email))
	}
	if cls.User != "" {
		details = append(details, fmt.Sprintf("User: %s", cls.User))
	}
	if cls.Name != "" {
		details = append(details, fmt.Sprintf("Name: %s", cls.Name))
	}

	// Algorithm confusion (none algorithm)
	sev := types.SeverityMedium
	conf := 0.7
	switch hdr.Alg {
	case "none":
		sev = types.SeverityCritical
		conf = 0.95
		details = append(details, "VULNERABILITY: alg=none — JWT signature verification bypass!")
	case "HS256", "HS384", "HS512":
		conf = 0.85
		details = append(details, "Symmetric algorithm — susceptible to key confusion if public key is used as HMAC secret")
	}

	if cls.Role != "" {
		details = append(details, fmt.Sprintf("Role: %s — potential privilege escalation target", cls.Role))
	}
	if cls.Admin {
		details = append(details, "admin: true — user has admin privileges in token")
		sev = types.SeverityHigh
	}
	if len(cls.Roles) > 0 {
		details = append(details, fmt.Sprintf("Roles: [%s] — privilege escalation targets", strings.Join(cls.Roles, ", ")))
	}

	expInfo := ""
	if cls.Exp > 0 {
		expStr := fmt.Sprintf("Expiry: %.0f", cls.Exp)
		details = append(details, expStr)
		expInfo = fmt.Sprintf("exp=%.0f", cls.Exp)
	}

	meta := map[string]string{
		"algorithm": hdr.Alg,
		"type":      hdr.Typ,
	}
	if cls.Role != "" {
		meta["role"] = cls.Role
	}
	if cls.Email != "" {
		meta["email"] = cls.Email
	}
	if cls.Sub != "" {
		meta["subject"] = cls.Sub
	}
	if expInfo != "" {
		meta["expiry"] = expInfo
	}

	return types.Finding{
		Type:        types.FindingSecret,
		Name:        "JWT Token Decoded",
		Severity:    sev,
		Description: fmt.Sprintf("JSON Web Token decoded — %s", strings.Join(details, " | ")),
		// The claims are the finding and they are in Metadata; the signed
		// token itself is a bearer credential and has no business in a
		// report.
		Evidence:   types.RedactSecretValue(raw),
		Confidence: conf,
		Metadata:   meta,
	}
}

func decodeBase64URL(s string) string {
	s = strings.TrimRight(s, "=")
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return ""
	}
	return string(b)
}

func extractCookieValue(c string) string {
	parts := strings.SplitN(c, ";", 2)
	kv := strings.SplitN(parts[0], "=", 2)
	if len(kv) == 2 {
		return kv[1]
	}
	return ""
}

// cookieShape returns a Set-Cookie header with ONLY its value masked. The
// cookie name and the attributes (Path, Domain, SameSite, Secure, HttpOnly)
// are the actionable half of the finding — the value is a live session
// credential and must not be recopied into a report.
func cookieShape(c string) string {
	parts := strings.Split(strings.TrimSpace(c), ";")
	nameValue := strings.TrimSpace(parts[0])
	if eq := strings.IndexByte(nameValue, '='); eq >= 0 {
		nameValue = nameValue[:eq+1] + types.RedactSecretValue(nameValue[eq+1:])
	} else {
		nameValue = types.RedactSecretValue(nameValue)
	}
	out := append([]string{nameValue}, nonEmptyAttrs(parts[1:])...)
	return strings.Join(out, "; ")
}

func nonEmptyAttrs(attrs []string) []string {
	out := make([]string, 0, len(attrs))
	for _, a := range attrs {
		if trimmed := strings.TrimSpace(a); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// cookieAttrSet returns the lowercase attribute-name set of one Set-Cookie
// string. Substring checks like Contains(c, "; Secure") miss the flag when the
// server writes ";secure", ";Secure", or ";  Secure", and falsely "find" it
// when a value merely contains the word — so tokenize the real attributes and
// match whole names (the leading "name=value" pair excluded).
func cookieAttrSet(c string) map[string]bool {
	set := map[string]bool{}
	parts := strings.Split(c, ";")
	for _, p := range parts[1:] {
		token := strings.ToLower(strings.TrimSpace(p))
		if token == "" {
			continue
		}
		if eq := strings.IndexByte(token, '='); eq >= 0 {
			token = strings.TrimSpace(token[:eq])
		}
		set[token] = true
	}
	return set
}
