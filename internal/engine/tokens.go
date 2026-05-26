package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/nice-scan/nice_scan/internal/types"
)

var (
	rxBearer      = regexp.MustCompile(`(?i)Bearer\s+([A-Za-z0-9\-_.]+(?:\.[A-Za-z0-9\-_.]+)+)`)
	rxBasicAuth   = regexp.MustCompile(`(?i)Basic\s+([A-Za-z0-9+/=]+)`)
	rxAccessToken = regexp.MustCompile(`(?i)access[_\-]token["']?\s*[:=]\s*["']([A-Za-z0-9\-_.]+)["']`)
	rxAPIToken    = regexp.MustCompile(`(?i)api[_\-]key|api[_\-]token|app[_\-]token["']?\s*[:=]\s*["']([A-Za-z0-9\-_.@]+)["']`)
	rxSecret      = regexp.MustCompile(`(?i)secret["']?\s*[:=]\s*["']([A-Za-z0-9\-_.@!]+)["']`)
	rxPassword    = regexp.MustCompile(`(?i)password["']?\s*[:=]\s*["']([^"']{6,})["']`)
	rxSession     = regexp.MustCompile(`(?i)session["']?\s*[:=]\s*["']([A-Za-z0-9\-_.%]+)["']`)
	rxAuth        = regexp.MustCompile(`(?i)authorization["']?\s*[:=]\s*["']([^"']+)["']`)

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
				Evidence:    fmt.Sprintf("Token: %s...", truncate(m[1], 30)),
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
					Evidence:    fmt.Sprintf("%s=%s...", name, truncate(val, 20)),
					Confidence:  0.9,
					Metadata: map[string]string{
						"cookie": name,
						"raw":    c,
					},
				})

				if !strings.Contains(c, "; Secure") && strings.HasPrefix(resp.RequestURL, "https") {
					findings = append(findings, types.Finding{
						Type:        types.FindingMisconfig,
						Name:        fmt.Sprintf("Session Cookie Missing Secure Flag: %s", name),
						Severity:    types.SeverityMedium,
						Description: "Session cookie transmitted over HTTPS without Secure flag — possible session hijacking via man-in-the-middle",
						Evidence:    fmt.Sprintf("Cookie: %s (missing Secure flag on HTTPS)", c),
						Confidence:  0.9,
					})
				}
				if !strings.Contains(c, "; HttpOnly") {
					findings = append(findings, types.Finding{
						Type:        types.FindingMisconfig,
						Name:        fmt.Sprintf("Session Cookie Missing HttpOnly Flag: %s", name),
						Severity:    types.SeverityLow,
						Description: "Session cookie accessible via JavaScript — possible XSS-based session theft",
						Evidence:    fmt.Sprintf("Cookie: %s (missing HttpOnly)", c),
						Confidence:  0.9,
					})
				}
			}
		}
	}

	patterns := []struct {
		rx    *regexp.Regexp
		name  string
		sev   types.Severity
		desc  string
		conf  float64
	}{
		{rxAccessToken, "Access Token Leaked", types.SeverityCritical, "Access token exposed in response body", 0.85},
		{rxAPIToken, "API Key / Token Leaked", types.SeverityCritical, "API key or token exposed in response body", 0.85},
		{rxSecret, "Secret Key Leaked", types.SeverityCritical, "Secret key exposed in response body", 0.8},
		{rxPassword, "Password Leaked", types.SeverityCritical, "Password or credential exposed in response body", 0.85},
		{rxAuth, "Authorization Credential Leaked", types.SeverityHigh, "Authorization credential exposed in response", 0.75},
		{rxBasicAuth, "Basic Auth Credential", types.SeverityHigh, "Base64-encoded Basic Authentication credentials found", 0.8},
	}

	for _, p := range patterns {
		select {
		case <-ctx.Done():
			return findings
		default:
		}
		for _, m := range p.rx.FindAllStringSubmatch(body, -1) {
			val := ""
			if len(m) > 1 {
				val = truncate(m[1], 30)
			} else {
				val = truncate(m[0], 40)
			}
			findings = append(findings, types.Finding{
				Type:        types.FindingSecret,
				Name:        p.name,
				Severity:    p.sev,
				Description: p.desc,
				Evidence:    val,
				Confidence:  p.conf,
			})
		}
	}

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
	json.Unmarshal([]byte(hdrStr), &hdr)
	json.Unmarshal([]byte(clsStr), &cls)

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
	if hdr.Alg == "none" {
		sev = types.SeverityCritical
		conf = 0.95
		details = append(details, "VULNERABILITY: alg=none — JWT signature verification bypass!")
	} else if hdr.Alg == "HS256" || hdr.Alg == "HS384" || hdr.Alg == "HS512" {
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
		Evidence:    truncate(raw, 80),
		Confidence:  conf,
		Metadata:    meta,
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
