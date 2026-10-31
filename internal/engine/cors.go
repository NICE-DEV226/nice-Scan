package engine

import (
	"context"
	"fmt"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// corsProbeOrigin is the Origin value the engine's CORS probe sends
// (see Scanner.buildProbes). The analyzer asserts origin reflection by
// checking that the response echoes exactly this value: keeping the two
// sides in one shared constant is what makes the assertion true.
const corsProbeOrigin = "https://evil.com"

// CORSAnalyzer reports only what a single response can prove. Four earlier
// claims were removed by the audit because no header combination supports
// them:
//
//   - "ACAO: * + ACAC: true is Critical": browsers reject that pair outright
//     (Fetch spec — the wildcard is not honoured with credentials), so no
//     origin can read anything. It is kept as Info: a configuration error
//     with no security impact, not an exposure.
//   - "ACAO: * is Medium": the wildcard is the default for public resources
//     and grants exactly what a plain cross-origin fetch already grants.
//   - "ACAO matches * as a substring => reflective with credentials": a
//     value like https://*.example.com reflects no origin at all. Only an
//     exact echo of the probed origin counts, as the doc comment above has
//     always said.
//   - "ACAM lists PUT" / "ACAH contains *": neither is a vulnerability on its
//     own; both fired on ordinary API gateways.
//
// Every finding retained below is grounded in response bytes: an exact echo
// of the probed origin, ACAO: null, or the credentialed wildcard.
type CORSAnalyzer struct{}

func NewCORSAnalyzer() *CORSAnalyzer {
	return &CORSAnalyzer{}
}

func (a *CORSAnalyzer) Name() string {
	return "cors"
}

func (a *CORSAnalyzer) Analyze(ctx context.Context, resp *types.Response) []types.Finding {
	if resp == nil || resp.Headers == nil {
		return nil
	}

	acos := resp.Headers.Values("Access-Control-Allow-Origin")
	if len(acos) == 0 {
		return nil
	}
	// A repeated ACAO makes the browser reject the CORS response entirely,
	// so no claim about it can be true — an upstream proxy that duplicates
	// the header must not produce a High.
	if len(acos) > 1 {
		return nil
	}

	aco := strings.TrimSpace(acos[0])
	if aco == "" {
		return nil
	}

	// Browsers only honour an exact ACAO match, and credentials require the
	// literal "true" (case-insensitive, no leading/trailing space).
	creds := strings.EqualFold(strings.TrimSpace(resp.Headers.Get("Access-Control-Allow-Credentials")), "true")

	echoesProbe := strings.EqualFold(aco, corsProbeOrigin)
	nullOrigin := strings.EqualFold(aco, "null")
	wildcard := aco == "*"

	switch {
	case echoesProbe && creds:
		return []types.Finding{{
			Type:     types.FindingMisconfig,
			Name:     "CORS Origin Reflection with Credentials",
			Severity: types.SeverityHigh,
			Description: fmt.Sprintf("The server echoed the probed attacker origin (%s) verbatim in Access-Control-Allow-Origin "+
				"with Access-Control-Allow-Credentials: true — a page on that origin can read authenticated responses", corsProbeOrigin),
			Evidence:   fmt.Sprintf("Origin: %s -> ACAO: %s | ACAC: true (verbatim echo)", corsProbeOrigin, aco),
			Confidence: 0.9,
			Metadata: map[string]string{
				"aco":    aco,
				"acac":   "true",
				"origin": corsProbeOrigin,
			},
		}}

	case echoesProbe:
		return []types.Finding{{
			Type:     types.FindingMisconfig,
			Name:     "CORS Arbitrary Origin Reflection",
			Severity: types.SeverityLow,
			Description: fmt.Sprintf("The server echoed the probed attacker origin (%s) verbatim without allowing credentials — "+
				"impact is limited to responses readable without cookies, so this is only actionable on endpoints that "+
				"authenticate without them (IP allow-lists, tokens in the URL)", corsProbeOrigin),
			Evidence:   fmt.Sprintf("Origin: %s -> ACAO: %s | no ACAC", corsProbeOrigin, aco),
			Confidence: 0.8,
			Metadata: map[string]string{
				"aco":    aco,
				"origin": corsProbeOrigin,
			},
		}}

	case nullOrigin && creds:
		return []types.Finding{{
			Type:     types.FindingMisconfig,
			Name:     "CORS Null Origin Allowed with Credentials",
			Severity: types.SeverityHigh,
			Description: "Access-Control-Allow-Origin: null with credentials enabled — a sandboxed iframe or data: URI sends " +
				"Origin: null and can read authenticated responses",
			Evidence:   "ACAO: null | ACAC: true",
			Confidence: 0.9,
			Metadata:   map[string]string{"aco": "null", "acac": "true"},
		}}

	case nullOrigin:
		return []types.Finding{{
			Type:        types.FindingMisconfig,
			Name:        "CORS Null Origin Allowed",
			Severity:    types.SeverityLow,
			Description: "Access-Control-Allow-Origin: null without credentials — a sandboxed iframe can read unauthenticated responses on this endpoint",
			Evidence:    "ACAO: null",
			Confidence:  0.8,
			Metadata:    map[string]string{"aco": "null"},
		}}

	case wildcard && creds:
		return []types.Finding{{
			Type:     types.FindingMisconfig,
			Name:     "CORS Wildcard with Credentials (Invalid)",
			Severity: types.SeverityInfo,
			Description: "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true — browsers reject " +
				"this combination, so no origin can read credentialed responses. Reported as a configuration error only: " +
				"the intent is broken, not the security boundary",
			Evidence:   "ACAO: * | ACAC: true",
			Confidence: 0.9,
			Metadata:   map[string]string{"aco": "*", "acac": "true"},
		}}
	}

	return nil
}
