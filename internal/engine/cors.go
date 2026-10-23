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

	var findings []types.Finding

	aco := resp.Headers.Get("Access-Control-Allow-Origin")
	acac := resp.Headers.Get("Access-Control-Allow-Credentials")
	acm := resp.Headers.Get("Access-Control-Allow-Methods")
	ach := resp.Headers.Get("Access-Control-Allow-Headers")

	// Reflection can only be asserted against the origin the scanner itself
	// probed with (engine.go sends this header) and honoured by browsers
	// only on an exact ACAO match: substring containment would call
	// "https://evil.com.attacker.tld" a reflection of "https://evil.com".
	if aco == "" {
		return nil
	}

	if aco == "*" && acac == "true" {
		findings = append(findings, types.Finding{
			Type:        types.FindingMisconfig,
			Name:        "Wildcard CORS with Credentials",
			Severity:    types.SeverityCritical,
			Description: "CORS allows any origin (Access-Control-Allow-Origin: *) with credentials enabled — any website can read this resource on behalf of authenticated users",
			Evidence:    "ACAO: * | ACAC: true",
			Confidence:  0.95,
			Metadata: map[string]string{
				"aco":  aco,
				"acac": acac,
			},
		})
		return findings
	}

	if strings.Contains(aco, "*") && acac == "true" {
		findings = append(findings, types.Finding{
			Type:        types.FindingMisconfig,
			Name:        "Reflective CORS with Credentials",
			Severity:    types.SeverityCritical,
			Description: "CORS reflects arbitrary origins with credentials enabled — potential data exfiltration",
			Evidence:    fmt.Sprintf("ACAO: %s | ACAC: %s", aco, acac),
			Confidence:  0.85,
			Metadata: map[string]string{
				"aco":  aco,
				"acac": acac,
			},
		})
		return findings
	}

	if aco == "*" {
		findings = append(findings, types.Finding{
			Type:        types.FindingMisconfig,
			Name:        "Wildcard CORS Origin",
			Severity:    types.SeverityMedium,
			Description: "Access-Control-Allow-Origin is set to wildcard, allowing any domain to read responses",
			Evidence:    "ACAO: *",
			Confidence:  0.9,
		})
	}

	if strings.EqualFold(strings.TrimSpace(aco), corsProbeOrigin) {
		if acac == "true" {
			findings = append(findings, types.Finding{
				Type:        types.FindingMisconfig,
				Name:        "CORS Origin Reflection with Credentials",
				Severity:    types.SeverityHigh,
				Description: "CORS header reflects the probed attacker origin verbatim with credentials enabled",
				Evidence:    fmt.Sprintf("ACAO: %s | ACAC: true | Origin echoed", aco),
				Confidence:  0.8,
				Metadata: map[string]string{
					"aco":  aco,
					"acac": acac,
				},
			})
		} else {
			findings = append(findings, types.Finding{
				Type:        types.FindingMisconfig,
				Name:        "CORS Arbitrary Origin Reflection",
				Severity:    types.SeverityMedium,
				Description: "CORS reflects the probed attacker origin even without credentials — any site can read unauthenticated responses",
				Evidence:    fmt.Sprintf("ACAO: %s | Origin echoed", aco),
				Confidence:  0.75,
				Metadata: map[string]string{
					"aco": aco,
				},
			})
		}
	}

	if aco == "null" {
		findings = append(findings, types.Finding{
			Type:        types.FindingMisconfig,
			Name:        "CORS Null Origin Allowed",
			Severity:    types.SeverityHigh,
			Description: "Access-Control-Allow-Origin: null — sandboxed iframes and data: URIs can read responses",
			Evidence:    "ACAO: null",
			Confidence:  0.7,
		})
	}

	if acm != "" && strings.Contains(acm, "PUT") {
		findings = append(findings, types.Finding{
			Type:        types.FindingMisconfig,
			Name:        "CORS Allows PUT Method",
			Severity:    types.SeverityLow,
			Description: "CORS allows the PUT HTTP method via Access-Control-Allow-Methods",
			Evidence:    fmt.Sprintf("ACAO: %s | ACAM: %s", aco, acm),
			Confidence:  0.6,
		})
	}

	if ach != "" && strings.Contains(ach, "*") {
		findings = append(findings, types.Finding{
			Type:        types.FindingMisconfig,
			Name:        "CORS Wildcard Allowed Headers",
			Severity:    types.SeverityLow,
			Description: "Access-Control-Allow-Headers contains wildcard allowing any custom header",
			Evidence:    fmt.Sprintf("ACAH: %s", ach),
			Confidence:  0.5,
		})
	}

	return findings
}
