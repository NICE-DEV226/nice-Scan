package engine

import (
	"context"
	"fmt"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

type HTTPMethodsAnalyzer struct{}

func NewHTTPMethodsAnalyzer() *HTTPMethodsAnalyzer {
	return &HTTPMethodsAnalyzer{}
}

func (a *HTTPMethodsAnalyzer) Name() string {
	return "http_methods"
}

func (a *HTTPMethodsAnalyzer) Analyze(ctx context.Context, resp *types.Response) []types.Finding {
	if resp == nil {
		return nil
	}

	var findings []types.Finding

	allow := resp.Headers.Get("Allow")
	if allow == "" {
		allow = resp.Headers.Get("Public")
	}
	if allow == "" {
		return nil
	}

	allowed := strings.ToUpper(allow)
	methods := strings.FieldsFunc(allowed, func(r rune) bool {
		return r == ',' || r == ' '
	})

	var risky []string
	for _, m := range methods {
		m = strings.TrimSpace(m)
		switch m {
		case "TRACE", "TRACK":
			risky = append(risky, m+" (XST attack)")
		case "PUT":
			risky = append(risky, m+" (file upload)")
		case "DELETE":
			risky = append(risky, m+" (resource deletion)")
		case "CONNECT":
			risky = append(risky, m+" (tunneling)")
		case "PATCH":
			risky = append(risky, m+" (partial modify)")
		}
	}

	if len(risky) > 0 {
		sev := types.SeverityMedium
		if containsAny(allowed, "TRACE", "TRACK") {
			sev = types.SeverityHigh
		}
		findings = append(findings, types.Finding{
			Type:        types.FindingMisconfig,
			Name:        "Risky HTTP Methods Enabled",
			Severity:    sev,
			Description: "Server allows potentially dangerous HTTP methods",
			Evidence:    fmt.Sprintf("Allow: %s", allow),
			Confidence:  0.9,
			Metadata: map[string]string{
				"allowed": allow,
				"risky":   strings.Join(risky, ", "),
			},
		})
	}

	return findings
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
