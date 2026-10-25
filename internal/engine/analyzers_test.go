package engine

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// Phase 5 — engine analyzer regressions (pure response -> findings logic).

func respWithHeaders(h map[string]string) *types.Response {
	hdr := http.Header{}
	for k, v := range h {
		hdr.Set(k, v)
	}
	return &types.Response{StatusCode: 200, Headers: hdr, Body: []byte("ok")}
}

func hasFinding(fs []types.Finding, name string) bool {
	for _, f := range fs {
		if f.Name == name {
			return true
		}
	}
	return false
}

func TestHeaderAnalyzerFlagsMissingSecurityHeaders(t *testing.T) {
	h := NewHeaderAnalyzer()
	fs := h.Analyze(context.Background(), respWithHeaders(nil))

	for _, name := range []string{
		"Missing CSP Header",
		"Missing HSTS Header",
		"Missing X-Frame-Options",
		"Missing X-Content-Type-Options",
		"Missing Referrer-Policy",
	} {
		if !hasFinding(fs, name) {
			t.Errorf("expected finding %q, got %+v", name, fs)
		}
	}
}

func TestHeaderAnalyzerSilentWhenHeadersPresent(t *testing.T) {
	h := NewHeaderAnalyzer()
	resp := respWithHeaders(map[string]string{
		"Content-Security-Policy":   "default-src 'self'",
		"Strict-Transport-Security": "max-age=31536000",
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "no-referrer",
	})
	if fs := h.Analyze(context.Background(), resp); len(fs) != 0 {
		t.Errorf("all headers set: no findings expected, got %+v", fs)
	}
}

func TestHeaderAnalyzerDisclosesTechnologies(t *testing.T) {
	h := NewHeaderAnalyzer()
	resp := respWithHeaders(map[string]string{
		"Server":       "Express/4.17.1",
		"X-Powered-By": "PHP/8.1.0",
	})
	fs := h.Analyze(context.Background(), resp)
	if !hasFinding(fs, "Server Version Disclosure") || !hasFinding(fs, "Technology Disclosure") {
		t.Errorf("expected tech disclosures, got %+v", fs)
	}

	// Bare "nginx"/"apache" without a version stays quiet.
	resp2 := respWithHeaders(map[string]string{"Server": "nginx"})
	if hasFinding(h.Analyze(context.Background(), resp2), "Server Version Disclosure") {
		t.Errorf("generic nginx banner must not be flagged as high-value disclosure")
	}

	// The inversion the review caught: nginx WITH a version is the actual
	// disclosure case the old logic silenced.
	resp3 := respWithHeaders(map[string]string{"Server": "nginx/1.24.2"})
	if !hasFinding(h.Analyze(context.Background(), resp3), "Server Version Disclosure") {
		t.Errorf("nginx/1.24.2 must be flagged as version disclosure")
	}
}

func TestCORSAnalyzerWildcardWithCredentials(t *testing.T) {
	c := NewCORSAnalyzer()
	resp := respWithHeaders(map[string]string{
		"Access-Control-Allow-Origin":      "*",
		"Access-Control-Allow-Credentials": "true",
	})
	fs := c.Analyze(context.Background(), resp)
	if len(fs) != 1 || fs[0].Severity != types.SeverityCritical {
		t.Fatalf("wildcard CORS + credentials must be critical, got %+v", fs)
	}
}

func TestCORSAnalyzerReflectiveWithCredentials(t *testing.T) {
	c := NewCORSAnalyzer()
	resp := respWithHeaders(map[string]string{
		"Access-Control-Allow-Origin":      corsProbeOrigin,
		"Access-Control-Allow-Credentials": "true",
	})
	fs := c.Analyze(context.Background(), resp)
	if len(fs) == 0 || fs[0].Name != "CORS Origin Reflection with Credentials" || fs[0].Severity != types.SeverityHigh {
		t.Fatalf("verbatim origin echo with credentials must be flagged High, got %+v", fs)
	}
}

func TestCORSAnalyzerReflectionWithoutCredentials(t *testing.T) {
	c := NewCORSAnalyzer()
	resp := respWithHeaders(map[string]string{
		"Access-Control-Allow-Origin": corsProbeOrigin,
	})
	fs := c.Analyze(context.Background(), resp)
	if len(fs) == 0 || fs[0].Name != "CORS Arbitrary Origin Reflection" || fs[0].Severity != types.SeverityMedium {
		t.Fatalf("reflection without credentials must be flagged Medium, got %+v", fs)
	}
}

func TestCORSAnalyzerNoSubstringFalsePositive(t *testing.T) {
	// ACAO merely containing the probe origin as a substring is not a
	// reflection: browsers only honour exact matches.
	c := NewCORSAnalyzer()
	resp := respWithHeaders(map[string]string{
		"Access-Control-Allow-Origin":      "https://evil.com.attacker.tld",
		"Access-Control-Allow-Credentials": "true",
	})
	fs := c.Analyze(context.Background(), resp)
	for _, f := range fs {
		if strings.Contains(f.Name, "Reflection") {
			t.Errorf("substring ACAO must not count as reflection: %+v", fs)
		}
	}
}

func TestCORSAnalyzerWildcardAloneAndNullOrigin(t *testing.T) {
	c := NewCORSAnalyzer()

	fs := c.Analyze(context.Background(), respWithHeaders(map[string]string{
		"Access-Control-Allow-Origin": "*",
	}))
	if !hasFinding(fs, "Wildcard CORS Origin") {
		t.Errorf("expected wildcard-origin Medium finding, got %+v", fs)
	}

	fs = c.Analyze(context.Background(), respWithHeaders(map[string]string{
		"Access-Control-Allow-Origin": "null",
	}))
	if !hasFinding(fs, "CORS Null Origin Allowed") {
		t.Errorf("expected null-origin High finding, got %+v", fs)
	}
}

func TestCORSAnalyzerNoACAOIsQuiet(t *testing.T) {
	c := NewCORSAnalyzer()
	if fs := c.Analyze(context.Background(), respWithHeaders(nil)); fs != nil {
		t.Errorf("no ACAO header must produce no findings, got %+v", fs)
	}
}
