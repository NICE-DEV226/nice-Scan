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

func TestCORSAnalyzerWildcardWithCredentialsIsNotCritical(t *testing.T) {
	// Browsers reject ACAO:* together with ACAC:true (Fetch spec), so no
	// origin can read anything. The pair is a configuration error and was
	// previously reported Critical on ordinary CDN/gateway setups.
	c := NewCORSAnalyzer()
	resp := respWithHeaders(map[string]string{
		"Access-Control-Allow-Origin":      "*",
		"Access-Control-Allow-Credentials": "true",
	})
	fs := c.Analyze(context.Background(), resp)
	if len(fs) != 1 {
		t.Fatalf("expected exactly one finding, got %+v", fs)
	}
	if fs[0].Severity != types.SeverityInfo {
		t.Fatalf("wildcard + credentials is not exploitable: severity %q, want %q", fs[0].Severity, types.SeverityInfo)
	}
}

func TestCORSAnalyzerWildcardAloneIsQuiet(t *testing.T) {
	// Access-Control-Allow-Origin: * is the default for public resources and
	// grants nothing a plain cross-origin fetch does not already grant.
	c := NewCORSAnalyzer()
	if fs := c.Analyze(context.Background(), respWithHeaders(map[string]string{
		"Access-Control-Allow-Origin": "*",
	})); len(fs) != 0 {
		t.Fatalf("wildcard without credentials must not be flagged, got %+v", fs)
	}
}

func TestCORSAnalyzerStarHostPatternIsNotReflection(t *testing.T) {
	// "https://*.example.com" contains a star but reflects no origin.
	c := NewCORSAnalyzer()
	fs := c.Analyze(context.Background(), respWithHeaders(map[string]string{
		"Access-Control-Allow-Origin":      "https://*.example.com",
		"Access-Control-Allow-Credentials": "true",
	}))
	if len(fs) != 0 {
		t.Fatalf("a star inside a host pattern must not be read as reflection: %+v", fs)
	}
}

func TestCORSAnalyzerDuplicateOriginHeaderIsRejectedByBrowsers(t *testing.T) {
	c := NewCORSAnalyzer()
	hdr := http.Header{}
	hdr.Add("Access-Control-Allow-Origin", corsProbeOrigin)
	hdr.Add("Access-Control-Allow-Origin", corsProbeOrigin)
	hdr.Set("Access-Control-Allow-Credentials", "true")
	resp := &types.Response{StatusCode: 200, Headers: hdr, Body: []byte("ok")}
	if fs := c.Analyze(context.Background(), resp); len(fs) != 0 {
		t.Fatalf("duplicated ACAO is rejected by the browser, so no finding may be claimed: %+v", fs)
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
	if len(fs) == 0 || fs[0].Name != "CORS Arbitrary Origin Reflection" {
		t.Fatalf("expected an origin-reflection finding, got %+v", fs)
	}
	// Without credentials the browser sends no cookies, so the impact is
	// conditional on cookie-less authentication: Low, not Medium.
	if fs[0].Severity != types.SeverityLow {
		t.Fatalf("reflection without credentials severity %q, want %q", fs[0].Severity, types.SeverityLow)
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

func TestCORSAnalyzerNullOriginSeverityFollowsCredentials(t *testing.T) {
	c := NewCORSAnalyzer()

	// A sandboxed iframe sends Origin: null; with credentials that is a real
	// read primitive.
	fs := c.Analyze(context.Background(), respWithHeaders(map[string]string{
		"Access-Control-Allow-Origin":      "null",
		"Access-Control-Allow-Credentials": "true",
	}))
	if len(fs) != 1 || fs[0].Severity != types.SeverityHigh {
		t.Fatalf("null origin with credentials must be High, got %+v", fs)
	}

	// Without credentials the same header is a low-severity observation.
	fs = c.Analyze(context.Background(), respWithHeaders(map[string]string{
		"Access-Control-Allow-Origin": "null",
	}))
	if len(fs) != 1 || fs[0].Severity != types.SeverityLow {
		t.Fatalf("null origin without credentials must be Low, got %+v", fs)
	}
}

func TestCORSAnalyzerCredentialsValueIsCaseInsensitive(t *testing.T) {
	c := NewCORSAnalyzer()
	fs := c.Analyze(context.Background(), respWithHeaders(map[string]string{
		"Access-Control-Allow-Origin":      corsProbeOrigin,
		"Access-Control-Allow-Credentials": " True ",
	}))
	if !hasFinding(fs, "CORS Origin Reflection with Credentials") {
		t.Fatalf("ACAC: "+"\" True \""+" is honoured by browsers, got %+v", fs)
	}
}

func TestCORSAnalyzerNoACAOIsQuiet(t *testing.T) {
	c := NewCORSAnalyzer()
	if fs := c.Analyze(context.Background(), respWithHeaders(nil)); fs != nil {
		t.Errorf("no ACAO header must produce no findings, got %+v", fs)
	}
}
