package hacker

import (
	"net/http"
	"testing"
)

func findingsByType(fs []Finding) map[string]Finding {
	out := make(map[string]Finding, len(fs))
	for _, f := range fs {
		out[f.Type] = f
	}
	return out
}

// The old checker lowercased the whole Set-Cookie value and looked for
// "secure" anywhere in it: a cookie *named* secure_pref was treated as
// carrying the Secure attribute. Attributes must be parsed, not grepped.
func TestCookieAttributesAreParsedNotSubstringMatched(t *testing.T) {
	hdr := http.Header{}
	hdr.Add("Set-Cookie", "secure_pref=abc123; Path=/; HttpOnly; SameSite=Lax")
	got := findingsByType(analyzeSecurityHeaders("https://example.com", "example.com", hdr))

	if _, ok := got["cookie_missing_secure"]; !ok {
		t.Fatalf("a cookie named secure_pref has no Secure attribute — must be reported: %+v", got)
	}
	if _, ok := got["cookie_missing_httponly"]; ok {
		t.Error("HttpOnly is present and must not be reported missing")
	}

	hdr = http.Header{}
	hdr.Add("Set-Cookie", "sid=abc; Secure; HttpOnly; SameSite=Strict; Path=/")
	got = findingsByType(analyzeSecurityHeaders("https://example.com", "example.com", hdr))
	for _, typ := range []string{"cookie_missing_secure", "cookie_missing_httponly", "cookie_missing_samesite"} {
		if _, ok := got[typ]; ok {
			t.Errorf("fully flagged cookie still reported %s: %+v", typ, got)
		}
	}
}

func TestCookieSameSiteNoneWithoutSecureIsRejectedByBrowsers(t *testing.T) {
	hdr := http.Header{}
	hdr.Add("Set-Cookie", "sess=xyz; Path=/; HttpOnly; SameSite=None")
	got := findingsByType(analyzeSecurityHeaders("https://example.com", "example.com", hdr))
	if _, ok := got["cookie_samesite_none_insecure"]; !ok {
		t.Fatalf("SameSite=None without Secure is dropped by browsers — must be reported: %+v", got)
	}
}

func TestCookieHostPrefixRequirements(t *testing.T) {
	hdr := http.Header{}
	hdr.Add("Set-Cookie", "__Host-sid=abc; Path=/app; HttpOnly; Secure")
	got := findingsByType(analyzeSecurityHeaders("https://example.com", "example.com", hdr))
	f, ok := got["cookie_host_prefix_violation"]
	if !ok {
		t.Fatalf("__Host- with Path=/app is rejected by browsers — must be reported: %+v", got)
	}
	if f.Severity != SevMedium {
		t.Errorf("severity = %v, want Medium", f.Severity)
	}
}

func TestCSPUnsafeInline(t *testing.T) {
	// No nonce/hash: 'unsafe-inline' really does allow injected inline
	// scripts, so this is a claim the spec supports.
	hdr := http.Header{}
	hdr.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'")
	got := findingsByType(analyzeSecurityHeaders("https://example.com", "example.com", hdr))
	if _, ok := got["csp_unsafe_inline"]; !ok {
		t.Fatalf("'unsafe-inline' without nonce/hash must be reported: %+v", got)
	}

	// With a nonce, browsers ignore 'unsafe-inline' (CSP3): reporting it
	// would be a finding the spec contradicts.
	hdr.Set("Content-Security-Policy", "default-src 'self'; script-src 'nonce-abc123' 'unsafe-inline'")
	got = findingsByType(analyzeSecurityHeaders("https://example.com", "example.com", hdr))
	if _, ok := got["csp_unsafe_inline"]; ok {
		t.Errorf("nonce present ⇒ 'unsafe-inline' is ignored, must not be reported: %+v", got)
	}
}

func TestCSPWildcardAndSafety(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Content-Security-Policy", "default-src *; object-src 'none'")
	got := findingsByType(analyzeSecurityHeaders("https://example.com", "example.com", hdr))
	if _, ok := got["csp_wildcard_source"]; !ok {
		t.Fatalf("default-src * must be reported: %+v", got)
	}

	// A policy restricting scripts to the origin is not a finding.
	hdr.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' https://cdn.example.com; object-src 'none'; frame-ancestors 'none'")
	got = findingsByType(analyzeSecurityHeaders("https://example.com", "example.com", hdr))
	for _, typ := range []string{"csp_wildcard_source", "csp_unsafe_inline", "csp_unsafe_eval", "csp_no_default_src", "missing_framing_protection", "missing_csp"} {
		if _, ok := got[typ]; ok {
			t.Errorf("safe policy reported %s: %+v", typ, got)
		}
	}
}

func TestHSTSQuality(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Strict-Transport-Security", "max-age=0")
	got := findingsByType(analyzeSecurityHeaders("https://example.com", "example.com", hdr))
	if _, ok := got["hsts_disabled"]; !ok {
		t.Fatalf("max-age=0 is ignored by browsers — must be reported: %+v", got)
	}

	hdr.Set("Strict-Transport-Security", "max-age=600")
	got = findingsByType(analyzeSecurityHeaders("https://example.com", "example.com", hdr))
	if _, ok := got["hsts_short_max_age"]; !ok {
		t.Fatalf("10-minute max-age must be flagged as short: %+v", got)
	}

	hdr.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	got = findingsByType(analyzeSecurityHeaders("https://example.com", "example.com", hdr))
	for _, typ := range []string{"hsts_disabled", "hsts_short_max_age", "hsts_no_subdomains", "missing_hsts"} {
		if _, ok := got[typ]; ok {
			t.Errorf("good HSTS reported %s: %+v", typ, got)
		}
	}
}

func TestXFOInvalidValue(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("X-Frame-Options", "ALLOW-FROM https://partner.example")
	got := findingsByType(analyzeSecurityHeaders("https://example.com", "example.com", hdr))
	if _, ok := got["xfo_invalid_value"]; !ok {
		t.Fatalf("ALLOW-FROM is ignored by browsers — must be reported: %+v", got)
	}
	if _, ok := got["missing_framing_protection"]; ok {
		t.Error("the header is present; calling it missing would overstate")
	}
}
