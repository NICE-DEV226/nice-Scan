package hacker

import (
	"testing"
)

// Phase 2 — OPSEC regressions for host-bound data ingest and same-host
// gating of actions driven by remote data.

func TestIsDomainScopedURL(t *testing.T) {
	accept := []string{
		"https://example.com/admin",
		"https://api.example.com/graphql",
		"http://example.com:8080/x",
	}
	reject := []string{
		"https://other-site.com/admin",
		"https://notexample.com/admin",
		"https://example.com.evil.com/admin",
		"https://evil.com/?u=https://example.com/admin",
	}
	for _, u := range accept {
		if !isDomainScopedURL(u, "example.com") {
			t.Errorf("%q must be in scope for example.com", u)
		}
	}
	for _, u := range reject {
		if isDomainScopedURL(u, "example.com") {
			t.Errorf("%q must NOT be in scope for example.com", u)
		}
	}
}

func TestSameHostStrict(t *testing.T) {
	accept := [][2]string{
		{"https://example.com/login", "https://example.com/other"},
		{"http://example.com", "https://example.com/sub"},
	}
	reject := [][2]string{
		{"https://other.com/login", "https://example.com"},
		{"https://example.com:8443/login", "https://example.com"},
		{"not a url", "https://example.com"},
	}
	for _, c := range accept {
		if !sameHostStrict(c[0], c[1]) {
			t.Errorf("sameHostStrict(%q,%q) must be true", c[0], c[1])
		}
	}
	for _, c := range reject {
		if sameHostStrict(c[0], c[1]) {
			t.Errorf("sameHostStrict(%q,%q) must be false (fail closed)", c[0], c[1])
		}
	}
}

func TestCrtShFilterMustNotAcceptSiblingTLD(t *testing.T) {
	// Regression against the previously accepted sibling-TLD fallback:
	// a scan of target.com must never propagate sibling-target.co names
	// that crt.sh might return for certificate transparency matches.
	entries := []crtShEntry{
		{CommonName: "target.com", NameValue: "target.com"},
		{CommonName: "wiki.target.com", NameValue: "wiki.target.com"},
		{CommonName: "sibling-target.co", NameValue: "sibling-target.co"},
		{CommonName: "*.target.com", NameValue: "*.\ntarget.com\ncert.target.com"},
	}
	got := filterCrtShNames(entries, "target.com")

	want := []string{"wiki.target.com", "cert.target.com"}
	if len(got) != len(want) {
		t.Fatalf("filtered subdomains = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d]=%q, want %q", i, got[i], want[i])
		}
	}
}
