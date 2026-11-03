package fingerprint

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// Phase 5 — fingerprint signature matching regressions (pure logic).

func respWithServer(v string) *types.Response {
	return &types.Response{
		StatusCode: 200,
		Headers:    http.Header{"Server": []string{v}},
		Body:       []byte("<html></html>"),
	}
}

func TestFingerprintVersionsExtractedFromHeaders(t *testing.T) {
	f := New()

	// nginx
	fs := f.Analyze(context.Background(), respWithServer("nginx/1.24.0"))
	var nginx *types.Finding
	for i, fd := range fs {
		if fd.Name == "nginx" {
			nginx = &fs[i]
		}
	}
	if nginx == nil {
		t.Fatalf("Server nginx/1.24.0 must trigger the nginx signature, got %+v", fs)
	}

	// Apache
	fs = f.Analyze(context.Background(), respWithServer("Apache/2.4.41 (Unix)"))
	var apache *types.Finding
	for i, fd := range fs {
		if fd.Name == "Apache HTTP Server" {
			apache = &fs[i]
		}
	}
	if apache == nil {
		t.Fatalf("Server Apache/2.4.41 must trigger the Apache signature, got %+v", fs)
	}
}

func TestFingerprintNoInventedEvidence(t *testing.T) {
	// A response carrying no known tech must produce no findings: the
	// engine reports what matched, it never guesses.
	f := New()
	resp := &types.Response{
		StatusCode: 200,
		Headers:    http.Header{},
		Body:       []byte("<html><body>plain</body></html>"),
	}
	if fs := f.Analyze(context.Background(), resp); len(fs) != 0 {
		t.Errorf("plain response must not be fingerprinted: %+v", fs)
	}
}

func TestSignatureMatchEchoesResponseEvidence(t *testing.T) {
	// Evidence strings are built from the raw response, not static copy:
	// an operator reading a finding must be able to reproduce it.
	s := Signature{
		Name:       "nginx",
		Confidence: 0.97,
		Headers:    hdr("Server", `(?i)nginx(?:/([\d.]+))?`),
	}
	resp := respWithServer("nginx/1.24.0")
	matched, evidence, version := s.Match(resp)
	if !matched {
		t.Fatal("signature must match its own declared header")
	}
	if !strings.Contains(evidence, "nginx/1.24.0") {
		t.Errorf("evidence must echo the observed header value, got %q", evidence)
	}
	if version != "1.24.0" {
		t.Errorf("version extraction must capture the pinned group, got %q", version)
	}

	// A bare nginx banner with no version yields a match but no version.
	_, _, version = s.Match(respWithServer("nginx"))
	if version != "" {
		t.Errorf("versionless banner must not invent a version, got %q", version)
	}
}

func TestGenericSignaturesDoNotFalsePositive(t *testing.T) {
	// Regression: HTML/Script patterns are OR-matched, so one loose pattern
	// fires a whole tech. "image:" matched Magento's `mage\s*:` and any React
	// app matched Preact's bare `createElement`. A non-Magento, non-Preact
	// page that only contains those substrings must NOT be fingerprinted.
	f := New()
	body := []byte(`<html><head><script>
		const icon = { image: "logo.png" };
		function h(tag){ return document.createElement(tag); }
	</script></head><body>Product gallery</body></html>`)
	resp := &types.Response{
		StatusCode: 200,
		Headers:    http.Header{},
		Body:       body,
	}
	for _, fd := range f.Analyze(context.Background(), resp) {
		if fd.Name == "Magento" {
			t.Errorf("`image:` must not match Magento: %+v", fd)
		}
		if fd.Name == "Preact" {
			t.Errorf("bare `createElement` must not match Preact: %+v", fd)
		}
	}

	// The anchored markers still have to fire — the fix removed noise, not the
	// signal.
	respM := &types.Response{StatusCode: 200, Headers: http.Header{},
		Body: []byte(`<html><script>window.Mage = { RequireJS: {} };</script></html>`)}
	if !containsTech(f.Analyze(context.Background(), respM), "Magento") {
		t.Error("window.Mage must still match Magento")
	}
	respP := &types.Response{StatusCode: 200, Headers: http.Header{},
		Body: []byte(`<html><script>import { h } from "preact";</script></html>`)}
	if !containsTech(f.Analyze(context.Background(), respP), "Preact") {
		t.Error(`from "preact" must still match Preact`)
	}
}

// Same FP class as Preact/Magento, one layer down: a page that merely
// *mentions* GraphQL or FastAPI in prose is not a target that serves them.
// HTML patterns match the whole body, so the old bare `graphql`/`fastapi`
// substrings fired a whole-technology claim from any lowercase mention.
func TestProseMentionsDoNotFingerprintAPIFrameworks(t *testing.T) {
	f := New()
	prose := &types.Response{StatusCode: 200, Headers: http.Header{},
		Body: []byte(`<html><body><p>This tutorial covers graphql queries and why we chose fastapi on the backend.</p></body></html>`)}
	for _, fd := range f.Analyze(context.Background(), prose) {
		if fd.Name == "GraphQL" {
			t.Errorf("prose `graphql` must not fingerprint GraphQL: %+v", fd)
		}
		if fd.Name == "FastAPI" {
			t.Errorf("prose `fastapi` must not fingerprint FastAPI: %+v", fd)
		}
	}

	// The anchored markers still fire — noise removed, signal kept.
	gql := &types.Response{StatusCode: 200, Headers: http.Header{},
		Body: []byte(`<html><div id="graphiql"><script>ApolloProvider</script></div></html>`)}
	if !containsTech(f.Analyze(context.Background(), gql), "GraphQL") {
		t.Error("graphiql/ApolloProvider must still match GraphQL")
	}
	fast := &types.Response{StatusCode: 200, Headers: http.Header{},
		Body: []byte(`{"openapi":"3.1.0","info":{"title":"FastAPI","version":"1.0"}}`)}
	if !containsTech(f.Analyze(context.Background(), fast), "FastAPI") {
		t.Error(`served openapi info.title must still match FastAPI`)
	}
}

func containsTech(fs []types.Finding, name string) bool {
	for _, fd := range fs {
		if fd.Name == name {
			return true
		}
	}
	return false
}
