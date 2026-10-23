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
