package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// A credential that only exists once the response is decoded must be surfaced.
// The raw, quote-shaped matchers see a base64/URL blob and the unquoted value
// and miss it entirely — this is the "even buried" case.
func TestBuriedCredentialsRevealedByDecoding(t *testing.T) {
	te := NewTokenExtractor()

	b64 := "token: cGFzc3dvcmQ9IlMzY3IzdC1QYXNzISI=" // base64(password="S3cr3t-Pass!")
	fs := te.Analyze(context.Background(), respFromBody(b64))
	if !hasFindingNamed(fs, "revealed by base64") {
		t.Errorf("a base64-encoded password must resurface after decoding: %+v", fs)
	}

	urlEnc := "%70%61%73%73%77%6F%72%64%3D%22%53%33%63%72%33%74%2D%50%61%73%73%21%22"
	fs2 := te.Analyze(context.Background(), respFromBody("param="+urlEnc))
	if !hasFindingNamed(fs2, "revealed by URL encoding") {
		t.Errorf("a URL-encoded password must resurface after decoding: %+v", fs2)
	}

	// A random base64 blob that decodes to binary/text with no secret must not
	// produce buried-credential noise.
	fs3 := te.Analyze(context.Background(), respFromBody("data= aGVsbG8gd29ybGQgZnJpZW5k"))
	for _, f := range fs3 {
		if strings.Contains(f.Name, "revealed by") {
			t.Errorf("non-secret base64 must not raise a buried finding: %+v", f)
		}
	}
}

// Unquoted `KEY=value` credentials (env/config/minified-JS style) are invisible
// to the quoted matchers; they must be caught, and placeholders rejected.
func TestUnquotedCredentialDetection(t *testing.T) {
	te := NewTokenExtractor()

	fs := te.Analyze(context.Background(), respFromBody(" DB_PASSWORD=S3cr3tP@ss \n"))
	if !hasFindingNamed(fs, "unquoted value") {
		t.Errorf("an unquoted password assignment should surface: %+v", fs)
	}

	// Placeholder / template values are not real credentials.
	fs2 := te.Analyze(context.Background(), respFromBody(" password = changeme ; password=${DB_PASS} "))
	for _, f := range fs2 {
		if strings.Contains(f.Name, "unquoted value") {
			t.Errorf("placeholder/template values must not be reported: %+v", f)
		}
	}
}

// Basic-Auth must be decoded to a usable user, with the password masked so no
// plaintext credential enters the report.
func TestBasicAuthDecodedAndMasked(t *testing.T) {
	te := NewTokenExtractor()

	body := "fetch(u,{headers:{Authorization:'Basic YWRtaW46UzNjcjN0UEBzcw=='}})" // admin:S3cr3tP@ss
	fs := te.Analyze(context.Background(), respFromBody(body))

	var decoded *int
	for i := range fs {
		if strings.Contains(fs[i].Name, "Basic Auth Credential (decoded)") {
			idx := i
			decoded = &idx
		}
	}
	if decoded == nil {
		t.Fatalf("a decodable Basic credential should be reported as decoded: %+v", fs)
	}
	f := fs[*decoded]
	if !strings.Contains(f.Evidence, "user: admin") {
		t.Errorf("the username should be shown so the operator can act: %q", f.Evidence)
	}
	if strings.Contains(f.Evidence, "S3cr3tP@ss") {
		t.Errorf("the password must be masked, not reproduced in plaintext: %q", f.Evidence)
	}
}

func hasFindingNamed(fs []types.Finding, sub string) bool {
	for _, f := range fs {
		if strings.Contains(f.Name, sub) {
			return true
		}
	}
	return false
}
