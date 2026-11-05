package engine

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// The API-token regex once matched the BARE label "api_key" (the ":= value"
// clause bound only to the last alternation), so any page mentioning
// api_key/api-token as a word raised a CRITICAL "API Key Leaked" whose
// "evidence" was the label itself. A leak requires a value bound to the label.

func respFromBody(body string) *types.Response {
	return &types.Response{
		StatusCode: 200,
		Headers:    http.Header{},
		Body:       []byte(body),
		FinalURL:   "https://example.com/",
		RequestURL: "https://example.com/",
	}
}

func TestAPITokenLabelWithoutValueIsNotLeak(t *testing.T) {
	te := NewTokenExtractor()
	fs := te.Analyze(context.Background(), respFromBody(
		`var api_key; // documented parameter name api_token here`))
	for _, f := range fs {
		if strings.Contains(f.Name, "API Key") {
			t.Errorf("bare keyword without a value must not be a leak: %+v", f)
		}
	}
}

func TestAPITokenWithValueIsLeak(t *testing.T) {
	te := NewTokenExtractor()
	fs := te.Analyze(context.Background(), respFromBody(
		`{"api_key": "sk-live-a1b2c3d4e5f6g7h8"}`))
	var found bool
	for _, f := range fs {
		if !strings.Contains(f.Name, "API Key") {
			continue
		}
		// The report must keep the shape that identifies the secret (the sk-l
		// provider prefix, the length) and drop the value: the first 30
		// characters of a key are the beginning of a live key.
		if strings.Contains(f.Evidence, "sk-l") &&
			!strings.Contains(f.Evidence, "a1b2c3d4e5f6g7h8") {
			found = true
		}
	}
	if !found {
		t.Errorf("a real key=value must surface with a redacted value as evidence: %+v", fs)
	}
}

func TestCookieAttrSetTokenizesAttributes(t *testing.T) {
	cases := []struct {
		setCookie    string
		wantSecure   bool
		wantHttpOnly bool
		wantSameSite bool
	}{
		{"sid=abc; Secure; HttpOnly; SameSite=Lax", true, true, true},
		{"sid=abc;secure", true, false, false},            // no space after ";"
		{"__Secure-id=abc; HttpOnly", false, true, false}, // name contains "secure", attribute does not
		{"sid=abc", false, false, false},
	}
	for _, c := range cases {
		set := cookieAttrSet(c.setCookie)
		if set["secure"] != c.wantSecure {
			t.Errorf("%q secure=%v want %v", c.setCookie, set["secure"], c.wantSecure)
		}
		if set["httponly"] != c.wantHttpOnly {
			t.Errorf("%q httponly=%v want %v", c.setCookie, set["httponly"], c.wantHttpOnly)
		}
		if set["samesite"] != c.wantSameSite {
			t.Errorf("%q samesite=%v want %v", c.setCookie, set["samesite"], c.wantSameSite)
		}
	}
}

func TestCookieShapeMasksValueAndKeepsAttributes(t *testing.T) {
	const live = "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8"
	shape := cookieShape("sid=" + live + "; Path=/; Secure; SameSite=Lax")
	if strings.Contains(shape, live) {
		t.Errorf("cookieShape leaked the session value: %q", shape)
	}
	for _, fact := range []string{"sid=", "Path=/", "Secure", "SameSite=Lax"} {
		if !strings.Contains(shape, fact) {
			t.Errorf("cookieShape dropped %q — the attributes are the actionable half: %q", fact, shape)
		}
	}
}

// The flag findings are the reason the shape exists: they must state which
// attributes the header carries without carrying a live session token.
func TestCookieFlagFindingsKeepAttributesWithoutTheValue(t *testing.T) {
	const live = "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8"
	resp := respFromBody("")
	resp.Headers = http.Header{"Set-Cookie": []string{"sid=" + live + "; Path=/; SameSite=Lax"}}
	te := NewTokenExtractor()
	fs := te.Analyze(context.Background(), resp)

	var shape string
	var flags int
	for _, f := range fs {
		if r, ok := f.Metadata["raw"]; ok {
			shape = r
		}
		if strings.Contains(f.Name, "Missing Secure") || strings.Contains(f.Name, "Missing HttpOnly") {
			flags++
			if strings.Contains(f.Evidence, live) {
				t.Errorf("%s shipped the live cookie value: %q", f.Name, f.Evidence)
			}
			if !strings.Contains(f.Evidence, "SameSite=Lax") {
				t.Errorf("%s dropped the attributes a triager needs: %q", f.Name, f.Evidence)
			}
		}
	}
	if flags != 2 {
		t.Fatalf("flag findings = %d, want the Secure and HttpOnly pair", flags)
	}
	if shape == "" {
		t.Fatal("a session cookie finding must record the header shape")
	}
	if strings.Contains(shape, live) {
		t.Errorf("metadata.raw shipped the live session value: %q", shape)
	}
	if !strings.Contains(shape, "Path=/") {
		t.Errorf("metadata.raw = %q, want the attributes kept", shape)
	}
}
