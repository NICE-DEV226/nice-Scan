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
		if strings.Contains(f.Name, "API Key") && strings.Contains(f.Evidence, "sk-live") {
			found = true
		}
	}
	if !found {
		t.Errorf("a real key=value must surface with the value as evidence: %+v", fs)
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
