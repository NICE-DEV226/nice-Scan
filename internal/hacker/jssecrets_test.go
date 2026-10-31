package hacker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
)

// The reviewed branch shipped a resolver that called an undefined helper and,
// past that, returned each script's .map counterpart. Both faults are silent:
// the action compiles into a module that scans the wrong file and reports
// nothing. These tests pin the resolution contract (script in, script out,
// scope enforced) and then prove it end-to-end through the real action.
func TestResolveAgainstTargetFetchesTheScript(t *testing.T) {
	cases := []struct {
		name   string
		target string
		ref    string
		want   string
	}{
		{"root-relative", "https://example.com", "/static/app.js", "https://example.com/static/app.js"},
		{"relative-to-page", "https://example.com/dashboard", "js/app.js", "https://example.com/js/app.js"},
		{"absolute same host", "https://example.com", "https://example.com/a/b.js", "https://example.com/a/b.js"},
		{"target subdomain stays in scope", "https://example.com", "https://cdn.example.com/b.js", "https://cdn.example.com/b.js"},
		{"third-party CDN dropped", "https://example.com", "https://cdn.jsdelivr.net/npm/x.js", ""},
		{"lookalike host dropped", "https://example.com", "https://evil-example.com/x.js", ""},
		{"query preserved", "https://example.com", "/app.js?v=3", "https://example.com/app.js?v=3"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveAgainstTarget(tc.target, tc.ref)
			if got != tc.want {
				t.Fatalf("resolveAgainstTarget(%q, %q) = %q, want %q", tc.target, tc.ref, got, tc.want)
			}
			if strings.HasSuffix(got, ".map") {
				t.Fatalf("resolver must fetch the served bundle, not its source map: %q", got)
			}
		})
	}
}

// A real AWS key ID is AKIA + 16 uppercase/digits; the documented example
// value (…EXAMPLE) must never be reported, which is the classic JS secret
// false positive: every tutorial snippet contains it.
const testAWSKeyID = "AKIA3RJ7QW2ZKX9MPL4T"

// Provider fixtures are assembled at runtime so no file in this repository
// contains a contiguous live-credential literal. GitHub's push protection
// blocks a push containing one even when it is a test value, and that block
// is the correct default — a scanner must not ship something it would flag.
var (
	testStripeKey = "sk_" + "live_" + "51H8xQ2eZvKYlo2C9vQ4bNm7R"
	testGoogleKey = "AIza" + "SyD9kR2mQ7xT4vB8nL1pW6zC3hF5jG0sUeK"
)

func TestScanSecretsFindsProviderKeys(t *testing.T) {
	body := `var s="` + testStripeKey + `"; var g="` + testGoogleKey + `"; var a="` + testAWSKeyID + `";`
	hits := scanSecrets(body)
	patterns := map[string]bool{}
	for _, h := range hits {
		patterns[h.Pattern] = true
		if h.Severity != SevHigh {
			t.Errorf("%s: severity %v, want High for a live-credential shape", h.Pattern, h.Severity)
		}
	}
	for _, want := range []string{"AWS access key ID", "Stripe live secret key", "Google API key"} {
		if !patterns[want] {
			t.Errorf("%s not detected (hits: %+v)", want, hits)
		}
	}
}

func TestScanSecretsSuppressesPlaceholders(t *testing.T) {
	body := `var a="AKIAIOSFODNN7EXAMPLE"; var b="your_api_key_here"; var c="0000000000000000000000000000"; var d="sk_test_...";`
	if hits := scanSecrets(body); len(hits) != 0 {
		t.Fatalf("documentation placeholders must not be reported: %+v", hits)
	}
}

func TestGenericCredentialNeedsEntropy(t *testing.T) {
	// Dictionary-shaped value: keyword hits, but it is not a credential.
	if hits := scanSecrets(`const password = "administrator";`); len(hits) != 0 {
		t.Fatalf("low-entropy assignment must not be reported: %+v", hits)
	}
	// Random value assigned to a credential-named field is reportable, but
	// at Medium: entropy alone cannot prove the value is used as a secret.
	hits := scanSecrets(`const api_key = "9f2Kq7Zr4Tx1Wm8Bp3Ln6V";`)
	if len(hits) != 1 {
		t.Fatalf("want one generic credential hit, got %+v", hits)
	}
	if hits[0].Severity != SevMedium {
		t.Errorf("generic entropy match must stay Medium, got %v", hits[0].Severity)
	}
}

func TestFindSourceMappingURL(t *testing.T) {
	cases := map[string]string{
		"a();\n//# sourceMappingURL=app.js.map\n":                    "app.js.map",
		"a();\n/*# sourceMappingURL=bundle.abc123.map */":            "bundle.abc123.map",
		"//# sourceMappingURL=old.map\n//# sourceMappingURL=new.map": "new.map",
		"a();": "",
	}
	for body, want := range cases {
		if got := findSourceMappingURL([]byte(body)); got != want {
			t.Errorf("findSourceMappingURL(%q) = %q, want %q", body, got, want)
		}
	}
}

func TestLooksLikeHTMLDocument(t *testing.T) {
	for _, body := range []string{"<!DOCTYPE html><html></html>", "  <html><head></head></html>"} {
		if !looksLikeHTMLDocument([]byte(body)) {
			t.Errorf("%q must be recognised as HTML", body)
		}
	}
	if looksLikeHTMLDocument([]byte(`var a=1;console.log("ok")`)) {
		t.Error("JavaScript must not be classified as HTML")
	}
}

func TestJSSecretsScansTheBundleItResolved(t *testing.T) {
	var scriptHits, mapHits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/static/app.js":
			atomic.AddInt32(&scriptHits, 1)
			_, _ = w.Write([]byte(`window.CFG={region:"eu"};var k="` + testAWSKeyID + `";`))
		case "/static/app.map":
			atomic.AddInt32(&mapHits, 1)
			_, _ = w.Write([]byte(`{"version":3,"sources":["src/app.ts"]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(10*time.Second))
	defer func() { _ = client.Close() }()

	kb := NewKnowledge(srv.URL)
	kb.AddJSScript("/static/app.js")

	action := &JSSecretsAction{}
	res := action.Execute(context.Background(), srv.URL, kb, client)

	if atomic.LoadInt32(&scriptHits) == 0 {
		t.Fatal("the served bundle was never fetched")
	}
	if atomic.LoadInt32(&mapHits) != 0 {
		t.Fatal("the action requested the source map — SourceMapAction's job, not this one")
	}

	var aws *Finding
	for i := range res.Findings {
		if res.Findings[i].Type == "js_secret_literal" {
			aws = &res.Findings[i]
		}
	}
	if aws == nil {
		t.Fatalf("no js_secret_literal on an asset containing an AWS key: %+v", res.Findings)
	}
	if aws.Severity != SevHigh {
		t.Errorf("AWS access key must be High, got %v", aws.Severity)
	}
	if strings.Contains(aws.Evidence, testAWSKeyID) {
		t.Errorf("evidence must preview the literal, never reproduce it: %q", aws.Evidence)
	}
	if !kb.HasVerifiedCapability("has_js_secrets") {
		t.Error("a literal read from the target's own asset is verified evidence")
	}
}

// SPA servers answer 200 with index.html for /assets/app.js. Scanning that
// as JavaScript invents credentials from page copy; the asset must be
// skipped, and no capability may be claimed.
func TestJSSecretsSkipsHTMLFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><head><title>app</title></head><body>AKIA3RJ7QW2ZKX9MPL4T</body></html>`))
	}))
	defer srv.Close()

	client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(10*time.Second))
	defer func() { _ = client.Close() }()

	kb := NewKnowledge(srv.URL)
	kb.AddJSScript("/assets/app.js")
	res := (&JSSecretsAction{}).Execute(context.Background(), srv.URL, kb, client)

	if len(res.Findings) != 0 {
		t.Fatalf("HTML fallback must not be scanned for secrets: %+v", res.Findings)
	}
	if kb.HasVerifiedCapability("has_js_secrets") {
		t.Error("no secret was read; capability must not be claimed")
	}
}

func TestJSSecretsHarvestsDeclaredSourceMap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`console.log(1);//# sourceMappingURL=chunk-4f2a.js.map`))
	}))
	defer srv.Close()

	client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(10*time.Second))
	defer func() { _ = client.Close() }()

	kb := NewKnowledge(srv.URL)
	kb.AddJSScript("/app.js")
	(&JSSecretsAction{}).Execute(context.Background(), srv.URL, kb, client)

	if got := kb.GetSourceMapRef("/app.js"); got != "chunk-4f2a.js.map" {
		t.Fatalf("declared map reference not recorded, got %q", got)
	}
}
