package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/fingerprint"
	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// catchAllShell is served BYTE-IDENTICAL for every unknown path — a real
// client-side-routing SPA, exactly what produces the self-probe false positives
// (a 200 on /graphql, /wp-admin, /admin/login is just the index.html again). It
// also carries admin/dashboard words to bait the auth analyzer, and a password
// form is deliberately ABSENT from the shell.
var catchAllShell = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">` +
	`<title>App</title></head><body><div id="root"></div>` +
	`<p>admin dashboard panel backend manager area</p>` +
	`<script src="/static/js/main.js"></script>` +
	`</body></html>` + strings.Repeat("pad-pad-pad-pad ", 160)

var realLoginPage = `<!DOCTYPE html><html><head><title>Sign in</title></head><body>` +
	`<form action="/login"><input name="username" type="text">` +
	`<input name="password" type="password"><button>Login</button></form>` +
	`</body></html>` + strings.Repeat("x", 500)

// TestSPACatchAllDoesNotFingerprintOrSurfaceAdmin is the regression for the
// self-probe FP class: on an SPA that answers every path with the identical
// index shell, the scanner must NOT report a technology or an admin surface
// merely because IT requested /graphql or /wp-admin. It must still report a
// genuine, distinct page (/login's real form) — proving the suppression is a
// byte-identity gate, not a blanket mute.
func TestSPACatchAllDoesNotFingerprintOrSurfaceAdmin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/login" {
			_, _ = w.Write([]byte(realLoginPage))
			return
		}
		_, _ = w.Write([]byte(catchAllShell)) // identical for /, /graphql, /wp-admin, ...
	}))
	defer srv.Close()

	client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(5*time.Second))
	defer func() { _ = client.Close() }()

	scanner := NewScanner(&types.Config{Workers: 4, Timeout: 5 * time.Second, FollowRedirects: true}, client)
	scanner.RegisterAnalyzers(fingerprint.New(), NewAuthAnalyzer())
	res := scanner.Scan(context.Background(), []string{srv.URL})

	names := map[string]int{}
	for _, f := range res.Findings {
		names[f.Name]++
	}

	if names["GraphQL"] > 0 {
		t.Errorf("self-probed /graphql fingerprinted as a technology (soft-404 FP): %+v", res.Findings)
	}
	for _, f := range res.Findings {
		if strings.Contains(f.Name, "Admin") && strings.Count(f.Evidence, "URL:") > 1 {
			t.Errorf("admin finding carries a multi-URL evidence wall instead of one page: name=%q evidence=%q", f.Name, f.Evidence)
		}
	}

	if names["Login Form Detected"] == 0 {
		t.Error("the distinct real /login page must still be analyzed and its login form reported (suppression must not be blanket)")
	}

	// Provenance has to tell the two halves of the soft-404 comparison apart:
	// the paths that only echoed the shell must name the shell signature they
	// matched and be graded as showing nothing, and the login page — which
	// differed from that same shell — must be graded on the differential it
	// actually passed, not on the analyzer's own optimism.
	for _, f := range res.Findings {
		if f.Prov == nil {
			t.Errorf("engine-stamped finding %q reached the report with no provenance", f.Name)
			continue
		}
		if strings.HasSuffix(f.Prov.RequestURL, "/graphql") {
			t.Errorf("a path that only echoed the shell was still reported: %+v", f)
		}
		if f.Name == "Login Form Detected" {
			if f.Prov.BaselineRef == "" {
				t.Error("the login finding must name the shell signature it differed from")
			}
			if got := types.GradeOf(f); got != types.GradeIndicated {
				t.Errorf("login grade = %q, want indicated: a distinct page is a signal, not a proof", got)
			}
			if f.Prov.PathOrigin != types.PathSynthesized {
				t.Errorf("path origin = %q, want synthesized: /login came off the scanner's wordlist", f.Prov.PathOrigin)
			}
		}
	}
}

func TestResponseSigDistinguishesBodies(t *testing.T) {
	base := &types.Response{StatusCode: 200, ContentType: "text/html", Body: []byte("hello")}
	same := &types.Response{StatusCode: 200, ContentType: "text/html", Body: []byte("hello")}
	if ResponseSig(base) != ResponseSig(same) {
		t.Error("identical status+ctype+body must share a signature")
	}
	diffBody := &types.Response{StatusCode: 200, ContentType: "text/html", Body: []byte("hellO")}
	if ResponseSig(base) == ResponseSig(diffBody) {
		t.Error("a different body must change the signature")
	}
	diffStatus := &types.Response{StatusCode: 301, ContentType: "text/html", Body: []byte("hello")}
	if ResponseSig(base) == ResponseSig(diffStatus) {
		t.Error("a different status must change the signature")
	}
	diffType := &types.Response{StatusCode: 200, ContentType: "application/json", Body: []byte("hello")}
	if ResponseSig(base) == ResponseSig(diffType) {
		t.Error("a different content-type must change the signature")
	}
}

func TestUnderBaseBoundary(t *testing.T) {
	cases := []struct {
		u, base string
		want    bool
	}{
		{"http://a.com/graphql", "http://a.com", true},
		{"http://a.com", "http://a.com", true},
		{"http://a.com/?x=1", "http://a.com", true},
		{"http://a.com.evil.com/", "http://a.com", false}, // must not smuggle a foreign host
		{"http://other/", "http://a.com", false},
		{"http://a.com", "", false},
	}
	for _, c := range cases {
		if got := underBase(c.u, c.base); got != c.want {
			t.Errorf("underBase(%q,%q)=%v want %v", c.u, c.base, got, c.want)
		}
	}
}

func TestOwnerSigLongestMatch(t *testing.T) {
	bs := baselineSet{
		homepage: map[string]bool{"http://a.com": true},
		bases: []baseEntry{
			{"http://a.com", "SIG_HOME"},
			{"http://a.com/app", "SIG_APP"},
		},
	}
	// /app/... must resolve to the more specific base.
	if sig, ok := bs.ownerSig(&types.Request{URL: "http://a.com/app/x"}); !ok || sig != "SIG_APP" {
		t.Errorf("longest-prefix owner: got (%q,%v) want (SIG_APP,true)", sig, ok)
	}
	if sig, ok := bs.ownerSig(&types.Request{URL: "http://a.com/graphql"}); !ok || sig != "SIG_HOME" {
		t.Errorf("fallback owner: got (%q,%v) want (SIG_HOME,true)", sig, ok)
	}
	if _, ok := bs.ownerSig(&types.Request{URL: "http://nope/"}); ok {
		t.Error("unowned request must report false")
	}
}

func TestIsHomepage(t *testing.T) {
	bs := baselineSet{homepage: map[string]bool{"http://a.com": true}, bases: []baseEntry{{"http://a.com", "S"}}}
	if !bs.isHomepage(&types.Request{URL: "http://a.com"}) {
		t.Error("the root GET is the homepage")
	}
	if bs.isHomepage(&types.Request{URL: "http://a.com/graphql"}) {
		t.Error("a probe path is not the homepage")
	}
	if !bs.isHomepage(nil) {
		t.Error("a request-less response cannot be attributed; must not be tagged")
	}
}
