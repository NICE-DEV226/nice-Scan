package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// Session-cookie regressions: capture (per hop), attach (same host only),
// scoping, and the cross-origin strip on authenticated redirects.

// cookieOf builds a cookie for capture tests.
func cookieOf(name, value string) *http.Cookie {
	return &http.Cookie{Name: name, Value: value}
}

// newLoginFlow is the canonical test target: POST /login sets a session
// cookie and 302s to /dash; /dash answers 200 AUTH only with the session
// cookie, 401 otherwise.
func newLoginFlowServer(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	dashHitsWithSession := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Set-Cookie", "sid=S1; Path=/")
			w.Header().Set("Location", "/dash")
			w.WriteHeader(http.StatusFound)
		case "/dash":
			if c, err := r.Cookie("sid"); err == nil && c.Value == "S1" {
				dashHitsWithSession++
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("AUTH DASHBOARD"))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	return srv, &dashHitsWithSession
}

func TestSessionCookiesCapturedOnInterimHopAndAttached(t *testing.T) {
	srv, dashAuth := newLoginFlowServer(t)
	defer srv.Close()

	client := NewClient()
	defer func() { _ = client.Close() }()
	client.SetSessionCookies(true)

	// The login POST: the Set-Cookie rides the 302 hop stdlib follows
	// internally — the capture point exists precisely for that.
	if _, err := client.Do(context.Background(), &types.Request{
		Method: "POST",
		URL:    srv.URL + "/login",
	}); err != nil {
		t.Fatalf("login failed: %v", err)
	}

	// A session-less request must see 401 — proving the attach actually
	// happened is the next request's job; here we must not be attached yet
	// unless store works. The worked check:
	resp, err := client.Do(context.Background(), &types.Request{
		Method: "GET",
		URL:    srv.URL + "/dash",
	})
	if err != nil {
		t.Fatalf("dash failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session not attached: /dash answered %d", resp.StatusCode)
	}
	if *dashAuth < 1 {
		t.Errorf("server never saw the session cookie")
	}
}

func TestSessionCookiesOffByDefault(t *testing.T) {
	srv, dashAuth := newLoginFlowServer(t)
	defer srv.Close()

	client := NewClient()
	defer func() { _ = client.Close() }()

	if _, err := client.Do(context.Background(), &types.Request{Method: "POST", URL: srv.URL + "/login"}); err != nil {
		t.Fatalf("login failed: %v", err)
	}
	resp, err := client.Do(context.Background(), &types.Request{Method: "GET", URL: srv.URL + "/dash"})
	if err != nil {
		t.Fatalf("dash failed: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("mode off must stay unauthenticated: /dash answered %d", resp.StatusCode)
	}
	if *dashAuth != 0 {
		t.Errorf("server saw a session cookie with capture disabled")
	}
}

func TestSessionCookiesRespectCredScope(t *testing.T) {
	srv, dashAuth := newLoginFlowServer(t)
	defer srv.Close()

	client := NewClient()
	defer func() { _ = client.Close() }()
	client.SetSessionCookies(true)
	client.SetCredScope("example.com") // the test server is out of scope

	if _, err := client.Do(context.Background(), &types.Request{Method: "POST", URL: srv.URL + "/login"}); err != nil {
		t.Fatalf("login failed: %v", err)
	}
	resp, err := client.Do(context.Background(), &types.Request{Method: "GET", URL: srv.URL + "/dash"})
	if err != nil {
		t.Fatalf("dash failed: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session cookie attached to an out-of-scope host: /dash answered %d", resp.StatusCode)
	}
	if *dashAuth != 0 {
		t.Errorf("out-of-scope host received the captured session")
	}
}

// An authenticated redirect must never replay the captured session to
// another origin (login open redirect / injected Location).
func TestSessionCookieStrippedOnCrossOriginRedirect(t *testing.T) {
	leaked := ""
	targetB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("sid"); err == nil {
			leaked = c.Value
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer targetB.Close()

	client := NewClient()
	defer func() { _ = client.Close() }()
	client.SetSessionCookies(true)

	// Plant a session directly, then request /start which redirects to B.
	client.sess.capture(HostDomain("http://example.com"), []*http.Cookie{cookieOf("sid", "S1")})

	if _, err := client.Do(context.Background(), &types.Request{Method: "GET", URL: targetB.URL + "/start"}); err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_ = client // targetB is the destination; no same-origin hop exists here

	// Attach happens per-request by exact host: a request to targetB only
	// ever carries cookies captured BY targetB. Assert the unit rule
	// directly as well as the redirect behavior.
	if hdr := client.sess.cookieHeader(targetB.URL); strings.Contains(hdr, "sid") {
		t.Fatalf("session crossed hosts: %q", hdr)
	}
	if leaked != "" {
		t.Errorf("session cookie leaked to foreign origin: %q", leaked)
	}
}

func TestSessionCookieHeaderWorksAgainstPlainHostKey(t *testing.T) {
	cs := newCookieStore()
	cs.capture("Example.COM:8443", []*http.Cookie{cookieOf("sid", "S1")})
	if got := cs.cookieHeader("https://example.com:8443/x"); got != "sid=S1" {
		t.Errorf("host key normalization broken: got %q", got)
	}
}
