package transport

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// Phase 2 — credential scoping and redirect replay regressions.

func TestCookieNotReplayedOnCrossHostRedirect(t *testing.T) {
	cookieSeenCrossHost := ""

	// B: cross-origin (different port = different origin) final target.
	targetB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("sessionid"); err == nil && c != nil {
			cookieSeenCrossHost = c.Value
		}
		w.WriteHeader(200)
	}))
	defer targetB.Close()

	// A: redirects to B with a 302.
	targetA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetB.URL+"/next", http.StatusFound)
	}))
	defer targetA.Close()

	client := NewClient(WithCookie("sessionid=SECRET; Path=/"), WithFollowRedirects(true))
	defer func() { _ = client.Close() }()

	resp, err := client.Do(context.Background(), &types.Request{
		Method: "GET",
		URL:    targetA.URL + "/start",
	})
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_ = resp

	if cookieSeenCrossHost != "" {
		t.Errorf("operator cookie was replayed to a cross-origin redirect target: %q", cookieSeenCrossHost)
	}
}

func TestCookieKeptOnSameHostRedirect(t *testing.T) {
	cookieSeen := ""

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/next", http.StatusFound)
		case "/next":
			if c, err := r.Cookie("sessionid"); err == nil && c != nil {
				cookieSeen = c.Value
			}
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()

	client := NewClient(WithCookie("sessionid=SECRET; Path=/"), WithFollowRedirects(true))
	defer func() { _ = client.Close() }()

	_, err := client.Do(context.Background(), &types.Request{
		Method: "GET",
		URL:    srv.URL + "/start",
	})
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	if cookieSeen != "SECRET" {
		t.Errorf("same-host redirect must keep the operator cookie, got %q", cookieSeen)
	}
}

type scopeServerSuite struct {
	cookieSeen string
	srv        *httptest.Server
}

func newScopeServer(t *testing.T) *scopeServerSuite {
	t.Helper()

	s := &scopeServerSuite{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("sessionid"); err == nil {
			s.cookieSeen = c.Value
		}
		w.WriteHeader(200)
	}))
	return s
}

func TestCredScopeBlocksOutOfScopeHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Deterministic out-of-scope check: a loopback server whose URL the
	// operator explicitly did NOT scope must not receive the cookie.
	srv := newScopeServer(t)
	defer srv.srv.Close()

	client := NewClient(WithCookie("sessionid=SECRET"))
	defer func() { _ = client.Close() }()
	client.SetCredScope("example.com")

	_, err := client.Do(ctx, &types.Request{Method: "GET", URL: srv.srv.URL + "/x"})
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if srv.cookieSeen != "" {
		t.Errorf("cookie attached to out-of-scope host: %q", srv.cookieSeen)
	}

	// In-scope check: same host, but scoped to it → cookie must flow.
	srv2 := newScopeServer(t)
	defer srv2.srv.Close()
	host := HostDomain(srv2.srv.URL)
	client2 := NewClient(WithCookie("sessionid=SECRET"), WithCredScope([]string{host}))
	defer func() { _ = client2.Close() }()
	_, err = client2.Do(ctx, &types.Request{Method: "GET", URL: srv2.srv.URL + "/y"})
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if srv2.cookieSeen != "SECRET" {
		t.Errorf("in-scope host must receive the operator cookie, got %q", srv2.cookieSeen)
	}
}

func TestHostDomain(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"https://example.com/a", "example.com"},
		{"http://sub.Domain.COM:8080/x", "sub.domain.com"},
		{"example.com", "example.com"},
		{"", ""},
		{"https://example.com:443/foo", "example.com"},
	}
	for _, c := range cases {
		if got := HostDomain(c.in); got != c.want {
			t.Errorf("HostDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestProxyURLShapes(t *testing.T) {
	accept := []string{"http://127.0.0.1:8080", "https://p.example:8080", "socks5://p:1080"}
	reject := []string{"file:///etc/passwd", "://bad", "burp://1.2.3.4", ""}

	for _, u := range accept {
		if err := proxyShapeErr(u); err != nil {
			t.Errorf("proxy %q should be accepted, got %v", u, err)
		}
	}
	for _, u := range reject {
		if err := proxyShapeErr(u); err == nil {
			t.Errorf("proxy %q should be rejected", u)
		}
	}
}

// proxyShapeErr mirrors the validation logic in cmd validateProxy: parse,
// scheme allowlist, host presence.
func proxyShapeErr(proxy string) error {
	parsed, err := url.Parse(proxy)
	if err != nil {
		return err
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "socks5":
	default:
		return fmt.Errorf("unsupported proxy scheme %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("missing proxy host")
	}
	return nil
}

// Scope names hosts, not channels: an in-scope redirect that changes the
// port (a different service behind the same name) or the scheme (https →
// http downgrade) must not receive operator credentials.
func TestScopedCredsNotReplayedOnPortChangeRedirect(t *testing.T) {
	cookieSeen := ""
	targetB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("sessionid"); err == nil {
			cookieSeen = c.Value
		}
		w.WriteHeader(200)
	}))
	defer targetB.Close()

	targetA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetB.URL+"/next", http.StatusFound)
	}))
	defer targetA.Close()

	client := NewClient(WithCookie("sessionid=SECRET"), WithFollowRedirects(true))
	defer func() { _ = client.Close() }()
	// Both test servers live on 127.0.0.1: the hostname scope matches the
	// redirect destination — only the channel rule may stop the replay.
	client.SetCredScope("127.0.0.1")

	if _, err := client.Do(context.Background(), &types.Request{Method: "GET", URL: targetA.URL + "/start"}); err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if cookieSeen != "" {
		t.Errorf("operator cookie rode an in-scope redirect across ports: %q", cookieSeen)
	}
}

func TestSameChannelRules(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"https://app.example.com", "http://app.example.com", false}, // downgrade
		{"https://app.example.com", "https://app.example.com:8443", false},
		{"https://app.example.com", "https://app.example.com:443", true}, // default port
		{"https://app.example.com:443", "https://cdn.example.com", true}, // port+scheme ok, host checked by scope
		{"http://app.example.com", "http://app.example.com", true},
	}
	for _, c := range cases {
		u1, _ := url.Parse(c.a)
		u2, _ := url.Parse(c.b)
		if got := sameChannel(u1, u2); got != c.want {
			t.Errorf("sameChannel(%s, %s) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// The session store is origin-strict, not host-strict: a cookie captured
// on :8443 must never replay to :443 behind the same name.
func TestCookieStoreKeyedPerOriginPort(t *testing.T) {
	cs := newCookieStore()
	cs.capture("https://example.com:8443/login", []*http.Cookie{cookieOf("sid", "S1")})

	if hdr := cs.cookieHeader("https://example.com/x"); strings.Contains(hdr, "sid") {
		t.Error("cookie captured on :8443 replayed to default-https :443")
	}
	if hdr := cs.cookieHeader("https://example.com:8443/other"); hdr != "sid=S1" {
		t.Errorf("same origin must replay, got %q", hdr)
	}
}
