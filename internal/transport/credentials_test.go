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

func requestCookieElse(r *http.Request) string {
	c, err := r.Cookie("sessionid")
	if err != nil {
		return ""
	}
	return c.Value
}

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
	defer client.Close()

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
	defer client.Close()

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
	defer client.Close()
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
	defer client2.Close()
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
