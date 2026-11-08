package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// The scope boundary: what a caller may be pointed at, as opposed to what may
// carry the operator's credentials (credentials_test.go).

// asLocalhost rewrites a loopback test-server URL to the name "localhost",
// so two httptest servers can be distinct hosts for the scope rule while
// staying on loopback (the scope matches hostnames, and ports are stripped).
func asLocalhost(srvURL string) string {
	return strings.Replace(srvURL, "127.0.0.1", "localhost", 1)
}

func countingServer(seen *bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = true
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "hit")
	}))
}

func TestDoRefusesHostOutsideScope(t *testing.T) {
	insideSeen, outsideSeen := false, false
	inside := countingServer(&insideSeen)
	defer inside.Close()
	outside := countingServer(&outsideSeen)
	defer outside.Close()

	client := NewClient(WithTargetScope(asLocalhost(inside.URL)))
	defer func() { _ = client.Close() }()

	_, err := client.Do(context.Background(), &types.Request{Method: "GET", URL: outside.URL + "/probe"})
	if !errors.Is(err, types.ErrOutOfScope) {
		t.Fatalf("want ErrOutOfScope, got %v", err)
	}
	if outsideSeen {
		t.Fatal("the refused request still reached the out-of-scope host")
	}

	if _, err := client.Do(context.Background(), &types.Request{Method: "GET", URL: asLocalhost(inside.URL) + "/probe"}); err != nil {
		t.Fatalf("in-scope request failed: %v", err)
	}
	if !insideSeen {
		t.Fatal("the in-scope request never reached the target")
	}
}

// TestUnscopedClientKeepsLegacyDestinations pins the fail-open default:
// interactive sessions build a client before a target is known, and turning
// enforcement on without a scope would refuse all of their traffic.
func TestUnscopedClientKeepsLegacyDestinations(t *testing.T) {
	seen := false
	srv := countingServer(&seen)
	defer srv.Close()

	client := NewClient()
	defer func() { _ = client.Close() }()

	if _, err := client.Do(context.Background(), &types.Request{Method: "GET", URL: srv.URL}); err != nil {
		t.Fatalf("unscoped client must still reach any host: %v", err)
	}
	if !seen {
		t.Fatal("handler never hit")
	}
}

func TestScopeRequiresDotBoundary(t *testing.T) {
	client := NewClient(WithTargetScope("https://example.com/"))
	defer func() { _ = client.Close() }()

	cases := []struct {
		url  string
		want bool
	}{
		{"http://example.com/", true},
		{"http://app.example.com/x", true},
		{"http://deep.sub.example.com:8443/x", true},
		// A suffix without the dot is a different registrable host, not a
		// subdomain: this is the exact shape of a scope-bypassing hostname.
		{"http://evilexample.com/", false},
		{"http://notexample.com/", false},
		{"http://example.com.evil.net/", false},
		{"http://127.0.0.1/", false},
		{"not a url at all", false},
	}
	for _, tc := range cases {
		if got := client.scopeAllows(tc.url); got != tc.want {
			t.Errorf("scopeAllows(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

func TestIPLiteralScopeIsExact(t *testing.T) {
	client := NewClient(WithTargetScope("http://10.0.0.5:8080"))
	defer func() { _ = client.Close() }()

	if !client.scopeAllows("http://10.0.0.5/api") {
		t.Error("the literal host itself must be in scope")
	}
	// The suffix rule must not turn an IP range into a wildcard.
	if client.scopeAllows("http://10.0.0.55/") {
		t.Error("10.0.0.55 is not under 10.0.0.5")
	}
	if client.scopeAllows("http://localhost/") {
		t.Error("a name is not the scoped IP")
	}
}

func TestAdmitFailsClosedOnUnparseableURL(t *testing.T) {
	client := NewClient(WithTargetScope("example.com"))
	defer func() { _ = client.Close() }()

	if err := client.admit("http://ex ample/"); err == nil {
		t.Error("an unparseable URL must not be admitted")
	}
	if err := client.admit(""); err == nil {
		t.Error("an empty URL must not be admitted")
	}
	// With no scope configured there is no boundary to enforce.
	unscoped := NewClient()
	defer func() { _ = unscoped.Close() }()
	if err := unscoped.admit("http://anywhere/"); err != nil {
		t.Errorf("unscoped admit must be inert: %v", err)
	}
}

func TestDoBatchReportsOutOfScopeAndClosesChannel(t *testing.T) {
	seen := false
	srv := countingServer(&seen)
	defer srv.Close()

	client := NewClient(WithTargetScope("target.example"))
	defer func() { _ = client.Close() }()

	reqs := []*types.Request{
		{Method: "GET", URL: srv.URL + "/a"},
		{Method: "GET", URL: srv.URL + "/b"},
	}
	results := make(chan *types.Result, len(reqs))
	done := make(chan struct{})
	go func() {
		client.DoBatch(context.Background(), reqs, results, 2)
		close(done)
	}()

	var refused int
	timeout := time.After(10 * time.Second)
	for r := range results {
		if errors.Is(r.Error, types.ErrOutOfScope) && r.Response == nil {
			refused++
			continue
		}
		t.Fatalf("unexpected batch result: %+v", r)
	}
	select {
	case <-done:
	case <-timeout:
		t.Fatal("DoBatch did not close the results channel")
	}
	if refused != len(reqs) {
		t.Fatalf("refused %d of %d requests", refused, len(reqs))
	}
	if seen {
		t.Fatal("the batch still touched the out-of-scope host")
	}
}

func TestRedirectLeavingScopeAborts(t *testing.T) {
	outsideSeen := false
	outside := countingServer(&outsideSeen)
	defer outside.Close()

	inside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, outside.URL+"/landed", http.StatusFound)
	}))
	defer inside.Close()

	client := NewClient(WithTargetScope(asLocalhost(inside.URL)), WithFollowRedirects(true))
	defer func() { _ = client.Close() }()

	_, err := client.Do(context.Background(), &types.Request{Method: "GET", URL: asLocalhost(inside.URL) + "/start"})
	if !errors.Is(err, types.ErrOutOfScope) {
		t.Fatalf("want ErrOutOfScope from the redirect, got %v", err)
	}
	if !strings.Contains(err.Error(), "leaves the target scope") {
		t.Errorf("the error must name the redirect as the leaver: %v", err)
	}
	if outsideSeen {
		t.Fatal("the redirect still delivered the request to the third-party host")
	}
}

// A redirect inside the target is the ordinary case (http→https, /→/index).
// Refusing it would break every real scan.
func TestSameHostRedirectStillFollowedUnderEnforcement(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/next", http.StatusFound)
		default:
			path = r.URL.Path
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	client := NewClient(WithTargetScope(asLocalhost(srv.URL)), WithFollowRedirects(true))
	defer func() { _ = client.Close() }()

	resp, err := client.Do(context.Background(), &types.Request{Method: "GET", URL: asLocalhost(srv.URL) + "/start"})
	if err != nil {
		t.Fatalf("same-host redirect refused: %v", err)
	}
	if resp == nil || resp.FinalURL == "" {
		t.Fatalf("no response: %+v", resp)
	}
	if path != "/next" {
		t.Errorf("want the redirect followed, landed on %q", path)
	}
}

func TestCredScopeFollowsTargetScope(t *testing.T) {
	// WithTargetScope fills the credential scope when nothing else did, so
	// the two lists cannot drift into "requests go here, secrets go
	// everywhere".
	client := NewClient(WithTargetScope("example.com"), WithCookie("sessionid=SECRET"))
	defer func() { _ = client.Close() }()

	if !client.credsAllowedFor("https://app.example.com/") {
		t.Error("in-scope credentials must still attach")
	}
	if client.credsAllowedFor("https://evil.com/") {
		t.Error("credentials must not ride outside the target scope")
	}
}

func TestIPBlocked(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"10.1.2.3", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"172.32.0.1", false}, // just outside RFC1918
		{"192.168.1.1", true},
		{"169.254.169.254", true}, // cloud metadata
		{"169.254.1.1", true},
		{"100.64.0.1", true}, // CGNAT
		{"100.127.255.255", true},
		{"100.128.0.0", false},
		{"0.0.0.0", true},
		{"198.18.0.1", true}, // benchmarking
		{"fc00::1", true},
		{"fe80::1", true},
		{"::ffff:169.254.169.254", true}, // v4-mapped metadata
		{"::ffff:127.0.0.1", true},
		{"224.0.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"93.184.216.34", false},
		{"2001:4860:4860::8888", false},
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("bad test IP %q", tc.ip)
		}
		if got := ipBlocked(ip); got != tc.want {
			t.Errorf("ipBlocked(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestRouteAddressesDialsOnlyVettedAnswers(t *testing.T) {
	ips := []net.IPAddr{
		{IP: net.ParseIP("169.254.169.254")},
		{IP: net.ParseIP("93.184.216.34")},
	}
	got, err := routeAddresses("target.example", "443", ips)
	if err != nil {
		t.Fatalf("a public answer must stay dialable: %v", err)
	}
	if len(got) != 1 || got[0] != "93.184.216.34:443" {
		t.Fatalf("want only the vetted literal, got %v", got)
	}

	// Every answer internal: refuse, naming the address that was rejected.
	_, err = routeAddresses("target.example", "80", []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}})
	if !errors.Is(err, types.ErrInternalTarget) {
		t.Fatalf("want ErrInternalTarget, got %v", err)
	}
	if !strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("the refusal must name the address: %v", err)
	}

	if _, err := routeAddresses("target.example", "80", nil); err == nil {
		t.Error("an empty answer set must not produce a dial plan")
	}
}

func TestGuardRefusesLoopbackByNameBeforeDialing(t *testing.T) {
	seen := false
	srv := countingServer(&seen)
	defer srv.Close()

	client := NewClient(WithPrivateNetworkAllowed(false))
	defer func() { _ = client.Close() }()

	_, err := client.Do(context.Background(), &types.Request{
		Method:  "GET",
		URL:     srv.URL,
		Timeout: 5 * time.Second,
	})
	if !errors.Is(err, types.ErrInternalTarget) {
		t.Fatalf("want ErrInternalTarget from the dial guard, got %v", err)
	}
	if seen {
		t.Fatal("the guarded dial still reached the listener")
	}
}

// A scanner legitimately targets its own dev server, so loopback stays
// dialable unless the operator opts into the guard.
func TestLoopbackAllowedByDefault(t *testing.T) {
	seen := false
	srv := countingServer(&seen)
	defer srv.Close()

	client := NewClient()
	defer func() { _ = client.Close() }()

	if _, err := client.Do(context.Background(), &types.Request{Method: "GET", URL: srv.URL}); err != nil {
		t.Fatalf("default options must still reach loopback: %v", err)
	}
	if !seen {
		t.Fatal("handler never hit")
	}
}

func TestGuardSurfacesResolveFailure(t *testing.T) {
	res := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, fmt.Errorf("no dns in the test environment")
		},
	}
	client := NewClient(WithPrivateNetworkAllowed(false), withResolver(res))
	defer func() { _ = client.Close() }()

	_, err := client.Do(context.Background(), &types.Request{Method: "GET", URL: "http://name-that-cannot-resolve.example/"})
	if err == nil || !strings.Contains(err.Error(), "guard: resolve") {
		t.Fatalf("want the resolve failure attributed to the guard, got %v", err)
	}
}

// The interactive shell re-arms the destination boundary per command through
// SetTargetScope: an in-scope host must pass and an out-of-scope host must be
// refused, and clearing the scope must restore fail-open behavior for callers
// that opted out of enforcement.
func TestSetTargetScopeRuntime(t *testing.T) {
	allowed := false
	// Two httptest servers share the 127.0.0.1 host; rewriting one to the
	// "localhost" name makes them distinct hosts for the scope rule, the
	// same trick the redirect tests use.
	srvIn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { allowed = true }))
	defer srvIn.Close()
	srvOut := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srvOut.Close()
	inURL := asLocalhost(srvIn.URL)

	client := NewClient()
	defer func() { _ = client.Close() }()

	// Before any scope is set the out-of-scope host is reachable.
	if _, err := client.Do(context.Background(), &types.Request{Method: "GET", URL: srvOut.URL}); err != nil {
		t.Fatalf("unscoped client should reach srvOut: %v", err)
	}

	client.SetTargetScope(HostDomain(inURL))

	if _, err := client.Do(context.Background(), &types.Request{Method: "GET", URL: inURL}); err != nil {
		t.Fatalf("in-scope host refused: %v", err)
	}
	if !allowed {
		t.Fatal("handler never hit")
	}
	if _, err := client.Do(context.Background(), &types.Request{Method: "GET", URL: srvOut.URL}); err == nil {
		t.Fatal("out-of-scope host was not refused after SetTargetScope")
	}

	// Clearing restores the previous (unscoped) behavior.
	client.SetTargetScope()
	if _, err := client.Do(context.Background(), &types.Request{Method: "GET", URL: srvOut.URL}); err != nil {
		t.Fatalf("cleared scope should restore reachability: %v", err)
	}
}
