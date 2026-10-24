package hacker

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

func loginResp(status int, body, finalURL string, setCookies ...string) *types.Response {
	h := make(http.Header)
	for _, c := range setCookies {
		h.Add("Set-Cookie", c)
	}
	return &types.Response{
		StatusCode: status,
		Body:       []byte(body),
		Headers:    h,
		FinalURL:   finalURL,
	}
}

func baseFailedLogin() loginFingerprint {
	// What a failed login looks like on a following client (200 on /login).
	return fingerprintLogin(loginResp(200, "welcome to our shop", "http://shop.local/login"))
}

// The rewritten verdict is differential: a single response, however
// "successful-looking", can never claim a valid credential on its own.
func TestLoginVerdictRejectsStaticWelcomePageWithoutDelta(t *testing.T) {
	base := baseFailedLogin()
	// Same endpoint, identical shape, navbar carries "Logout", body carries
	// "Welcome" — the old word-matching returned true here.
	r := loginResp(200, "welcome to our shop — logout", "http://shop.local/login")
	if loginVerdict(r, base, true) {
		t.Fatal("static welcome/logout page without any delta must NOT validate credentials")
	}
	// Even a larger body with success words is not evidence.
	r = loginResp(200, strings.Repeat("x", 5000)+" welcome logout my account dashboard", "http://shop.local/login")
	if loginVerdict(r, base, true) {
		t.Fatal("word/size-only evidence must not validate credentials")
	}
}

func TestLoginVerdictAcceptsCookieDeltaOnStableChurn(t *testing.T) {
	base := baseFailedLogin()
	r := loginResp(200, "welcome to our shop", "http://shop.local/login", "session=sid123; Path=/")
	if !loginVerdict(r, base, true) {
		t.Fatal("new session cookie on the drained endpoint is a valid credential signal")
	}
	// Rotating-value endpoints: a junk baseline that ALSO holds the same
	// cookie names (rotating CSRF/session ids) makes value deltas
	// meaningless when the churn is untrusted; only a name-set change can
	// still signal.
	churnBase := fingerprintLogin(loginResp(200, "welcome to our shop",
		"http://shop.local/login", "csrf=stable; session=sid-A"))
	r = loginResp(200, "welcome to our shop", "http://shop.local/login", "csrf=random-2; session=sid-RANDOM")
	if loginVerdict(r, churnBase, false) {
		t.Fatal("cookie VALUE churn with unchanged names must not validate (rotating-cookie endpoints)")
	}
	// On a stable endpoint the value delta IS the session handoff.
	if !loginVerdict(r, churnBase, true) {
		t.Fatal("cookie value delta on trusted churn validates the credential")
	}
}

func TestLoginVerdictAcceptsFinalPathDelta(t *testing.T) {
	base := baseFailedLogin()
	r := loginResp(200, "no magic words here", "http://shop.local/dashboard", "session=sid123; Path=/")
	if !loginVerdict(r, base, true) {
		t.Fatal("final navigation to a non-login destination validates credentials")
	}
}

func TestLoginVerdictRejectsPRGFailureUnderFollowingClient(t *testing.T) {
	// POST → 302 → final page at /login?err=... (path /login, static text)
	base := fingerprintLogin(loginResp(200, "login page", "http://shop.local/login?err=1"))
	r := loginResp(200, "login page", "http://shop.local/login?err=2")
	if loginVerdict(r, base, true) {
		t.Fatal("PRG failure flow must not validate credentials")
	}
}

func TestLoginVerdictRejectsFailWordsEvenWithDeltas(t *testing.T) {
	base := baseFailedLogin()
	// A dashboard shell whose JS carries the literal word "failed" —
	// conservative false negative beats a false positive credential claim.
	r := loginResp(200, `{"msg":"request failed"} dashboard`, "http://shop.local/dashboard", "session=sid123")
	if loginVerdict(r, base, true) {
		t.Fatal("failure markers in the final body must veto every signal")
	}
}

func TestLoginVerdictRedirectModeNonFollowing(t *testing.T) {
	// followRedirects=false semantics: the 302 itself is the final hop.
	baseline := loginResp(302, "", "http://shop.local/login", "")
	h := make(http.Header)
	h.Set("Location", "/login?err=17")
	baseline.Headers = h
	base := fingerprintLogin(baseline)

	ok := loginResp(302, "", "http://shop.local/login", "")
	ok.Headers = h.Clone()
	ok.Headers.Set("Location", "/dashboard")

	if !loginVerdict(ok, base, true) {
		t.Fatal("same-host reroute to a non-failure destination validates the credential")
	}

	// Timestamped query on the SAME failure path — the old code compared
	// Locations verbatim; path-only comparison rejects it.
	same := loginResp(302, "", "http://shop.local/login", "")
	same.Headers = h.Clone()
	same.Headers.Set("Location", "/login?err=18&nonce=999")
	if loginVerdict(same, base, true) {
		t.Fatal("nonce-bearing failure redirect must not validate")
	}

	cross := loginResp(302, "", "http://shop.local/login", "")
	cross.Headers = h.Clone()
	cross.Headers.Set("Location", "https://evil.example.net/dashboard")
	if loginVerdict(cross, base, true) {
		t.Fatal("cross-host redirect destination is never a credential claim")
	}
}

func TestLoginVerdictFailClosedOnUnknownOrigin(t *testing.T) {
	if loginVerdict(loginResp(200, "dashboard", "http://shop.local/dashboard"), loginFingerprint{}, true) {
		t.Fatal("unknown origin baseline must fail closed")
	}
}

// ── Integration: differential logic against real HTTP shapes ────────────

// Static-text PRG app: every POST 302s back to the same login page that
// statically contains "Welcome … Logout" and rotates the session cookie
// value on every response. The old word-matching credited admin:admin;
// the differential verdict must credit nothing.
func TestLoginSprayStaticPRGAppCreditsNothing(t *testing.T) {
	page := `<html><body><form action="/login" method="post">` +
		`<input name="username"><input name="password">` +
		`<button>Login</button></form><p>Welcome to our community</p><nav>Logout</nav></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: fmt.Sprintf("%d", time.Now().UnixNano())})
		if r.Method == http.MethodPost {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		_, _ = fmt.Fprint(w, page)
	}))
	defer srv.Close()

	client := transport.NewClient(transport.WithTimeout(5*time.Second), transport.WithRetries(0))
	kb := NewKnowledge(srv.URL)
	kb.AddPage(Page{URL: srv.URL + "/login", Forms: 1})

	res := (&LoginBruteAction{}).Execute(context.Background(), srv.URL, kb, client)
	for _, f := range res.Findings {
		if f.Type == "login_valid" {
			t.Fatalf("static PRG app must not produce a valid credential; got %q", f.Name)
		}
	}
	if res.Findings[0].Type != "login_brute_complete" {
		t.Fatalf("expected the no-cred info finding, got %q", res.Findings[0].Type)
	}
	for _, c := range kb.GetCredentials() {
		if c.Valid {
			t.Fatalf("knowledge base recorded a valid credential on a static PRG app")
		}
	}
}

// Redirect app with a genuinely working admin:admin pair.
func TestLoginSprayFindsRealCredential(t *testing.T) {
	formPage := `<html><body><form action="/login" method="post">` +
		`<input name="username"><input name="password"><button>Login</button></form>` +
		`<p>Error box placeholder</p></body></html>`
	dashboard := `<html><body><h1>Dashboard</h1><nav>Logout</nav></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/dashboard":
			_, _ = fmt.Fprint(w, dashboard)
		case r.URL.Path == "/login" && r.Method == http.MethodPost:
			_ = r.ParseForm()
			if r.FormValue("username") == "admin" && r.FormValue("password") == "admin" {
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "real-session"})
				http.Redirect(w, r, "/dashboard", http.StatusFound)
				return
			}
			http.Redirect(w, r, "/login?err=1", http.StatusFound)
		default:
			_, _ = fmt.Fprint(w, formPage)
		}
	}))
	defer srv.Close()

	client := transport.NewClient(transport.WithTimeout(5*time.Second), transport.WithRetries(0))
	kb := NewKnowledge(srv.URL)
	kb.AddPage(Page{URL: srv.URL + "/login", Forms: 1})

	res := (&LoginBruteAction{}).Execute(context.Background(), srv.URL, kb, client)
	found := 0
	for _, f := range res.Findings {
		if f.Type == "login_valid" {
			found++
			if !strings.Contains(f.Name, "admin:admin") {
				t.Fatalf("credential '%s' claimed valid — admin:admin is the only configured pair", f.Name)
			}
		}
	}
	if found != 1 {
		t.Fatalf("expected exactly one valid credential, got %d", found)
	}
	valid := 0
	for _, c := range kb.GetCredentials() {
		if c.Valid {
			valid++
		}
	}
	if valid != 1 {
		t.Fatalf("expected one valid credential in the KB, got %d", valid)
	}
	if len(res.Actions) == 0 {
		t.Fatal("post-login crawl should have been spawned for real credentials")
	}
}
