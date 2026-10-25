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

// Orchestration wiring regressions. The review proved end-to-end that with
// capability-gated Requires the SQLi module NEVER ran against an injectable
// target (nothing in the scheduled flow ever produced has_sqli) and the XSS
// module only ran when ANOTHER finding's remote-controlled text happened to
// contain the word "xss" (the OOB finding description). Both verdicts are
// self-gated at the protocol level, so the actions must be self-qualifying.
// These tests run the real Brain loop — not Execute directly — so a
// regression of the wiring cannot hide behind a direct call again.

// booleanInjectableApp: ?id= — OR 1=1 returns one extra row, AND 1=2 zero
// rows, errors never fire. A closed-valve param echoes canary text.
func booleanInjectableApp(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var xssSeen []string
	seed := "appseed-static-content"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.FormValue("id")
		echo := r.FormValue("q")
		if echo != "" {
			xssSeen = append(xssSeen, echo)
		}
		switch {
		case strings.Contains(id, "OR 1=1"):
			_, _ = fmt.Fprintf(w, "<html><body>listing lorem %s %s %s</body></html>", seed, seed, echo)
		case strings.Contains(id, "AND 1=2"):
			if echo != "" {
				_, _ = fmt.Fprintf(w, "<html><body>%s</body></html>", echo)
			} else {
				_, _ = w.Write([]byte("<html><body></body></html>"))
			}
		case id != "":
			_, _ = fmt.Fprintf(w, "<html><body>one row lorem %s %s</body></html>", seed, echo)
		default:
			_, _ = w.Write([]byte(`<html><body>index <a href="/?id=7&amp;q=x">listing</a></body></html>`))
		}
	}))
	return srv, &xssSeen
}

func runBrainActionSet(t *testing.T, target string, actions ...Action) *Report {
	t.Helper()
	client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(10*time.Second))
	defer func() { _ = client.Close() }()
	b := NewBrain(target, client, actions...)
	rep := b.Run(context.Background())
	reportsDirFor(t, target) // the actions dump extractions under reports/
	return rep
}

// With zero seeded capabilities, the self-gated verdicts must run from the
// crawler's own target knowledge and emit both wire-grounded findings.
// The hidden-token buildFormData fix: a form whose CSRF marker is only
// valid with its pre-rendered value is now testable. Feeding an arbitrary
// filler ("=test") previously made every such endpoint fail login
// validation — a silent false negative the spray never noticed.
func csrfValidatedApp(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/" && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`<html><body><form action="/login" method="post">` +
				`<input type="hidden" name="csrf_token" value="SEC-8831">` +
				`<input name="username"><input type="password" name="password">` +
				`<button>Login</button></form></body></html>`))
		case r.URL.Path == "/login" && r.Method == http.MethodPost:
			_ = r.ParseForm()
			if r.FormValue("csrf_token") != "SEC-8831" {
				http.Redirect(w, r, "/login?err=csrf", http.StatusFound)
				return
			}
			if r.FormValue("username") == "admin" && r.FormValue("password") == "admin" {
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "real-session"})
				http.Redirect(w, r, "/dashboard", http.StatusFound)
				return
			}
			http.Redirect(w, r, "/login?err=1", http.StatusFound)
		case r.URL.Path == "/dashboard":
			_, _ = w.Write([]byte("<html><body>Dashboard</body></html>"))
		default:
			_, _ = w.Write([]byte("<html><body>login</body></html>"))
		}
	}))
	return srv
}

func TestLoginSprayFillsCSRFTokenFromForm(t *testing.T) {
	srv := csrfValidatedApp(t)
	defer srv.Close()

	client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(10*time.Second))
	defer func() { _ = client.Close() }()

	resp, _ := client.Do(context.Background(), &types.Request{Method: "GET", URL: srv.URL + "/"})
	action, fields := extractLoginForm(string(resp.Body))
	if action == "" || len(fields) == 0 {
		t.Fatalf("login form extraction failed (action=%q fields=%d)", action, len(fields))
	}

	body := buildFormData(fields, "admin", "admin")
	if !strings.Contains(body, "csrf_token=SEC-8831") {
		t.Fatalf("buildFormData must carry the pre-rendered token: %q", body)
	}
	if !strings.Contains(body, "username=admin") || !strings.Contains(body, "password=admin") {
		t.Fatalf("credential fields lost: %q", body)
	}

	base, trusted := establishLoginBaseline(context.Background(), client, actionAfter(srv.URL, action), fields)
	if base == nil {
		t.Fatal("endpoint rejected two junk POSTs even with the token filled")
	}
	r, _ := postLoginForm(context.Background(), client, actionAfter(srv.URL, action), fields, "admin", "admin")
	if !loginVerdict(r, *base, trusted) {
		t.Fatalf("valid credential rejected on a CSRF-gated endpoint: status=%d final=%s", r.StatusCode, r.FinalURL)
	}
}

// actionAfter resolves the form's action against the page it was served
// from, mirroring the spray's own resolution.
func actionAfter(base, action string) string {
	if action == "" || action == "/" {
		return base
	}
	if res := resolveURL(action, base); res != "" {
		return res
	}
	return base
}

func TestBrainRunsSQLiWithoutCapabilitySeed(t *testing.T) {
	srv, _ := booleanInjectableApp(t)
	defer srv.Close()

	rep := runBrainActionSet(t, srv.URL, &CrawlAction{}, &SQLiAction{})
	if rep == nil {
		t.Fatal("no report")
	}
	var boolFound *Finding
	for i := range rep.Findings {
		if rep.Findings[i].Type == "sqli_boolean" {
			boolFound = &rep.Findings[i]
		}
	}
	if boolFound == nil {
		t.Fatalf("orchestrated brain produced no sqli_boolean on an injectable target — wiring regressed; findings: %+v", rep.Findings)
	}
}

func TestBrainRunsXSSWithoutCapabilitySeed(t *testing.T) {
	srv, xssSeen := booleanInjectableApp(t)
	defer srv.Close()

	rep := runBrainActionSet(t, srv.URL, &CrawlAction{}, &XSSAction{})
	var confirmed *Finding
	for i := range rep.Findings {
		if rep.Findings[i].Type == "xss_confirmed" ||
			rep.Findings[i].Type == "xss_script_context" ||
			rep.Findings[i].Type == "xss_reflection_points" {
			confirmed = &rep.Findings[i]
		}
	}
	// The reflection points finding is the baseline surfacing of the echo
	// param; a full xss_confirmed depends on context classification. The
	// wiring claim: the canary was SENT through its own action.
	if confirmed == nil {
		t.Fatalf("orchestrated brain produced no XSS finding on a reflecting target; findings: %+v", rep.Findings)
	}
	sawCanary := false
	for _, e := range *xssSeen {
		if strings.Contains(e, "nsx") && len(e) > len("nsx") {
			sawCanary = true
		}
	}
	if !sawCanary {
		t.Errorf("the XSS canary never went on the wire from the orchestrated run")
	}
}

// The hotspot of the old wiring: the run must not depend on ANY finding's
// remote text. Dilute the flow with a passive finding whose text is
// packed with misleading keywords; the verdicts must still execute.
func TestBrainVerdictsAreIndependentOfFindingText(t *testing.T) {
	srv, _ := booleanInjectableApp(t)
	defer srv.Close()

	client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(10*time.Second))
	defer func() { _ = client.Close() }()
	b := NewBrain(srv.URL, client, &CrawlAction{}, &SQLiAction{}, &XSSAction{})

	b.kb.AddFinding(Finding{
		Type:     "oob_ready",
		Name:     "OOB callback server ready",
		Severity: SevInfo,
		Description: "Listening on 127.0.0.1 — the old description charity 'blind SSRF/SSTI/XSS " +
			"detection' was the accidental seed of the whole XSS flow; this text no longer gates execution",
	})

	rep := b.Run(context.Background())
	hasSQLi, hasXSS := false, false
	for i := range rep.Findings {
		switch rep.Findings[i].Type {
		case "sqli_boolean":
			hasSQLi = true
		case "xss_confirmed", "xss_script_context", "xss_reflection_points":
			hasXSS = true
		}
	}
	if !hasSQLi || !hasXSS {
		t.Fatalf("execution independent of finding text regressed (sqli=%v xss=%v)", hasSQLi, hasXSS)
	}
}
