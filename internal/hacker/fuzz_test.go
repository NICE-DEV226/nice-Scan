package hacker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
)

func runFuzz(t *testing.T, handler http.HandlerFunc) []Finding {
	t.Helper()
	srv := httptest.NewServer(handler)
	defer srv.Close()

	client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(10*time.Second))
	defer func() { _ = client.Close() }()

	kb := NewKnowledge(srv.URL)
	return (&FuzzAction{}).Execute(context.Background(), srv.URL, kb, client).Findings
}

// A catch-all SPA answers 200 + index.html for every path. Reporting 50
// "hidden endpoints" from that is the fuzzer's worst false positive: the
// control request identifies the behaviour and suppresses the lot.
func TestFuzzSuppressesCatchAllSPA(t *testing.T) {
	page := `<!doctype html><html><head><title>shop</title></head><body><div id="root"></div><script src="/app.js"></script></body></html>`
	findings := runFuzz(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(page))
	})

	if len(findings) != 0 {
		t.Fatalf("catch-all SPA must produce no endpoint findings, got %+v", findings)
	}
}

// A directory index is hygiene, not a discovered endpoint: it used to be
// reported HIGH purely because the path answered 200.
func TestFuzzDirectoryListingIsLow(t *testing.T) {
	findings := runFuzz(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/static":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>Index of /static</title></head><body><h1>Index of /static</h1><a href="../">[To Parent Directory]</a><a href="app.js">app.js</a></body></html>`))
		default:
			http.NotFound(w, r)
		}
	})

	var listing *Finding
	for i := range findings {
		if findings[i].Type == "directory_listing" {
			listing = &findings[i]
		}
		if findings[i].Type == "endpoint" && strings.Contains(findings[i].Name, "/static") {
			t.Errorf("a directory index must not be reported as an endpoint: %+v", findings[i])
		}
	}
	if listing == nil {
		t.Fatalf("directory listing not reported: %+v", findings)
	}
	if listing.Severity != SevLow {
		t.Errorf("directory listing severity = %v, want Low", listing.Severity)
	}
}

func TestFuzzSensitivePathNeedsContentProof(t *testing.T) {
	findings := runFuzz(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.git/config":
			_, _ = w.Write([]byte("[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n\turl = https://example.com/x\n"))
		case "/admin":
			// A real page, but nothing that proves an admin console.
			_, _ = w.Write([]byte("<html><body><h1>You are not signed in</h1><p>Please sign in to continue.</p></body></html>"))
		default:
			http.NotFound(w, r)
		}
	})

	var git, admin *Finding
	for i := range findings {
		if findings[i].Type != "endpoint" {
			continue
		}
		if strings.Contains(findings[i].Name, ".git") {
			git = &findings[i]
		}
		if strings.Contains(findings[i].Name, "/admin") {
			admin = &findings[i]
		}
	}
	if git == nil || git.Severity != SevHigh {
		t.Fatalf(".git/config with a [core] section is a confirmed exposure (High), got %+v", git)
	}
	if admin == nil {
		t.Fatalf("reachable /admin should still be reported: %+v", findings)
	}
	if admin.Severity != SevMedium {
		t.Errorf("/admin without console markers = %v, want Medium (existence unproven as console)", admin.Severity)
	}
}

// Static servers ignore query strings. The old probe called that "the
// endpoint accepts the parameter" 18 times per scan.
func TestFuzzParameterNeedsResponseChange(t *testing.T) {
	home := "<html><body><h1>Shop</h1><p>A page long enough to pass the size floor.</p></body></html>"
	findings := runFuzz(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(home))
	})
	for _, f := range findings {
		if f.Type == "parameter" {
			t.Fatalf("ignored query string must not be reported as an accepted parameter: %+v", f)
		}
	}

	findings = runFuzz(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.RawQuery != "" {
			_, _ = w.Write([]byte(home + strings.Repeat("<p>extra results returned for your query</p>", 40)))
			return
		}
		_, _ = w.Write([]byte(home))
	})
	found := false
	for _, f := range findings {
		if f.Type == "parameter" {
			found = true
		}
	}
	if !found {
		t.Fatalf("a parameter that changes the response must be reported: %+v", findings)
	}
}
