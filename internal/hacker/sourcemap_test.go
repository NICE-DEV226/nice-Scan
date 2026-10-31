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

func TestParseSourceMapRejectsNonMaps(t *testing.T) {
	cases := []struct {
		name string
		body string
		ok   bool
	}{
		{"valid v3", `{"version":3,"sources":["src/a.ts"],"names":[],"mappings":""}`, true},
		{"version 2", `{"version":2,"sources":["src/a.ts"]}`, false},
		{"empty sources", `{"version":3,"sources":[]}`, false},
		{"json but not a map", `{"error":"not found"}`, false},
		{"not json", `<html><body>404</body></html>`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, got := parseSourceMap([]byte(tc.body))
			if got != tc.ok {
				t.Fatalf("parseSourceMap(%q) ok = %v, want %v", tc.body, got, tc.ok)
			}
		})
	}
}

// Guessing `<js>.map` alone misses hidden-source-map builds and renamed
// bundles. The declared reference must come first, then both conventions.
func TestSourceMapCandidates(t *testing.T) {
	got := sourceMapCandidates("https://example.com", "/static/app.js", "bundle.abc123.map")
	want := []string{
		"https://example.com/static/bundle.abc123.map", // declared
		"https://example.com/static/app.js.map",        // webpack convention
		"https://example.com/static/app.map",           // terser convention
	}
	if len(got) != len(want) {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidate %d = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}

	// Out-of-scope declared map is dropped; conventions stay.
	got = sourceMapCandidates("https://example.com", "/static/app.js", "https://cdn.evil.com/x.map")
	for _, c := range got {
		if strings.Contains(c, "evil.com") {
			t.Fatalf("third-party declared map must be dropped: %v", got)
		}
	}
	if len(got) != 2 {
		t.Fatalf("expected the two conventions only, got %v", got)
	}

	// Inline data: maps are not fetched.
	for _, c := range sourceMapCandidates("https://example.com", "/a.js", "data:application/json;base64,e30=") {
		if strings.HasPrefix(c, "data:") {
			t.Fatalf("data: URI must not become a fetch candidate: %v", c)
		}
	}
}

func TestSourceMapDeclaredNameEndToEnd(t *testing.T) {
	var appMapHits, bundleMapHits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/static/app.js":
			_, _ = w.Write([]byte(`!function(){console.log(1)}();//# sourceMappingURL=bundle.abc123.map`))
		case "/static/bundle.abc123.map":
			atomic.AddInt32(&bundleMapHits, 1)
			_, _ = w.Write([]byte(`{"version":3,"file":"app.js","sources":["webpack://app/src/config.ts"],"names":[],"mappings":"","sourcesContent":["const REGION=\"eu\";\nconst KEY=\"AKIA3RJ7QW2ZKX9MPL4T\";\n"]}`))
		case "/static/app.js.map":
			atomic.AddInt32(&appMapHits, 1)
			http.NotFound(w, r)
		case "/static/app.map":
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(10*time.Second))
	defer func() { _ = client.Close() }()

	kb := NewKnowledge(srv.URL)
	kb.AddJSScript("/static/app.js")

	// The JS scan runs first in the real registry (priority 41 vs 43); it
	// is the step that hands over the declared map name.
	(&JSSecretsAction{}).Execute(context.Background(), srv.URL, kb, client)
	if ref := kb.GetSourceMapRef("/static/app.js"); ref != "bundle.abc123.map" {
		t.Fatalf("sourceMappingURL not harvested, got %q", ref)
	}

	res := (&SourceMapAction{}).Execute(context.Background(), srv.URL, kb, client)

	if atomic.LoadInt32(&bundleMapHits) == 0 {
		t.Fatal("the declared map was never requested")
	}
	if atomic.LoadInt32(&appMapHits) != 0 {
		t.Error("convention candidate fetched after the declared map already validated")
	}

	var exposed, secret *Finding
	for i := range res.Findings {
		switch res.Findings[i].Type {
		case "source_map_exposed":
			exposed = &res.Findings[i]
		case "source_map_secret":
			secret = &res.Findings[i]
		}
	}
	if exposed == nil {
		t.Fatalf("no source_map_exposed finding: %+v", res.Findings)
	}
	if exposed.Severity != SevHigh {
		t.Errorf("a map carrying sourcesContent exposes original source: severity %v, want High", exposed.Severity)
	}
	if secret == nil {
		t.Fatalf("a credential inside sourcesContent must be reported: %+v", res.Findings)
	}
	if strings.Contains(secret.Evidence, "AKIA3RJ7QW2ZKX9MPL4T") {
		t.Errorf("evidence must redact the literal: %q", secret.Evidence)
	}
	if !kb.HasVerifiedCapability("has_sourcemaps") {
		t.Error("a parsed v3 map read from the target is verified evidence")
	}
}

func TestSourceMapWithoutContentIsMedium(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app.js.map" {
			_, _ = w.Write([]byte(`{"version":3,"sources":["src/a.ts","src/b.ts"],"names":["a"],"mappings":"AAAA"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(10*time.Second))
	defer func() { _ = client.Close() }()

	kb := NewKnowledge(srv.URL)
	kb.AddJSScript("/app.js")
	res := (&SourceMapAction{}).Execute(context.Background(), srv.URL, kb, client)

	if len(res.Findings) != 1 {
		t.Fatalf("want exactly one finding, got %+v", res.Findings)
	}
	if res.Findings[0].Severity != SevMedium {
		t.Errorf("paths-only map is Medium, got %v", res.Findings[0].Severity)
	}
}

// An SPA that answers 200 with index.html for every path must not be
// reported as exposing a source map.
func TestSourceMapIgnoresHTMLFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><head><title>app</title></head><body><div id=root></div></body></html>`))
	}))
	defer srv.Close()

	client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(10*time.Second))
	defer func() { _ = client.Close() }()

	kb := NewKnowledge(srv.URL)
	kb.AddJSScript("/app.js")
	if res := (&SourceMapAction{}).Execute(context.Background(), srv.URL, kb, client); len(res.Findings) != 0 {
		t.Fatalf("HTML fallback is not a source map: %+v", res.Findings)
	}
}
