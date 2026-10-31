package hacker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
)

// The Fuzzer gates on has_pages, which CrawlAction declared in
// Metadata.Provides but never recorded. The planner therefore skipped the
// Fuzzer forever and every capability behind it (has_api → LFI, CMD) was
// unreachable: the run ended after the crawl against every target.
func TestCrawlerUnlocksTheFuzzer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app.js" {
			_, _ = w.Write([]byte(`console.log(1)`))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><title>home</title></head><body>
			<a href="/second">next</a><script src="/app.js"></script></body></html>`))
	}))
	defer srv.Close()

	client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(10*time.Second))
	defer func() { _ = client.Close() }()

	kb := NewKnowledge(srv.URL)
	(&CrawlAction{}).Execute(context.Background(), srv.URL, kb, client)

	if !kb.HasVerifiedCapability("has_pages") {
		t.Fatal("a fetched page is executed evidence that pages exist — has_pages must be verified")
	}

	capMap := make(map[string]bool)
	verified := make(map[string]bool)
	for _, c := range kb.GetCapabilities() {
		capMap[c.Name] = true
		if c.Origin == OriginVerified {
			verified[c.Name] = true
		}
	}
	if !ActionRequirementsMet((&FuzzAction{}).Metadata(), capMap, verified) {
		t.Fatalf("Fuzzer requirements still unmet after a successful crawl: caps=%v", capMap)
	}
}
