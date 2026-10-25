package transport

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// Wave A — wire-truth regressions. Every test here locks a production
// failure mode found by the double senior review (architect + pentest).

// ── A1: the client must never blind itself by accepting compressed bodies
// it does not decompress. When the caller sets Accept-Encoding itself,
// net/http stops transparently decompressing; the fix removes that header
// and lets the transport negotiate gzip and hand back plain bytes.
func newGzipServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Real-world CDNs and nginx compress whenever the client says it
		// can — this handler asserts exactly that shape.
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(http.StatusOK)
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			_, _ = zw.Write([]byte(body))
			_ = zw.Close()
			_, _ = w.Write(buf.Bytes())
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
}

func TestGzipBodyNeverDeliveredRaw(t *testing.T) {
	const canary = "NSX-GZIP-CANARY-77231"
	srv := newGzipServer(t, "<html><body>"+canary+"</body></html>")
	defer srv.Close()

	client := NewClient()
	defer func() { _ = client.Close() }()

	resp, err := client.Do(context.Background(), &types.Request{
		Method: "GET",
		URL:    srv.URL + "/",
	})
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	if strings.Contains(string(resp.Body), "<") == false && len(resp.Body) > 0 {
		t.Fatalf("body is not HTML: %q", resp.Body)
	}
	if bytes.HasPrefix(resp.Body, []byte{0x1f, 0x8b}) {
		t.Fatalf("raw gzip delivered to scanners: %q…", resp.Body[:min(len(resp.Body), 12)])
	}

	// The end-to-end consequence: detection layers must see the canary.
	if !strings.Contains(string(resp.Body), canary) {
		t.Errorf("canary missing from decompressed body — detections would be blind: %q", strings.TrimSpace(string(resp.Body)))
	}
}

// ── A2: POSTs must never be retried. A timeout on a state-changing POST
// means the first attempt MIGHT have been processed; a resend double-
// submits credentials or state. Server-side hiccups (500/429) on
// idempotent GETs keep the retry.
func TestRepostDisabledForStateChangingMethods(t *testing.T) {
	postHits, getHits := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			postHits++
		case "GET":
			getHits++
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := NewClient(WithRetries(2), WithRetryWait(10*time.Millisecond, 20*time.Millisecond))
	defer func() { _ = client.Close() }()

	ctx := context.Background()

	// State-changing: exactly one attempt, whatever the server hiccup.
	respPost, err := client.Do(ctx, &types.Request{Method: "POST", URL: srv.URL + "/login"})
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	if postHits != 1 {
		t.Fatalf("POST resubmitted on server error: %d attempts (must be exactly 1)", postHits)
	}
	if respPost.StatusCode != http.StatusInternalServerError {
		t.Errorf("single-attempt response lost: got %d", respPost.StatusCode)
	}

	// Idempotent: a 500 is retried through the policy.
	respGet, err := client.Do(ctx, &types.Request{Method: "GET", URL: srv.URL + "/"})
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	if getHits != 3 { // initial + 2 retries
		t.Errorf("GET retry policy broken: got %d attempts, want 3", getHits)
	}
	if respGet.StatusCode != http.StatusInternalServerError {
		t.Errorf("final GET response lost through retries: got %d", respGet.StatusCode)
	}
}

// Mid-response timeouts are the other double-submit vector: the server may
// fully process the request after the client gave up.
func TestPostTimeoutSendsExactlyOneAttempt(t *testing.T) {
	postHits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		postHits++
		time.Sleep(700 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewClient(WithRetries(2), WithRetryWait(10*time.Millisecond, 20*time.Millisecond))
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, _ = client.Do(ctx, &types.Request{Method: "POST", URL: srv.URL + "/login"})

	if postHits != 1 {
		t.Fatalf("POST resubmitted on timeout: %d attempts (must be exactly 1)", postHits)
	}
}

// ── A3: resp.Duration must measure the wire attempt, without rate-limit
// wait or retry backoff, because time-based oracles gate on it.
func TestResponseDurationExcludesRateLimitWait(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewClient(WithRateLimit(1)) // 1 req/s: the second request waits ~1s
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	first, err := client.Do(ctx, &types.Request{Method: "GET", URL: srv.URL + "/a"})
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	second, err := client.Do(ctx, &types.Request{Method: "GET", URL: srv.URL + "/b"})
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}

	waited := client.Stats().RateLimited
	if waited < 1 {
		t.Fatalf("rate limiter did not count a delayed request: %+v", client.Stats())
	}
	if second.Duration > 500*time.Millisecond {
		t.Fatalf("resp.Duration carried the rate-limit wait: %v (wire attempt must stay isolated)", second.Duration)
	}
	if first.Duration > 500*time.Millisecond {
		t.Fatalf("first requires no wait but reported %v", first.Duration)
	}
}
