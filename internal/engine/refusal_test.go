package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/fingerprint"
	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// A scan the boundary refused must never be reported as a scan that found
// nothing. The two look identical in a findings list and mean opposite things.

func TestScanCountsBoundaryRefusals(t *testing.T) {
	seen := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = true
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(catchAllShell))
	}))
	defer srv.Close()

	client := transport.NewClient(
		transport.WithTargetScope("target.example"),
		transport.WithRetries(0),
		transport.WithTimeout(5*time.Second),
	)
	defer func() { _ = client.Close() }()

	scanner := NewScanner(&types.Config{Workers: 4, Timeout: 5 * time.Second, FollowRedirects: true}, client)
	scanner.RegisterAnalyzers(fingerprint.New(), NewAuthAnalyzer())
	res := scanner.Scan(context.Background(), []string{srv.URL})

	if res.Stats.Total == 0 {
		t.Fatal("the scanner planned no probes")
	}
	if res.Stats.Refused != res.Stats.Total {
		t.Errorf("want every request refused, got Refused=%d of Total=%d", res.Stats.Refused, res.Stats.Total)
	}
	if res.Stats.Completed != 0 {
		t.Errorf("refused requests must not count as completed: %+v", res.Stats)
	}
	if len(res.Findings) != 0 {
		t.Errorf("a scan that never reached the target produced findings: %+v", res.Findings)
	}
	if seen {
		t.Fatal("the refused scan still reached the server")
	}
}

func TestSuccessfulScanReportsNoRefusals(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(catchAllShell))
	}))
	defer srv.Close()

	client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(5*time.Second))
	defer func() { _ = client.Close() }()

	scanner := NewScanner(&types.Config{Workers: 4, Timeout: 5 * time.Second, FollowRedirects: true}, client)
	scanner.RegisterAnalyzer(fingerprint.New())
	res := scanner.Scan(context.Background(), []string{srv.URL})

	if res.Stats.Completed == 0 {
		t.Fatalf("nothing completed: %+v", res.Stats)
	}
	if res.Stats.Refused != 0 {
		t.Errorf("an ordinary scan must report no refusals, got %d", res.Stats.Refused)
	}
}
