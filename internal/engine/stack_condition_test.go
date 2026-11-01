package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/fingerprint"
	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// Fingerprint-first conditioning: the scanner reads the stack from the
// homepage BEFORE building the probe set, so a PHP box is not sprayed with
// Spring actuator or WordPress paths, and an unclassifiable target keeps
// the full battery (stated honestly, not silently dropped).

func TestBuildProbesFiltering(t *testing.T) {
	s := NewScanner(&types.Config{Timeout: time.Second}, nil)

	php := fingerprint.Classify(&types.Response{Headers: http.Header{
		"X-Powered-By": []string{"PHP/8.2"},
	}, Body: []byte("<html></html>")})

	reqs := s.buildProbes("http://x", php)
	urls := make([]string, len(reqs))
	for i, r := range reqs {
		urls[i] = r.URL
	}
	joined := strings.Join(urls, " ")
	for _, want := range []string{"/phpinfo.php", "/robots.txt", "/.env"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("PHP stack must probe %s, got %v", want, urls)
		}
	}
	for _, ban := range []string{"/wp-login.php", "/actuator/env"} {
		if strings.Contains(joined, ban) {
			t.Fatalf("PHP stack must NOT probe foreign-family %s: %v", ban, urls)
		}
	}

	unknown := fingerprint.Classify(&types.Response{Headers: http.Header{}, Body: []byte("<html></html>")})
	reqs2 := s.buildProbes("http://x", unknown)
	if len(reqs2) <= len(reqs) {
		t.Fatalf("unknown stack must keep the full set (%d probes) above the filtered one (%d)", len(reqs2), len(reqs))
	}
}

func TestScanReportsConditionedStack(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.Header().Set("X-Powered-By", "PHP/8.2")
		_, _ = w.Write([]byte("<html><body>hi</body></html>"))
	}))
	defer srv.Close()

	cfg := types.DefaultConfig()
	client := transport.NewClient(transport.WithRetries(0), transport.WithTimeout(2*time.Second))
	defer func() { _ = client.Close() }()

	scanner := NewScanner(cfg, client)
	res := scanner.Scan(context.Background(), []string{srv.URL})

	if len(res.Stacks) != 1 || !res.Stacks[0].Conditioned {
		t.Fatalf("scan must report the conditioned stack, got %+v", res.Stacks)
	}

	mu.Lock()
	defer mu.Unlock()
	hasPHPInfo := false
	for _, p := range paths {
		if p == "/actuator/env" || p == "/wp-login.php" {
			t.Fatalf("PHP target was sprayed with foreign-family probe %s: %v", p, paths)
		}
		if p == "/phpinfo.php" {
			hasPHPInfo = true
		}
	}
	if !hasPHPInfo {
		t.Fatalf("phpinfo must still be probed on a PHP stack: %v", paths)
	}
}
