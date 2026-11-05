package recon

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/engine"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

const spaShell = `<!doctype html><html><head><title>VANSTORE</title></head>
<body><form action="/admin/login" method="post"><input name="username"><input type="password" name="password"></form>
<script src="/static/chart.js"></script></body></html>`

// catchAll answers every path with the shell above — what a client-side-routing
// SPA does, and the case the soft-404 baseline exists to defeat. It counts hits
// so a caller can assert what a call actually put on the wire.
func catchAll(hits *int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(hits, 1)
		w.Header().Set("Server", "nginx/1.25.1")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(spaShell))
	})
}

func TestNewFailsClosedWithoutAScope(t *testing.T) {
	for _, scope := range [][]string{nil, {}, {""}, {"  "}} {
		svc, err := New(Options{Config: types.DefaultConfig(), Scope: scope})
		if svc != nil {
			t.Errorf("New(%q) returned a service, want none", strings.Join(scope, ","))
		}
		if !errors.Is(err, ErrNoScope) {
			t.Errorf("New(%q) err = %v, want ErrNoScope", strings.Join(scope, ","), err)
		}
	}
}

// The service exists so a caller that is not a human at a terminal can read one
// target cheaply before aiming anything. One GET, and the answer must carry the
// shell signature and the grade of every claim it makes.
func TestBaselineIsOneGETAndCarriesTheGrade(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(catchAll(&hits))
	defer srv.Close()

	svc, err := New(Options{Config: types.DefaultConfig(), Scope: []string{srv.URL}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = svc.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	first, err := svc.Baseline(ctx, srv.URL)
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("Baseline issued %d requests, want the one homepage GET: a caller deciding what to probe next must not pay for fifty guesses", got)
	}
	if first.Status != http.StatusOK || first.Size != int64(len(spaShell)) {
		t.Errorf("baseline = %+v, want the served shell", first)
	}
	if first.Sig == "" {
		t.Error("an empty signature cannot be compared against later responses")
	}

	second, err := svc.Baseline(ctx, srv.URL)
	if err != nil {
		t.Fatalf("second Baseline: %v", err)
	}
	if second.Sig != first.Sig {
		t.Errorf("sig drifted between two identical responses: %q vs %q", first.Sig, second.Sig)
	}

	if len(first.Findings) == 0 {
		t.Fatal("the analyzers drew nothing from a page that declares a server, a login form and a JS asset")
	}
	for _, f := range first.Findings {
		grade := types.GradeOf(f)
		if grade == "" {
			t.Errorf("finding %q carries no grade: a machine consumer cannot rank it", f.Name)
		}
	}
}

// The stack is read from the baseline response, so a caller can condition its
// next move on what the target said it runs rather than on a guess.
func TestBaselineClassifiesTheStackFromTheSameResponse(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(catchAll(&hits))
	defer srv.Close()

	svc, err := New(Options{Config: types.DefaultConfig(), Scope: []string{srv.URL}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = svc.Close() }()

	b, err := svc.Baseline(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}
	if !strings.Contains(strings.ToLower(b.Stack.Server), "nginx") {
		t.Errorf("stack server = %q, want the declared nginx read off the baseline response", b.Stack.Server)
	}
}

// A scan through the service must aim nothing outside its scope: the boundary
// slice C put on the transport has to hold at this entry point too, because
// this is the one a script or a model calls.
func TestScanCannotBeAimedOutsideItsScope(t *testing.T) {
	var victimHits int32
	victim := httptest.NewServer(catchAll(&victimHits))
	defer victim.Close()

	var targetHits int32
	target := httptest.NewServer(catchAll(&targetHits))
	defer target.Close()

	svc, err := New(Options{Config: types.DefaultConfig(), Scope: []string{target.URL}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = svc.Close() }()

	// A scope is matched on the host, and both httptest servers live on
	// 127.0.0.1, so the out-of-scope one is reached under its other loopback
	// name: same machine, different host, and the boundary must see that.
	offScope := strings.Replace(victim.URL, "127.0.0.1", "localhost", 1)

	res, err := svc.Scan(context.Background(), []string{offScope})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := atomic.LoadInt32(&victimHits); got != 0 {
		t.Errorf("the out-of-scope host served %d requests, want 0", got)
	}
	if res.Stats.Refused == 0 {
		t.Errorf("stats = %+v, want the refused requests counted, or a refused scan reads as a clean target", res.Stats)
	}
}

// The roster is the answer to "what does a scan do". Registering it here is
// what makes `scan` and `audit` the same operation instead of two copies.
func TestScanRegistersTheDefaultRoster(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(catchAll(&hits))
	defer srv.Close()

	svc, err := New(Options{Config: types.DefaultConfig(), Scope: []string{srv.URL}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = svc.Close() }()

	res, err := svc.Scan(context.Background(), []string{srv.URL})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	want := DefaultAnalyzers(svc.Scanner().XSSCanary())
	if len(res.AnalyzerNames) != len(want) {
		t.Fatalf("analyzers = %v, want the %d-name default roster", res.AnalyzerNames, len(want))
	}
	for i, a := range want {
		if res.AnalyzerNames[i] != a.Name() {
			t.Errorf("analyzer %d = %q, want %q", i, res.AnalyzerNames[i], a.Name())
		}
	}
	if atomic.LoadInt32(&hits) <= 1 {
		t.Errorf("a full scan made %d requests, want the homepage GET plus probes", hits)
	}
}

// A narrowed roster is how `tech` and `tls` stay one-capability commands without
// filtering a full scan's findings afterwards.
func TestAnalyzersOptionNarrowsTheRoster(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(catchAll(&hits))
	defer srv.Close()

	svc, err := New(Options{
		Config:    types.DefaultConfig(),
		Scope:     []string{srv.URL},
		Analyzers: []engine.Analyzer{engine.NewHeaderAnalyzer()},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = svc.Close() }()

	res, err := svc.Scan(context.Background(), []string{srv.URL})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.AnalyzerNames) != 1 || res.AnalyzerNames[0] != "headers" {
		t.Errorf("analyzers = %v, want only the header analyzer", res.AnalyzerNames)
	}
}
