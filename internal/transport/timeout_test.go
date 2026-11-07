package transport

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// Request-deadline regressions: types.Request.Timeout was declared but
// never consumed — every action inherited whatever the caller's context
// happened to carry, and a silent server could hold a worker forever.

func TestPerRequestTimeoutHonored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
		_, _ = w.Write([]byte("late"))
	}))
	defer srv.Close()

	client := NewClient(WithRetries(0))
	defer func() { _ = client.Close() }()

	start := time.Now()
	_, err := client.Do(context.Background(), &types.Request{
		Method:  "GET",
		URL:     srv.URL,
		Timeout: 100 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("a 100ms budget against a 2s server must fail")
	}
	if !errors.Is(err, types.ErrTimeout) {
		t.Fatalf("want types.ErrTimeout, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 1*time.Second {
		t.Fatalf("timeout fired late (%s): the budget is not enforced", elapsed)
	}
}

func TestClientDefaultTimeoutAppliesWhenRequestHasNone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	client := NewClient(WithRetries(0), WithTimeout(100*time.Millisecond))
	defer func() { _ = client.Close() }()

	_, err := client.Do(context.Background(), &types.Request{Method: "GET", URL: srv.URL})
	if !errors.Is(err, types.ErrTimeout) {
		t.Fatalf("client-level timeout must bound requests: got %v", err)
	}
}

func TestCallerContextCancelStillReturnsContextError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	client := NewClient(WithRetries(0), WithTimeout(0)) // no per-attempt budget
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := client.Do(ctx, &types.Request{Method: "GET", URL: srv.URL})
		errCh <- err
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("operator cancellation must not be relabeled as timeout: got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled context did not unblock the request")
	}
}

// A refused connection is not a timeout. Classifying a timeout from the error
// rather than from the context must not swallow every dial failure: a dead
// target has to keep reading as unreachable, not as slow.
func TestConnectionRefusedIsNotClassifiedAsTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	client := NewClient(WithRetries(0), WithTimeout(2*time.Second))
	defer func() { _ = client.Close() }()

	_, err = client.Do(context.Background(), &types.Request{Method: "GET", URL: "http://" + addr})
	if errors.Is(err, types.ErrTimeout) {
		t.Fatalf("a refused connection must not read as a timeout: %v", err)
	}
	if !errors.Is(err, types.ErrRequestFailed) {
		t.Fatalf("want ErrRequestFailed, got %v", err)
	}
}

// The transport timer winning the race is the case the fix exists for:
// ResponseHeaderTimeout fires while the per-request context is still alive,
// so the context carries no deadline signal at all. The error itself has to
// be read — this test fails with ErrRequestFailed without that read.
func TestResponseHeaderTimeoutIsClassifiedAsTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	// Client budget (transport timer) 50ms; request budget 5s. The
	// transport fires first and the context stays alive.
	client := NewClient(WithRetries(0), WithTimeout(50*time.Millisecond))
	defer func() { _ = client.Close() }()

	_, err := client.Do(context.Background(), &types.Request{
		Method:  "GET",
		URL:     srv.URL,
		Timeout: 5 * time.Second,
	})
	if !errors.Is(err, types.ErrTimeout) {
		t.Fatalf("a response-header timeout must read as ErrTimeout, got %v", err)
	}
}

// A timeout is one condition, so it gets one retry decision: an idempotent
// GET that times out is retried with a fresh per-attempt budget. If the
// verdict were allowed to fall back to ErrRequestFailed whenever the
// transport timer won the race, the same slow host would be retried or
// dropped depending on scheduling — the intermittency this fix removes.
func TestIdempotentTimeoutIsRetried(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	client := NewClient(WithRetries(1), WithRetryWait(5*time.Millisecond, 10*time.Millisecond))
	defer func() { _ = client.Close() }()

	_, err := client.Do(context.Background(), &types.Request{
		Method:  "GET",
		URL:     srv.URL,
		Timeout: 100 * time.Millisecond,
	})
	if !errors.Is(err, types.ErrTimeout) {
		t.Fatalf("want ErrTimeout through retries, got %v", err)
	}
	if !errors.Is(err, types.ErrMaxRetries) {
		t.Fatalf("want ErrMaxRetries after exhausting the budget, got %v", err)
	}

	// Count asynchronously: the transport can report cancellation before
	// the handler goroutine has even started.
	waitUntil := time.Now().Add(2 * time.Second)
	for hits.Load() < 2 && time.Now().Before(waitUntil) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // grace: a third attempt would land here
	if got := hits.Load(); got != 2 {
		t.Fatalf("idempotent timeout must be retried exactly once: %d attempt(s), want 2", got)
	}
}

func TestRateLimiterBucketSeededFull(t *testing.T) {
	rl := NewRateLimiter(5)
	defer rl.Stop()

	// Before seeding, the first Wait on an idle limiter blocked until the
	// 1s refill tick.
	start := time.Now()
	if rl.Wait(context.Background()) {
		t.Fatalf("first request on a fresh limiter must not report a wait (elapsed %s)", time.Since(start))
	}
	if rl.tokens != 4 {
		t.Fatalf("seeded bucket must decrement, tokens=%d", rl.tokens)
	}
}

func TestCloseStopsRateLimiterRefill(t *testing.T) {
	client := NewClient(WithRateLimit(2))
	rl := client.rl
	if rl == nil {
		t.Fatal("test client must carry a limiter")
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	rl.mu.Lock()
	done := rl.done
	rl.mu.Unlock()
	if !done {
		t.Fatal("Client.Close must stop the refill goroutine")
	}

	// A waiter must be released rather than stranded on cond.Wait.
	blocked := make(chan bool, 1)
	go func() { blocked <- rl.Wait(context.Background()) }()
	select {
	case <-blocked:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Wait did not return after Stop")
	}
}
