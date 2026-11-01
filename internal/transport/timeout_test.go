package transport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
