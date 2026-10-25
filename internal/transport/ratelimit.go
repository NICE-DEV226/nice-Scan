package transport

import (
	"context"
	"sync"
	"time"
)

type RateLimiter struct {
	rate     int
	interval time.Duration
	tokens   int
	mu       sync.Mutex
	cond     *sync.Cond
	done     bool
}

func NewRateLimiter(ratePerSecond int) *RateLimiter {
	if ratePerSecond <= 0 {
		ratePerSecond = 1000
	}
	rl := &RateLimiter{
		rate:     ratePerSecond,
		interval: time.Second / time.Duration(ratePerSecond),
	}
	rl.cond = sync.NewCond(&rl.mu)
	go rl.refill()
	return rl
}

func (rl *RateLimiter) refill() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		if rl.done {
			rl.mu.Unlock()
			return
		}
		rl.tokens = rl.rate
		rl.cond.Broadcast()
		rl.mu.Unlock()
	}
}

// Wait consumes one token, blocking while none are available. It reports
// whether the caller was actually delayed (statistics must not count
// requests that went through immediately).
func (rl *RateLimiter) Wait(ctx context.Context) bool {
	waited := false

	rl.mu.Lock()
	defer rl.mu.Unlock()

	for rl.tokens <= 0 && !rl.done {
		waited = true
		select {
		case <-ctx.Done():
			return waited
		default:
		}
		rl.cond.Wait()
	}

	if rl.tokens > 0 {
		rl.tokens--
	}
	return waited
}

func (rl *RateLimiter) Stop() {
	rl.mu.Lock()
	rl.done = true
	rl.cond.Broadcast()
	rl.mu.Unlock()
}
