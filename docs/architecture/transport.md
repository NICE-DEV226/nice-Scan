# Transport Layer Architecture

## Design Goals

1. **Maximum throughput** - Connection reuse, HTTP/2 multiplexing
2. **Stability under load** - Graceful degradation, adaptive behavior
3. **Low latency** - Minimal allocations, streaming reads
4. **Resilience** - Retry with backoff, timeout protection

## Client Configuration

```
┌────────────────────────────────────────────────────┐
│                  Client                             │
│  ┌──────────────────────────────────────────────┐  │
│  │           http.Client (net/http)              │  │
│  │  ┌────────────────────────────────────────┐  │  │
│  │  │        http.Transport                    │  │  │
│  │  │  - MaxIdleConns: 200                    │  │  │
│  │  │  - MaxIdleConnsPerHost: 20              │  │  │
│  │  │  - IdleConnTimeout: 90s                 │  │  │
│  │  │  - TLSHandshakeTimeout: 10s             │  │  │
│  │  │  - ForceAttemptHTTP2: true              │  │  │
│  │  │  - DialContext: custom dialer           │  │  │
│  │  │    - Timeout: 10s                       │  │  │
│  │  │    - KeepAlive: 30s                     │  │  │
│  │  └────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────┐  │
│  │           Retry Engine                        │  │
│  │  - Max retries: 2 (configurable)             │  │
│  │  - Backoff: exponential + full jitter        │  │
│  │  - Retry on: timeout, 429, 5xx, connection   │  │
│  └──────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────┐  │
│  │           Rate Limiter                        │  │
│  │  - Token bucket (1s refill)                  │  │
│  │  - Per-process, shared across workers        │  │
│  └──────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────┘
```

## Connection Lifecycle

1. **Dial** - TCP connection with 10s timeout
2. **TLS Handshake** - 10s timeout, HTTP/2 negotiation
3. **Request** - Context-based timeout (default 15s)
4. **Response Read** - Limited to 10MB max body
5. **Keep-Alive** - Connection returned to pool (30s idle max)
6. **Idle Timeout** - 90s before closing idle connections

## Retry Policy

Triggers:
- Context deadline exceeded
- Rate limited (HTTP 429)
- Server error (HTTP 5xx)
- Connection reset / DNS failure

Backoff calculation:
```
backoff = minWait * 2^(attempt-1)
jitter = random(0, minWait)
wait = backoff + jitter
cap = maxWait
```

Default: minWait=500ms, maxWait=5s, maxRetries=2

## Rate Limiting

Token bucket refilled every second.
Workers wait for available tokens before executing.
Zero rate limit = no throttling.
