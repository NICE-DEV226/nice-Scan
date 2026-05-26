# NICE_SCAN Architecture

## Overview

NICE_SCAN is a modular, high-performance security reconnaissance engine designed for professional security assessments.

```
┌──────────────────────────────────────────────────────┐
│                    CLI (Cobra)                        │
├──────────────────────────────────────────────────────┤
│                    Engine                             │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────┐   │
│  │ Scanner   │  │ Analyzer │  │ Worker Pool       │   │
│  │ Orchestr. │──│ Pipeline │──│ 64 workers        │   │
│  └──────────┘  └──────────┘  └───────────────────┘   │
├──────────────────────────────────────────────────────┤
│                    Transport                          │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────┐   │
│  │ HTTP/1.1  │  │ HTTP/2   │  │ Connection Pool   │   │
│  │ Client   │  │ Client   │  │ 200 idle conns     │   │
│  └──────────┘  └──────────┘  └───────────────────┘   │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────┐   │
│  │ Retry    │  │ Rate     │  │ Keep-Alive        │   │
│  │ Engine   │──│ Limiter  │──│ 30s               │   │
│  └──────────┘  └──────────┘  └───────────────────┘   │
├──────────────────────────────────────────────────────┤
│                    Analyzers                          │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────┐   │
│  │Fingerprint│  │ Headers  │  │    TLS            │   │
│  │ Engine   │  │ Analyzer │  │   Analyzer        │   │
│  └──────────┘  └──────────┘  └───────────────────┘   │
│  ┌────────────────────────────────────────────────┐   │
│  │           Exposure Analyzer                    │   │
│  └────────────────────────────────────────────────┘   │
├──────────────────────────────────────────────────────┤
│                    Output                             │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────┐   │
│  │ Terminal  │  │   JSON   │  │   HTML/Markdown   │   │
│  │(LipGloss) │  │ Renderer │  │   (future)        │   │
│  └──────────┘  └──────────┘  └───────────────────┘   │
└──────────────────────────────────────────────────────┘
```

## Module Responsibilities

### Transport Layer
- HTTP/1.1 and HTTP/2 request execution
- Connection pooling with aggressive keep-alive
- Adaptive retry with exponential backoff + jitter
- Token-bucket rate limiting
- Per-request timeout via context
- Proxy support (HTTP, SOCKS future)

### Engine Layer
- Worker pool for concurrent request execution
- Results collection from worker channels
- Analyzer pipeline (each response passes through all analyzers)
- Panic recovery per analyzer
- Graceful shutdown via context

### Analyzers
Each analyzer implements the `Analyzer` interface:
```go
type Analyzer interface {
    Name() string
    Analyze(ctx context.Context, resp *types.Response) []types.Finding
}
```

- **Fingerprint**: Technology detection via headers, cookies, HTML, CSP, JS
- **Headers**: Security header analysis, cookie flag checks
- **TLS**: Version, cipher, certificate analysis
- **Exposures**: Sensitive file detection

### Output
- Terminal (LipGloss-styled tables and severity indicators)
- JSON (CI/CD-friendly structured output)

## Concurrency Model

The worker pool pattern:
1. N requests enqueued into a buffered channel
2. M workers (default 64) read from the channel
3. Each worker has its own goroutine with shared transport
4. Results streamed back via results channel
5. Backpressure via channel buffering

## Design Decisions

### Standard library HTTP over fasthttp
- Better ecosystem compatibility (HTTP/2, TLS, proxy)
- Battle-tested by years of production use
- Sufficient performance with proper tuning
- Easier to extend with custom TLS fingerprinting

### Goroutine workers over thread pool
- Lightweight goroutines (2KB stack vs MB for threads)
- Go scheduler handles M:N threading
- Channel-based communication avoids shared state

### Retry with full jitter
- Prevents thundering herd on retry
- Better for rate-limited scenarios
- Configurable min/max wait
