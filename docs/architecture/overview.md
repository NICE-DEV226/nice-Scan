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

## Service Boundary (`internal/recon`, `internal/exploit`)

The CLI is an adapter, not the only consumer. Two packages own the decisions
that make a run safe, so a script, the TUI or a model inherits them instead of
copying the command's code:

- `recon.New` builds a target-scoped client, registers the analyzer roster and
  returns graded findings. It fails closed when no scope is given and renders
  nothing — a service that prints is a service a model cannot call.
- `exploit.NewService` does the same for the active modules: an explicit scope
  (the target must be inside it), a client built from the operator's config
  (timeout, rate-limit, proxy, `EnforceScope`, `BlockInternal`), and consent
  read from `Config.Destructive`. The state-changing entry points
  (`BruteforceLogin` spray, `RoleTampering`, `RegisterAccount`,
  `ExploitPasswordReset`) return `ErrConsentRequired` before they build a
  request, so a refusal costs the target zero bytes. `BruteforceLogin` with a
  single credential is the operator's explicit attempt and is not a spray.

| Decision | Where it lives | Fail-closed behaviour |
|---|---|---|
| Where requests may go | `transport.WithTargetScope` (destination allow-list + dial guard) | no scope → `ErrNoScope`, refused request counted apart from a failure |
| Whether state may change | `exploit.Options.Consent` ← `Config.Destructive` | no consent → `ErrConsentRequired`, no request sent |
| What a finding means | `types.Provenance` + `types.GradeOf` | a hand-written confidence can reach *indicated*, never *proven* |
| What a machine receives | `types.RedactFinding` + JSON sink | credential-shaped values masked at the source |

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
