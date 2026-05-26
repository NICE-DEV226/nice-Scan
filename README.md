# NICE_SCAN

**Fast. Precise. Intelligent.**

Modern Security Reconnaissance Engine

---

NICE_SCAN is a professional-grade CLI tool for authorized security reconnaissance. It combines high-performance HTTP scanning, intelligent technology fingerprinting, and comprehensive security analysis into a single, fast, modular tool.

## Features

- **High-Performance HTTP Engine** — Connection pooling, HTTP/2, keep-alive, adaptive retries
- **Technology Fingerprinting** — Detect frameworks, CMS, CDNs, WAFs, cloud providers
- **Security Header Analysis** — CSP, HSTS, CORS, cookie security flags
- **TLS Analysis** — Version, cipher suites, certificate validation
- **Exposure Detection** — .env, .git, source maps, backups, directory listing
- **Beautiful CLI** — LipGloss-styled terminal output with severity colors
- **CI/CD Ready** — JSON output, SARIF (future), GitHub Actions integration
- **Modular Architecture** — Plugin-based analyzer system

## Installation

```bash
# From source
go install github.com/NICE-DEV226/nice-Scan@latest
```

## Quick Start

```bash
# Full scan
nice_scan scan https://example.com

# Technology detection only
nice_scan tech https://example.com

# TLS analysis
nice_scan tls https://example.com

# JSON output for CI/CD
nice_scan scan https://example.com --json
```

## Documentation

- [Architecture Overview](docs/architecture/overview.md)
- [Transport Layer](docs/architecture/transport.md)

## Development

```bash
# Build
go build -o nice_scan.exe ./cmd/nice_scan

# Test
go test -race -v ./...

# Lint
golangci-lint run ./...
```

## License

This tool is intended exclusively for authorized security testing.
