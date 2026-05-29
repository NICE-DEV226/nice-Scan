# NICE_SCAN

**Fast. Precise. Intelligent.** — Modern Security Reconnaissance Engine

NICE_SCAN is a professional-grade CLI tool for authorized security reconnaissance. It combines high-performance HTTP scanning, intelligent technology fingerprinting, and an **autonomous hack agent** with a decision engine that chains attacks automatically.

```bash
# Quick start — full autonomous hack in one command
nice_scan hack example.com -R report.html
```

## Installation

### Option 1: Go install (requires Go 1.24+)
```bash
go install github.com/NICE-DEV226/nice-Scan/cmd/nice_scan@latest
```

### Option 2: One-liner installer
**macOS / Linux:**
```bash
curl -sfL https://raw.githubusercontent.com/NICE-DEV226/nice-Scan/main/scripts/install.sh | sh
```

**Windows (PowerShell 7+):**
```powershell
powershell -ExecutionPolicy Bypass -c "iex \"& { $(irm https://raw.githubusercontent.com/NICE-DEV226/nice-Scan/main/scripts/install.ps1) }\""
```

### Option 3: Download pre-built binary
Download the latest release for your platform from the [Releases page](https://github.com/NICE-DEV226/nice-Scan/releases).

### Option 4: Build from source
```bash
git clone https://github.com/NICE-DEV226/nice-Scan.git
cd nice-Scan
make build
# or: go build -o nice_scan ./cmd/nice_scan
```

## Quick Start

```bash
# See all commands
nice_scan --help

# Full autonomous hack (most powerful — try this first!)
nice_scan hack https://example.com

# With HTML report
nice_scan hack https://example.com -R report.html

# With custom timeout (default: 5s per action)
nice_scan hack https://example.com --timeout 10s -R report.html

# Standard reconnaissance scan
nice_scan scan https://example.com

# Technology detection only
nice_scan tech https://example.com

# TLS analysis
nice_scan tls https://example.com

# Active exploitation modules
nice_scan exploit https://example.com --login --idor 1-100

# Interactive shell (persistent session)
nice_scan shell

# JSON output for CI/CD
nice_scan scan https://example.com --json
```

## Features

### 🧠 Autonomous Hack Agent
Run `nice_scan hack target.com` and the Decision Engine autonomously:
1. **Passive recon** — crt.sh, Wayback Machine (no requests to target)
2. **Web crawl** — BFS discovery of pages, forms, endpoints, JS files
3. **Fuzzing** — hidden endpoints (42 paths) and parameter discovery (16 params)
4. **Port scan** — concurrent TCP connect (30 ports × 3 hosts)
5. **Attack modules** — JWT forge, SQLi, XSS, LFI, CMD injection, file upload, GraphQL introspection
6. **Login bruteforce** — 40 common credentials against discovered login forms
7. **S3 enumeration** — 20 bucket name candidates, concurrent checking
8. **OOB callback server** — blind SSRF/SSTI/XSS detection
9. **Attack chain detection** — CORS→XSS, JWT→Admin, Secrets→Cloud, Upload→RCE, and more
10. **Real data extraction** — SQLi → user dump, LFI → file read, CMD → shell output, S3 → bucket dump

```
$ nice_scan hack example.com --timeout 15s -R report.html
  NICE HACKER — DECISION ENGINE
  Target: https://example.com
  Actions loaded: 14

    Step 4  [19s]  ─
  ┌────────────────────────────────────────────────┐
  │ S3 Bucket Enumeration  Check subdomains        │
  └────────────────────────────────────────────────┘
  !! CRITICAL Public S3 bucket: example-files
  ◈ Spawned: S3 Bucket Dumper

    Step 5  [23s]  ─
  ┌────────────────────────────────────────────────┐
  │ S3 Bucket Dumper  List + download contents     │
  └────────────────────────────────────────────────┘
  !! CRITICAL S3 bucket listing: 18 files
  ▸ HIGH     S3 file: samples/config.json
```

### 🔍 Full Scan Suite
- **High-Performance HTTP Engine** — Connection pooling, HTTP/2, keep-alive, adaptive retries
- **Technology Fingerprinting** — 165 signatures: detect frameworks, CMS, CDNs, WAFs, cloud providers
- **Security Header Analysis** — CSP, HSTS, CORS, cookie security flags
- **TLS Analysis** — Version, cipher suites, certificate validation
- **Exposure Detection** — .env, .git, source maps, backups, directory listing
- **Active Exploitation** — Login brute, IDOR, privilege escalation, token reuse, registration, password reset, session fixation

## HTML Reports

Use `-R report.html` with `scan`, `audit`, or `hack` commands to generate a detailed HTML attack report with severity breakdown, risk scoring, and all findings.

```bash
nice_scan hack https://example.com -R report.html
# → Opens report.html in browser
```

## Development

```bash
# Build
make build

# Run (with optional args)
make run ARGS="hack example.com --timeout 10s"

# Test
make test

# Cross-compile for all platforms
make build-all

# Lint
make lint
```

## Trust & Security

NICE_SCAN takes supply chain security seriously. Every release is cryptographically verified.

| What | How |
|------|-----|
| **Code integrity** | All commits GPG-signed |
| **Binary integrity** | SHA256 checksums published for every release |
| **Release authenticity** | Checksums file signed with project GPG key (`.sig`) |
| **Build provenance** | Sigstore/cosign attestation (SLSA Level 2) |
| **Dependency transparency** | SPDX SBOM in every release |
| **Auditability** | Full source at [github.com/NICE-DEV226/nice-Scan](https://github.com/NICE-DEV226/nice-Scan) |

### Verify before running

```bash
# Download release assets
gh release download v0.2.0 --pattern "checksums*" -R NICE-DEV226/nice-Scan

# Verify SHA256
sha256sum --check nice_scan_v0.2.0_checksums.txt --ignore-missing

# Verify GPG signature
gpg --verify nice_scan_v0.2.0_checksums.txt.sig nice_scan_v0.2.0_checksums.txt

# Most trustworthy: build from source
git clone https://github.com/NICE-DEV226/nice-Scan.git && cd nice-Scan && go build ./cmd/nice_scan
```

See [SECURITY.md](SECURITY.md) for full details.

## Documentation

- [Architecture Overview](docs/architecture/overview.md)
- [Transport Layer](docs/architecture/transport.md)
- [ARCHITECTURE.md](ARCHITECTURE.md) — Detailed system architecture

## Legal

This tool is intended exclusively for authorized security testing of systems you own or have explicit permission to test. Unauthorized use may violate applicable laws.
