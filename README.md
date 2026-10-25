<p align="center">
  <a href="https://github.com/NICE-DEV226/nice-Scan/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/NICE-DEV226/nice-Scan/ci.yml?branch=main&style=flat-square&logo=githubactions&label=CI&color=58D6E6" alt="CI"/></a>
  <a href="https://github.com/NICE-DEV226/nice-Scan/releases/latest"><img src="https://img.shields.io/github/v/release/NICE-DEV226/nice-Scan?style=flat-square&logo=github&label=Release&color=B484E6" alt="Latest release"/></a>
  <img src="https://img.shields.io/badge/version-0.2.1-7DCFFF?style=flat-square&logo=go&logoColor=white" alt="Version"/>
</p>

<p align="center">
  <code>Fast. Precise. Intelligent.</code><br/>
  <em>Modern Security Reconnaissance Engine — Autonomous Attack Chaining &amp; Real Data Extraction</em>
</p>

---

## Overview

**nice_scan** is a command-line offensive security tool for authorized engagements. It combines high-performance HTTP scanning, technology fingerprinting, and an autonomous Decision Engine that chains attacks, extracts real data, and renders a full HTML report — from a single command.

Every claim in a report is tied to the evidence that supports it. Server-verified findings, passively observed signals and untested hypotheses are labelled differently, so the risk score reflects what the scanner actually executed, not what it guessed.

```shell
# Full autonomous attack with an HTML report
nice_scan hack example.com -R report.html

# One-line install (fail-closed installer)
curl -sfL https://raw.githubusercontent.com/NICE-DEV226/nice-Scan/main/scripts/install.sh | sh
```

## Features

### Autonomous Hack Agent

Run `nice_scan hack <target>` and the Decision Engine plans and executes the attack actions, then chains forward: every structural finding can spawn its exploitation module.

| | |
|---|---|
| **Reconnaissance** | Passive recon (crt.sh, Wayback — zero target requests) · BFS crawl (pages, forms, JS) · path fuzzing · concurrent port scan · S3 bucket enumeration |
| **Exploitation** | SQLi detection + data extraction · LFI detection + file read · XSS verification · login brute-force vs. differential baseline · JWT forge · GraphQL introspection |
| **Decision Engine** | Attack chain patterns (CORS→XSS, JWT→Admin, Upload→RCE) · forward-chaining planner · session management · knowledge base with capability derivation |
| **Output** | HTML attack report (risk scoring, findings timeline, evidence) · extracted artifacts under `reports/<target>/` · live TUI dashboard · interactive REPL · JSON for CI/CD |

### Honest verdicts

A claim needs evidence, not keywords:

- **Confirmed (server-verified)** — a probe was executed and the target's response carries the structural proof (SQL error oracle, `uid=` output from a marked command, attacker marker reflected in an executable context).
- **Observed** — a signal was directly seen on the target (a login form, an admin keyword, an upload field) without executing an exploit over it.
- **Hypothesis** — a chain the engine *would* run if it existed, reported as such.

Risk scoring weights executed severity highest and never lets an untested chain outscore a confirmed finding. State-modifying actions (command injection probes, web shell upload, account registration) are disabled unless the operator passes `--destructive`.

## Quick Start

```shell
# Autonomous hack — detection, chaining, extraction, HTML report
nice_scan hack example.com -R report.html

# Interactive reconnaissance shell
nice_scan shell

# Real-time dashboard with live findings
nice_scan scan example.com -i

# Time-boxed engagement
nice_scan hack example.com --timeout 30s -R report.html

# Exploitation modules
nice_scan exploit https://example.com --login --idor 1-100

# Technology fingerprinting
nice_scan tech https://example.com
```

## Installation

> **Package managers:** nice_scan currently ships through GitHub Releases and
> `go install` only. No Scoop bucket, Winget identity or Homebrew tap is
> published — installation commands circulating elsewhere (such as `winget
> install --id NICE-DEV226.nice-Scan` or `scoop install nice-scan/nice_scan`)
> target package IDs this project does not own.

The installer is **fail-closed**: it resolves one release tag, verifies SHA256
checksums and the GPG signature first, and aborts with nothing installed if any
step fails.

### Linux / macOS

```bash
curl -sfL https://raw.githubusercontent.com/NICE-DEV226/nice-Scan/main/scripts/install.sh | sh
```

Or with Go 1.24+ (builds from the pinned release tag):

```bash
go install github.com/NICE-DEV226/nice-Scan/cmd/nice_scan@v0.2.1
```

### Windows — PowerShell 7+

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/NICE-DEV226/nice-Scan/main/scripts/install.ps1 -OutFile install.ps1
powershell -ExecutionPolicy RemoteSigned -File install.ps1
```

### Manual

Download the binary for your platform from the [Releases page](https://github.com/NICE-DEV226/nice-Scan/releases), verify the checksums, and extract:

```bash
curl -sSfL https://github.com/NICE-DEV226/nice-Scan/releases/latest/download/nice_scan_latest_linux_amd64.tar.gz | tar xz
sudo mv nice_scan /usr/local/bin/
```

### Build from Source

```bash
git clone https://github.com/NICE-DEV226/nice-Scan.git
cd nice-Scan
make build
# or: go build -o nice_scan ./cmd/nice_scan
```

## Commands

| Command | Description |
|---------|-------------|
| `hack <target>` | Autonomous attack chain — detection, chaining, data extraction<!--, HTML report --> |
| `scan <target>` | Standard reconnaissance scan (headers, TLS, fingerprint, endpoints) |
| `exploit <target>` | Exploitation modules (login, IDOR, privesc, token/session reuse) |
| `tech <target>` | Technology fingerprinting only (165 signatures) |
| `tls <target>` | TLS/SSL analysis (ciphers, certs, protocol versions) |
| `shell` | Interactive REPL reconnaissance shell |

### Global flags

| Flag | Description |
|------|-------------|
| `--workers, -w` | Concurrent workers (default 64) |
| `--timeout` | Per-request timeout |
| `--rate-limit` | Requests per second (0 = unlimited) |
| `--proxy` | HTTP proxy URL |
| `--cookie` | Cookie header included in every request |
| `--header` | Custom headers, repeatable (`key:value`) |
| `--follow-redirects` / `--max-redirects` | Redirect policy (default: follow, 5 hops) |
| `--json, -j` | JSON output for pipelines |
| `--interactive, -i` | Live dashboard |
| `--report, -R` | Detailed HTML report file |
| `--destructive` | **Explicit consent for state-modifying actions** (command/shell upload, registration) |
| `--version` / `--verbose, -v` | Version / verbose output |

### `exploit` module flags

| Flag | Module |
|------|--------|
| `--login` | Credential brute-force against login forms (differential verdict vs. junk baseline) |
| `--idor 1-100` | IDOR enumeration range |
| `--role` | Role/privilege escalation via parameters and headers |
| `--token` | Token and session reuse on protected endpoints (tokens are harvested from the target; none are invented, an empty harvest is reported) |
| `--reset` | Password reset flows — user enumeration and token leaks |
| `--session` | Session fixation and cookie security |
| `--register` | Account registration testing — **refused without `--destructive`** (account creation modifies target state) |
| `--all` | Run every non-destructive module (registration still requires `--destructive`) |

<details>
<summary><strong>Attack walkthrough</strong> — a sample <code>hack</code> run</summary>

```
$ nice_scan hack example.com --timeout 15s -R report.html

  ◈ NICE HACKER — DECISION ENGINE
  Target: https://example.com
  Actions loaded (destructive modules gated by --destructive)

    Step 1  Passive Reconnaissance  → crt.sh: 3 subdomains (+ wayback)
    Step 2  Crawl Endpoints         → 47 paths discovered
    Step 3  SQL Injection           → CRITICAL  login.php (param: id)
            ◈ Spawned: SQLi Data Extraction
    Step 4  SQLi Extraction         → CRITICAL  142 user records
    Step 5  Local File Inclusion    → CRITICAL  /etc/passwd via page=
            ◈ Spawned: LFI File Read
    Step 6  LFI File Read           → CRITICAL  12 structural records
    Step 7  Attack Chain Detection  → hypothesis chains listed
    Step 8  Report Generation       → report.html

  ── Extraction Summary ──
  📁 reports/example.com/
  ├── sql_dump/  users.sql          (142 records)
  ├── lfi_files/ passwd, shadow, .env, …
  └── credentials.txt               (8 credentials)
```

</details>

## Trust & Supply Chain Security

| Layer | State | Verification |
|-------|-------|--------------|
| Binary integrity | SHA256 checksums published per release | `sha256sum --check checksums.txt --ignore-missing` |
| Release authenticity | GPG-signed `checksums.txt` when signing keys are configured | `gpg --verify checksums.txt.sig checksums.txt` |
| Build provenance | GitHub build-provenance attestations + cosign keyless bundles at release time (releases cut after 2026-10-24; nothing retroactive) | `gh attestation verify <file> -R NICE-DEV226/nice-Scan` |
| SBOM | SPDX SBOM emitted per release | present in the release assets |
| Code integrity | Commits are **not** systematically GPG-signed | `git log --show-signature` |
| Distribution | GitHub Releases + `go install <tag>` | — |

The installers (`scripts/install.sh`, `scripts/install.ps1`) fail closed: a missing
checksum file, an uncovered archive or a failed signature aborts with nothing
installed. The `go install` path anchors strictly to the resolved release tag —
no `@latest`, no `main` HEAD.

### Quick verification

```bash
# Release assets
gh release download v0.2.1 --pattern "checksums*" -R NICE-DEV226/nice-Scan

# SHA256
sha256sum --check nice_scan_0.2.1_checksums.txt --ignore-missing

# GPG (when signing is configured)
gpg --verify nice_scan_0.2.1_checksums.txt.sig nice_scan_0.2.1_checksums.txt

# Most trustworthy: build from a pinned tag and audit what you run
git clone --branch v0.2.1 https://github.com/NICE-DEV226/nice-Scan.git
cd nice-Scan && go build ./cmd/nice_scan
```

> The maintainer GPG key is imported on first use from `keyserver.ubuntu.com`
> (hkps) and must match the pinned fingerprint
> `4CE466095C5B3185883288C593FBFE29F62FA4DB` (verified out-of-band, published in
> [SECURITY.md](SECURITY.md)) — a mismatched key makes `install.sh` abort. For a
> hardcoded chain of trust, clone and build from source.

## Development

```bash
make build            # build the CLI
make run ARGS="hack example.com --timeout 10s"
make test             # tests
make build-all        # cross-compile (linux/windows/darwin, amd64/arm64)
make lint             # golangci-lint (gofmt, goimports, staticcheck, …)
make vet
make snapshot         # full local release snapshot
make release
```

Continuous integration runs the suite with race detection on every push to
`main`, and enforces the lint/formatting gate (`.golangci.yml`). Pull requests
must keep both green.

### Architecture

```
cmd/nice_scan/          CLI entry point (Cobra commands)
internal/
  hacker/               Decision Engine (planner, chaining, knowledge base, actions)
  engine/               Analysis modules (SQLi, XSS, CORS, TLS, tokens, auth, …)
  exploit/              Exploitation modules (login, IDOR, privesc, token, session)
  fingerprint/          Technology fingerprinting (165 signatures)
  transport/            HTTP client (pooling, retry policy, HTTP/2, session/hops)
  shell/                Interactive REPL shell
  tui/                  Terminal UI (live dashboard)
  output/               Output renderers (terminal, JSON, HTML)
  types/                Shared types
scripts/                Install scripts (install.sh, install.ps1)
docs/                   Landing page & documentation
```

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — detailed system design
- [docs/architecture/overview.md](docs/architecture/overview.md) — architecture overview
- [docs/architecture/transport.md](docs/architecture/transport.md) — transport layer
- [CONTRIBUTING.md](CONTRIBUTING.md) — development workflow & conventions
- [SECURITY.md](SECURITY.md) — security policy, vulnerability reporting and the honest supply-chain inventory

## Legal

This tool is intended exclusively for **authorized security testing** of systems you own
or have explicit written permission to test. Unauthorized use may violate applicable laws.
The authors accept no liability for misuse or damage caused by this tool.

---

<p align="center">
  <sub>Built with <a href="https://go.dev/">Go</a> · <a href="https://github.com/spf13/cobra">Cobra</a> · <a href="https://github.com/charmbracelet/bubbletea">BubbleTea</a> · <a href="https://github.com/charmbracelet/lipgloss">LipGloss</a></sub><br/>
  <sub>© 2026 NICE-DEV226</sub>
</p>
