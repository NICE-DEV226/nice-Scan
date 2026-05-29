<p align="center">
  <br/>
  <img src="https://img.shields.io/badge/version-0.1.0-7DCFFF?style=for-the-badge&logo=go&logoColor=white" alt="Version"/>
  <img src="https://img.shields.io/github/actions/workflow/status/NICE-DEV226/nice-Scan/ci.yml?branch=main&style=for-the-badge&logo=github&label=CI&color=58D6E6" alt="CI"/>
  <img src="https://img.shields.io/github/actions/workflow/status/NICE-DEV226/nice-Scan/release.yml?branch=main&style=for-the-badge&logo=goreleaser&label=Release&color=B484E6" alt="Release"/>
  <img src="https://img.shields.io/github/v/release/NICE-DEV226/nice-Scan?style=for-the-badge&logo=github&color=5CE6A0" alt="Latest Release"/>
  <img src="https://img.shields.io/github/license/NICE-DEV226/nice-Scan?style=for-the-badge&color=E6586A" alt="License"/>
</p>

<p align="center">
  <code>Fast. Precise. Intelligent.</code><br/>
  <em>Modern Security Reconnaissance Engine — Autonomous Attack Chaining & Real Data Extraction</em>
</p>

<br/>

## Overview

NICE_SCAN is a professional-grade offensive security tool that combines high-performance HTTP scanning, intelligent technology fingerprinting, and an **autonomous Decision Engine** that chains attacks, extracts real data, and generates professional HTML reports — all from a single command.

```shell
# ── Full autonomous hack ────────────────────────────
nice_scan hack example.com -R report.html

# ── One-line install ────────────────────────────────
curl -sfL https://raw.githubusercontent.com/NICE-DEV226/nice-Scan/main/scripts/install.sh | sh
```

<br/>

## Features

### Autonomous Hack Agent
Run `nice_scan hack target.com` and the Decision Engine autonomously executes 14 attack actions with forward-chaining:

<table>
<tr>
<td width="50%">

**🔍 Reconnaissance**
- Passive recon (crt.sh, Wayback Machine — zero target requests)
- Web crawl (BFS discovery: pages, forms, JS files)
- Fuzzing (42 paths, 16 params)
- Concurrent port scan (20 goroutines, 30 ports × 3 hosts)
- S3 bucket enumeration (20 candidates)

</td>
<td width="50%">

**💥 Exploitation & Chaining**
- SQLi detection + auto data extraction (user tables)
- LFI detection + auto file read (`/etc/passwd`, configs)
- CMD injection + auto shell execution
- File upload + auto web shell deployment
- JWT forge (`alg=none` + 40 common secrets)
- XSS, GraphQL introspection, login brute-force

</td>
</tr>
<tr>
<td width="50%">

**🧠 Decision Engine**
- 10 attack chain patterns (CORS→XSS, JWT→Admin, Secrets→Cloud, Upload→RCE)
- Forward-chaining: each finding auto-spawns exploit modules
- Thread-safe dynamic planner with priority queue
- Session management (persistent cookies, tokens, JWT)
- Knowledge base with auto-capability derivation

</td>
<td width="50%">

**📊 Professional Output**
- HTML attack reports (dark theme, risk scoring, findings timeline)
- Extracted data saved to `reports/{target}/` (SQL dumps, LFI files, shell output, S3 buckets)
- Real-time TUI dashboard with progress bars + findings stream
- Interactive REPL shell (command history, session context)
- JSON output for CI/CD pipelines

</td>
</tr>
</table>

<br/>

## Quick Start

```shell
# Full autonomous hack — 14 actions, auto-chaining, HTML report
nice_scan hack example.com -R report.html

# Interactive reconnaissance shell
nice_scan shell

# Real-time dashboard with live findings
nice_scan scan example.com -i

# Time-boxed engagement (ideal for bug bounties)
nice_scan hack target.com --timeout 30s -R report.html

# Exploitation modules
nice_scan exploit https://example.com --login --idor 1-100

# Technology fingerprinting
nice_scan tech https://example.com

# JSON output
nice_scan scan https://example.com --json
```

<br/>

## Installation

### Package Managers

<details open>
<summary><strong>Scoop</strong> (Windows)</summary>

```powershell
scoop bucket add nice-scan https://github.com/NICE-DEV226/nice-Scan
scoop install nice-scan/nice_scan
```
</details>

<details>
<summary><strong>Winget</strong> (Windows)</summary>

```powershell
winget install --id NICE-DEV226.nice-Scan
```
</details>

<details>
<summary><strong>Homebrew</strong> (macOS / Linux)</summary>

```bash
brew install NICE-DEV226/tap/nice-scan
```
</details>

### Direct Install

<details>
<summary><strong>Go Install</strong> (cross-platform, requires Go 1.24+)</summary>

```bash
go install github.com/NICE-DEV226/nice-Scan/cmd/nice_scan@latest
```
</details>

<details>
<summary><strong>One-liner Installer</strong> (macOS / Linux)</summary>

```bash
curl -sfL https://raw.githubusercontent.com/NICE-DEV226/nice-Scan/main/scripts/install.sh | sh
```
</details>

<details>
<summary><strong>One-liner Installer</strong> (Windows PowerShell 7+)</summary>

```powershell
powershell -ExecutionPolicy Bypass -c "iex \"& { $(irm https://raw.githubusercontent.com/NICE-DEV226/nice-Scan/main/scripts/install.ps1) }\""
```
</details>

<details>
<summary><strong>Manual</strong> — download from GitHub Releases</summary>

Download the latest binary for your platform from the [Releases page](https://github.com/NICE-DEV226/nice-Scan/releases), verify the checksums, and extract.

```bash
# Example: Linux amd64
curl -sSfL https://github.com/NICE-DEV226/nice-Scan/releases/latest/download/nice_scan_latest_linux_amd64.tar.gz | tar xz
sudo mv nice_scan /usr/local/bin/
```
</details>

### Build from Source

```bash
git clone https://github.com/NICE-DEV226/nice-Scan.git
cd nice-Scan
make build
# or: go build -o nice_scan ./cmd/nice_scan
```

<br/>

## Attack Walkthrough

```
$ nice_scan hack example.com --timeout 15s -R report.html

  ◈ NICE HACKER — DECISION ENGINE
  Target: https://example.com
  Actions loaded: 14

    Step 1  [0s]  ──────────────────────────────────
  ┌────────────────────────────────────────────────┐
  │ Passive Reconnaissance                         │
  └────────────────────────────────────────────────┘
  ▸ INFO     crt.sh subdomains: 3 found (+ wayback)

    Step 2  [2s]  ──────────────────────────────────
  ┌────────────────────────────────────────────────┐
  │ Crawl Endpoints                                │
  └────────────────────────────────────────────────┘
  ▸ INFO     Paths discovered: 47

    Step 3  [4s]  ──────────────────────────────────
  ┌────────────────────────────────────────────────┐
  │ SQL Injection  Checking 16 params              │
  └────────────────────────────────────────────────┘
  !! CRITICAL SQLi: login.php (param: id)
  ◈ Spawned: SQLi Data Extractor

    Step 4  [5s]  ──────────────────────────────────
  ┌────────────────────────────────────────────────┐
  │ SQLi Data Extraction  Dump user tables         │
  └────────────────────────────────────────────────┘
  !! CRITICAL Users extracted: 142 records

    Step 5  [7s]  ──────────────────────────────────
  ┌────────────────────────────────────────────────┐
  │ Local File Inclusion                           │
  └────────────────────────────────────────────────┘
  !! CRITICAL LFI: /etc/passwd via page= param
  ◈ Spawned: LFI File Reader

    Step 6  [8s]  ──────────────────────────────────
  ┌────────────────────────────────────────────────┐
  │ LFI File Read  Extract sensitive files         │
  └────────────────────────────────────────────────┘
  !! CRITICAL Files: 12 (passwd, shadow, .env, config...)

    Step 7  [10s]  ─────────────────────────────────
  ┌────────────────────────────────────────────────┐
  │ Attack Chain Detection                         │
  └────────────────────────────────────────────────┘
  ◈ CORS + XSS Chain: api allows all origins
  ◈ JWT + Admin Chain: weak secret forgeable
  ◈ Secrets + Cloud Chain: 8 credentials in extracted files

    Step 8  [12s]  ─────────────────────────────────
  ┌────────────────────────────────────────────────┐
  │ Report Generation                              │
  └────────────────────────────────────────────────┘
  ✓ Risk Score: 10.0 / 10
  ✓ Report: report.html

  ── Extraction Summary ──
  📁 reports/example.com/
  ├── sql_dump/users.sql          (142 records)
  ├── lfi_files/passwd
  ├── lfi_files/shadow
  ├── lfi_files/config.php
  └── credentials.txt             (8 credentials)
```

<br/>

## Trust & Supply Chain Security

Every release is cryptographically signed and verifiable. NICE_SCAN follows SLSA Level 2 practices with full supply chain transparency.

| Layer | Method | Verification Command |
|-------|--------|---------------------|
| **Code Integrity** | All commits GPG-signed | `git log --show-signature` |
| **Binary Integrity** | SHA256 checksums | `sha256sum --check checksums.txt` |
| **Release Authenticity** | GPG-signed checksums | `gpg --verify checksums.txt.sig checksums.txt` |
| **Build Provenance** | Sigstore/cosign (keyless OIDC) | `cosign verify-blob --bundle checksums.sigstore.json checksums.txt` |
| **Dependency Transparency** | SPDX SBOM | `syft scan nice_scan --from-release NICE-DEV226/nice-Scan:v0.1.0` |
| **Verifiable Build** | `gh attestation verify` | `gh attestation verify nice_scan_linux_amd64.tar.gz --repo NICE-DEV226/nice-Scan` |

### Quick Verification

```bash
# Download release assets
gh release download v0.1.0 --pattern "checksums*" -R NICE-DEV226/nice-Scan

# Verify SHA256
sha256sum --check nice_scan_0.1.0_checksums.txt --ignore-missing

# Verify GPG signature
gpg --verify nice_scan_0.1.0_checksums.txt.sig nice_scan_0.1.0_checksums.txt

# Verify Sigstore (keyless OIDC)
cosign verify-blob --bundle nice_scan_0.1.0_checksums.txt.sigstore.json nice_scan_0.1.0_checksums.txt

# Most trustworthy: build from source
git clone https://github.com/NICE-DEV226/nice-Scan.git && cd nice-Scan && go build ./cmd/nice_scan
```

> **Note:** The project GPG public key is published to `keyserver.ubuntu.com` (fingerprint: `4CE466095C5B3185883288C593FBFE29F62FA4DB`). Verify with `gpg --recv-keys 93FBFE29F62FA4DB`.

See [SECURITY.md](SECURITY.md) for the full security policy and [cosign.pub](cosign.pub) for the cosign public key.

<br/>

## Commands

| Command | Description |
|---------|-------------|
| `hack <target>` | **Full autonomous attack chain** — 14 actions, auto-chaining, data extraction |
| `scan <target>` | Standard reconnaissance scan (headers, TLS, fingerprint, endpoints) |
| `tech <target>` | Technology fingerprinting only (165 signatures) |
| `tls <target>` | TLS/SSL analysis (ciphers, certs, protocol versions) |
| `exploit <target>` | Active exploitation modules (login brute, IDOR, privesc, token) |
| `shell` | Interactive REPL reconnaissance shell |
| `--version` | Display version |
| `--help` | Display help |

<br/>

## Development

```bash
# Build
make build

# Run with args
make run ARGS="hack example.com --timeout 10s"

# Test with race detection
make test

# Cross-compile (linux + windows + darwin, amd64 + arm64)
make build-all

# Lint
make lint

# Vet
make vet

# Goreleaser snapshot
make snapshot

# Full release
make release
```

### Architecture

```
cmd/nice_scan/          CLI entry point (Cobra commands)
internal/
  hacker/               Decision Engine (types, planner, chaining, knowledge, brain)
  engine/               Analysis modules (SQLi, XSS, CORS, TLS, tokens, auth, etc.)
  exploit/              Exploitation modules (login, IDOR, privesc, token, session)
  fingerprint/          Technology fingerprinting (165+ signatures)
  transport/            HTTP client (connection pooling, retries, H2)
  shell/                Interactive REPL shell
  tui/                  Terminal UI (live dashboard)
  output/               Output renderers (terminal, JSON, HTML)
  types/                Shared types
scripts/                Install scripts (install.sh, install.ps1)
docs/                   Landing page & documentation
```

<br/>

## Documentation

- [Architecture Overview](docs/architecture/overview.md)
- [Transport Layer](docs/architecture/transport.md)
- [ARCHITECTURE.md](ARCHITECTURE.md) — Detailed system design
- [CONTRIBUTING.md](CONTRIBUTING.md) — Development workflow & conventions
- [SECURITY.md](SECURITY.md) — Security policy & vulnerability reporting

<br/>

## Legal

This tool is intended exclusively for **authorized security testing** of systems you own or have explicit permission to test. Unauthorized use may violate applicable laws. The authors assume no liability and are not responsible for any misuse or damage caused by this tool.

---

<p align="center">
  <sub>Built with <a href="https://go.dev/">Go</a> · <a href="https://github.com/spf13/cobra">Cobra</a> · <a href="https://github.com/charmbracelet/bubbletea">BubbleTea</a> · <a href="https://github.com/charmbracelet/lipgloss">LipGloss</a></sub><br/>
  <sub>Released under MIT License · © 2026 NICE-DEV226</sub>
</p>
