# Contributing

## 🤝 How to Contribute

We welcome contributions — whether it's fixing bugs, adding features, improving documentation, or reporting issues.

### Quick Start

```bash
git clone https://github.com/NICE-DEV226/nice-Scan.git
cd nice-Scan
make build
make run ARGS="hack example.com --timeout 10s"
```

### Development Workflow

1. **Pick an issue** — or create one before starting significant work
2. **Create a feature branch** — `git checkout -b feat/my-change`
3. **Write code** — follow conventions below
4. **Run checks** — `make vet && make test`
5. **Commit** — signed commits only (`git commit -S`)
6. **Push and open a PR** — against the `develop` branch

## 🧪 Interactive Features

All interactive modes are part of the single `nice_scan` binary — they're always available regardless of installation method.

| Command | Description |
|---------|-------------|
| `nice_scan shell` | **Persistent TUI shell** — type `scan`, `audit`, `tech`, `tls`, `exploit` without restarting. Full scrollback, session context, command history. |
| `nice_scan scan example.com -i` | **Live dashboard** — real-time progress bars, spinner, findings stream as they arrive. |
| `nice_scan hack example.com` | **Decision Engine** — step-by-step autonomous attack with elapsed time, spawn notifications, KB summary. |

## 🏗 Architecture

```
cmd/nice_scan/        CLI entrypoint (Cobra commands)
internal/
  engine/             Scan engine + analyzers (headers, TLS, CORS, SQLi, XSS...)
  exploit/            Active exploitation (login brute, IDOR, privesc, tokens...)
  fingerprint/        Technology detection (165 signatures)
  hacker/             Decision Engine — autonomous attack agent (brain, planner, chaining)
  output/             Terminal rendering + JSON output
  transport/          HTTP client (pooling, retries, rate limiting, H2)
  types/              Shared types (config, findings, requests, results)
  shell/              Interactive TUI shell (BubbleTea)
  tui/                Live dashboard TUI (BubbleTea)
scripts/
  install.sh          Unix installer (checksum + GPG verification)
  install.ps1         Windows installer (checksum + Authenticode verification)
```

### Key Design Decisions

- **Single binary** — all features (scan, hack, shell, TUI) compile into one static binary
- **Deterministic builds** — `go build` with `CGO_ENABLED=0` for reproducible artifacts
- **Action interface** — hacker actions return `ActionResult{Findings, Actions}` enabling forward-chaining
- **LipGloss styling** — graphite/slate palette, no green-on-black, consistent severity colors

## ✅ Before Submitting

- [ ] `make vet` — no warnings
- [ ] `make test` — all tests pass
- [ ] `go build ./...` — compiles cleanly
- [ ] Commit signed with GPG (`git commit -S`)
- [ ] Branch based on `develop`, not `main`
- [ ] PR description explains what and why

## 📝 Code Conventions

- **Go 1.24+** idioms (range-over-func, clear(), slices, maps)
- **No external comments** on code — code should be self-documenting
- **Import grouping**: stdlib → external → internal
- **Error handling**: wrap errors with `fmt.Errorf("context: %w", err)`
- **Concurrency**: use `errgroup.Group` for goroutines, `sync` for shared state
- **No global state** — pass dependencies explicitly

### Naming

| Convention | Example |
|-----------|---------|
| Package names | `hacker`, `transport`, `fingerprint` |
| Interfaces | `Action`, `Analyzer` |
| Error vars | `ErrNotFound`, `ErrTimeout` |
| Test helpers | `newTestClient()`, `mockAction{}` |

## 🔐 Security

- **Signed commits required** — configure GPG key and use `git commit -S`
- **No hardcoded secrets** — use environment variables or config
- **Report vulnerabilities** via email (not public issues) — see [SECURITY.md](SECURITY.md)

### Setting Up GPG Signing

```bash
gpg --full-generate-key
git config --global user.signingkey <KEY-ID>
git config --global commit.gpgsign true
```

## 📦 Releases

Releases are automated via GoReleaser. A maintainer triggers:

```bash
git tag v0.x.x
git push origin v0.x.x
goreleaser release --clean
```

Every release produces:
- Pre-built binaries for Windows/macOS/Linux × amd64/arm64
- SHA256 checksums (signed with GPG)
- Sigstore/SLSA provenance attestation
- SPDX SBOM

## ❓ Questions

Open a [Discussion](https://github.com/NICE-DEV226/nice-Scan/discussions) for questions, ideas, or general help.
