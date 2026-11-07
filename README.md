<p align="center">
  <a href="https://github.com/NICE-DEV226/nice-Scan">
    <img src="https://img.shields.io/badge/nice__scan-security%20recon-7DCFFF?style=for-the-badge&logo=go&logoColor=white" alt="nice_scan"/>
  </a>
</p>

<p align="center">
  <a href="https://github.com/NICE-DEV226/nice-Scan/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/NICE-DEV226/nice-Scan/ci.yml?branch=main&style=flat-square&logo=githubactions&label=CI&color=58D6E6" alt="CI status"/></a>
  <a href="https://github.com/NICE-DEV226/nice-Scan/releases/latest"><img src="https://img.shields.io/github/v/release/NICE-DEV226/nice-Scan?style=flat-square&logo=github&label=release&color=B484E6" alt="Latest release"/></a>
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.24%2B-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go 1.24+"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-3FB950?style=flat-square" alt="MIT license"/></a>
  <a href="SECURITY.md"><img src="https://img.shields.io/badge/security%20policy-read-f85149?style=flat-square" alt="Security policy"/></a>
</p>

<p align="center">
  <strong>A defensive-first reconnaissance and validation CLI for authorized security work.</strong><br/>
  <sub>Fast HTTP scanning · technology fingerprinting · an evidence-driven decision engine that chains checks and proves what it claims.</sub>
</p>

---

**nice_scan** is a command-line tool for *authorized* security testing. It performs
reconnaissance, fingerprinting, and controlled validation of common web
vulnerabilities, then reports each result at the confidence the evidence actually
supports. It is built to be honest: a finding states whether it was executed and
server-verified, merely observed, or an untested hypothesis — so a report tells
you what is real, not what is scary.

> **Use only on systems you own or are explicitly authorized to test.** See
> [Responsible use](#responsible-use).

## Table of contents

- [Why this design](#why-this-design)
- [Capabilities](#capabilities)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Global flags](#global-flags)
- [The `exploit` modules](#the-exploit-modules)
- [Output and reporting](#output-and-reporting)
- [Supply chain and release integrity](#supply-chain-and-release-integrity)
- [Development](#development)
- [Architecture](#architecture)
- [Documentation](#documentation)
- [Responsible use](#responsible-use)
- [License](#license)

## Why this design

Most scanners drown operators in keyword matches. nice_scan ties every claim to a
concrete verification state:

| Verdict | What it means | How it earns the label |
|---|---|---|
| **Confirmed** | Server-verified | A probe was executed and the target's response carries structural proof (an error oracle, a marked command's output, a canary reflected in an executable context, a session cookie issued only on a valid login). |
| **Observed** | Seen on the target, not exploited | A real signal was directly fetched (a login form, an upload field, a set of exposed headers) with no state-changing action run over it. |
| **Hypothesis** | A chain the engine would attempt | Reported as a plan, never as a breach. |

Two rules follow from this:

1. **Differential baselines, not single responses.** A claim compares against a
   control (a junk-credential round, an anonymous request, the endpoint's own
   modal response size) so the verdict rests on a delta, not a status code.
2. **Consent gates state changes.** Login spray, role/privilege tampering,
   account registration, discovered-credential attempts, and file/command probes
   modify target state. They are **disabled unless you pass `--destructive`** (or
   enable `consent on` in the shell).

## Capabilities

| Area | What nice_scan does |
|---|---|
| **Reconnaissance** | Passive sources (crt.sh, Wayback) that send zero requests to the target · BFS crawl of pages, forms, and JS · path fuzzing · concurrent TCP port scan · S3 bucket enumeration |
| **Fingerprinting** | 165 technology signatures, version extraction, and stack classification cached per target |
| **Validation** | SQLi detection with a differential oracle · LFI detection and bounded file read · canary-based XSS reflection with context classification · login validation against a junk baseline · JWT analysis · GraphQL introspection |
| **Decision engine** | Forward-chaining planner · knowledge base with capability derivation · session/context reuse · attack-chain patterns surfaced as hypotheses |
| **Output** | Terminal report with severity and confidence · live TUI dashboard · interactive REPL shell · JSON for pipelines · HTML engagement report with a findings timeline and evidence |

## Installation

nice_scan ships through **GitHub Releases** and **`go install`** only. There is
no Homebrew tap, Scoop bucket, or Winget identity; any `brew install`,
`scoop install`, or `winget install` command you see elsewhere targets package
IDs this project does not own and is not maintained here.

The installers are **fail-closed**: they resolve a single release tag, verify the
SHA256 checksum and the GPG signature over `checksums.txt` first, and abort with
nothing installed if any step fails.

### Linux and macOS

```bash
curl -sfL https://raw.githubusercontent.com/NICE-DEV226/nice-Scan/main/scripts/install.sh | sh

# The installer drops nice_scan in ~/.local/bin and records it in your shell rc.
# For the CURRENT terminal, pick it up without reopening:
export PATH="$HOME/.local/bin:$PATH"

nice_scan --help
```

The installer places the binary in **`~/.local/bin`** (or, if it builds via
`go install`, in **`$(go env GOPATH)/bin`**) and appends that directory to your
`PATH` in the shell rc file it finds (`.zshrc` / `.bashrc` / `.zprofile` /
`.profile`), so new terminals find it automatically. If you installed through the
`go install` path, export that directory instead:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

> **`nice_scan` "disappears" after a reboot?** It is on disk — it simply is not
> on that login shell's `PATH`. Re-run the export above (or the installer) and it
> is reachable again. The current installer writes the `PATH` line into your rc
> files so the install survives a restart.

### From source with Go (1.24+)

```bash
go install github.com/NICE-DEV226/nice-Scan/cmd/nice_scan@latest
```

`go install` resolves the newest release tag itself. To pin an exact, audited
version (recommended), name the tag instead of `latest`:

```bash
go install github.com/NICE-DEV226/nice-Scan/cmd/nice_scan@v0.3.4
```

### Windows (PowerShell 7+)

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/NICE-DEV226/nice-Scan/main/scripts/install.ps1 -OutFile install.ps1
pwsh -ExecutionPolicy Bypass -File install.ps1
```

### Manual download

Download the archive for your platform from the
[Releases page](https://github.com/NICE-DEV226/nice-Scan/releases), verify it (see
[Release verification](#release-verification)), and install it anywhere on your
`PATH` — for example `/usr/local/bin` on Linux/macOS.

### Build from source

```bash
git clone https://github.com/NICE-DEV226/nice-Scan.git
cd nice-Scan
go build -o nice_scan ./cmd/nice_scan
```

## Quick start

```bash
# Autonomous reconnaissance + validation, with an HTML engagement report
nice_scan hack example.com -R report.html

# Standard scan with a live dashboard
nice_scan scan example.com -i

# Deep audit: verbose, every module in detail, HTML report on by default
nice_scan audit example.com

# Fingerprinting and TLS analysis only
nice_scan tech example.com
nice_scan tls https://example.com

# Targeted exploitation modules (non-destructive by default)
nice_scan exploit https://example.com --idor 1-100 --token

# Interactive REPL shell
nice_scan shell
```

Time-box a run and prove you consented to state-changing checks:

```bash
nice_scan hack example.com --timeout 30s -R report.html --destructive
```

## Commands

| Command | Description |
|---|---|
| `hack <target>` | Autonomous chain — reconnaissance, fingerprinting, validation, and forward-chaining, with optional HTML report |
| `scan <target>` | Standard reconnaissance scan — headers, TLS, fingerprint, endpoints |
| `audit <target>` | Deep scan: forces verbose output, details every module, and writes an HTML report by default |
| `exploit <target>` | Individual exploitation modules (login, IDOR, privesc, token/session reuse) — see below |
| `tech <target>` | Technology fingerprinting only (165 signatures) |
| `tls <target>` | TLS/SSL analysis — ciphers, certificates, protocol versions |
| `shell` | Interactive REPL: run checks against one or more targets, with command history, clipboard copy, and a `consent` toggle |
| `update` | Self-update to the latest release, checksum-verified, with the previous binary kept as `nice_scan.old` for rollback |

Run `nice_scan <command> --help` for each command's full flag set.

## Global flags

| Flag | Default | Description |
|---|---|---|
| `-w, --workers <n>` | `64` | Concurrent workers |
| `--timeout <dur>` | config | Per-request timeout (e.g. `10s`) |
| `--retries <n>` | config | Max retries per request |
| `--rate-limit <n>` | `0` | Requests per second (`0` = unlimited) |
| `--proxy <url>` | — | HTTP proxy URL |
| `--cookie <value>` | — | `Cookie` header included in every request |
| `--header key:value` | — | Custom header, repeatable |
| `--follow-redirects` | `true` | Follow redirects |
| `--max-redirects <n>` | `5` | Redirect hop limit |
| `--allow-out-of-scope` | `false` | **Turn the target boundary off.** By default the target host is a hard limit: a request aimed at another host is refused before anything goes on the wire, and a redirect that leaves it aborts (credentials were already stripped there; the probe itself is now refused too). Use this for a site whose redirects legitimately land on another domain. Passive sources (`crt.sh`, Wayback) and the OOB callback sink have their own clients and are unaffected |
| `--block-internal` | `false` | Refuse to dial addresses that are not globally routable: loopback, RFC1918, link-local (so `169.254.169.254`), CGNAT. The name is resolved and the resolved literal is dialled, which also defeats a hostname pointing inward. Off by default — scanning your own dev server is a legitimate use. Silently disabled under a proxy, which sees the destination instead of us |
| `-j, --json` | `false` | Machine-readable JSON output |
| `-i, --interactive` | `false` | Live TUI dashboard |
| `-R, --report <file>` | — | Write a detailed HTML report |
| `-v, --verbose` | `false` | Verbose output |
| `--destructive` | `false` | **Consent to state-modifying actions** (login spray, role tamper, registration, discovered-credential attempts). Required to enable them; targets must be authorized |
| `--no-update-check` | `false` | Disable the automatic new-release check (also `NICE_SCAN_NO_UPDATE_CHECK=1`) |
| `--version` | — | Print the version |

## The `exploit` modules

Non-destructive by default. Modules that modify target state refuse to run
without `--destructive`.

The boundary is enforced in the package, not only by the flags: `exploit.NewService`
refuses to exist without an explicit target scope and takes consent from
`Config.Destructive` (the `--destructive` flag), so a script, the shell or a model
driving the library inherits the destination allow-list and the consent gate
instead of copying the CLI's checks. The state-changing entry points return
`ErrConsentRequired` **before** they build a request — a refusal costs the target
zero bytes.

| Flag | Module | Consent |
|---|---|---|
| `--idor <start-end>` | IDOR enumeration with a **per-endpoint modal baseline** (only referents that differ from their *own* endpoint are flagged) | no |
| `--token` | Token/session reuse on protected endpoints — tokens are **harvested from the target**; nothing is invented, and an empty harvest is reported honestly | no |
| `--session` | Session cookie hardening on login surfaces (`Secure`/`HttpOnly`, ID entropy). Fixation needs a credentialed login and is reported as *not tested* | no |
| `--reset` | Password-reset flows — user enumeration split and token leaks; sends live mail and can mint tokens | **yes** |
| `--access` | Replays admin paths anonymously vs. with the session — a **differential** access check; reports real gains or states plainly that nothing was verified | no |
| `--creds user:pass` | Attempt a specific credential pair, then attach the session to `--access` verification | no\* |
| `--login` | Credential spray against login forms, verdict differential vs. a junk baseline | **yes** |
| `--role` | Role/privilege escalation via parameters and headers (tampered requests) | **yes** |
| `--register` | Account registration testing (creates state) | **yes** |
| `--all` | Run every module; the destructive ones still require `--destructive` | mixed |

\* An operator-supplied credential is not sprayed at the target beyond the single
attempt; automatic exploitation of *discovered* leaked credentials is consent-gated.

## Output and reporting

`hack` and `audit` render a terminal report grouped by severity, with a
confidence value and an evidence line for each finding. Use `--json` for machine
consumption and `-R report.html` for a shareable engagement report (risk score,
findings timeline, evidence). Extracted artifacts are written under
`reports/<target>/` with restrictive `0700` permissions.

Every finding name and evidence is run through sanitization, and plaintext
secrets are **masked by default** (the provider prefix and the length are
preserved, the value is not) so credentials never leak into terminal
scrollback, JSON, or the HTML report. Masking happens where the credential is
*found*, not only where it is printed: a truncated session token is still the
beginning of a live session token.

`--json` is the machine-facing path and prints nothing but the report — no
banner — so it can be piped straight into `jq` or into a model. Each finding
carries a `grade` (`proven` > `corroborated` > `indicated` > `unverified`) and,
where the engine earned one, a `prov` object naming the request, whether the
path was observed or synthesized, and the differential the claim rests on. That
is what lets an automated consumer rank findings without a human re-reading
every evidence line, and it is why the same masking rules apply there.

The snippet below is **illustrative** — actual findings depend on the target. It
shows the point of the design: nice_scan records an escaped reflection but does
**not** inflate it into an executable-XSS claim, because encoded markup cannot run
as reflected.

```
◈ MEDIUM
  ⚠  Session cookie missing HttpOnly                         92% confidence
     Set-Cookie: sid=<masked len=32>; Secure

◈ LOW
  ○  XSS reflection (escaped)                                45% confidence
     search=&lt;svg onload=alert(…)&gt;   (entity-encoded — does not execute)
```

## Supply chain and release integrity

| Layer | Status | How to verify |
|---|---|---|
| Binary integrity | SHA256 `checksums.txt` published per release | `sha256sum --check <checksums> --ignore-missing` |
| Release authenticity | `checksums.txt` GPG-signed | `gpg --verify <checksums>.sig <checksums>` |
| Build provenance | GitHub provenance attestations for releases cut after 2026-10-24 (not retroactive) | `gh attestation verify <file> -R NICE-DEV226/nice-Scan` |
| SBOM | SPDX SBOM emitted per release | in the release assets |
| Source trust | Commits are **not** systematically GPG-signed | build from a pinned tag and audit it |
| Distribution | GitHub Releases + `go install <tag>` | — |

The pinned maintainer GPG fingerprint is
`4CE466095C5B3185883288C593FBFE29F62FA4DB`, imported on first use from
`keyserver.ubuntu.com` over `hkps`. A key that does not match this fingerprint
makes `install.sh` abort rather than validate an unexpected signature. The full
policy, including the honest limitations of the above, is in
[SECURITY.md](SECURITY.md).

### Release verification

```bash
TAG=v0.3.4
gh release download "$TAG" --pattern "checksums*" -R NICE-DEV226/nice-Scan
sha256sum --check nice_scan_*_checksums.txt --ignore-missing
gpg --verify nice_scan_*_checksums.txt.sig nice_scan_*_checksums.txt
```

For a hardcoded chain of trust, the most verifiable option is always to build
from the tag you audit:

```bash
git clone --branch v0.3.4 --depth 1 https://github.com/NICE-DEV226/nice-Scan.git
cd nice-Scan && go build -o nice_scan ./cmd/nice_scan
```

## Development

```bash
make build            # build the CLI
make test             # run the test suite
make run ARGS="hack example.com --timeout 10s"
make build-all        # cross-compile (linux/windows/darwin, amd64/arm64)
make lint             # golangci-lint (gofmt, staticcheck, …)
make vet              # go vet
make govulncheck      # known-vulnerability scan of dependencies
make snapshot         # local release snapshot (goreleaser)
```

CI (GitHub Actions) enforces, on every push and pull request: `golangci-lint` →
`build` → `go test -race -count=1` → `govulncheck`. A change is not "done" until
CI is green. Contributor details and conventions are in
[CONTRIBUTING.md](CONTRIBUTING.md).

### Architecture

```
cmd/nice_scan/     CLI entry point — Cobra commands, flag wiring, rendering choice
internal/
  hacker/          Decision engine: planner, forward-chaining, knowledge base, actions
  engine/          Analysis modules: SQLi, XSS, CORS, headers, TLS, tokens, auth, creds
  recon/           Evidence service: scoped client + analyzer roster -> graded findings,
                   no rendering (the CLI, the TUI and any scripted caller drive this)
  exploit/         Exploitation modules: login, IDOR, privesc, token, session
  detect/          Shared evidence primitives: canaries and classified reflection
  fingerprint/     Technology fingerprinting (165 signatures, stack classifier)
  transport/       HTTP client: pooling, retries, HTTP/2, session/redirect hops, credentials
  shell/           Interactive REPL (history, clipboard copy, consent toggle)
  tui/             Live terminal dashboard (BubbleTea)
  output/          Renderers: terminal, JSON, HTML
  types/           Shared types, sanitization, secret masking
  update/          Self-update with checksum verification and rollback
scripts/           Install scripts (install.sh, install.ps1)
docs/              Landing page and architecture documentation
```

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — system design
- [docs/architecture/overview.md](docs/architecture/overview.md) — architecture overview
- [docs/architecture/transport.md](docs/architecture/transport.md) — transport layer
- [CONTRIBUTING.md](CONTRIBUTING.md) — development workflow and conventions
- [SECURITY.md](SECURITY.md) — security policy, vulnerability reporting, and the supply-chain inventory

## Responsible use

nice_scan is intended exclusively for **authorized security testing** of systems
you own or have explicit written permission to test. Unauthorized scanning or
exploitation may be illegal in your jurisdiction. The authors accept no
liability for misuse or damage. State-changing capabilities are consent-gated for
this reason, but the gate is a safeguard, not a substitute for authorization — you
are responsible for staying within scope.

To report a vulnerability in nice_scan itself, follow [SECURITY.md](SECURITY.md);
do not open a public issue for an unfixed security problem.

## License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for the full text.

---

<p align="center">
  <sub>Built with <a href="https://go.dev/">Go</a> · <a href="https://github.com/spf13/cobra">Cobra</a> · <a href="https://github.com/charmbracelet/bubbletea">BubbleTea</a> · <a href="https://github.com/charmbracelet/lipgloss">Lipgloss</a></sub>
</p>
