# Security Policy

## 🔐 Trust & Verification

NICE_SCAN is a security tool — you should be able to trust that the binary you run is exactly the code published in this repository.

### Supply Chain — actual state (honest inventory)

| Layer | Actual State | Notes |
|-------|-------------|-------|
| **Source** | Commits **are not** GPG-signed as a rule | `git log --show-signature` tells you which are; do not assume |
| **Checksums** | `checksums.txt` published per release | SHA256 over every archive |
| **Release signing** | GPG-signed `checksums.txt` when keys are configured | Importers fail closed: a missing checksum/file or failed verification aborts the install (both installers) |
| **Provenance (SLSA/cosign)** | Not yet published | The release workflow includes cosign/syft plumbing, but no `checksums.sigstore.json` bundles nor `gh attestation` artifacts are shipped today. Do not attempt `cosign verify-blob` — there is nothing published to verify against |
| **SBOM** | Intended per release via syft | Verify presence in a given release's assets before relying on it |
| **Distribution** | GitHub Releases + `go install <tag>` | There is **no** Homebrew formula, and **no** winget or scoop package today. The installer installs from GitHub Releases only |

### Verify a Release (works today)

```bash
# 1. Download the release assets
gh release download vX.Y.Z --pattern "checksums*" -R NICE-DEV226/nice-Scan

# 2. Verify the checksums file was signed by the project key (if GPG is set up)
gpg --verify checksums.txt.sig checksums.txt

# 3. Verify your downloaded binary matches
sha256sum --check checksums.txt --ignore-missing
```

The installers (`scripts/install.sh`, `scripts/install.ps1`) do exactly this
and **fail closed**: no checksums file, an uncovered archive or a failed
GPG verification aborts with nothing installed.

> **Trust root:** the GPG key is imported from `https://github.com/NICE-DEV226.gpg` on first use (TOFU). For a stronger setup, verify the key fingerprint out-of-band with the maintainer and remove the auto-import step.

### Project GPG Key

The project GPG key ID/fingerprint will be published here once the release
signing key is finalized. Until then, treat any fingerprint seen in docs,
issues or chat as unverified and confirm it out-of-band.

> Note: `README.md` may reference a historical fingerprint (`4CE4…A4DB`); at this time no key with that fingerprint is bound in this file as authoritative.

### Build from Source (audit path)

The audit path is to build from a **pinned tag**, not a floating branch:

```bash
git clone --branch vX.Y.Z https://github.com/NICE-DEV226/nice-Scan.git
cd nice-Scan
go build -o nice_scan ./cmd/nice_scan
sha256sum nice_scan   # compare against your own audit, not a published sum
```

This lets you audit the exact tag before running the binary.

## 🐛 Reporting Vulnerabilities

If you discover a security vulnerability in NICE_SCAN, please report it privately:

1. **Do NOT** open a public GitHub issue
2. Use GitHub's "Report a vulnerability" (Security Advisories → Private reporting) on this repository; maintainers receive it privately
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected versions
   - Potential impact

### Response Timeline

| Timeframe | Action |
|-----------|--------|
| 48 hours | Acknowledgment of receipt |
| 7 days | Initial assessment and mitigation plan |
| 30 days | Fix released (depending on severity) |

### Scope

The following are **in scope**:
- Vulnerabilities in the NICE_SCAN codebase (transport, scanner, report, shell, installer, CI)
- Dependency vulnerabilities
- Supply chain security issues

The following are **out of scope**:
- Reports about targets scanned *with* NICE_SCAN (that's your responsibility)
- Theoretical attacks requiring physical access or modified source
- Social-engineering of terminal/emulator bugs that do not involve a nice_scan defect

## 📦 Dependency Management

Dependencies are tracked via:
- `go.sum` (checksum database)
- Dependabot alerts (automated)
- SBOM when published with a release (`nice_scan_*_sbom.spdx.json`)
- `golangci-lint` in CI (pinned version)

## 📜 Honesty Statement

- The scanner reports risk only from **executed evidence**: credentials that
  actually authenticated, secret files actually read, tokens actually
  accepted. Text found on a page mentioning "admin"/"login"/"secret" is
  tracked as a *hint* (`?name` in the output) and cannot trigger
  credentialed actions or risk escalations.
- The interactive session binds operator cookie/headers to the scanned host
  and never replays them to cross-host redirects or third-party recon APIs.
- Claims about the tool's own supply chain that are not implemented today
  are marked "Not yet published" rather than asserted.
