# Security Policy

## 🔐 Trust & Verification

NICE_SCAN is a security tool — you should be able to trust that the binary you run is exactly the code published in this repository.

### Supply Chain

| Layer | Protection | How |
|-------|-----------|-----|
| **Source** | Signed commits | All commits are signed with GPG |
| **Build** | Reproducible builds | `go build ./cmd/nice_scan` produces deterministic output |
| **Release** | GPG-signed checksums | Every release's `checksums.txt` is signed with the project GPG key |
| **Provenance** | Sigstore / SLSA | Binaries are attested with cosign for verifiable build provenance |
| **Dependencies** | SBOM | Every release includes an SPDX Software Bill of Materials |
| **Distribution** | Multiple channels | GitHub Releases + go install + Homebrew/Scoop (audited formulas) |

### Verify a Release

```bash
# 1. Download the release assets
gh release download v0.2.0 --pattern "checksums*" -R NICE-DEV226/nice-Scan

# 2. Verify the checksums file SHA256
sha256sum nice_scan_v0.2.0_checksums.txt

# 3. Verify the checksums file was signed by the project
gpg --verify nice_scan_v0.2.0_checksums.txt.sig nice_scan_v0.2.0_checksums.txt

# 4. Verify your downloaded binary matches
sha256sum --check nice_scan_v0.2.0_checksums.txt --ignore-missing

# 5. (Advanced) Verify Sigstore provenance
cosign verify-blob \
  --certificate nice_scan_v0.2.0_checksums.pem \
  --signature nice_scan_v0.2.0_checksums.sig \
  nice_scan_v0.2.0_checksums.txt
```

### Project GPG Key

```
Key ID:      [TBD — generate and publish]
Fingerprint: [TBD — generate and publish]
```

The public key is published at:
- `https://github.com/NICE-DEV226.gpg`
- `https://keys.openpgp.org/`

### Build from Source (Most Trustworthy)

The most trustworthy way to use NICE_SCAN is to build from source:

```bash
git clone https://github.com/NICE-DEV226/nice-Scan.git
cd nice-Scan
go build -o nice_scan ./cmd/nice_scan
```

This lets you audit the code and verify the build is deterministic.

## 🐛 Reporting Vulnerabilities

If you discover a security vulnerability in NICE_SCAN, please report it privately:

1. **Do NOT** open a public GitHub issue
2. Email details to **[TBD — security contact]**
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
- Vulnerabilities in the NICE_SCAN codebase
- Dependency vulnerabilities (reported via SBOM + Dependabot)
- Supply chain security issues

The following are **out of scope**:
- Reports about targets scanned *with* NICE_SCAN (that's your responsibility)
- Theoretical attacks requiring physical access or modified source

## 📦 Dependency Management

Dependencies are tracked via:
- `go.sum` (checksum database)
- Dependabot alerts (automated)
- SBOM in every release (`nice_scan_*_sbom.spdx.json`)
- `golangci-lint` + `govulncheck` in CI
