#!/usr/bin/env bash
# NICE_SCAN Installer — macOS / Linux
#
# Downloads the official release from GitHub, verifies SHA256 + GPG signature,
# and installs to ~/.local/bin (no sudo required).
#
# Usage:
#   curl -sfL https://raw.githubusercontent.com/NICE-DEV226/nice-Scan/main/scripts/install.sh | sh
#   curl -sfL https://raw.githubusercontent.com/NICE-DEV226/nice-Scan/main/scripts/install.sh | sh -s -- --version v0.2.0
#
# Trust & Security:
#   - Downloads ONLY via HTTPS from github.com
#   - Verifies SHA256 checksum against published checksums file
#   - Verifies GPG signature when possible (requires gpg + cosign)
#   - Installs to ~/.local/bin (user-local, no sudo)
#   - Source code at https://github.com/NICE-DEV226/nice-Scan
#   - Repo GPG key: https://github.com/NICE-DEV226.gpg

set -euo pipefail

# ── Config ──
REPO="NICE-DEV226/nice-Scan"
BINARY="nice_scan"
APPNAME="NICE_SCAN"
INSTALL_DIR="${HOME}/.local/bin"
VERSION="${1:-latest}"

# ── Colors ──
RED='\033[0;31m'
GREEN='\033[0;32m'  
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
DIM='\033[2m'
NC='\033[0m'

info()  { printf "${CYAN}::${NC} %s\n" "$*"; }
ok()    { printf "${GREEN}✔${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}⚠${NC} %s\n" "$*"; }
err()   { printf "${RED}✘${NC} %s\n" "$*"; }
dim()   { printf "${DIM}%s${NC}\n" "$*"; }

# ── Header ──
cat <<EOF

  $(tput bold)$APPNAME Installer$(tput sgr0)
  $REPO
  $(printf '%.0s─' $(seq 1 56))

EOF

# ── Preflight ──
if ! command -v curl &>/dev/null; then
    err "curl is required. Install it first."
    exit 1
fi

if ! command -v tar &>/dev/null; then
    err "tar is required."
    exit 1
fi

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) err "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# ── Go install (most trustworthy — builds from auditable source) ──
if command -v go &>/dev/null; then
    GO_MINOR=$(go version | sed -n 's/.*go1\.\([0-9]\+\).*/\1/p')
    if [ -n "$GO_MINOR" ] && [ "$GO_MINOR" -ge 24 ] 2>/dev/null; then
        info "Go 1.$GO_MINOR detected — installing from source (most trustworthy)..."
        dim "→ go install github.com/${REPO}/cmd/${BINARY}@${VERSION}"
        go install "github.com/${REPO}/cmd/${BINARY}@${VERSION}"
        GOBIN=$(go env GOPATH)/bin
        ok "${BINARY} installed to ${GOBIN}/${BINARY}"
        if ! echo "$PATH" | grep -q "$GOBIN"; then
            warn "Add ${GOBIN} to your PATH:"
            dim "  export PATH=\"\$PATH:${GOBIN}\""
        fi
        exit 0
    fi
    warn "Go version < 1.24. Falling back to binary download."
fi

# ── Download release ──
info "Fetching latest release from GitHub..."
dim "→ https://api.github.com/repos/${REPO}/releases/latest"

RELEASE_JSON=$(curl -sfL "https://api.github.com/repos/${REPO}/releases/latest")
TAG=$(echo "$RELEASE_JSON" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": "\(.*\)",/\1/')
dim "Release: ${TAG}"

ARCHIVE_NAME="${BINARY}_${TAG}_${OS}_${ARCH}.tar.gz"
ASSET_URL=$(echo "$RELEASE_JSON" | grep "browser_download_url" | grep "$ARCHIVE_NAME" | head -1 | sed 's/.*"browser_download_url": "\(.*\)",/\1/')

if [ -z "$ASSET_URL" ]; then
    err "No release binary found for ${OS}/${ARCH}."
    err "Check https://github.com/${REPO}/releases"
    warn "Falling back to source build..."
    if ! command -v go &>/dev/null; then
        err "Go is required. Install Go 1.24+ from https://go.dev/dl/"
        exit 1
    fi
    TMPDIR=$(mktemp -d)
    info "Cloning source from https://github.com/${REPO}.git..."
    git clone --depth 1 "https://github.com/${REPO}.git" "$TMPDIR" 2>&1 | sed 's/^/  /'
    pushd "$TMPDIR" >/dev/null
    info "Building from source..."
    go build -ldflags "-s -w -X main.version=${VERSION}" -o "$BINARY" ./cmd/nice_scan 2>&1 | sed 's/^/  /'
    popd >/dev/null
    mkdir -p "$INSTALL_DIR"
    mv "${TMPDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
    rm -rf "$TMPDIR"
    ok "Binary built from source — fully auditable"
    INSTALLED_FROM_SOURCE=true
else
    TMPDIR=$(mktemp -d)
    DL_PATH="${TMPDIR}/${ARCHIVE_NAME}"

    info "Downloading ${ARCHIVE_NAME}..."
    dim "→ ${ASSET_URL}"
    curl -sfL "$ASSET_URL" -o "$DL_PATH"

    # ── Download checksums ──
    CHECKSUMS_URL=$(echo "$RELEASE_JSON" | grep "browser_download_url" | grep "checksums" | head -1 | sed 's/.*"browser_download_url": "\(.*\)",/\1/' || true)
    
    if [ -n "$CHECKSUMS_URL" ]; then
        info "Verifying SHA256 checksum..."
        CHECKSUMS_PATH="${TMPDIR}/checksums.txt"
        curl -sfL "$CHECKSUMS_URL" -o "$CHECKSUMS_PATH"
        
        EXPECTED_HASH=$(grep "$ARCHIVE_NAME" "$CHECKSUMS_PATH" | awk '{print $1}')
        if [ -n "$EXPECTED_HASH" ]; then
            ACTUAL_HASH=$(sha256sum "$DL_PATH" | awk '{print $1}')
            if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
                err "CHECKSUM MISMATCH — download may be tampered!"
                err "  Expected: ${EXPECTED_HASH}"
                err "  Actual:   ${ACTUAL_HASH}"
                err "  Aborting installation. Do NOT run the downloaded file."
                rm -rf "$TMPDIR"
                exit 1
            fi
            ok "SHA256 checksum verified — file integrity confirmed"
        else
            warn "No matching checksum found — skipping verification"
        fi

        # ── GPG verification (if available) ──
        if command -v gpg &>/dev/null; then
            SIG_URL=$(echo "$RELEASE_JSON" | grep "browser_download_url" | grep "checksums.*\.sig" | head -1 | sed 's/.*"browser_download_url": "\(.*\)",/\1/' || true)
            if [ -n "$SIG_URL" ]; then
                info "Verifying GPG signature..."
                SIG_PATH="${TMPDIR}/checksums.txt.sig"
                curl -sfL "$SIG_URL" -o "$SIG_PATH"
                
                # Import repo's public key if not already trusted
                gpg --list-keys "NICE-DEV226" &>/dev/null || {
                    warn "Importing NICE-DEV226 GPG key..."
                    curl -sfL "https://github.com/NICE-DEV226.gpg" | gpg --import 2>&1 | sed 's/^/  /'
                }
                
                if gpg --verify "$SIG_PATH" "$CHECKSUMS_PATH" 2>&1; then
                    ok "GPG signature verified — release authenticity confirmed"
                else
                    warn "GPG signature could not be verified (key may need trust)"
                    dim "  Run: gpg --keyserver keys.openpgp.org --search-keys NICE-DEV226"
                fi
            fi
        fi
    else
        warn "No checksum file in release — skipping integrity verification"
        warn "Verify manually: gh release download --pattern checksums -R ${REPO}"
    fi

    # ── Extract ──
    info "Extracting..."
    tar -xzf "$DL_PATH" -C "$TMPDIR"
    
    mkdir -p "$INSTALL_DIR"
    # Handle different archive structures
    if [ -f "${TMPDIR}/${BINARY}" ]; then
        mv "${TMPDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
    else
        find "$TMPDIR" -name "${BINARY}" -exec mv {} "${INSTALL_DIR}/" \;
    fi
    rm -rf "$TMPDIR"
    INSTALLED_FROM_SOURCE=false
fi

chmod +x "${INSTALL_DIR}/${BINARY}"

# ── PATH setup ──
if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
    warn "Add ${INSTALL_DIR} to your PATH:"
    dim "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    # Auto-add to shell config
    for RC in "${HOME}/.bashrc" "${HOME}/.zshrc"; do
        if [ -f "$RC" ] && ! grep -q "\.local/bin" "$RC" 2>/dev/null; then
            echo "" >> "$RC"
            echo "# Added by nice_scan installer" >> "$RC"
            echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$RC"
            dim "  Added to ${RC}"
        fi
    done
fi

# ── Binary info ──
FILE_SIZE=$(ls -lh "${INSTALL_DIR}/${BINARY}" | awk '{print $5}')
FILE_HASH=$(sha256sum "${INSTALL_DIR}/${BINARY}" | awk '{print $1}')

# ── Success ──
echo ""
printf "  $(tput dim)%s$(tput sgr0)\n" "$(printf '%.0s─' $(seq 1 56))"
ok "${BINARY} installed successfully"
echo ""
dim "  Location:  ${INSTALL_DIR}/${BINARY}"
dim "  Version:   ${VERSION}"
dim "  Size:      ${FILE_SIZE}"
dim "  SHA256:    ${FILE_HASH}"
echo ""
info "Get started:"
echo "    nice_scan --help"
echo "    nice_scan hack example.com"
echo "    nice_scan hack example.com -R report.html"
echo ""

# ── Security advisory ──
warn "Only run this tool on systems you own or have explicit permission to test."
warn "Unauthorized use may violate applicable laws."
echo ""
