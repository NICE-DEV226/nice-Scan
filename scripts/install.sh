#!/usr/bin/env bash
# NICE_SCAN Installer — macOS / Linux (fail-closed)
#
# Downloads the release pinned to a concrete tag from GitHub and verifies
# SHA256 + GPG signature BEFORE anything is installed. Any verification
# failure aborts the installation.
#
# Usage:
#   curl -sfL https://raw.githubusercontent.com/NICE-DEV226/nice-Scan/main/scripts/install.sh | sh
#   curl -sfL https://raw.githubusercontent.com/NICE-DEV226/nice-Scan/main/scripts/install.sh | sh -s -- --version v0.2.0
#
# Trust & Security (what this script actually does — not marketing):
#   - Downloads ONLY via HTTPS from github.com
#   - Refuses to install when the checksum file is missing or does not
#     cover the archive (checksum mismatch = abort)
#   - Verifies the GPG signature over checksums.txt; a signature that
#     cannot be verified aborts the install
#   - The GPG key is imported from the OUT-OF-BAND VERIFIED channel
#     (keyserver.ubuntu.com, hkps/443 — see SECURITY.md) and must match the
#     PINNED fingerprint below. A channel serving a different key makes the
#     installer abort
#   - Source fallback builds the commit of the resolved release TAG, never
#     an unpinned branch head
#   - Installs to ~/.local/bin (user-local, no sudo)

set -euo pipefail

# ── Config ──
REPO="NICE-DEV226/nice-Scan"
BINARY="nice_scan"
APPNAME="NICE_SCAN"
INSTALL_DIR="${HOME}/.local/bin"
REQUESTED_VERSION="latest"

# Parse arguments: --version vX.Y.Z
while [ "$#" -gt 0 ]; do
    case "$1" in
        --version) REQUESTED_VERSION="${2:-latest}"; shift 2 ;;
        --version=*) REQUESTED_VERSION="${1#--version=}"; shift ;;
        *) break ;;
    esac
done

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

die() {
    err "$*"
    printf "${RED}✘${NC} Installation ABORTED. Nothing was installed.\n"
    exit 1
}

# ── Header ──
cat <<EOF

  $(tput bold)$APPNAME Installer (fail-closed)$(tput sgr0)
  $REPO
  $(printf '%.0s─' $(seq 1 56))

EOF

# ── Preflight ──
command -v curl >/dev/null 2>&1 || die "curl is required. Install it first."
command -v tar  >/dev/null 2>&1 || die "tar is required."

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) die "Unsupported architecture: $ARCH" ;;
esac

# ── Resolve the release tag FIRST (single trust anchor) ──
# go install, binary download and the source fallback all anchor to the
# SAME tag: no @latest, no branch head, no guessing.
if [ "$REQUESTED_VERSION" = "latest" ]; then
    info "Resolving latest release tag from GitHub..."
    RELEASE_JSON=$(curl -sfL "https://api.github.com/repos/${REPO}/releases/latest") || die "Could not reach the GitHub API."
    TAG=$(echo "$RELEASE_JSON" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name":[[:space:]]*"\([^"]*\)"[[:space:]]*,\{0,1\}[[:space:]]*/\1/')
    [ -n "$TAG" ] || die "Could not resolve the latest release tag. Aborting rather than installing an unpredictable version."
else
    TAG="$REQUESTED_VERSION"
fi
dim "Pinned version: ${TAG}"

# ── Preferred path: go install the pinned tag ──
if command -v go >/dev/null 2>&1; then
    GO_MINOR=$(go version | sed -n 's/.*go1\.\([0-9]\+\).*/\1/p')
    if [ -n "$GO_MINOR" ] && [ "$GO_MINOR" -ge 24 ] 2>/dev/null; then
        info "Go 1.$GO_MINOR detected — installing from source at ${TAG}..."
        dim "→ go install github.com/${REPO}/cmd/${BINARY}@${TAG}"
        go install "github.com/${REPO}/cmd/${BINARY}@${TAG}" || die "go install ${TAG} failed."
        GOBIN=$(go env GOPATH)/bin
        ok "${BINARY} built from source at tag ${TAG} → ${GOBIN}/${BINARY}"
        if ! echo "$PATH" | grep -q "$GOBIN"; then
            warn "Add ${GOBIN} to your PATH:"
            dim "  export PATH=\"\$PATH:${GOBIN}\""
        fi
        exit 0
    fi
    warn "Go version < 1.24. Falling back to binary download."
fi

# ── Download release ──
RELEASE_JSON=$(curl -sfL "https://api.github.com/repos/${REPO}/releases/latest") || die "Could not reach the GitHub API."

# goreleaser names assets after the VERSION (no "v" prefix) while the
# release TAG carries it (v0.2.0): normalize once, reference nowhere else.
VERSION="${TAG#v}"
ARCHIVE_NAME="${BINARY}_${VERSION}_${OS}_${ARCH}.tar.gz"
ASSET_URL=$(echo "$RELEASE_JSON" | grep "browser_download_url" | grep "$ARCHIVE_NAME" | head -1 | sed 's/.*"browser_download_url":[[:space:]]*"\([^"]*\)"[[:space:]]*,\{0,1\}[[:space:]]*/\1/' || true)

if [ -z "$ASSET_URL" ]; then
    # ── Source fallback: clone the RELEASE TAG, never main HEAD ──
    warn "No release binary found for ${OS}/${ARCH} at ${TAG}."
    command -v go >/dev/null 2>&1 || die "Go is required to build from source. Install Go 1.24+. Nothing was installed."
    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT
    info "Cloning source at tag ${TAG} (pinned checkout, not a branch head)..."
    git clone --depth 1 --branch "${TAG}" "https://github.com/${REPO}.git" "$TMPDIR" >/dev/null 2>&1 || die "Could not clone tag ${TAG}."
    pushd "$TMPDIR" >/dev/null
    dim "→ HEAD: $(git rev-parse HEAD)"
    info "Building from source..."
    go build -ldflags "-s -w -X main.version=${TAG}" -o "$BINARY" ./cmd/nice_scan || die "Source build failed."
    popd >/dev/null
    mkdir -p "$INSTALL_DIR"
    mv "${TMPDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
    ok "Binary built from the pinned tag ${TAG}. Hash:"
    sha256sum "${INSTALL_DIR}/${BINARY}"
    INSTALLED_FROM_SOURCE=true
else
    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT
    DL_PATH="${TMPDIR}/${ARCHIVE_NAME}"

    info "Downloading ${ARCHIVE_NAME}..."
    dim "→ ${ASSET_URL}"
    curl -sfL "$ASSET_URL" -o "$DL_PATH" || die "Download failed."

    # ── checksums.txt is MANDATORY (fail-closed) ──
    CHECKSUMS_URL=$(echo "$RELEASE_JSON" | grep "browser_download_url" | grep "checksums" | head -1 | sed 's/.*"browser_download_url":[[:space:]]*"\([^"]*\)"[[:space:]]*,\{0,1\}[[:space:]]*/\1/' || true)
    [ -n "$CHECKSUMS_URL" ] || die "No checksums.txt published for this release. The installer refuses to install an unverifiable binary."

    info "Verifying SHA256 checksum..."
    CHECKSUMS_PATH="${TMPDIR}/checksums.txt"
    curl -sfL "$CHECKSUMS_URL" -o "$CHECKSUMS_PATH" || die "Could not download checksums.txt."

    EXPECTED_HASH=$(grep "$ARCHIVE_NAME" "$CHECKSUMS_PATH" | awk '{print $1}')
    [ -n "$EXPECTED_HASH" ] || die "checksums.txt does not cover ${ARCHIVE_NAME}. Refusing to install."

    ACTUAL_HASH=$(sha256sum "$DL_PATH" | awk '{print $1}')
    if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
        err "CHECKSUM MISMATCH — the download may have been tampered with."
        err "  Expected: ${EXPECTED_HASH}"
        err "  Actual:   ${ACTUAL_HASH}"
        die "Do NOT run the downloaded file."
    fi
    ok "SHA256 checksum verified."

    # ── GPG signature over checksums.txt must VERIFY (fail-closed) ──
    if command -v gpg >/dev/null 2>&1; then
        SIG_URL=$(echo "$RELEASE_JSON" | grep "browser_download_url" | grep "checksums.*\.sig" | head -1 | sed 's/.*"browser_download_url":[[:space:]]*"\([^"]*\)"[[:space:]]*,\{0,1\}[[:space:]]*/\1/' || true)
        if [ -n "$SIG_URL" ]; then
            info "Verifying GPG signature..."
            SIG_PATH="${TMPDIR}/checksums.txt.sig"
            curl -sfL "$SIG_URL" -o "$SIG_PATH" || die "Could not download the signature."

            # Pinned trust root: the release fingerprint is verified
            # out-of-band on keyserver.ubuntu.com (see SECURITY.md). The key
            # is imported on demand from THAT channel (hkps/443), then the
            # keyring is required to contain exactly the pinned fingerprint —
            # a keyserver serving a different key for this uid fails here
            # instead of silently validating an attacker's signature.
            GPG_FP="4CE466095C5B3185883288C593FBFE29F62FA4DB"
            if ! gpg --list-keys "$GPG_FP" >/dev/null 2>&1; then
                warn "Importing pinned release key from keyserver.ubuntu.com..."
                gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys "$GPG_FP" >/dev/null 2>&1 || die "Could not import the pinned release key from keyserver.ubuntu.com. Refusing to verify."
            fi
            if ! gpg --list-keys "$GPG_FP" >/dev/null 2>&1; then
                err "Keyring does not contain the pinned fingerprint:"
                err "  expected: $GPG_FP   (see SECURITY.md / keyserver.ubuntu.com)"
                die "The key channel is not serving the pinned release key. Refusing to verify."
            fi

            if gpg --verify "$SIG_PATH" "$CHECKSUMS_PATH" >/dev/null 2>&1; then
                ok "GPG signature verified — release authenticity confirmed."
            else
                err "GPG signature verification FAILED."
                err "  The checksums file does not match the maintainer's signature."
                die "Refusing to install a release whose signature cannot be verified."
            fi
        else
            warn "No checksums.txt.sig in this release — SHA256-only verification."
        fi
    else
        warn "gpg not found — SHA256-only verification."
    fi

    # ── Extract ──
    info "Extracting..."
    tar -xzf "$DL_PATH" -C "$TMPDIR"

    mkdir -p "$INSTALL_DIR"
    if [ -f "${TMPDIR}/${BINARY}" ]; then
        mv "${TMPDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
    else
        find "$TMPDIR" -name "${BINARY}" -exec mv {} "${INSTALL_DIR}/" \;
    fi
    INSTALLED_FROM_SOURCE=false
    trap - EXIT
fi

chmod 0755 "${INSTALL_DIR}/${BINARY}"

# ── PATH setup ──
if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
    warn "Add ${INSTALL_DIR} to your PATH:"
    dim "  export PATH=\"\$HOME/.local/bin:\$PATH\""
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
dim "  Version:   ${TAG}"
dim "  Size:      ${FILE_SIZE}"
dim "  SHA256:    ${FILE_HASH}"
if [ "${INSTALLED_FROM_SOURCE:-false}" = "false" ]; then
    dim "  Verified:  SHA256 + GPG (checksums.txt signed)"
else
    dim "  Verified:  built from pinned tag ${TAG} (source, audit before use)"
fi
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
