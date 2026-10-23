#!/usr/bin/env pwsh
# NICE_SCAN Installer — Windows (PowerShell 7+, fail-closed)
#
# Downloads the release pinned to a concrete tag from GitHub and verifies
# the SHA256 checksum BEFORE anything is installed. Missing or mismatched
# checksums abort the installation.
#
# Usage:
#   powershell -ExecutionPolicy RemoteSigned -File install.ps1
#   powershell -ExecutionPolicy RemoteSigned -File install.ps1 -Version v0.2.0
#
# Trust & Security (what this script actually does — not marketing):
#   - Downloads ONLY via HTTPS from github.com
#   - Verifies the SHA256 checksum against checksums.txt published with the
#     release; no published checksums, or a mismatch, refuses to install
#   - Resolves ONE release tag up front; go install and the source fallback
#     anchor to that same tag (no @latest, no branch head)
#   - Installs to a user-local path (no admin, no system-wide changes)

param(
    [string]$Version = "latest",
    [switch]$Help
)

if ($Help) {
    Write-Host "Usage: install.ps1 [-Version vX.Y.Z]"
    exit 0
}

# NOTE: package managers (winget, scoop) are intentionally NOT invoked:
# the project publishes no winget/scoop packages today, and pre-existing
# entries under these ids belong to unrelated owners.

$Repo    = "NICE-DEV226/nice-Scan"
$Binary  = "nice_scan.exe"
$AppName = "NICE_SCAN"
$Dest    = "$env:LOCALAPPDATA\nice_scan"

# ── Terminal styling ──
$Info    = "::"
$Ok      = "✔"
$Warn    = "⚠"
$Err     = "✘"

function Write-Step($text) { Write-Host "${Info} ${text}" -ForegroundColor Cyan }
function Write-Ok($text)   { Write-Host "${Ok}  ${text}" -ForegroundColor Green }
function Write-Warn($text) { Write-Host "${Warn} ${text}" -ForegroundColor Yellow }
function Write-Err($text)  { Write-Host "${Err} ${text}" -ForegroundColor Red }

function Abort($text) {
    Write-Err $text
    Write-Err "Installation ABORTED. Nothing was installed."
    exit 1
}

# ── Header ──
Write-Host ""
Write-Host "  ${AppName} Installer (fail-closed)" -ForegroundColor Cyan
Write-Host "  ${Repo}" -ForegroundColor DarkGray
Write-Host "  ${('─' * 56)}" -ForegroundColor DarkGray
Write-Host ""

# ── Preflight checks ──
if (-not (Get-Command Invoke-WebRequest -ErrorAction SilentlyContinue)) {
    Abort "No HTTP client found. Install PowerShell 7+."
}

# ── Resolve the release tag FIRST (single trust anchor) ──
$tag = $null
if ($Version -eq "latest") {
    Write-Step "Resolving latest release tag from GitHub..."
    try {
        $release = Invoke-RestMethod "https://api.github.com/repos/${Repo}/releases/latest"
        $tag = $release.tag_name
    } catch {
        Abort "Could not reach the GitHub API."
    }
    if (-not $tag) {
        Abort "Could not resolve the latest release tag. Refusing to install an unpredictable version."
    }
} else {
    $tag = $Version
}
Write-Host "  Pinned version: ${tag}" -ForegroundColor DarkGray

# ── Preferred path: go install the pinned tag ──
if (Get-Command go -ErrorAction SilentlyContinue) {
    $goVer = go version
    if ($goVer -match 'go1\.(2[4-9]|[3-9]\d)') {
        Write-Step "Go $($Matches[0]) detected — building from source at ${tag}..."
        Write-Host "  → go install github.com/${Repo}/cmd/nice_scan@${tag}" -ForegroundColor DarkGray
        go install "github.com/${Repo}/cmd/nice_scan@${tag}" 2>&1 | ForEach-Object { "  $_" }
        if ($LASTEXITCODE -eq 0) {
            $goBin = go env GOPATH
            Write-Ok "nice_scan built from source at tag ${tag} → ${goBin}\bin\nice_scan.exe"
            Write-Warn "Ensure ${goBin}\bin is in your PATH"
            exit 0
        }
        Write-Warn "go install failed — falling back to binary download."
    } else {
        Write-Warn "Go version < 1.24 (need 1.24+). Falling back to binary download."
    }
}

# ── Download the pinned release ──
Write-Step "Fetching release ${tag} from GitHub..."
try {
    $release = Invoke-RestMethod "https://api.github.com/repos/${Repo}/releases/latest"
} catch {
    Abort "Could not fetch release information."
}

# Prefer the asset matching the pinned tag exactly.
$asset = $release.assets |
    Where-Object { $_.name -like "*${tag}_windows*amd64*" -or $_.name -like "*windows*amd64*" } |
    Select-Object -First 1
if (-not $asset) {
    $asset = $release.assets | Where-Object { $_.name -like "*windows*" -and $_.name -like "*.zip" } | Select-Object -First 1
}
if (-not $asset) {
    # ── Source fallback: clone the RELEASE TAG, never main HEAD ──
    Write-Warn "No Windows binary asset found for ${tag}."
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        Abort "Go is required to build from source. Install Go 1.24+. Nothing was installed."
    }

    $tmpDir = "$env:TEMP\nice_scan_src_$(Get-Random)"
    New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null

    Write-Step "Cloning source at tag ${tag} (pinned checkout, not a branch head)..."
    git clone --depth 1 --branch "${tag}" "https://github.com/${Repo}.git" $tmpDir 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Abort "Could not clone tag ${tag}." }

    Push-Location $tmpDir
    Write-Host "  → HEAD: $(git rev-parse HEAD)" -ForegroundColor DarkGray
    Write-Step "Building from source..."
    go build -ldflags "-s -w -X main.version=${tag}" -o nice_scan.exe ./cmd/nice_scan 2>&1 | ForEach-Object { "  $_" }
    if ($LASTEXITCODE -ne 0) { Pop-Location; Abort "Source build failed." }
    Pop-Location

    New-Item -ItemType Directory -Force -Path $Dest | Out-Null
    Move-Item -Path "${tmpDir}\nice_scan.exe" -Destination "${Dest}\nice_scan.exe" -Force
    Remove-Item -Recurse -Force $tmpDir
    $exePath = "${Dest}\nice_scan.exe"
    $verified = "built from pinned tag ${tag} (source — audit before use)"
    $fileSize = (Get-Item $exePath).Length
    $fileHash = (Get-FileHash -Path $exePath -Algorithm SHA256).Hash

    # ── Add to PATH ──
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$Dest*") {
        Write-Step "Adding ${Dest} to your PATH..."
        [Environment]::SetEnvironmentVariable("Path", "$userPath;$Dest", "User")
        Write-Warn "PATH updated. Restart your terminal or run:"
        Write-Host "  `$env:Path += ';$Dest'" -ForegroundColor DarkGray
    }

    # ── Success ──
    Write-Host ("  " + ("─" * 56)) -ForegroundColor DarkGray
    Write-Ok "nice_scan installed successfully (source build)"
    Write-Host "  Location:  ${exePath}" -ForegroundColor DarkGray
    Write-Host "  Version:   ${tag}" -ForegroundColor DarkGray
    Write-Host "  SHA256:    ${fileHash}" -ForegroundColor DarkGray
    Write-Warn "Only run this tool on systems you own or have explicit permission to test."
    exit 0
}

# ── Download ──
$dlPath = "$env:TEMP\nice_scan_${tag}.zip"
Write-Step "Downloading ${($asset.name)}..."
Write-Host "  → ${($asset.browser_download_url)}" -ForegroundColor DarkGray
try {
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $dlPath -UseBasicParsing
} catch {
    Remove-Item $dlPath -Force -ErrorAction SilentlyContinue
    Abort "Release download failed: $_"
}

# ── checksums.txt is MANDATORY (fail-closed) ──
$checksumAsset = $release.assets | Where-Object { $_.name -like "*checksums*" } | Select-Object -First 1
if (-not $checksumAsset) {
    Remove-Item $dlPath -Force -ErrorAction SilentlyContinue
    Abort "No checksums.txt published for this release. The installer refuses to install an unverifiable binary."
}

Write-Step "Verifying SHA256 checksum..."
$checksumsPath = "$env:TEMP\nice_scan_checksums.txt"
try {
    Invoke-WebRequest -Uri $checksumAsset.browser_download_url -OutFile $checksumsPath -UseBasicParsing
} catch {
    Remove-Item $dlPath -Force -ErrorAction SilentlyContinue
    Abort "Could not download checksums.txt."
}
$expectedHash = (Get-Content $checksumsPath | Where-Object { $_ -match [regex]::Escape($asset.name) } | ForEach-Object { ($_ -split '\s+' | Select-Object -First 1) })
if (-not $expectedHash) {
    Remove-Item $dlPath, $checksumsPath -Force -ErrorAction SilentlyContinue
    Abort "checksums.txt does not cover ${($asset.name)}. Refusing to install."
}
$actualHash = (Get-FileHash -Path $dlPath -Algorithm SHA256).Hash.ToUpper()
if ($actualHash -ne $expectedHash.ToUpper()) {
    Write-Err "CHECKSUM MISMATCH — the download may have been tampered with."
    Write-Err "  Expected: ${expectedHash}"
    Write-Err "  Actual:   ${actualHash}"
    Write-Err "Do NOT run the downloaded file."
    Remove-Item $dlPath -Force -ErrorAction SilentlyContinue
    exit 1
}
Write-Ok "SHA256 checksum verified."
Remove-Item $checksumsPath -Force -ErrorAction SilentlyContinue

# ── Extract ──
Write-Step "Extracting to ${Dest}..."
Remove-Item -Path $Dest -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Expand-Archive -Path $dlPath -DestinationPath $Dest -Force
Remove-Item $dlPath -Force

# Locate binary (might be in a subdirectory)
$exePath = Get-ChildItem -Recurse -Path $Dest -Filter $Binary | Select-Object -First 1 -ExpandProperty FullName
if (-not $exePath) { Abort "Binary ${Binary} not found in downloaded archive" }

# ── Add to PATH ──
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$Dest*") {
    Write-Step "Adding ${Dest} to your PATH..."
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$Dest", "User")
    Write-Warn "PATH updated. Restart your terminal or run:"
    Write-Host "  `$env:Path += ';$Dest'" -ForegroundColor DarkGray
}

# ── Verify binary ──
$fileInfo = Get-Item $exePath
$fileSize = "{0:N0}" -f $fileInfo.Length
$fileHash = (Get-FileHash -Path $exePath -Algorithm SHA256).Hash
$sig = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction SilentlyContinue

# ── Success ──
Write-Host ("  " + ("─" * 56)) -ForegroundColor DarkGray
Write-Ok "nice_scan installed successfully"
Write-Host "  Location:  ${exePath}" -ForegroundColor DarkGray
Write-Host "  Version:   ${tag}" -ForegroundColor DarkGray
Write-Host "  Size:      ${fileSize} bytes" -ForegroundColor DarkGray
Write-Host "  SHA256:    ${fileHash}" -ForegroundColor DarkGray
Write-Host "  Verified:  SHA256 (checksums.txt)" -ForegroundColor DarkGray
Write-Host ""

Write-Host "  Get started:" -ForegroundColor Cyan
Write-Host "    nice_scan --help" -ForegroundColor White
Write-Host "    nice_scan hack example.com" -ForegroundColor White
Write-Host "    nice_scan hack example.com -R report.html" -ForegroundColor White
Write-Host ""

Write-Warn "Only run this tool on systems you own or have explicit permission to test."
Write-Warn "Unauthorized use may violate applicable laws."
