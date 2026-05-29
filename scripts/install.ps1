#!/usr/bin/env pwsh
# NICE_SCAN Installer — Windows (PowerShell 7+)
#
# Downloads the official release from GitHub, verifies the SHA256 checksum,
# and installs to a user-local directory (no admin required).
#
# Usage:
#   powershell -ExecutionPolicy RemoteSigned -File install.ps1
#   winget install NICE-DEV226.nice-Scan              (if configured)
#   scoop install nice-scan                            (if configured)
#
# Trust & Security:
#   - Downloads ONLY via HTTPS from github.com
#   - Verifies SHA256 checksum against published checksums file
#   - Installs to user-local path (no admin, no system-wide changes)
#   - Source code at https://github.com/NICE-DEV226/nice-Scan
#   - All releases signed with GPG — verify with:
#     gh release download --pattern *.sig && gpg --verify nice_scan.exe.sig

param(
    [string]$Version = "latest",
    [switch]$SkipChecksum,
    [switch]$Help
)

if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path
    exit 0
}

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
function Write-Ok($text)  { Write-Host "${Ok}  ${text}" -ForegroundColor Green }
function Write-Warn($text){ Write-Host "${Warn} ${text}" -ForegroundColor Yellow }
function Write-Err($text) { Write-Host "${Err} ${text}" -ForegroundColor Red }

# ── Header ──
Write-Host ""
Write-Host "  ${AppName} Installer" -ForegroundColor Cyan
Write-Host "  ${Repo}" -ForegroundColor DarkGray
Write-Host "  ${('─' * 56)}" -ForegroundColor DarkGray
Write-Host ""

# ── Preflight checks ──
if (-not (Get-Command curl -ErrorAction SilentlyContinue) -and -not (Get-Command Invoke-WebRequest -ErrorAction SilentlyContinue)) {
    Write-Err "No HTTP client found. Install curl or PowerShell 7+."
    exit 1
}

# ── Detect package managers (preferred path — signed packages) ──
if (Get-Command scoop -ErrorAction SilentlyContinue) {
    Write-Step "Scoop detected — installing via official bucket..."
    Write-Host "  → scoop bucket add nice-scan https://github.com/${Repo}"
    Write-Host "  → scoop install nice-scan"
    scoop bucket add nice-scan "https://github.com/${Repo}" 2>&1 | Out-Null
    scoop install nice-scan 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "nice_scan installed via Scoop"
        exit 0
    }
    Write-Warn "Scoop install failed — falling back to manual install."
}

if (Get-Command winget -ErrorAction SilentlyContinue) {
    Write-Step "WinGet detected — installing via official package..."
    Write-Host "  → winget install --id NICE-DEV226.nice-Scan"
    winget install --id NICE-DEV226.nice-Scan 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "nice_scan installed via WinGet"
        exit 0
    }
    Write-Warn "WinGet install failed — falling back to manual install."
}

# ── Go install (trusted — builds from source) ──
if (Get-Command go -ErrorAction SilentlyContinue) {
    $goVer = go version
    if ($goVer -match 'go1\.(2[4-9]|[3-9]\d)') {
        Write-Step "Go $($Matches[0]) detected — installing from source (most trustworthy)..."
        Write-Host "  → go install github.com/${Repo}/cmd/nice_scan@${Version}"
        go install "github.com/${Repo}/cmd/nice_scan@${Version}" 2>&1 | ForEach-Object { "  $_" }
        if ($LASTEXITCODE -eq 0) {
            $goBin = go env GOPATH
            Write-Ok "nice_scan installed to ${goBin}\bin\nice_scan.exe"
            Write-Warn "Ensure ${goBin}\bin is in your PATH"
            exit 0
        }
        Write-Warn "go install failed — falling back to binary download."
    } else {
        Write-Warn "Go version < 1.24 (need 1.24+). Falling back to binary download."
    }
} else {
    Write-Warn "Go not found — will download pre-built binary."
}

# ── Download release ──
Write-Step "Fetching latest release information from GitHub..."
Write-Host "  → https://api.github.com/repos/${Repo}/releases/latest" -ForegroundColor DarkGray

try {
    $release = Invoke-RestMethod "https://api.github.com/repos/${Repo}/releases/latest"
    $tag = $release.tag_name
    Write-Host "  Release: ${tag}" -ForegroundColor DarkGray

    $asset = $release.assets | Where-Object { $_.name -like "*windows*amd64*" } | Select-Object -First 1
    if (-not $asset) {
        $asset = $release.assets | Where-Object { $_.name -like "*windows*" -and $_.name -like "*.zip" } | Select-Object -First 1
    }
    if (-not $asset) {
        throw "No Windows release asset found for ${tag}. Check https://github.com/${Repo}/releases"
    }

    # Also find checksum file
    $checksumAsset = $release.assets | Where-Object { $_.name -like "*checksums*" } | Select-Object -First 1

    $dlPath = "$env:TEMP\nice_scan_${tag}.zip"

    # ── Download ──
    Write-Step "Downloading ${($asset.name)}..."
    Write-Host "  → ${($asset.browser_download_url)}" -ForegroundColor DarkGray
    Write-Host "  → ${($asset.size / 1MB).ToString('F1')} MB" -ForegroundColor DarkGray
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $dlPath -UseBasicParsing

    # ── Verify checksum (if available) ──
    if ($checksumAsset -and -not $SkipChecksum) {
        Write-Step "Verifying SHA256 checksum..."
        $checksumsPath = "$env:TEMP\nice_scan_checksums.txt"
        Invoke-WebRequest -Uri $checksumAsset.browser_download_url -OutFile $checksumsPath -UseBasicParsing
        $expectedHash = (Get-Content $checksumsPath | Where-Object { $_ -match [regex]::Escape($asset.name) } | ForEach-Object { $_ -split '\s+' | Select-Object -First 1 })
        if ($expectedHash) {
            $actualHash = (Get-FileHash -Path $dlPath -Algorithm SHA256).Hash.ToUpper()
            if ($actualHash -ne $expectedHash.ToUpper()) {
                Write-Err "CHECKSUM MISMATCH — download may be tampered!"
                Write-Err "  Expected: ${expectedHash}"
                Write-Err "  Actual:   ${actualHash}"
                Write-Err "  Aborting installation. Do NOT run the downloaded file."
                Remove-Item $dlPath -Force -ErrorAction SilentlyContinue
                exit 1
            }
            Write-Ok "SHA256 checksum verified — file integrity confirmed"
        } else {
            Write-Warn "No matching checksum found for ${($asset.name)} — skipping verification"
        }
        Remove-Item $checksumsPath -Force -ErrorAction SilentlyContinue
    } elseif (-not $SkipChecksum) {
        Write-Warn "No checksum file in release — skipping integrity verification"
        Write-Warn "Recommend verifying manually:"
        Write-Host "  gh release download --pattern checksums -R ${Repo}" -ForegroundColor DarkGray
    }

    # ── Extract ──
    Write-Step "Extracting to ${Dest}..."
    Remove-Item -Path $Dest -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $Dest | Out-Null
    Expand-Archive -Path $dlPath -DestinationPath $Dest -Force
    Remove-Item $dlPath -Force

    # Locate binary (might be in a subdirectory)
    $exePath = Get-ChildItem -Recurse -Path $Dest -Filter $Binary | Select-Object -First 1 -ExpandProperty FullName
    if (-not $exePath) { throw "Binary ${Binary} not found in downloaded archive" }

} catch {
    Write-Err "Release download failed: $_"
    Write-Warn "Falling back to source build..."

    # ── Build from source ──
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        Write-Err "Go is required to build from source. Install Go 1.24+ from https://go.dev/dl/"
        exit 1
    }

    $tmpDir = "$env:TEMP\nice_scan_src_$(Get-Random)"
    New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null

    Write-Step "Cloning source from https://github.com/${Repo}.git..."
    git clone --depth 1 "https://github.com/${Repo}.git" $tmpDir 2>&1 | ForEach-Object { "  $_" }
    if ($LASTEXITCODE -ne 0) { throw "git clone failed" }

    Push-Location $tmpDir
    Write-Step "Building from source (this may take a moment)..."
    go build -ldflags "-s -w -X main.version=${Version}" -o nice_scan.exe ./cmd/nice_scan 2>&1 | ForEach-Object { "  $_" }
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }
    Pop-Location

    New-Item -ItemType Directory -Force -Path $Dest | Out-Null
    Move-Item -Path "${tmpDir}\nice_scan.exe" -Destination "${Dest}\nice_scan.exe" -Force
    Remove-Item -Recurse -Force $tmpDir
    $exePath = "${Dest}\nice_scan.exe"

    Write-Ok "Binary built from source — fully auditable"
}

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

# Check if binary is signed (Windows Authenticode)
$sig = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction SilentlyContinue

# ── Success ──
Write-Host ""
Write-Host ("  " + ("─" * 56)) -ForegroundColor DarkGray
Write-Ok "nice_scan installed successfully"
Write-Host ""
Write-Host "  Location:  ${exePath}" -ForegroundColor DarkGray
Write-Host "  Version:   ${Version}" -ForegroundColor DarkGray
Write-Host "  Size:      ${fileSize} bytes" -ForegroundColor DarkGray
Write-Host "  SHA256:    ${fileHash}" -ForegroundColor DarkGray
if ($sig) {
    Write-Host "  Signed by: $($sig.SignerCertificate.Subject)" -ForegroundColor DarkGray
}
Write-Host ""
Write-Host "  Get started:" -ForegroundColor Cyan
Write-Host "    nice_scan --help" -ForegroundColor White
Write-Host "    nice_scan hack example.com" -ForegroundColor White
Write-Host "    nice_scan hack example.com -R report.html" -ForegroundColor White
Write-Host ""

# ── Security advisory ──
Write-Warn "Only run this tool on systems you own or have explicit permission to test."
Write-Warn "Unauthorized use may violate applicable laws."
Write-Host ""
