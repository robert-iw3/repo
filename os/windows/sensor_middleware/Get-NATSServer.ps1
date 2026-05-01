<#
.SYNOPSIS
    Downloads NATS Server v2.14.0 (Windows AMD64) with SHA-256 validation.
.NOTES
    Run from the sensor middleware project root.
    nats-server.exe will be placed in the current directory.
#>

$NatsVersion  = "v2.14.0"
$Asset        = "nats-server-$NatsVersion-windows-amd64.zip"
$BaseUrl      = "https://github.com/nats-io/nats-server/releases/download/$NatsVersion"
$ZipUrl       = "$BaseUrl/$Asset"
$HashUrl      = "$BaseUrl/SHA256SUMS"
$DownloadDir  = $PWD.Path
$ZipPath      = Join-Path $DownloadDir $Asset
$HashFile     = Join-Path $DownloadDir "SHA256SUMS"

$ESC = [char]27
$cG  = "$ESC[92m"; $cR = "$ESC[91m"; $cC = "$ESC[96m"; $cY = "$ESC[93m"; $c0 = "$ESC[0m"

Write-Host "`n$cC[*] NATS Server Acquisition Pipeline ($NatsVersion)$c0`n"

# ── 1. Download the ZIP and SHA256SUMS ─────────────────────────────────────────
Write-Host "  [1/4] Downloading $Asset ..."
Invoke-WebRequest -Uri $ZipUrl  -OutFile $ZipPath -UseBasicParsing
Write-Host "  [1/4] Downloading SHA256SUMS ..."
Invoke-WebRequest -Uri $HashUrl -OutFile $HashFile -UseBasicParsing

# ── 2. Extract expected hash from the SHA256SUMS manifest ──────────────────────
Write-Host "  [2/4] Validating SHA-256 integrity ..."
$ExpectedLine = Get-Content $HashFile | Where-Object { $_ -match [regex]::Escape($Asset) }
if (-not $ExpectedLine) {
    Write-Host "  $cR[FAIL]$c0 Asset '$Asset' not found in SHA256SUMS manifest."
    Exit 1
}
# SHA256SUMS format: "<hash>  <filename>" (two spaces)
$ExpectedHash = ($ExpectedLine -split '\s+')[0].Trim().ToUpper()

# ── 3. Compute actual hash and compare ─────────────────────────────────────────
$ActualHash = (Get-FileHash $ZipPath -Algorithm SHA256).Hash.ToUpper()

if ($ActualHash -eq $ExpectedHash) {
    Write-Host "  $cG[PASS]$c0 SHA-256 verified."
    Write-Host "         Expected : $ExpectedHash"
    Write-Host "         Actual   : $ActualHash"
} else {
    Write-Host "  $cR[FAIL]$c0 SHA-256 MISMATCH — download may be corrupted or tampered."
    Write-Host "         Expected : $ExpectedHash"
    Write-Host "         Actual   : $ActualHash"
    Remove-Item $ZipPath -Force
    Exit 1
}

# ── 4. Extract nats-server.exe to project root ────────────────────────────────
Write-Host "  [3/4] Extracting nats-server.exe ..."
Expand-Archive -Path $ZipPath -DestinationPath $DownloadDir -Force

$ExtractedDir = Join-Path $DownloadDir "nats-server-$NatsVersion-windows-amd64"
$NatsExe      = Join-Path $ExtractedDir "nats-server.exe"

if (Test-Path $NatsExe) {
    $FinalPath = Join-Path $DownloadDir "nats-server.exe"
    Move-Item -Path $NatsExe -Destination $FinalPath -Force
    Remove-Item $ExtractedDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  $cG[OK]$c0 nats-server.exe → $FinalPath"
} else {
    Write-Host "  $cR[FAIL]$c0 nats-server.exe not found in archive."
    Exit 1
}

# ── 5. Quick smoke test ───────────────────────────────────────────────────────
Write-Host "  [4/4] Smoke test ..."
$ver = & $FinalPath --version 2>&1
Write-Host "  $cG[OK]$c0 $ver"

Remove-Item $ZipPath  -Force -ErrorAction SilentlyContinue
Remove-Item $HashFile -Force -ErrorAction SilentlyContinue

$SizeMB = [math]::Round(((Get-Item $FinalPath).Length / 1MB), 2)
Write-Host "`n$cC╔════════════════════════════════════════════════════╗$c0"
Write-Host "$cC║$c0 $cG NATS Server $NatsVersion Ready$c0"
Write-Host "$cC║$c0  Binary  : $FinalPath"
Write-Host "$cC║$c0  Size    : $SizeMB MB"
Write-Host "$cC║$c0  SHA-256 : $($ActualHash.Substring(0,16))..."
Write-Host "$cC║$c0"
Write-Host "$cC║$c0  Start:  $cY.\nats-server.exe$c0"
Write-Host "$cC║$c0  Verify: $cY.\nats-server.exe --version$c0"
Write-Host "$cC╚════════════════════════════════════════════════════╝$c0`n"