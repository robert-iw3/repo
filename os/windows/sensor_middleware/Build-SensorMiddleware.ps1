<#
.SYNOPSIS
    Sensor Middleware — Rust Workspace Compiler Pipeline

.DESCRIPTION
    Compiles the Sensor Middleware Rust workspace into four native executables:
      • core_ingress.exe   — Telemetry API gateway
      • worker_splunk.exe  — Splunk HEC adapter
      • worker_elastic.exe — Elastic Bulk API adapter
      • worker_sql.exe     — SQL Server TDS/Webhook adapter

    The pipeline ensures the full native MSVC toolchain is available before
    compilation, automatically installing Visual Studio Build Tools and the
    Rust stable toolchain if they are missing.

    Steps:
      1. Validate / install MSVC Desktop C++ Workload & Windows SDK (UCRT).
      2. Validate / install the Rust stable toolchain (x86_64-pc-windows-msvc).
      3. Initialise vcvars64 and run `cargo build --release --workspace`
         inside a native cmd.exe context (prevents mspdbsrv.exe hangs).
      4. Validate compiled binaries, compute SHA-256 hashes, write a manifest.
      5. Stage release artifacts into a `dist\` directory ready for deployment.

.PARAMETER Clean
    When specified, runs `cargo clean` before building.

.PARAMETER SkipToolchainCheck
    When specified, skips MSVC and Rust toolchain validation (assumes they
    are already installed and on PATH). Useful in CI where the image is
    pre-provisioned.

.NOTES
    Author : Robert Weber
    Must be run as Administrator (MSVC installer requires elevation).
#>
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$Clean,
    [switch]$SkipToolchainCheck
)

$ErrorActionPreference = 'Stop'

# ── Paths ──────────────────────────────────────────────────────────────────────
$WorkingDir       = $PSScriptRoot   # Script lives in the workspace root
$DistDir          = Join-Path $WorkingDir "dist"
$BinDir           = Join-Path $WorkingDir "target\release"
$ManifestFile     = Join-Path $DistDir "build_manifest.json"

$ExpectedBinaries = @(
    "core_ingress.exe",
    "worker_splunk.exe",
    "worker_elastic.exe",
    "worker_sql.exe"
)

# ── ANSI colours ───────────────────────────────────────────────────────────────
$ESC    = [char]27
$cRed   = "$ESC[91m"
$cGreen = "$ESC[92m"
$cYellow= "$ESC[93m"
$cCyan  = "$ESC[96m"
$cGray  = "$ESC[90m"
$cBold  = "$ESC[1m"
$cReset = "$ESC[0m"

function Write-Step {
    param([string]$Phase, [string]$Message, [string]$Detail = "")
    $stamp = "[{0:HH:mm:ss}]" -f (Get-Date)
    Write-Host "$cCyan$stamp$cReset $cYellow[$Phase]$cReset $Message"
    if ($Detail) { Write-Host "           $cGray$Detail$cReset" }
}

Write-Host ""
Write-Host "$cCyan$cBold╔══════════════════════════════════════════════════════════════╗$cReset"
Write-Host "$cCyan$cBold║   SENSOR MIDDLEWARE — RUST WORKSPACE COMPILER PIPELINE      ║$cReset"
Write-Host "$cCyan$cBold╚══════════════════════════════════════════════════════════════╝$cReset"
Write-Host ""

# ═══════════════════════════════════════════════════════════════════════════════
# 1.  MSVC BUILD TOOLS & UCRT WORKLOAD VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════
$vsInstallPath = $null

if (-not $SkipToolchainCheck) {
    Write-Step "MSVC" "Verifying MSVC Desktop Workload & Universal C Runtime..."

    $vsWherePath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vsWherePath) {
        $paths = & $vsWherePath -latest -products * -property installationPath
        if ($paths) {
            $vsInstallPath = if ($paths -is [array]) { $paths[0] } else { $paths }
        }
    }

    if ([string]::IsNullOrWhiteSpace($vsInstallPath)) {
        foreach ($fp in @(
            "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools",
            "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Community",
            "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Professional",
            "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Enterprise"
        )) {
            if (Test-Path (Join-Path $fp "VC\Auxiliary\Build\vcvars64.bat")) {
                $vsInstallPath = $fp; break
            }
        }
    }

    Write-Step "MSVC" "Fetching Microsoft Build Tools bootstrapper..."
    $vsBuildTools = Join-Path $env:TEMP "vs_buildtools.exe"
    Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vs_buildtools.exe" `
                      -OutFile $vsBuildTools -UseBasicParsing

    if (-not [string]::IsNullOrWhiteSpace($vsInstallPath) -and (Test-Path $vsInstallPath)) {
        Write-Host "  $cGreen[+]$cReset Visual Studio environment found: $vsInstallPath"
        Write-Step "MSVC" "Ensuring C++ workload is present (silent modify)..."

        $modArgs = "modify --installPath `"$vsInstallPath`" " +
                   "--add Microsoft.VisualStudio.Workload.VCTools " +
                   "--includeRecommended --quiet --wait --norestart --nocache"
        $modProc = Start-Process -FilePath $vsBuildTools -ArgumentList $modArgs `
                                 -Wait -PassThru

        if ($modProc.ExitCode -eq 0 -or $modProc.ExitCode -eq 3010) {
            Write-Host "  $cGreen[+]$cReset C++ workload & Windows SDK synced."
        } else {
            Write-Host "  $cYellow[!]$cReset Bootstrapper returned $($modProc.ExitCode)."
        }
    } else {
        Write-Host "  $cYellow[-]$cReset Visual Studio Build Tools not found. Installing..."
        Write-Host "  $cYellow[!]$cReset Downloading C++ workload (~2 GB). This may take 5-10 min."

        $instArgs = "--quiet --wait --norestart --nocache " +
                    "--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
        $instProc = Start-Process -FilePath $vsBuildTools -ArgumentList $instArgs `
                                  -Wait -PassThru

        if ($instProc.ExitCode -eq 0 -or $instProc.ExitCode -eq 3010) {
            Write-Host "  $cGreen[+]$cReset MSVC Build Tools installed."
            $vsInstallPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools"
        } else {
            Write-Host "`n$cRed[!] CRITICAL: MSVC installation failed (exit $($instProc.ExitCode)).$cReset"
            Remove-Item $vsBuildTools -Force -ErrorAction SilentlyContinue
            Exit 1
        }
    }
    Remove-Item $vsBuildTools -Force -ErrorAction SilentlyContinue
} else {
    Write-Step "MSVC" "Skipped (SkipToolchainCheck)" ""
    # Still need vsInstallPath for vcvars
    foreach ($fp in @(
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Community",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Professional",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Enterprise"
    )) {
        if (Test-Path (Join-Path $fp "VC\Auxiliary\Build\vcvars64.bat")) {
            $vsInstallPath = $fp; break
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# 2.  RUST TOOLCHAIN VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════
if (-not $SkipToolchainCheck) {
    Write-Step "RUST" "Verifying Rust toolchain (cargo)..."
    try {
        $null = Get-Command cargo -ErrorAction Stop
        $rustVer = (& cargo --version 2>&1) -join ''
        Write-Host "  $cGreen[+]$cReset $rustVer"
    } catch {
        Write-Host "  $cYellow[-]$cReset Rust not found. Installing via rustup..."
        $RustUpPath = Join-Path $env:TEMP "rustup-init.exe"
        Invoke-WebRequest -Uri "https://win.rustup.rs" -OutFile $RustUpPath -UseBasicParsing
        $rp = Start-Process -FilePath $RustUpPath `
              -ArgumentList "-y --default-toolchain stable --default-host x86_64-pc-windows-msvc" `
              -Wait -PassThru
        if ($rp.ExitCode -ne 0) {
            Write-Host "`n$cRed[!] CRITICAL: Rust installation failed.$cReset"
            Exit 1
        }
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("Path","User")
        Write-Host "  $cGreen[+]$cReset Rust toolchain installed."
        Remove-Item $RustUpPath -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Step "RUST" "Skipped (SkipToolchainCheck)" ""
}

# ═══════════════════════════════════════════════════════════════════════════════
# 3.  NATIVE VCVARS COMPILATION
# ═══════════════════════════════════════════════════════════════════════════════
Write-Step "BUILD" "Constructing native MSVC compilation context..."

$VcvarsPath = $null
if (-not [string]::IsNullOrWhiteSpace($vsInstallPath)) {
    $VcvarsPath = Join-Path $vsInstallPath "VC\Auxiliary\Build\vcvars64.bat"
}

$CleanLine = ""
if ($Clean) { $CleanLine = "cargo clean" }

$CompileWrapper = Join-Path $WorkingDir "_build_temp.cmd"
if ($VcvarsPath -and (Test-Path $VcvarsPath)) {
    $WrapperLogic = @"
@echo off
echo     [*] Initializing MSVC x64 linkers and Windows SDK...
call "$VcvarsPath"
if %ERRORLEVEL% NEQ 0 (
    echo     [!] CRITICAL: vcvars64.bat failed.
    exit /b %ERRORLEVEL%
)
echo     [*] MSVC environment mapped.
cd /d "$WorkingDir"
$CleanLine
echo     [*] Executing cargo build --release --workspace...
cargo build --release --workspace
exit /b %ERRORLEVEL%
"@
} else {
    Write-Host "  $cYellow[!]$cReset vcvars64.bat not found; building without MSVC env."
    $WrapperLogic = @"
@echo off
cd /d "$WorkingDir"
$CleanLine
echo     [*] Executing cargo build --release --workspace...
cargo build --release --workspace
exit /b %ERRORLEVEL%
"@
}

Set-Content -Path $CompileWrapper -Value $WrapperLogic

$buildStart = Get-Date
& cmd.exe /c $CompileWrapper
$buildElapsed = (Get-Date) - $buildStart

if ($LASTEXITCODE -ne 0) {
    Write-Host "`n$cRed[!] COMPILATION FAILED: cargo returned exit code $LASTEXITCODE$cReset"
    Remove-Item $CompileWrapper -Force -ErrorAction SilentlyContinue
    Exit 1
}
Remove-Item $CompileWrapper -Force -ErrorAction SilentlyContinue

Write-Step "BUILD" "Compilation succeeded" "Elapsed: $($buildElapsed.ToString('mm\:ss'))"

# ═══════════════════════════════════════════════════════════════════════════════
# 4.  BINARY VALIDATION & SHA-256 MANIFEST
# ═══════════════════════════════════════════════════════════════════════════════
Write-Step "VERIFY" "Validating compiled binaries..."

if (-not (Test-Path $DistDir)) { New-Item -ItemType Directory -Path $DistDir -Force | Out-Null }

$manifest = @{
    build_time    = (Get-Date -Format 'o')
    build_host    = $env:COMPUTERNAME
    rust_version  = ((& cargo --version 2>&1) -join '').Trim()
    elapsed_sec   = [math]::Round($buildElapsed.TotalSeconds, 1)
    binaries      = @()
}

$allPresent = $true
foreach ($bin in $ExpectedBinaries) {
    $srcPath = Join-Path $BinDir $bin
    if (-not (Test-Path $srcPath)) {
        Write-Host "  $cRed[FAIL]$cReset Missing: $bin"
        $allPresent = $false
        continue
    }

    $hash   = (Get-FileHash $srcPath -Algorithm SHA256).Hash
    $sizeMB = [math]::Round(((Get-Item $srcPath).Length / 1MB), 2)

    # Stage into dist/
    $destPath = Join-Path $DistDir $bin
    Copy-Item -Path $srcPath -Destination $destPath -Force

    Write-Host "  $cGreen[OK]$cReset $($bin.PadRight(24)) SHA256: $($hash.Substring(0,16))...  ($sizeMB MB)"

    $manifest.binaries += @{
        name   = $bin
        sha256 = $hash
        size_mb = $sizeMB
    }
}

if (-not $allPresent) {
    Write-Host "`n$cRed[!] CRITICAL: One or more binaries missing. Build incomplete.$cReset"
    Exit 1
}

if (Test-Path (Join-Path $WorkingDir "config.ini")) {
    Copy-Item (Join-Path $WorkingDir "config.ini") (Join-Path $DistDir "config.ini") -Force
}

$manifest | ConvertTo-Json -Depth 4 | Out-File $ManifestFile -Encoding UTF8
Write-Step "VERIFY" "Build manifest written" $ManifestFile

# ═══════════════════════════════════════════════════════════════════════════════
# 5.  SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "$cCyan$cBold╔══════════════════════════════════════════════════════════════╗$cReset"
Write-Host "$cCyan║$cReset $cGreen SUCCESS: Sensor Middleware Workspace Compiled$cReset"
Write-Host "$cCyan║$cReset"
foreach ($entry in $manifest.binaries) {
    Write-Host "$cCyan║$cReset   $($entry.name.PadRight(24))  $($entry.size_mb) MB"
}
Write-Host "$cCyan║$cReset"
Write-Host "$cCyan║$cReset   Elapsed  : $($buildElapsed.ToString('mm\:ss'))"
Write-Host "$cCyan║$cReset   Dist dir : $DistDir"
Write-Host "$cCyan║$cReset   Manifest : $ManifestFile"
Write-Host "$cCyan$cBold╚══════════════════════════════════════════════════════════════╝$cReset"
Write-Host ""