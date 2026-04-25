<#
.SYNOPSIS
    Data Sensor - Rust Engine Compiler Pipeline

.DESCRIPTION
    Compiles the native Rust Machine Learning engine into a C-Compatible Dynamic
    Link Library (DataSensor_ML.dll). Acquires TraceEvent dependencies via NuGet
    and executes cryptographic hashing for verification.
.AUTHOR
    Robert Weber
#>
#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'
$WorkingDir = $PWD.Path
$ProjectDir = $WorkingDir
$BinDir = Join-Path $WorkingDir "Bin"
$DepDir = "C:\ProgramData\DataSensor\Dependencies"
$FinalBinaryName = "DataSensor_ML.dll"

$ESC = [char]27
$cRed = "$ESC[91m"; $cCyan = "$ESC[96m"; $cGreen = "$ESC[92m"; $cYellow = "$ESC[93m"; $cReset = "$ESC[0m"

Write-Host "`n$cCyan[*] INITIATING DATA SENSOR RUST COMPILER PIPELINE (v1.0)$cReset"

# ============================================================================
# 1. MSVC BUILD TOOLS VALIDATION
# ============================================================================
Write-Host "    [*] Verifying MSVC Desktop Workload & Universal C Runtime (UCRT)..." -ForegroundColor Gray
$vsWherePath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsInstallPath = $null

if (Test-Path $vsWherePath) {
    $paths = & $vsWherePath -latest -products * -property installationPath
    if ($paths) { if ($paths -is [array]) { $vsInstallPath = $paths[0] } else { $vsInstallPath = $paths } }
}

if (-not $vsInstallPath) {
    Write-Host "`n$cRed[!] CRITICAL FAILURE: Microsoft Visual C++ Build Tools not found.$cReset"
    Write-Host "$cYellow[!] The Rust compiler requires the MSVC toolchain to link the Native DLL.$cReset"
    Exit
}
Write-Host "    [+] MSVC Toolchain verified at: $vsInstallPath" -ForegroundColor Green

# ============================================================================
# 2. DEPENDENCY ACQUISITION (NuGet: TraceEvent)
# ============================================================================
Write-Host "`n    [*] Validating unmanaged C# Dependencies..." -ForegroundColor Gray
if (-not (Test-Path $DepDir)) { New-Item -ItemType Directory -Path $DepDir -Force | Out-Null }
$TraceEventDll = Join-Path $DepDir "Microsoft.Diagnostics.Tracing.TraceEvent.dll"

if (-not (Test-Path $TraceEventDll)) {
    Write-Host "    [*] Acquiring TraceEvent package from NuGet..." -ForegroundColor Yellow
    $NugetUrl = "https://www.nuget.org/api/v2/package/Microsoft.Diagnostics.Tracing.TraceEvent/3.0.2"
    $ZipPath = Join-Path $DepDir "traceevent.zip"
    $ExtractPath = Join-Path $DepDir "extracted"

    Invoke-WebRequest -Uri $NugetUrl -OutFile $ZipPath -UseBasicParsing
    Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force

    $ExtractedDll = Join-Path $ExtractPath "lib\netstandard2.0\Microsoft.Diagnostics.Tracing.TraceEvent.dll"
    Copy-Item $ExtractedDll -Destination $TraceEventDll -Force

    Remove-Item $ZipPath -Force
    Remove-Item $ExtractPath -Recurse -Force
    Write-Host "    [+] TraceEvent.dll staged successfully in ProgramData." -ForegroundColor Green
} else {
    Write-Host "    [+] TraceEvent.dll already staged." -ForegroundColor Green
}

# ============================================================================
# 3. RUST COMPILATION PIPELINE
# ============================================================================
if (-not (Test-Path $BinDir)) { New-Item -ItemType Directory -Path $BinDir -Force | Out-Null }

Write-Host "`n    [*] Prepping Cargo build environment..." -ForegroundColor Gray
$CompileWrapper = Join-Path $WorkingDir "compile_native.cmd"
$WrapperLogic = @"
@echo off
cd /d "$ProjectDir"
set RUSTFLAGS=-C target-feature=+crt-static
cargo build --release
exit /b %ERRORLEVEL%
"@
Set-Content -Path $CompileWrapper -Value $WrapperLogic

Write-Host "    [*] Executing Cargo Release Build (LTO Enabled)..." -ForegroundColor Yellow
& cmd.exe /c $CompileWrapper

if ($LASTEXITCODE -ne 0) {
    Write-Host "`n$cRed[!] COMPILATION FAILED: Cargo returned exit code $LASTEXITCODE$cReset"
    Remove-Item $CompileWrapper -Force -ErrorAction SilentlyContinue
    Exit
}

# ============================================================================
# 4. EXTRACTION, HASHING & CLEANUP
# ============================================================================
$CompiledDll = Join-Path $ProjectDir "target\release\data_sensor_ml.dll"
$FinalDest = Join-Path $BinDir $FinalBinaryName

if (Test-Path $CompiledDll) {
    Copy-Item -Path $CompiledDll -Destination $FinalDest -Force

    $HashVal = (Get-FileHash $FinalDest -Algorithm SHA256).Hash
    $HashDest = Join-Path $BinDir ($FinalBinaryName -replace "\.dll$", ".sha256")
    $HashVal | Out-File -FilePath $HashDest -Encoding ascii -NoNewline

    Remove-Item $CompileWrapper -Force -ErrorAction SilentlyContinue

    $SizeMB = [math]::Round(((Get-Item $FinalDest).Length / 1MB), 2)
    Write-Host "`n$cCyan╔══════════════════════════════════════════════════════════════════════════╗$cReset"
    Write-Host "$cCyan║$cReset $cGreen SUCCESS: Native Data Sensor Engine Compiled Successfully"
    Write-Host "$cCyan║$cReset  Target : $FinalBinaryName"
    Write-Host "$cCyan║$cReset  Size   : $($SizeMB) MB"
    Write-Host "$cCyan║$cReset  SHA256 : $HashVal"
    Write-Host "$cCyan╚══════════════════════════════════════════════════════════════════════════╝$cReset`n"
} else {
    Write-Host "`n$cRed[!] ERROR: Expected output DLL not found in target/release directory.$cReset"
}