<#
.SYNOPSIS
    Deep Sensor v2.1 - Native AOT Telemetry Compiler (Staging Tool)

.DESCRIPTION
    A dedicated staging-environment script. It validates the presence of the
    required Microsoft build chains (.NET 10 SDK & C++ Desktop Tools), compiles
    the C# Telemetry Forwarder into a standalone Native AOT binary, and extracts
    the executable to the workspace for air-gapped packaging.
#>
#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

$ScriptDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ScriptDir)) { $ScriptDir = $PWD.Path }

$BuildDir = Join-Path $ScriptDir "TelemetryBuild_Temp"
$OutputBinary = Join-Path $ScriptDir "TelemetryForwarder.exe"

Write-Host "`n[*] Initializing Dedicated Native AOT Compiler..." -ForegroundColor Cyan

# ======================================================================
# 1. DEPENDENCY VALIDATION (STAGING ENVIRONMENT)
# ======================================================================
function Validate-BuildChain {
    Write-Host "[*] Validating Staging Environment Build Chain..." -ForegroundColor Yellow

    # A. Check for .NET 10 SDK
    $dotnetStatus = Get-Command "dotnet" -ErrorAction SilentlyContinue
    if (-not $dotnetStatus) {
        Write-Host "    [-] .NET 10 SDK is missing. Initiating installation..." -ForegroundColor Yellow
        $wingetStatus = Get-Command "winget" -ErrorAction SilentlyContinue
        if ($wingetStatus) {
            Start-Process -FilePath "winget.exe" -ArgumentList "install Microsoft.DotNet.SDK.10 -e --accept-source-agreements --accept-package-agreements --silent" -Wait -NoNewWindow
            $env:Path += ";C:\Program Files\dotnet"
        } else {
            throw "CRITICAL: winget is unavailable. Please install .NET 10 SDK manually."
        }
    } else {
        Write-Host "    [+] .NET 10 SDK validated." -ForegroundColor Green
    }

    # B. Check for C++ Desktop Build Tools (Required for Native AOT C++ Linker)
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $cppInstalled = $false

    if (Test-Path $vswhere) {
        $cppCheck = & $vswhere -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if (-not [string]::IsNullOrWhiteSpace($cppCheck)) { $cppInstalled = $true }
    }

    if (-not $cppInstalled) {
        Write-Host "    [-] C++ Build Tools missing. Downloading Visual Studio Build Tools..." -ForegroundColor Yellow
        $vsInstallerUrl = "https://aka.ms/vs/17/release/vs_buildtools.exe"
        $vsInstallerPath = "$env:TEMP\vs_buildtools.exe"

        Invoke-WebRequest -Uri $vsInstallerUrl -OutFile $vsInstallerPath -UseBasicParsing

        Write-Host "    [*] Executing silent installation of Desktop C++ Workload (This will take several minutes)..." -ForegroundColor Yellow
        $installArgs = "--quiet --wait --norestart --nocache --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
        $process = Start-Process -FilePath $vsInstallerPath -ArgumentList $installArgs -Wait -NoNewWindow -PassThru

        if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
            Write-Host "    [+] Visual Studio Build Tools installed successfully." -ForegroundColor Green
        } else {
            throw "CRITICAL: Visual Studio Build Tools installation failed with Exit Code $($process.ExitCode)."
        }
    } else {
        Write-Host "    [+] C++ Native Linker validated." -ForegroundColor Green
    }
}

Validate-BuildChain

# ======================================================================
# 2. SOURCE HYGIENE & PREPARATION
# ======================================================================
Write-Host "`n[*] Preparing Build Workspace..." -ForegroundColor Cyan

# Ensure old artifacts are cleared
if (Test-Path $BuildDir) { Remove-Item -Path $BuildDir -Recurse -Force }
New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
if (Test-Path $OutputBinary) { Remove-Item -Path $OutputBinary -Force }

$RequiredFiles = @("TelemetryForwarder.cs", "TelemetryForwarder.csproj", "Program.cs")
foreach ($file in $RequiredFiles) {
    $sourcePath = Join-Path $ScriptDir $file
    if (-not (Test-Path $sourcePath)) {
        throw "CRITICAL: Required source file '$file' not found in $ScriptDir."
    }
    Copy-Item -Path $sourcePath -Destination "$BuildDir\$file" -Force
}
Write-Host "    [+] Source files staged." -ForegroundColor Green

# ======================================================================
# 3. NATIVE AOT COMPILATION
# ======================================================================
Write-Host "`n[*] Executing Native AOT Compilation (win-x64)..." -ForegroundColor Cyan
Write-Host "    [*] This process strips the .NET runtime and compiles directly to machine code." -ForegroundColor Gray

try {
    Set-Location $BuildDir

    # Execute the publish command forcing Native AOT
    $process = Start-Process -FilePath "dotnet" -ArgumentList "publish -c Release -r win-x64 -o PublishOut /p:PublishAot=true" -Wait -NoNewWindow -PassThru

    if ($process.ExitCode -ne 0) {
        throw "dotnet publish exited with code $($process.ExitCode)"
    }

    $CompiledBin = Join-Path $BuildDir "PublishOut\TelemetryForwarder.exe"
    if (-not (Test-Path $CompiledBin)) {
        throw "Expected output binary not found at $CompiledBin"
    }

    # Extract the finalized binary back to the workspace root
    Copy-Item -Path $CompiledBin -Destination $OutputBinary -Force
    Set-Location $ScriptDir

    $Hash = (Get-FileHash -Path $OutputBinary -Algorithm SHA256).Hash

    Write-Host "`n[+] Compilation Successful!" -ForegroundColor Green
    Write-Host "    Binary Target : $OutputBinary"
    Write-Host "    SHA256 Hash   : $Hash"

} catch {
    Set-Location $ScriptDir
    Write-Host "`n[-] FATAL: Compilation failed: $($_.Exception.Message)" -ForegroundColor Red
    Exit 1
} finally {
    # ======================================================================
    # 4. WORKSPACE CLEANUP
    # ======================================================================
    if (Test-Path $BuildDir) {
        Write-Host "[*] Cleaning temporary build directory..." -ForegroundColor Gray
        Remove-Item -Path $BuildDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n[*] The TelemetryForwarder.exe is now ready. You may proceed with executing Build-AirGapPackage.ps1." -ForegroundColor Cyan