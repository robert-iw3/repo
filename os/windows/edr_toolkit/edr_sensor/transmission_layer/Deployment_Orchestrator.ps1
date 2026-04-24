<#
.SYNOPSIS
    Deep Visibility Sensor v2.1 - Native Transmission Deployer

.DESCRIPTION
    Intelligently deploys the Native AOT Telemetry Forwarder.
    It checks for a pre-compiled binary to minimize endpoint footprint.
    If missing, it validates and dynamically installs the .NET 10 SDK
    and C++ Desktop Build Tools before compiling natively.
#>
#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

$ServiceName = "DeepSensor_Telemetry"
$ServiceBinPath = "C:\ProgramData\DeepSensor\Bin\TelemetryForwarder.exe"
$HostDataDir = "C:\ProgramData\DeepSensor\Data"
$HostCertDir = "C:\ProgramData\DeepSensor\Certs"
$HostConfigDir = "C:\ProgramData\DeepSensor\Config"

$ScriptDir = $PSScriptRoot
$BuildDir = Join-Path $ScriptDir "NativeBuild"
$PreCompiledExe = Join-Path $ScriptDir "TelemetryForwarder.exe"

# ======================================================================
# 1. DEPENDENCY RESOLVER & COMPILER INSTALLATION
# ======================================================================
function Install-CompilerDependencies {
    Write-Host "`n[*] Validating Build Environment for Native AOT Compilation..." -ForegroundColor Cyan

    # A. Check for .NET 10 SDK
    $dotnetStatus = Get-Command "dotnet" -ErrorAction SilentlyContinue
    if (-not $dotnetStatus) {
        Write-Host "    [-] .NET SDK is missing. Initiating silent installation..." -ForegroundColor Yellow
        $wingetStatus = Get-Command "winget" -ErrorAction SilentlyContinue
        if ($wingetStatus) {
            Start-Process -FilePath "winget.exe" -ArgumentList "install Microsoft.DotNet.SDK.10 -e --accept-source-agreements --accept-package-agreements --silent" -Wait -NoNewWindow
            $env:Path += ";C:\Program Files\dotnet"
        } else {
            throw "CRITICAL: winget is unavailable. Please install .NET 10 SDK manually."
        }
    }

    # B. Check for C++ Desktop Build Tools (Required for AOT Linking)
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
    }
    Write-Host "    [+] Build Environment Validated." -ForegroundColor Green
}

# ======================================================================
# 2. DIRECTORY HYGIENE & CONFIGURATION
# ======================================================================
if (-not (Test-Path $HostDataDir)) { New-Item -ItemType Directory -Path $HostDataDir -Force | Out-Null }
if (-not (Test-Path $HostCertDir)) { New-Item -ItemType Directory -Path $HostCertDir -Force | Out-Null }
if (-not (Test-Path $HostConfigDir)) { New-Item -ItemType Directory -Path $HostConfigDir -Force | Out-Null }
if (-not (Test-Path "C:\ProgramData\DeepSensor\Bin")) { New-Item -ItemType Directory -Path "C:\ProgramData\DeepSensor\Bin" -Force | Out-Null }

Copy-Item -Path (Join-Path $ScriptDir "DeepSensor_Config.ini") -Destination $HostConfigDir -Force

# ======================================================================
# 3. BINARY DEPLOYMENT (INTELLIGENT ROUTING)
# ======================================================================
if (Test-Path $PreCompiledExe) {
    Write-Host "`n[*] Pre-compiled TelemetryForwarder.exe detected in package." -ForegroundColor Cyan
    Write-Host "    [*] Bypassing compiler installation to maintain pristine endpoint state." -ForegroundColor Green
    Copy-Item -Path $PreCompiledExe -Destination $ServiceBinPath -Force
} else {
    Write-Host "`n[!] Pre-compiled binary not found. Initiating dynamic compilation pipeline..." -ForegroundColor Yellow
    Install-CompilerDependencies

    if (Test-Path $BuildDir) { Remove-Item -Path $BuildDir -Recurse -Force }
    New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null

    Copy-Item -Path (Join-Path $ScriptDir "TelemetryForwarder.csproj") -Destination "$BuildDir\TelemetryForwarder.csproj" -Force
    Copy-Item -Path (Join-Path $ScriptDir "Program.cs") -Destination "$BuildDir\Program.cs" -Force
    Copy-Item -Path (Join-Path $ScriptDir "TelemetryForwarder.cs") -Destination "$BuildDir\TelemetryForwarder.cs" -Force

    Write-Host "[*] Compiling Native AOT Telemetry Forwarder..." -ForegroundColor Cyan
    try {
        Set-Location $BuildDir
        dotnet publish -c Release -r win-x64 -o PublishOut

        Copy-Item -Path "PublishOut\TelemetryForwarder.exe" -Destination $ServiceBinPath -Force
        Set-Location $ScriptDir
        Write-Host "[+] Native AOT compilation successful." -ForegroundColor Green
    } catch {
        Set-Location $ScriptDir
        Write-Host "[-] FATAL: Native AOT Compilation failed." -ForegroundColor Red
        Exit 1
    }
}

# ======================================================================
# 3.5. CRYPTOGRAPHIC PROVISIONING & LEAST PRIVILEGE ACLs
# ======================================================================
$CertFile = Join-Path $ScriptDir "sensor_mtls.pfx"
if (Test-Path $CertFile) {
    Write-Host "`n[*] Cryptographic material detected. Importing to Windows Certificate Store..." -ForegroundColor Yellow

    $CertPass = "dynamic_provisioning_password_here"
    $SecurePass = ConvertTo-SecureString -String $CertPass -AsPlainText -Force

    $Cert = Import-PfxCertificate -FilePath $CertFile -CertStoreLocation "Cert:\LocalMachine\My" -Password $SecurePass -Exportable:$false
    $Thumbprint = $Cert.Thumbprint

    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Cert)
    if ($rsa) {
        $keyName = $rsa.CspKeyContainerInfo.UniqueKeyContainerName

        $rsaPath = Join-Path $env:ProgramData "Microsoft\Crypto\RSA\MachineKeys\$keyName"
        $cngPath = Join-Path $env:ProgramData "Microsoft\Crypto\Keys\$keyName"

        $targetPath = $null
        if (Test-Path $rsaPath) { $targetPath = $rsaPath }
        elseif (Test-Path $cngPath) { $targetPath = $cngPath }

        if ($targetPath) {
            $acl = Get-Acl $targetPath
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\NetworkService", "Read", "Allow")
            $acl.AddAccessRule($accessRule)
            Set-Acl $targetPath $acl
            Write-Host "    [+] Cryptographic ACLs mapped for NetworkService at: $targetPath" -ForegroundColor Green
        } else {
            Write-Host "    [!] WARNING: Could not locate Private Key container to map ACLs." -ForegroundColor Red
        }
    }

    $IniContent = Get-Content -Path "$HostConfigDir\DeepSensor_Config.ini" -Raw
    $IniContent = $IniContent -replace '(?m)^CertThumbprint=.*', "CertThumbprint=$Thumbprint"
    Set-Content -Path "$HostConfigDir\DeepSensor_Config.ini" -Value $IniContent -Force

    Remove-Item $CertFile -Force
    Write-Host "    [+] Certificate successfully bound to OS. Thumbprint: $Thumbprint" -ForegroundColor Green
}

# ======================================================================
# 4. SERVICE HARDENING & LEAST PRIVILEGE DACLs
# ======================================================================
Write-Host "`n[*] Injecting Least-Privilege Access Controls..." -ForegroundColor Yellow
$null = icacls $HostDataDir /grant "NT AUTHORITY\NetworkService:(OI)(CI)RX" /q
$null = icacls $HostConfigDir /grant "NT AUTHORITY\NetworkService:(OI)(CI)RX" /q
$null = icacls $HostCertDir /grant "NT AUTHORITY\NetworkService:(OI)(CI)RX" /q

$serviceExists = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($serviceExists) {
    Write-Host "[*] Terminating existing service..." -ForegroundColor Yellow
    Stop-Service -Name $ServiceName -Force
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

Write-Host "[*] Registering DeepSensor_Telemetry Windows Service..." -ForegroundColor Yellow

$null = sc.exe create $ServiceName binPath= $ServiceBinPath start= auto obj= "NT AUTHORITY\NetworkService" displayname= "Deep Sensor Telemetry Uplink"

# Prevent local admins/malware from easily stopping the service
$secureSddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
$null = sc.exe sdset $ServiceName $secureSddl

# Auto-recovery
$null = sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/5000

Start-Service -Name $ServiceName
Write-Host "`n[+] Deployment Complete. The Native AOT service is now actively transmitting." -ForegroundColor Green