<#
.SYNOPSIS
    Sign Kernel Driver for HVCI / WHCP Compatibility
.DESCRIPTION
    Signs the kernel driver (.sys) and its catalog (.cat) with an EV code-signing
    certificate, validates expiry and EKU, and provides WHCP/HLK guidance.

    Run as Administrator.  Assumes .inf and .sys are in the working directory.

.NOTES
    Author      : Robert Weber
    Requirements: EV code-signing cert (.pfx), Windows SDK (signtool + inf2cat)

    To obtain an EV Code Signing Certificate:
      1. Choose a CA — DigiCert, GlobalSign, Sectigo, or SSL.com.
      2. Submit organisation docs for EV vetting (1-10 business days).
      3. Generate a CSR on FIPS 140-2 hardware (HSM or YubiKey).
      4. Receive cert on USB token or cloud HSM.
      5. After signing, submit to Microsoft WHCP for kernel-mode attestation.
         Signed + attested drivers load on HVCI/VBS-enabled systems.
#>

param (
    [string]$SysFile     = "endpoint_monitor_driver.sys",
    [string]$InfFile     = "driver.inf",
    [string]$CertPath    = "your_ev_cert.pfx",
    [securestring]$CertPassword = (Read-Host -AsSecureString "Enter cert password"),
    # RFC 3161 timestamp servers (SHA-256 capable):
    [string]$TimestampUrl = "http://timestamp.digicert.com",   # DigiCert RFC 3161
    # Alternative:        "http://timestamp.globalsign.com/tsa/r6advanced1"
    [string]$SdkUrl       = "https://go.microsoft.com/fwlink/?linkid=2262345",
    [string]$LogFile      = "sign_log.txt"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────────────────────────────────────
function Write-Log {
    param ([string]$Message, [string]$Level = "INFO")
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Write-Host $entry -ForegroundColor $(if ($Level -eq "ERROR") {"Red"} elseif ($Level -eq "WARN") {"Yellow"} else {"Cyan"})
    Add-Content -Path $LogFile -Value $entry -ErrorAction SilentlyContinue
}

function Invoke-NativeCommand {
    param ([string]$Exe, [string[]]$Args, [string]$Description)
    Write-Log "$Description ..."
    & $Exe @Args
    if ($LASTEXITCODE -ne 0) { throw "$Description failed (exit $LASTEXITCODE)" }
    Write-Log "$Description — OK"
}

# ─────────────────────────────────────────────────────────────────────────────
try {
    # Step 1 — Prerequisites ──────────────────────────────────────────────────
    foreach ($f in @($SysFile, $InfFile, $CertPath)) {
        if (-not (Test-Path $f)) { throw "Required file not found: $f" }
    }
    Write-Log "Prerequisite files present."

    # Step 2 — Certificate validation ─────────────────────────────────────────
    Write-Log "Validating certificate..."
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        (Resolve-Path $CertPath).Path, $CertPassword)

    if ($cert.NotAfter -lt (Get-Date)) {
        throw "Certificate expired: $($cert.NotAfter)"
    }
    # OID 1.3.6.1.5.5.7.3.3 = Code Signing EKU
    if ($cert.EnhancedKeyUsageList.ObjectId -notcontains "1.3.6.1.5.5.7.3.3") {
        throw "Certificate missing Code Signing EKU (1.3.6.1.5.5.7.3.3)"
    }
    if (-not $cert.Verify()) {
        Write-Log "Certificate chain not fully trusted locally (CA may not be installed). Proceeding." "WARN"
    }
    Write-Log "Certificate OK: $($cert.Subject) — expires $($cert.NotAfter)"

    # Step 3 — SDK installation (signtool + inf2cat) ───────────────────────────
    $signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    $inf2cat  = Get-Command inf2cat.exe  -ErrorAction SilentlyContinue

    if (-not $signtool -or -not $inf2cat) {
        Write-Log "Downloading Windows SDK..."
        $isoPath = Join-Path $env:TEMP "winsdk.iso"
        Invoke-WebRequest -Uri $SdkUrl -OutFile $isoPath
        Write-Log "Mounting SDK ISO..."
        $mount  = Mount-DiskImage -ImagePath $isoPath -StorageType ISO -PassThru
        $letter = ($mount | Get-Volume).DriveLetter
        Write-Log "Installing SDK from ${letter}:\ ..."
        Start-Process -FilePath "${letter}:\WinSDKSetup.exe" `
            -ArgumentList "/features OptionId.WindowsDesktopDebuggers OptionId.WindowsDesktopSoftwareDevelopmentKit /q /norestart" `
            -Wait
        Dismount-DiskImage -ImagePath $isoPath
        # Refresh PATH so newly installed tools are found.
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
        Write-Log "SDK installed."
    } else {
        Write-Log "signtool and inf2cat found in PATH."
    }

    # Step 4 — Generate .cat ──────────────────────────────────────────────────
    # BUG FIX: inf2cat must be invoked with & (call operator) in PowerShell.
    # Without &, PowerShell treats the bare command as a string expression and
    # silently does nothing — the .cat file is never generated.
    # Also targeting multiple OS versions ensures the catalog is valid on
    # Windows 10, Server 2022, and Windows 11.
    Invoke-NativeCommand inf2cat `
        @("/driver:.", "/os:10_X64,Server2022_X64,11_X64") `
        "inf2cat .cat generation"

    # Plaintext password extracted only in memory for signtool invocation.
    $plainPwd = (New-Object PSCredential "x", $CertPassword).GetNetworkCredential().Password

    # Step 5 — Sign .sys ──────────────────────────────────────────────────────
    # BUG FIX: /t (legacy SHA-1 AuthentiCode timestamp) replaced with:
    #   /tr  — RFC 3161 timestamp server URL
    #   /td sha256 — request SHA-256 digest from the timestamp server
    # The /t flag produces SHA-1 timestamps which are rejected by kernel
    # integrity checks on SHA-256 signed images (NTSTATUS 0xC0000428 at load).
    Invoke-NativeCommand signtool @(
        "sign",
        "/f",  $CertPath,
        "/p",  $plainPwd,
        "/tr", $TimestampUrl,    # RFC 3161 timestamp (was: /t)
        "/td", "sha256",         # SHA-256 timestamp digest
        "/fd", "sha256",         # SHA-256 file digest
        "/v",
        $SysFile
    ) "Sign $SysFile"

    # Step 6 — Sign .cat ──────────────────────────────────────────────────────
    Invoke-NativeCommand signtool @(
        "sign",
        "/f",  $CertPath,
        "/p",  $plainPwd,
        "/tr", $TimestampUrl,
        "/td", "sha256",
        "/fd", "sha256",
        "/v",
        "endpoint_monitor_driver.cat"
    ) "Sign .cat"

    # Step 7 — Verify signatures ──────────────────────────────────────────────
    # Validate before declaring success — catches cert-chain and hash mismatches.
    Invoke-NativeCommand signtool @("verify", "/pa", "/v", $SysFile) "Verify $SysFile"
    Invoke-NativeCommand signtool @("verify", "/pa", "/v", "endpoint_monitor_driver.cat") "Verify .cat"
    Write-Log "Signature verification passed."

    # Step 8 — WHCP / HVCI guidance ───────────────────────────────────────────
    Write-Log "=== Next steps for WHCP attestation (required for HVCI-enabled systems) ==="
    Write-Log "1. Download HLK: https://learn.microsoft.com/windows-hardware/test/hlk/"
    Write-Log "2. Run HLK Driver Compatibility tests in a test VM."
    Write-Log "3. Submit HLK package + signed .sys to Hardware Dev Center:"
    Write-Log "   https://partner.microsoft.com/dashboard/hardware (MS partner account required)"
    Write-Log "4. After attestation, the driver loads on HVCI / Secure Boot systems."

} catch {
    Write-Log "FATAL: $_" "ERROR"
    exit 1
} finally {
    # Clear the plaintext password from memory if it was assigned.
    if (Test-Path variable:plainPwd) { $plainPwd = $null }
}

Write-Log "Script complete. Driver signed. Proceed to HLK for full WHCP attestation."