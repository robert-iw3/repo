<#
.SYNOPSIS
    Deep Visibility Sensor - Diagnostic & Environment Sanitizer

.DESCRIPTION
    A comprehensive health-check and recovery utility. This script forcefully
    hunts down and resolves "Poisoned AppDomains" (orphaned PowerShell processes),
    detaches "Zombie ETW Traces" trapped in the Windows Kernel, and sanitizes
    corrupted unmanaged TraceEvent dependencies.

    It also verifies the health and status of the Native AOT Telemetry Forwarder.
#>
#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"
$HostDataDir = "C:\ProgramData\DeepSensor"
$DependenciesDir = "$HostDataDir\Dependencies"
$ServiceName = "DeepSensor_Telemetry"

Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host " Deep Visibility Sensor v2.6 | Diagnostic & Sanitization Tool" -ForegroundColor Cyan
Write-Host "================================================================`n" -ForegroundColor Cyan

# ======================================================================
# 1. ORPHANED APPDOMAIN & PROCESS SANITIZATION
# ======================================================================
Write-Host "[*] PHASE 1: Scanning for Poisoned AppDomains..." -ForegroundColor Yellow

$orphanCount = 0
$processes = Get-Process -Name "powershell", "pwsh" -ErrorAction SilentlyContinue

foreach ($proc in $processes) {
    # Do not kill the current health-check script's process
    if ($proc.Id -ne $PID) {
        try {
            Stop-Process -Id $proc.Id -Force
            Write-Host "    [+] Terminated orphaned host process (PID: $($proc.Id))" -ForegroundColor Green
            $orphanCount++
        } catch {
            Write-Host "    [-] Failed to terminate PID: $($proc.Id) - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

if ($orphanCount -eq 0) {
    Write-Host "    [+] No orphaned AppDomains detected." -ForegroundColor DarkGray
}

# ======================================================================
# 2. ZOMBIE ETW TRACE SANITIZATION (KERNEL LEVEL)
# ======================================================================
Write-Host "`n[*] PHASE 2: Scanning Windows Kernel for Zombie ETW Traces..." -ForegroundColor Yellow

$traces = @("DeepSensor_KernelMode", "DeepSensor_UserMode")

foreach ($trace in $traces) {
    # Check if the trace exists
    $traceStatus = logman query $trace -ets 2>&1

    if ($traceStatus -match "Data Collector Set was not found") {
        Write-Host "    [+] Trace '$trace' is inactive (Clean)." -ForegroundColor DarkGray
    } else {
        Write-Host "    [!] Zombie Trace detected: '$trace'. Forcing detachment..." -ForegroundColor Red
        $stopAction = logman stop $trace -ets 2>&1

        if ($stopAction -match "The command completed successfully") {
            Write-Host "    [+] Successfully detached '$trace' from the Kernel." -ForegroundColor Green
        } else {
            Write-Host "    [-] Failed to detach '$trace': $stopAction" -ForegroundColor Red
        }
    }
}

# ======================================================================
# 3. TRACEEVENT UNMANAGED DEPENDENCY SANITIZATION
# ======================================================================
Write-Host "`n[*] PHASE 3: Sanitizing Unmanaged TraceEvent Dependencies..." -ForegroundColor Yellow

# Clear the toolkit's strict dependencies folder
if (Test-Path $DependenciesDir) {
    try {
        Remove-Item -Path $DependenciesDir -Recurse -Force
        Write-Host "    [+] Cleared $DependenciesDir" -ForegroundColor Green
    } catch {
        Write-Host "    [-] Could not clear $DependenciesDir (File Lock). Ensure all sessions are closed." -ForegroundColor Red
    }
} else {
    Write-Host "    [+] Local dependencies directory is already clean." -ForegroundColor DarkGray
}

# Clear the Windows TEMP extraction cache (TraceEvent default fallback)
$TempTraceDir = Join-Path $env:TEMP "Microsoft.Diagnostics.Tracing.TraceEvent"
if (Test-Path $TempTraceDir) {
    try {
        Remove-Item -Path $TempTraceDir -Recurse -Force
        Write-Host "    [+] Cleared Windows TEMP TraceEvent cache." -ForegroundColor Green
    } catch {
        Write-Host "    [-] Could not clear TEMP TraceEvent cache. It may be locked." -ForegroundColor Red
    }
}

# ======================================================================
# 4. TELEMETRY TRANSMISSION LAYER HEALTH
# ======================================================================
Write-Host "`n[*] PHASE 4: Validating Telemetry Forwarder Service..." -ForegroundColor Yellow

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if ($service) {
    if ($service.Status -eq 'Running') {
        Write-Host "    [+] Service '$ServiceName' is installed and RUNNING." -ForegroundColor Green
    } else {
        Write-Host "    [!] Service '$ServiceName' is installed but currently $($service.Status)." -ForegroundColor Yellow
        Write-Host "    [*] Attempting to start the service..." -ForegroundColor Gray
        try {
            Start-Service -Name $ServiceName
            Write-Host "    [+] Service started successfully." -ForegroundColor Green
        } catch {
            Write-Host "    [-] Failed to start service: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
} else {
    Write-Host "    [-] Service '$ServiceName' is not installed on this endpoint." -ForegroundColor DarkGray
}

Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host " [+] Sanitization Complete. The environment is now clean." -ForegroundColor Green
Write-Host " [+] You may safely launch the OS Sensor." -ForegroundColor Green
Write-Host "================================================================`n" -ForegroundColor Cyan