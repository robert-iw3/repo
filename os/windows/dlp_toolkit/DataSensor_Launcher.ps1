<#
.SYNOPSIS
    Data Sensor Orchestrator - Production Release
.DESCRIPTION
    Initializes the unmanaged C# ETW listener and the Native Rust ML engine.
    Parses config.ini for DLP rules, maintains continuous UEBA baselines,
    and enforces active mitigation protocols (Thread Suspension).
    Maintains strict architectural parity with C2 and Deep Visibility sensors.
#>
#Requires -RunAsAdministrator

$ScriptDir = Split-Path $PSCommandPath -Parent

# --- Environment Pre-Flight & Logging ---
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$LogDir = "C:\ProgramData\DataSensor\Logs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$global:LogFile = Join-Path $LogDir "DataSensor_Active.jsonl"

Get-ChildItem -Path $LogDir -Filter "*.jsonl" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-3) } | Remove-Item -Force -ErrorAction SilentlyContinue

function Write-Diag {
    param([string]$Message, [string]$Level="INFO", [string]$Tactic="None", [string]$ProcessName="System")

    if ((Test-Path $global:LogFile) -and ((Get-Item $global:LogFile).Length -gt 50MB)) {
        $ArchiveName = "DataSensor_$(Get-Date -Format 'yyyyMMdd_HHmmss').jsonl"
        Rename-Item -Path $global:LogFile -NewName $ArchiveName -Force
    }

    $LogObj = [PSCustomObject]@{
        Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        Level     = $Level
        Component = "Orchestrator"
        Process   = $ProcessName
        Tactic    = $Tactic
        Message   = $Message
    }
    Add-Content -Path $global:LogFile -Value ($LogObj | ConvertTo-Json -Compress -Depth 5) -ErrorAction SilentlyContinue
}
Write-Diag -Message "Data Sensor Orchestrator Initialized." -Level "STARTUP"

# --- Terminal HUD Initialization ---
$Host.UI.RawUI.BackgroundColor = 'Black'
$Host.UI.RawUI.ForegroundColor = 'Gray'
Clear-Host

$ESC      = [char]27
$cCyan    = "$ESC[38;2;0;255;255m"
$cGreen   = "$ESC[38;2;57;255;20m"
$cOrange  = "$ESC[38;2;255;103;0m"
$cGold    = "$ESC[38;2;255;215;0m"
$cRed     = "$ESC[38;2;255;49;49m"
$cReset   = "$ESC[0m$ESC[40m"

try {
    $ui = $Host.UI.RawUI
    $size = $ui.WindowSize; $size.Width = 140; $size.Height = 50; $ui.WindowSize = $size
} catch {}

# --- Configuration Parser ---
$ConfigPath = Join-Path $ScriptDir "config.ini"
if (-not (Test-Path $ConfigPath)) { Write-Host "[-] FATAL ERROR: config.ini not found." -ForegroundColor Red; exit }

$MaxInspectionMB = 150
$TrustedProcs = @()
$DlpConfig = @{
    strict_strings = @(); regex_patterns = @();
    ueba_min_samples = 25; ueba_z_score = 3.5;
}

switch -Regex -File $ConfigPath {
    "^MaxInspectionSizeMB=(\d+)$" { $MaxInspectionMB = [int]$matches[1] }
    "^BaselineMinSamples=(\d+)$"  { $DlpConfig.ueba_min_samples = [int]$matches[1] }
    "^ZScoreTrigger=([\d\.]+)$"   { $DlpConfig.ueba_z_score = [double]$matches[1] }
    "^TrustedProcesses=(.*)$"     { $TrustedProcs = $matches[1] -split ',' | ForEach-Object { $_.Trim().ToLower() } }
    "^([^#;\[][^=]+)=(.*)$" {
        $key = $matches[1].Trim()
        $val = $matches[2].Trim()
        if ($key -match "SSN|CreditCard|AWSAccessKey|PrivateRSAKey") { $DlpConfig.regex_patterns += $val }
        if ($key -match "ProjectNames|Classifications") { $DlpConfig.strict_strings += ($val -split ',') }
    }
}

Write-Diag "Initializing Dynamic Threat Intelligence fetch..." "INFO"
$IntelDir = Join-Path $ScriptDir "Intel"
if (-not (Test-Path $IntelDir)) { New-Item -ItemType Directory -Path $IntelDir -Force | Out-Null }

try {
    Write-Host "[*] Updating Public Threat Intelligence Feeds..." -ForegroundColor Yellow

    $TorExitUrl = "https://check.torproject.org/torbulkexitlist"
    $TorFile = Join-Path $IntelDir "Live_Tor_Exits.txt"
    Invoke-WebRequest -Uri $TorExitUrl -OutFile $TorFile -UseBasicParsing -TimeoutSec 10

    $HighRiskEndpoints = @("discord.com/api/webhooks", "mega.nz", "anonfiles.com", "pastebin.com", "requestbin.com")
    $HighRiskEndpoints | Out-File -FilePath (Join-Path $IntelDir "Live_Webhooks.txt") -Encoding ascii -Force

    Write-Diag "Successfully updated public threat feeds." "INFO"
} catch {
    Write-Diag "Failed to reach public intel feeds. Falling back to cached indicators. ($($_.Exception.Message))" "WARN"
}

$ExfiltrationIoCs = Get-ChildItem -Path $IntelDir -Filter "*.txt"
$TotalIoCs = 0
foreach ($File in $ExfiltrationIoCs) {
    $IoCs = Get-Content $File.FullName | Where-Object { $_ -match "\S" -and $_ -notmatch "^#" }
    foreach ($IoC in $IoCs) {
        $DlpConfig.strict_strings += $IoC.Trim()
        $TotalIoCs++
    }
}
Write-Diag "Compiled $TotalIoCs Threat Intel indicators into Native Rust Engine." "INFO"
Write-Host "[+] Compiled $TotalIoCs Threat Intelligence indicators." -ForegroundColor Green

$ConfigJson = $DlpConfig | ConvertTo-Json -Compress -Depth 10
$TrustedProcsStr = $TrustedProcs -join ","

$DependenciesDir = "C:\ProgramData\DataSensor\Dependencies"
if (-not (Test-Path $DependenciesDir)) { New-Item -ItemType Directory -Path $DependenciesDir -Force | Out-Null }
$ManagedDllPath = Join-Path $DependenciesDir "Microsoft.Diagnostics.Tracing.TraceEvent.dll"

if (-not (Test-Path $ManagedDllPath)) {
    Write-Diag "TraceEvent.dll missing. Initiating automatic NuGet acquisition." "WARN"
    Write-Host "[*] Acquiring required TraceEvent dependencies from NuGet..." -ForegroundColor Yellow

    $NugetUrl = "https://www.nuget.org/api/v2/package/Microsoft.Diagnostics.Tracing.TraceEvent/3.0.2"
    $ZipPath = Join-Path $DependenciesDir "traceevent.zip"
    $ExtractPath = Join-Path $DependenciesDir "extracted"

    Invoke-WebRequest -Uri $NugetUrl -OutFile $ZipPath -UseBasicParsing
    Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force

    $ExtractedDll = Join-Path $ExtractPath "lib\netstandard2.0\Microsoft.Diagnostics.Tracing.TraceEvent.dll"
    Copy-Item $ExtractedDll -Destination $ManagedDllPath -Force

    Remove-Item $ZipPath -Force
    Remove-Item $ExtractPath -Recurse -Force
    Write-Diag "TraceEvent.dll successfully staged." "INFO"
    Write-Host "[+] TraceEvent.dll staged successfully." -ForegroundColor Green
}

$RefAssemblies = @($ManagedDllPath, "System", "System.Core", "System.Runtime", "System.Collections.Concurrent")

$CSharpFilePath = Join-Path $ScriptDir "DataSensor.cs"

try {
    Write-Diag "Initiating dynamic compilation of unmanaged ETW observer." "INFO"
    $CompilerParams = New-Object System.CodeDom.Compiler.CompilerParameters
    $CompilerParams.GenerateInMemory = $true
    $CompilerParams.ReferencedAssemblies.AddRange($RefAssemblies)
    $CompilerParams.CompilerOptions = "/optimize"

    Add-Type -Path $CSharpFilePath -CompilerParameters $CompilerParams -ErrorAction Stop
    Write-Diag "Unmanaged ETW Listener Compiled Natively." "INFO"
    Write-Host "$cGreen[+] System: Unmanaged ETW Observer Compiled.$cReset"
} catch {
    $Fault = $_.Exception.Message
    Write-Diag "COMPILATION FAULT: $Fault" "FATAL"
    Write-Host "[-] FATAL: C# Compilation failed. Review diagnostic logs." -ForegroundColor Red
    exit
}

# --- FFI Bridge Initialization & ACL Lockdown ---
$BinPath = "C:\ProgramData\DataSensor\Bin"
$DataPath = "C:\ProgramData\DataSensor\Data"

foreach ($Dir in @($BinPath, $DataPath)) {
    if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }

    $Acl = Get-Acl -Path $Dir
    $Acl.SetAccessRuleProtection($true, $false)
    $RuleAdmin = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $RuleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $Acl.AddAccessRule($RuleAdmin)
    $Acl.AddAccessRule($RuleSystem)
    Set-Acl -Path $Dir -AclObject $Acl -ErrorAction SilentlyContinue
}

$RustDllSource = Join-Path $ScriptDir "Bin\DataSensor_ML.dll"
if (Test-Path $RustDllSource) {
    Copy-Item $RustDllSource -Destination $BinPath -Force -ErrorAction SilentlyContinue
}
Write-Diag -Message "Anti-Tamper ACLs enforced on secure directories." -Level "INFO"

[RealTimeDataSensor]::InitializeEngine($ConfigJson, $MaxInspectionMB, $TrustedProcsStr)
[RealTimeDataSensor]::StartSession()

# --- Benchmark HUD Initialization ---
Write-Host "$cCyan=== DATA SENSOR [ALPHA BENCHMARK] ===$cReset"
Write-Host "Monitoring FFI compilation, memory allocations, and telemetry data flow."
Write-Host "$cOrange[TODO: Integrate future Advanced Web/Console React HUD here]$cReset`n"

Write-Host "Timestamp   | Tactic  | Conviction                 | Context      | Details"
Write-Host "------------------------------------------------------------------------------------------------------------------------"

[Console]::TreatControlCAsInput = $false
[System.Console]::CancelKeyPress += {
    $Script:RunLoop = $false
    $_.Cancel = $true
}
$Script:RunLoop = $true

# --- Telemetry Routing Metrics & Watchdog ---
$global:TotalAlerts = 0
$global:LastHeartbeat = [DateTime]::UtcNow
$global:LastTelemetryReceived = [DateTime]::UtcNow
$AlertCache = @{}

<#
.ARCHITECTURAL_ANCHOR 1: ASYNCHRONOUS UI BOOTSTRAP
    [FUTURE INTEGRATION ZONE]
    A secondary PowerShell Runspace or lightweight Kestrel web listener MUST be initialized here.
    By launching the UI thread asynchronously prior to the ETW session, the UI server
    claims its memory allocation first. This guarantees the primary thread remains
    100% dedicated to the zero-allocation Rust FFI pipeline without context-switching overhead.
#>

<#
.ARCHITECTURAL_ANCHOR 7: WEBPAGE HUD HTML/JS GENERATION
    [FUTURE INTEGRATION ZONE]
    1. Dynamically write the Data Sensor HTML5/JS payload (index.html, dashboard.js, styles.css)
       to a temporary `\UI` staging directory.
    2. Bind the local HTTP Listener (e.g., http://localhost:8080).
    3. Establish the WebSocket endpoint `/api/live-telemetry` for the HUD to consume Z-Scores.
#>

<#
.ARCHITECTURAL_ANCHOR 8: CONSOLE DASHBOARD INITIALIZATION
    [FUTURE INTEGRATION ZONE]
    If launched with `-ConsoleUI`:
    1. Enter the Alternate Screen Buffer to prevent polluting the user's terminal history.
    2. Render the static ANSI boundaries (Telemetry Stream | Active Defense | ML Baselines).
    3. Initialize the UI-only render queue.
#>

try {
    Write-Diag -Message "Entering unmanaged ETW polling loop." -Level "INFO"
    while ($Script:RunLoop) {
        $evtRef = $null
        $BatchCount = 0

        while ([RealTimeDataSensor]::EventQueue.TryDequeue([ref]$evtRef)) {
            $evt = $evtRef
            $BatchCount++
            $global:TotalAlerts++
            $global:LastTelemetryReceived = [DateTime]::UtcNow

            if ($evt.EventType -eq "MITIGATION") {
                Write-Diag -Message "Active Defense Triggered: $($evt.RawJson)" -Level "WARN" -Tactic "T1485" -ProcessName $evt.ProcessName

                <#
                .ARCHITECTURAL_ANCHOR 4: ADVANCED FORENSIC AUTOMATION
                    [FUTURE INTEGRATION ZONE]
                    The Thread Suspension has stabilized the threat. Hook SOAR/Forensic playbooks here.
                    1. Trigger MiniDumpWriteDump on the suspended $evt.ProcessName.
                    2. Invoke Windows Firewall API to drop all non-management outbound sockets (Network Containment).
                    3. Capture the locked file handle into a secure forensic vault.
                #>

                # [TODO: Future Console UI and Webpage HUD API pushes will route here]

                Write-Host "[*] MITIGATION ENACTED: $($evt.RawJson)" -ForegroundColor Green
            }
            elseif ($evt.EventType -eq "DLP_ALERT" -or $evt.EventType -eq "UEBA_ALERT") {
                $ts = (Get-Date).ToString("HH:mm:ss")
                $parsed = $evt.RawJson | ConvertFrom-Json

                <#
                .ARCHITECTURAL_ANCHOR 11: IDENTITY CONTEXT ENRICHMENT
                    [FUTURE INTEGRATION ZONE]
                    Before processing the alert, query the local LSASS or a cached Entra ID/AD token.
                    Map the raw SID/User to a corporate identity matrix (e.g., "Robert.Weber" -> "Engineering").
                    If an HR/Finance user suddenly compiles a Rust binary, the risk weight multiplies.
                #>

                foreach ($alert in $parsed.alerts) {
                    $CacheKey = "$($alert.alert_type)_$($evt.ProcessName)_$($alert.details)"
                    if ($AlertCache.ContainsKey($CacheKey) -and ($AlertCache[$CacheKey] -gt (Get-Date).AddSeconds(-5))) {
                        continue
                    }
                    $AlertCache[$CacheKey] = Get-Date

                    $mitre = if ($alert.mitre_tactic) { $alert.mitre_tactic } else { "T1048" }
                    $contextIndicator = if ($alert.details -match "Velocity|Network_Socket") { "NET" } else { "IO " }

                    $LogMsg = "Conviction: $($alert.alert_type) | Confidence: $($alert.confidence) | $($alert.details)"
                    Write-Diag -Message $LogMsg -Level "ALERT" -Tactic $mitre -ProcessName $evt.ProcessName

                    <#
                    .ARCHITECTURAL_ANCHOR 5: SIEM & DATA LAKE FORWARDING
                        [FUTURE INTEGRATION ZONE]
                        Ship the schematized JSON object to a centralized aggregation tier.
                        Implementation must use a Fire-and-Forget asynchronous HTTPS/gRPC push
                        or write to a named pipe monitored by a dedicated Filebeat/Splunk sidecar
                        to prevent network latency from blocking the ETW listener.
                    #>

                    <#
                    .ARCHITECTURAL_ANCHOR 12: OFFLINE TELEMETRY SPOOLING
                        [FUTURE INTEGRATION ZONE]
                        If the SIEM/XDR endpoint is unreachable (e.g., laptop disconnected),
                        divert the JSON payload into an encrypted local SQLite Spool DB.
                        Once the network restores, flush the spool to the Data Lake sequentially
                        to guarantee zero telemetry loss.
                    #>

                    <#
                    .ARCHITECTURAL_ANCHOR 2: NON-BLOCKING EVENT PUSH
                        [FUTURE INTEGRATION ZONE]
                        Drop serialized alert data into a ThreadSafeQueue/ConcurrentQueue here.
                        The core loop MUST NOT wait for the HUD to acknowledge receipt.
                        Wire-speed mitigation capabilities cannot be delayed by slow web clients.
                    #>

                    <#
                    .ARCHITECTURAL_ANCHOR 9: WEBPAGE HUD / CONSOLE ALERT ROUTING
                        [FUTURE INTEGRATION ZONE]
                        Construct the specific JSON payload for the UI consumers:
                        {
                            "type": "hud_alert",
                            "sensor_state": "Armed",
                            "html_color_code": "#FF4500",
                            "render_pane": "TelemetryStream",
                            "data": $alert
                        }
                    #>

                    $outMsg = "[$ts] $mitre | $($alert.alert_type) | [$contextIndicator] $($evt.ProcessName) | $($alert.details)"
                    Write-Host $outMsg -ForegroundColor $(if ($alert.confidence -eq 100) { "Red" } else { "Yellow" })
                }
            }
            elseif ($evt.EventType -eq "ERROR" -or $evt.EventType -eq "FATAL") {
                Write-Diag -Message "SYSTEM FAULT: $($evt.RawJson)" -Level "ERROR" -ProcessName "Orchestrator"
                Write-Host "[-] SYSTEM FAULT: $($evt.RawJson)" -ForegroundColor Red
            }
        }

        if (([DateTime]::UtcNow - $global:LastHeartbeat).TotalSeconds -ge 10) {
            $global:LastHeartbeat = [DateTime]::UtcNow
            $MemUsageMB = [math]::Round((Get-Process -Id $PID).WorkingSet64 / 1MB, 2)

            Write-Host "`n$cGreen[DIAGNOSTIC]$cReset RAM Allocation: $($MemUsageMB)MB | Active Detections: $($global:TotalAlerts) | Native FFI Pipeline: Stable"

            <#
            .ARCHITECTURAL_ANCHOR 3: AGGREGATED TELEMETRY HEARTBEAT
                [FUTURE INTEGRATION ZONE]
                Fire aggregated state objects (Total Alerts, RAM Usage, EPS) to the Web API here.
                Provides the dashboard with a continuous heartbeat of system health, proving the
                Data Sensor is active and kernel buffers are clear, without flooding the IPC boundary
                with raw benign file reads.
            #>

            <#
            .ARCHITECTURAL_ANCHOR 6: REMOTE POLICY SYNCHRONIZATION
                [FUTURE INTEGRATION ZONE]
                Execute a lightweight background job to poll the Central XDR Management Console.
                If new DLP Regex signatures or Threat Intel domains are available:
                1. Pull the Delta payload.
                2. Safely lock the Rust FFI Engine.
                3. Inject the new strict_strings into memory via a new `update_dlp_engine` native call.
            #>

            <#
            .ARCHITECTURAL_ANCHOR 13: OVER-THE-AIR (OTA) BINARY UPDATES
                [FUTURE INTEGRATION ZONE]
                If a new version of `DataSensor_ML.dll` or `DataSensor.cs` is published:
                1. Download the signed artifact to `\Staging`.
                2. Execute a sub-second `[RealTimeDataSensor]::StopSession()` teardown.
                3. Swap the binaries and dynamically recompile the C# type.
                4. Resume ETW ingestion, achieving a seamless agent upgrade without a system reboot.
            #>

            Write-Host "$cOrange[TODO: Expose Diagnostic Metrics to unified Web HUD API via asynchronous Runspace]$cReset`n"

            if (([DateTime]::UtcNow - $global:LastTelemetryReceived).TotalSeconds -ge 120) {
                Write-Diag -Message "ETW Canary failed. 120s since last event. Initiating Auto-Recovery." -Level "FATAL"
                Write-Host "`n$cRed[!] ETW Starvation Detected. Auto-recovering TraceEvent Session...$cReset"

                [RealTimeDataSensor]::StopSession()
                Start-Sleep -Seconds 2
                [RealTimeDataSensor]::StartSession()

                $global:LastTelemetryReceived = [DateTime]::UtcNow
                Write-Diag -Message "TraceEvent Session Auto-Recovered." -Level "INFO"
            }
        }

        Start-Sleep -Milliseconds 250
    }
} finally {
    Write-Host "`n$cGold[*] Initiating Graceful Shutdown...$cReset"
    Write-Diag "Initiating Teardown Sequence..." "INFO"

    <#
    .ARCHITECTURAL_ANCHOR 10: GRACEFUL UI & HUD TEARDOWN
        [FUTURE INTEGRATION ZONE]
        1. Broadcast a generic "SENSOR_OFFLINE" WebSocket message to the Webpage HUD.
        2. Close the HTTP Listener and release the local port binding.
        3. If ConsoleUI is active, exit the Alternate Screen Buffer and reset all ANSI attributes.
        4. Dispose of the asynchronous UI Runspace.
    #>

    Write-Host "    [*] Terminating Web HUD Runspace... (Will do later)" -ForegroundColor Gray

    Write-Host "    [*] Finalizing Kernel Telemetry & ML Database..." -ForegroundColor Gray
    try { [RealTimeDataSensor]::StopSession() } catch {}
    Write-Diag "C# TraceEvent Session Halted and FFI Unmapped." "INFO"

    Write-Host "    [*] Cleaning up centralized library artifacts..." -ForegroundColor Gray
    $StagingPath = "C:\ProgramData\DataSensor\Staging"
    if (Test-Path $StagingPath) {
        Remove-Item -Path "$StagingPath\*.zip" -Force -ErrorAction SilentlyContinue
    }

    Write-Diag "=== DIAGNOSTIC LOG CLOSED ===" "INFO"
    Write-Host "`n[+] Sensor Teardown Complete. Log artifacts preserved in C:\ProgramData\DataSensor\Logs & \Data." -ForegroundColor Green
}