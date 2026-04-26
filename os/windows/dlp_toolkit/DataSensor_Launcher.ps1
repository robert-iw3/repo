<#
.SYNOPSIS
    Data Sensor Orchestrator - Pre-Beta Candidate Release
.DESCRIPTION
    Initializes the unmanaged C# ETW listener and the Native Rust ML engine.
    Parses config.ini for DLP rules, maintains continuous UEBA baselines,
    and enforces active mitigation protocols (Thread Suspension).

@RW
#>
#Requires -RunAsAdministrator

[CmdletBinding()]
param (
    [switch]$Background,   # Suppresses the Console UI for silent service execution
    [switch]$ConsoleUI,    # Forces the ANSI terminal HUD to render
    [switch]$DebugMode     # Increases logging verbosity for the FFI boundary
)

$ScriptDir = Split-Path $PSCommandPath -Parent

# --- Environment Pre-Flight & Logging ---
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$LogDir = "C:\ProgramData\DataSensor\Logs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$global:LogFile = Join-Path $LogDir "DataSensor_Active.jsonl"
$global:DiagFile = Join-Path $LogDir "DataSensor_Diagnostic.log"

if (Test-Path $global:DiagFile) { Clear-Content -Path $global:DiagFile -Force -ErrorAction SilentlyContinue }

function Write-EngineDiag([string]$Message, [string]$Level="INFO") {
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    Add-Content -Path $global:DiagFile -Value "[$ts] [$Level] $Message" -ErrorAction SilentlyContinue
    if ($DebugMode) { Write-Host "[$Level] $Message" -ForegroundColor DarkGray }
}

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

    $JsonPayload = ($LogObj | ConvertTo-Json -Compress -Depth 5) + "`r`n"
    try {
        [System.IO.File]::AppendAllText($global:LogFile, $JsonPayload)
    } catch {
        Start-Sleep -Milliseconds 10
        try { [System.IO.File]::AppendAllText($global:LogFile, $JsonPayload) } catch {}
    }
}
Write-Diag "Data Sensor Orchestrator Initialized." "STARTUP"

# ======================================================================
# HUD / UI INITIALIZATION
# ======================================================================
$global:RecentAlerts = [System.Collections.Generic.List[PSCustomObject]]::new()
$global:StartupLogs = [System.Collections.Generic.List[string]]::new()
$global:TotalMitigations = 0
$global:TotalEvents = 0

function Write-StartupLog([string]$Message) {
    $ts = (Get-Date).ToString("HH:mm:ss")
    $global:StartupLogs.Add("[$ts] $Message")
    if ($global:StartupLogs.Count -gt 10) { $global:StartupLogs.RemoveAt(0) }
    Draw-StartupWindow
}

# Disable Windows QuickEdit Mode to prevent accidental process freezing
$QuickEditCode = @"
using System;
using System.Runtime.InteropServices;
public class ConsoleConfig {
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetStdHandle(int nStdHandle);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

    public static void DisableQuickEdit() {
        IntPtr consoleHandle = GetStdHandle(-10);
        if (GetConsoleMode(consoleHandle, out uint consoleMode)) {
            consoleMode &= ~0x0040U;
            SetConsoleMode(consoleHandle, consoleMode);
        }
    }
}
"@
Add-Type -TypeDefinition $QuickEditCode
[ConsoleConfig]::DisableQuickEdit()

$Host.UI.RawUI.BackgroundColor = 'Black'
$Host.UI.RawUI.ForegroundColor = 'Gray'
Clear-Host

# ======================================================================
# HUD & UI RENDERING ENGINE
# ======================================================================
$global:RecentAlerts = [System.Collections.Generic.List[PSCustomObject]]::new()
$global:StartupLogs = [System.Collections.Generic.List[string]]::new()
$global:TotalMitigations = 0
$global:TotalEvents = 0

$ESC      = [char]27
$cCyan    = "$ESC[38;2;0;255;255m"
$cGreen   = "$ESC[38;2;57;255;20m"
$cOrange  = "$ESC[38;2;255;103;0m"
$cGold    = "$ESC[38;2;255;215;0m"
$cRed     = "$ESC[38;2;255;49;49m"
$cWhite   = "$ESC[38;2;255;255;255m"
$cDark    = "$ESC[38;2;80;80;80m"
$cReset   = "$ESC[0m$ESC[40m"

try {
    $ui = $Host.UI.RawUI
    $buffer = $ui.BufferSize; $buffer.Width = 160; $buffer.Height = 3000; $ui.BufferSize = $buffer
    $size = $ui.WindowSize; $size.Width = 160; $size.Height = 55; $ui.WindowSize = $size
    [Console]::SetCursorPosition(0, 9)
} catch {}

function Draw-StartupWindow {
    $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
    [Console]::SetCursorPosition(0, 37)
    $UIWidth = 106

    Write-Host "$cCyan╔══════════════════════════════════════════════════════════════════════════════════════════════════════════╗$cReset"
    Write-Host "$cCyan║$cReset$cGreen  [ SENSOR INITIALIZATION ]$cReset$($(" " * 79))$cCyan║$cReset"
    Write-Host "$cCyan╠══════════════════════════════════════════════════════════════════════════════════════════════════════════╣$cReset"

    $recent = if ($global:StartupLogs.Count -gt 10) { $global:StartupLogs.GetRange($global:StartupLogs.Count - 10, 10) } else { $global:StartupLogs }

    for ($i = 0; $i -lt 10; $i++) {
        if ($i -lt $recent.Count) {
            $logLine = "    $($recent[$i])"
            if ($logLine.Length -gt ($UIWidth - 4)) { $logLine = $logLine.Substring(0, $UIWidth - 7) + "..." }
            $pad = " " * [math]::Max(0, ($UIWidth - $logLine.Length))
            Write-Host "$cCyan║$cReset$logLine$pad$cCyan║$cReset"
        } else {
            Write-Host "$cCyan║$cReset$($(" " * $UIWidth))$cCyan║$cReset"
        }
    }
    Write-Host "$cCyan╚══════════════════════════════════════════════════════════════════════════════════════════════════════════╝$cReset"
    [Console]::SetCursorPosition($curLeft, $curTop)
}

function Write-StartupLog([string]$Message) {
    $ts = (Get-Date).ToString("HH:mm:ss")
    $global:StartupLogs.Add("[$ts] $Message")
    if ($global:StartupLogs.Count -gt 10) { $global:StartupLogs.RemoveAt(0) }
    Draw-StartupWindow
}

function Draw-AlertWindow {
    $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
    [Console]::SetCursorPosition(0, 10)
    $UIWidth = 106

    Write-Host "$cCyan╔══════════════════════════════════════════════════════════════════════════════════════════════════════════╗$cReset"
    Write-Host "$cCyan║$cReset$cGreen  [ LIVE THREAT TELEMETRY ]$cReset$($(" " * 79))$cCyan║$cReset"
    Write-Host "$cCyan╠══════════════════════════════════════════════════════════════════════════════════════════════════════════╣$cReset"

    for ($i = 0; $i -lt 20; $i++) {
        if ($i -lt $global:RecentAlerts.Count) {
            $item = $global:RecentAlerts[$i]
            $cleanText = $item.Text -replace "`e\[[0-9;]*m",""
            $displayText = $item.Text

                if ($cleanText.Length -gt ($UIWidth - 5)) {
                    $displayText = $cleanText.Substring(0, $UIWidth - 5) + "..."
                    $pad = ""
                } else {
                    $pad = " " * ($UIWidth - $cleanText.Length - 2)
                }
            Write-Host "$cCyan║$cReset  $($item.Color)$displayText$cReset$pad$cCyan║$cReset"
        } else {
            Write-Host "$cCyan║$cReset$($(" " * $UIWidth))$cCyan║$cReset"
        }
    }

    Write-Host "$cCyan╠══════════════════════════════════════════════════════════════════════════════════════════════════════════╣$cReset"
    Write-Host "$cCyan║$cReset$cWhite  [ CTRL + C ] INITIATE TEARDOWN SEQUENCE$cReset$($(" " * 64))$cCyan║$cReset"
    Write-Host "$cCyan╚══════════════════════════════════════════════════════════════════════════════════════════════════════════╝$cReset"
    [Console]::SetCursorPosition($curLeft, $curTop)
}

function Add-AlertMessage([string]$Message, [string]$ColorCode) {
    $Message = $Message -replace "`t", " " -replace "`r", "" -replace "`n", " "
    $ts = (Get-Date).ToString("HH:mm:ss"); $prefix = "[$ts] "
    $global:RecentAlerts.Add([PSCustomObject]@{ Text = "$prefix$Message"; Color = $ColorCode })
    if ($global:RecentAlerts.Count -gt 20) { $global:RecentAlerts.RemoveAt(0) }
    $global:UiNeedsUpdate = $true
}

function Draw-Dashboard([long]$Events, [int]$Alerts, [string]$EtwHealth, [int]$QueueSize) {
    $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
    [Console]::SetCursorPosition(0, 0)
    $UIWidth = 110

    $mitreTags = @()
    foreach ($alert in $global:RecentAlerts) { if ($alert.Text -match "T\d{4}") { $mitreTags += $matches[0] } }
    $uniqueMitre = if ($mitreTags.Count -gt 0) { ($mitreTags | Select-Object -Unique) -join ", " } else { "None" }
    if ($uniqueMitre.Length -gt 25) { $uniqueMitre = $uniqueMitre.Substring(0, 22) + "..." }

    $lastAction = if ($global:RecentAlerts -match "MITIGATION") { "Thread Suspended" } else { "None" }
    $EtwState = if ($EtwHealth -eq "Good") { "ONLINE" } else { "DEGRADED" }
    $LogHealthStr = if ($QueueSize -gt 5000) { "SATURATED" } elseif ($QueueSize -gt 1000) { "BACKLOGGED" } else { "HEALTHY" }

    $EColor = if ($EtwHealth -eq "Good") { $cGreen } else { $cRed }
    $LColor = if ($LogHealthStr -eq "HEALTHY") { $cGreen } else { $cRed }

    Write-Host "$cCyan╔══════════════════════════════════════════════════════════════════════════════════════════════════════════╗$cReset"
    Write-Host "$cCyan║$cReset$cGold  ██ Data Sensor $cReset| Observational Telemetry & UEBA Baseline$($(" " * 48))$cCyan║$cReset"
    Write-Host "$cCyan╠══════════════════════════════════════════════════════════════════════════════════════════════════════════╣$cReset"
    Write-Host "$cCyan║$cReset$cOrange  [ ENGINE STATUS ]$cReset$($(" " * 34))$cOrange[ ACTIVE DEFENSE ]$cReset$($(" " * 35))$cCyan║$cReset"
    Write-Host "$cCyan║$cReset  Sensor Status : $EColor$($EtwState.PadRight(35))$cReset Defenses Engaged : $cRed$($global:TotalMitigations.ToString().PadRight(33))$cReset$cCyan║$cReset"
    Write-Host "$cCyan║$cReset  Pipeline Load : $LColor$($LogHealthStr.PadRight(13))$cReset (Q: $cWhite$($QueueSize.ToString().PadRight(16))$cReset) Total Alerts     : $cOrange$($Alerts.ToString().PadRight(33))$cReset$cCyan║$cReset"
    Write-Host "$cCyan║$cReset  Total Events  : $cWhite$($Events.ToString().PadRight(35))$cReset Last Action      : $cWhite$($lastAction.PadRight(33))$cReset$cCyan║$cReset"
    Write-Host "$cCyan║$cReset  Active Alerts : $cGold$($Alerts.ToString().PadRight(35))$cReset Vectors          : $cDark$($uniqueMitre.PadRight(33))$cReset$cCyan║$cReset"
    Write-Host "$cCyan╚══════════════════════════════════════════════════════════════════════════════════════════════════════════╝$cReset"

    if ($curTop -lt 10) { $curTop = 10 }
    [Console]::SetCursorPosition($curLeft, $curTop)
}

# --- Configuration Parser ---
$ConfigPath = Join-Path $ScriptDir "config.ini"
if (-not (Test-Path $ConfigPath)) { Write-Host "[-] FATAL ERROR: config.ini not found." -ForegroundColor Red; exit }

$global:SensorMode = "Monitoring"
$global:EnableUniversalLedger = $false
$MaxInspectionMB = 150
$TrustedProcs = @()
$DlpConfig = @{
    strict_strings = @(); regex_patterns = @();
    ueba_min_samples = 25; ueba_z_score = 3.5;
}

switch -Regex -File $ConfigPath {
    "^SensorMode=(.*)$"           { $global:SensorMode = $matches[1].Trim() }
    "^EnableUniversalLedger=(.*)$" { $global:EnableUniversalLedger = [System.Convert]::ToBoolean($matches[1].Trim()) }
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
    Write-StartupLog "Updating Public Threat Intelligence Feeds..."
    Write-Diag "Updating Public Threat Intelligence Feeds..." "INFO"

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
        $CleanIoC = $IoC.Trim()
        $DlpConfig.strict_strings += $CleanIoC
        $TotalIoCs++

        if ($CleanIoC -match "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$") {
            try {
                $ResolvedIPs = [System.Net.Dns]::GetHostAddresses($CleanIoC) | Select-Object -ExpandProperty IPAddressToString
                foreach ($IP in $ResolvedIPs) {
                    if ($DlpConfig.strict_strings -notcontains $IP) {
                        $DlpConfig.strict_strings += $IP
                        $TotalIoCs++
                    }
                }
            } catch {}
        }
    }
}
Write-Diag "Compiled $TotalIoCs Threat Intel indicators into Native Rust Engine." "INFO"

$ConfigJson = $DlpConfig | ConvertTo-Json -Compress -Depth 10
$TrustedProcsStr = $TrustedProcs -join ","

$DependenciesDir = "C:\ProgramData\DataSensor\Dependencies"
if (-not (Test-Path $DependenciesDir)) { New-Item -ItemType Directory -Path $DependenciesDir -Force | Out-Null }
$ManagedDllPath = Join-Path $DependenciesDir "Microsoft.Diagnostics.Tracing.TraceEvent.dll"

if (-not (Test-Path $ManagedDllPath)) {
    Write-Diag "TraceEvent.dll missing. Initiating automatic NuGet acquisition." "WARN"

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
}

$RefAssemblies = @(
    $ManagedDllPath,
    "System",
    "System.Core"
)

if ($PSVersionTable.PSVersion.Major -ge 6) {
    $RefAssemblies += @(
        "System.Runtime",
        "System.Collections",
        "System.Collections.Concurrent",
        "System.Threading",
        "System.Threading.Thread",
        "System.Diagnostics.Process",
        "System.ComponentModel.Primitives",
        "System.Private.CoreLib",
        "System.Runtime.InteropServices",
        "System.IO.FileSystem.DriveInfo",
        "System.Linq",
        "System.Linq.Expressions",
        "System.Text.RegularExpressions",
        "System.Security.Principal.Windows",
        "System.Security.Claims",
        "System.Net.Primitives",
        "netstandard"
    )
} else {
    $RefAssemblies += @(
        "System.Collections",
        "System.Collections.Concurrent",
        "System.Threading",
        "System.Threading.Thread",
        "System.Linq",
        "System.Linq.Expressions",
        "System.Text.RegularExpressions",
        "System.Runtime.InteropServices",
        "Microsoft.CSharp",
        "netstandard"
    )
}

$CSharpFilePath = Join-Path $ScriptDir "DataSensor.cs"

try {
    Write-Diag "Initiating dynamic compilation of unmanaged ETW observer." "INFO"
    Write-EngineDiag "Attempting Universal C# Native Compilation..." "INFO"

    [System.Reflection.Assembly]::LoadFrom($ManagedDllPath) | Out-Null

    if ($PSVersionTable.PSVersion.Major -lt 6) {
        $CompilerParams = New-Object System.CodeDom.Compiler.CompilerParameters
        $CompilerParams.GenerateInMemory = $true
        $CompilerParams.ReferencedAssemblies.AddRange($RefAssemblies)
        $CompilerParams.CompilerOptions = "/optimize"
        Add-Type -Path $CSharpFilePath -CompilerParameters $CompilerParams -ErrorAction Stop
    } else {
        Add-Type -Path $CSharpFilePath -ReferencedAssemblies $RefAssemblies -CompilerOptions "/optimize" -ErrorAction Stop
    }

    Write-Diag "Unmanaged ETW Listener Compiled Natively." "INFO"
    Write-EngineDiag "C# Compilation Successful. Module loaded into memory." "INFO"
} catch {
    $Fault = $_.Exception.Message
    Write-Diag "COMPILATION FAULT: $Fault" "FATAL"
    Write-EngineDiag "COMPILATION FAULT: $Fault" "FATAL"
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
Write-StartupLog "Anti-Tamper ACLs enforced on secure directories."

Write-StartupLog "Bootstrapping Native FFI Data Sensor..."
[RealTimeDataSensor]::InitializeEngine($ConfigJson, $MaxInspectionMB, $TrustedProcsStr, $global:EnableUniversalLedger)
[RealTimeDataSensor]::StartSession()

try { [console]::TreatControlCAsInput = $true } catch {}
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

# ======================================================================
# WEBPAGE HUD / RUNSPACE INITIALIZATION
# ======================================================================
$global:AlertQueue = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
$global:SystemMetrics = [hashtable]::Synchronized(@{ TotalAlerts = 0; RAM = 0; Status = "Armed" })

function Start-DataSensorHUD {
    param([string]$LogPath)
    Write-Diag "    [*] Initializing Live Browser HUD Bridge..." "STARTUP"

    $HtmlPayload = @'
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self';">
        <title>Data Sensor | Live Workbench</title>
        <style>
            :root { --bg-main: #0a0e14; --bg-card: #0d1117; --bg-hover: #161b22; --text-main: #c9d1d9; --text-muted: #8b949e; --neon-green: #39FF14; --neon-orange: #FF5F1F; --red: #ff4b4b; --blue: #58a6ff; --border: #30363d; }
            * { box-sizing: border-box; font-family: 'Segoe UI', system-ui, sans-serif; }
            body { background: var(--bg-main); color: var(--text-main); margin: 0; padding: 20px; display: flex; flex-direction: column; height: 100vh; overflow: hidden; }
            .header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 15px; border-bottom: 1px solid var(--border); }
            .header h1 { margin: 0; font-size: 1.5rem; color: #fff; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; }
            .header h1 span { color: var(--neon-green); }
            .btn-group { display: flex; gap: 10px; align-items: center; }
            .live-indicator { display: flex; align-items: center; gap: 8px; color: var(--neon-green); font-weight: bold; font-family: 'Consolas', monospace; text-transform: uppercase; border: 1px solid var(--neon-green); padding: 5px 12px; border-radius: 4px; background: rgba(57, 255, 20, 0.05); }
            .pulse { width: 8px; height: 8px; background-color: var(--neon-green); border-radius: 50%; box-shadow: 0 0 8px var(--neon-green); animation: throb 1.5s infinite; }
            @keyframes throb { 0% { transform: scale(0.8); opacity: 1; } 50% { transform: scale(1.3); opacity: 0.5; } 100% { transform: scale(0.8); opacity: 1; } }
            .toolbar { display: flex; justify-content: space-between; align-items: center; margin: 15px 0; }
            .search-box { width: 400px; padding: 10px 15px; background: var(--bg-card); border: 1px solid var(--border); border-radius: 4px; color: var(--neon-green); outline: none; font-family: 'Consolas', monospace; }
            .search-box:focus { border-color: var(--neon-green); box-shadow: 0 0 5px rgba(57, 255, 20, 0.2); }
            .tabs { display: flex; gap: 5px; }
            .tab { padding: 8px 20px; background: transparent; border: none; color: var(--text-muted); cursor: pointer; font-weight: 600; border-bottom: 2px solid transparent; text-transform: uppercase; }
            .tab.active { color: var(--neon-green); border-bottom: 2px solid var(--neon-green); }
            .workspace { display: flex; flex: 1; overflow: hidden; position: relative; gap: 15px; }
            .table-container { flex: 1; overflow: auto; background: var(--bg-card); border: 1px solid var(--border); }
            table { width: 100%; border-collapse: collapse; font-size: 0.85rem; text-align: left; }
            th { background: #161b22; padding: 12px 15px; position: sticky; top: 0; color: var(--text-muted); font-weight: 600; border-bottom: 1px solid var(--border); z-index: 10; text-transform: uppercase; }
            td { padding: 12px 15px; border-bottom: 1px solid var(--border); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 400px; }
            tr { cursor: pointer; transition: background 0.1s; }
            tr:hover { background: var(--bg-hover); }
            tr.selected { background: rgba(57, 255, 20, 0.05); box-shadow: inset 3px 0 0 var(--neon-green); }
            .tag { padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; text-transform: uppercase; }
            .tag-crit { background: rgba(255, 75, 75, 0.1); color: var(--red); border: 1px solid rgba(255, 75, 75, 0.3); }
            .tag-high { background: rgba(255, 95, 31, 0.1); color: var(--neon-orange); border: 1px solid rgba(255, 95, 31, 0.3); }
            .tag-info { background: rgba(57, 255, 20, 0.1); color: var(--neon-green); border: 1px solid rgba(57, 255, 20, 0.3); }
            .mono { font-family: 'Consolas', monospace; color: var(--text-muted); }
            .modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(10, 14, 20, 0.85); z-index: 100; justify-content: center; align-items: center; backdrop-filter: blur(5px); }
            .modal-content { background: var(--bg-card); border: 1px solid var(--border); border-radius: 6px; width: 70%; max-width: 800px; max-height: 80vh; display: flex; flex-direction: column; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
            .modal-header { display: flex; justify-content: space-between; align-items: center; padding: 15px 20px; border-bottom: 1px solid var(--border); background: #161b22; }
            .modal-header h2 { margin: 0; font-size: 1.1rem; color: var(--neon-green); text-transform: uppercase; letter-spacing: 1px; }
            .close-btn { background: transparent; border: none; color: var(--text-muted); font-size: 1.5rem; cursor: pointer; transition: color 0.2s; }
            .close-btn:hover { color: var(--red); }
            .modal-body { padding: 20px; overflow-y: auto; display: flex; flex-direction: column; gap: 8px; }
            .detail-row { display: flex; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 8px; }
            .detail-key { width: 150px; font-weight: 600; color: var(--blue); text-transform: uppercase; font-size: 0.85rem; flex-shrink: 0; }
            .detail-val { flex: 1; font-family: 'Consolas', monospace; color: var(--text-main); font-size: 0.9rem; word-break: break-all; white-space: pre-wrap; }
        </style>
    </head>
    <body>
        <div id="app-container" style="display:flex; flex-direction:column; height:100%;">
            <div class="header">
                <h1>Data Sensor <span>HUD</span></h1>
                <div class="btn-group">
                    <div class="live-indicator" id="apiStatus"><div class="pulse"></div> Auto-Tailing API</div>
                </div>
            </div>
            <div class="toolbar">
                <div class="tabs">
                    <button class="tab active" id="tab-core" onclick="setTab('core')">Security Events (<span id="count-core">0</span>)</button>
                    <button class="tab" id="tab-ueba" onclick="setTab('ueba')">UEBA Anomalies (<span id="count-ueba">0</span>)</button>
                    <button class="tab" id="tab-diag" onclick="setTab('diag')">Diagnostics (<span id="count-diag">0</span>)</button>
                </div>
                <input type="text" class="search-box" id="search" placeholder="Search processes, tactics, or details...">
            </div>
            <div class="workspace">
                <div class="table-container">
                    <table>
                        <thead>
                        <tr>
                            <th>Time</th>
                            <th>Tactic</th>
                            <th>Level</th>
                            <th>User</th> <th>Process</th>
                            <th>Message</th>
                        </tr>
                        </thead>
                        <tbody id="table-body"></tbody>
                    </table>
                </div>
            </div>
            <div class="modal-overlay" id="detailModal">
            <div class="modal-content">
                <div class="modal-header">
                    <h2>Event Telemetry Details</h2>
                    <button class="close-btn" onclick="closeModal()">&times;</button>
                </div>
                <div class="modal-body" id="modal-body"></div>
            </div>
        </div>

        <script>
            let coreData = []; let uebaData = []; let diagData = []; let currentTab = 'core'; let totalCount = 0; let failCount = 0;

            function setTab(tab) {
                currentTab = tab;
                document.getElementById('tab-core').classList.toggle('active', tab === 'core');
                document.getElementById('tab-ueba').classList.toggle('active', tab === 'ueba');
                document.getElementById('tab-diag').classList.toggle('active', tab === 'diag');
                renderTable();
            }

            function renderTable() {
                const term = document.getElementById('search').value.toLowerCase();
                const data = currentTab === 'core' ? coreData : (currentTab === 'ueba' ? uebaData : diagData);
                const tbody = document.getElementById('table-body');
                tbody.innerHTML = '';

                for (let i = data.length - 1; i >= 0; i--) {
                    const item = data[i];
                    if (JSON.stringify(item).toLowerCase().indexOf(term) === -1) continue;

                    const tr = document.createElement('tr');
                    const sanitize = (str) => { const div = document.createElement('div'); div.textContent = str || ''; return div.innerHTML || 'N/A'; };

                    const sev = (item.Level || '').toLowerCase();
                    const tagClass = (sev === 'alert' || sev === 'fatal' || sev === 'error') ? 'tag-crit' : (sev === 'warn' ? 'tag-high' : 'tag-info');

                    let timeClean = item.Timestamp ? item.Timestamp.split('T')[1] : '';
                    if (timeClean && timeClean.includes('Z')) timeClean = timeClean.replace('Z','');

                    let actorName = "SYSTEM";
                    let userMatch = item.Message.match(/User:\s*([^\s|]+)/);
                    if (userMatch) { actorName = userMatch[1]; }

                    tr.innerHTML = `
                        <td>${sanitize(timeClean)}</td>
                        <td style='color:var(--blue)'>${sanitize(item.Tactic)}</td>
                        <td><span class='tag ${tagClass}'>${sanitize(item.Level)}</span></td>
                        <td style='color:var(--orange); font-weight:600;'>${sanitize(actorName)}</td>
                        <td style='font-weight:600; color:var(--neon-green)'>${sanitize(item.Process)}</td>
                        <td class='mono'>${sanitize(item.Message)}</td>`;

                    tr.onclick = function() { openModal(item); };
                    tbody.appendChild(tr);
                }
            }

            function openModal(itemData) {
                const modalBody = document.getElementById('modal-body');
                modalBody.innerHTML = '';

                for (const [key, value] of Object.entries(itemData)) {
                    const row = document.createElement('div');
                    row.className = 'detail-row';
                    const displayValue = typeof value === 'object' ? JSON.stringify(value, null, 2) : value;
                    row.innerHTML = `<div class="detail-key">${key}</div><div class="detail-val">${displayValue}</div>`;
                    modalBody.appendChild(row);
                }

                document.getElementById('detailModal').style.display = 'flex';
            }

            function closeModal() {
                document.getElementById('detailModal').style.display = 'none';
            }

            document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });
            document.getElementById('detailModal').addEventListener('click', (e) => {
                if (e.target === document.getElementById('detailModal')) closeModal();
            });

            async function fetchTelemetry() {
                try {
                    const response = await fetch('./api/data');
                    if (!response.ok) throw new Error('API Offline');
                    failCount = 0;
                    const json = await response.json();

                    // Filter Data Sensor unified schema into 3 distinct panes
                    const newCore = json.events.filter(e => e.Level === "ALERT" && (!e.Message || e.Message.indexOf("UEBA_ANOMALY") === -1));
                    const newUeba = json.events.filter(e => e.Level === "ALERT" && e.Message && e.Message.indexOf("UEBA_ANOMALY") !== -1);
                    const newDiag = json.events.filter(e => e.Level !== "ALERT");

                    const newTotal = json.events.length;

                    if (newTotal !== totalCount) {
                        coreData = newCore; uebaData = newUeba; diagData = newDiag; totalCount = newTotal;
                        document.getElementById('count-core').innerText = coreData.length;
                        document.getElementById('count-ueba').innerText = uebaData.length;
                        document.getElementById('count-diag').innerText = diagData.length;
                        renderTable();
                    }
                } catch (err) {
                    failCount++;
                    if (failCount >= 3) {
                        document.getElementById('apiStatus').innerHTML = "<span style='color:var(--red)'>SENSOR OFFLINE</span>";
                        document.getElementById('apiStatus').style.borderColor = "var(--red)";
                        document.getElementById('apiStatus').style.color = "var(--red)";
                    }
                }
            }
            document.getElementById('search').addEventListener('input', renderTable);
            fetchTelemetry();
            setInterval(fetchTelemetry, 2000);
        </script>
    </body>
    </html>
'@

    $RunspaceCode = {
        param($HtmlStr, $LogFile)

        $EphPort = Get-Random -Minimum 49152 -Maximum 65535
        $OtpToken = [guid]::NewGuid().ToString("N")
        $BaseUrl = "http://127.0.0.1:$EphPort/"
        $SecureUrl = "$($BaseUrl)$OtpToken/"

        $Listener = New-Object System.Net.HttpListener
        $Listener.Prefixes.Add($BaseUrl)
        $Listener.Start()

        Start-Process $SecureUrl

        while ($Listener.IsListening) {
            try {
                $ContextAsync = $Listener.BeginGetContext($null, $null)
                $WaitResult = $false

                while (-not $WaitResult) {
                    $WaitResult = $ContextAsync.AsyncWaitHandle.WaitOne(1000)
                }

                $Context = $Listener.EndGetContext($ContextAsync)
                $Req = $Context.Request
                $Res = $Context.Response

                if (-not $Req.Url.LocalPath.StartsWith("/$OtpToken")) {
                    $Res.StatusCode = 403; $Res.Close(); continue
                }

                $ReqPath = $Req.Url.LocalPath.Replace("/$OtpToken", "")
                if ($ReqPath -eq "") { $ReqPath = "/" }

                $Res.Headers.Add("X-Frame-Options", "DENY")
                $Res.Headers.Add("X-Content-Type-Options", "nosniff")
                $Res.Headers.Add("Cache-Control", "no-store, max-age=0")

                if ($ReqPath -eq "/") {
                    $Buffer = [System.Text.Encoding]::UTF8.GetBytes($HtmlStr)
                    $Res.ContentType = "text/html; charset=utf-8"
                    $Res.ContentLength64 = $Buffer.Length
                    $Res.OutputStream.Write($Buffer, 0, $Buffer.Length)
                }
                elseif ($ReqPath -eq "/api/data") {
                    $Events = [System.Collections.Generic.List[string]]::new()

                    if (Test-Path $LogFile) {
                        try {
                            $fs = New-Object System.IO.FileStream($LogFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                            $sr = New-Object System.IO.StreamReader($fs)
                            $allText = $sr.ReadToEnd()
                            $sr.Close(); $fs.Close()

                            $Lines = $allText -split "`n" | Select-Object -Last 200
                            if ($Lines) {
                                foreach ($line in $Lines) {
                                    if ($line.Trim().StartsWith("{")) { $Events.Add($line.Trim()) }
                                }
                            }
                        } catch { }
                    }

                    $DiagPath = $LogFile.Replace("DataSensor_Active.jsonl", "DataSensor_Diagnostic.log")
                    if (Test-Path $DiagPath) {
                        try {
                            $DiagLines = Get-Content -Path $DiagPath -Tail 200 -ErrorAction SilentlyContinue
                            if ($DiagLines) {
                                foreach ($line in $DiagLines) {
                                    if ($line -match "^\[(.*?)\] \[(.*?)\] (.*)") {
                                        $ts = $matches[1]; $lvl = $matches[2]; $msg = $matches[3]
                                        $cleanMsg = $msg -replace '(["\\])', '\$1'
                                        $jsonObj = "{ `"Timestamp`": `"$ts`", `"Level`": `"$lvl`", `"Component`": `"Engine`", `"Process`": `"System`", `"Tactic`": `"Diag`", `"Message`": `"$cleanMsg`" }"
                                        $Events.Add($jsonObj)
                                    }
                                }
                            }
                        } catch { }
                    }

                    $JsonData = "{ `"events`": [" + ($Events -join ",") + "] }"
                    $Buffer = [System.Text.Encoding]::UTF8.GetBytes($JsonData)
                    $Res.ContentType = "application/json"
                    $Res.ContentLength64 = $Buffer.Length
                    $Res.OutputStream.Write($Buffer, 0, $Buffer.Length)
                }
                else { $Res.StatusCode = 404 }
                $Res.Close()
            } catch { break }
        }
    }

    $global:HudRunspace = [powershell]::Create().AddScript($RunspaceCode).AddArgument($HtmlPayload).AddArgument($LogPath)
    $global:HudRunspace.BeginInvoke() | Out-Null
}

Start-DataSensorHUD -LogPath $global:LogFile

try {
    Write-Diag -Message "Entering unmanaged ETW polling loop." -Level "INFO"
    while ($Script:RunLoop) {

        if (-not $Background) {
            try {
                if ([Console]::KeyAvailable) {
                    $keyInput = [Console]::ReadKey($true)
                    if ($keyInput.Key -eq 'C' -and $keyInput.Modifiers -match 'Control') {
                        Write-Host "`n[!] Graceful shutdown initiated by user via CTRL+C..." -ForegroundColor Yellow
                        break
                    }
                }
            } catch { /* Suppress stream read faults in headless environments */ }
        }

        $evtRef = $null
        $BatchCount = 0

        while ([RealTimeDataSensor]::EventQueue.TryDequeue([ref]$evtRef)) {
            $evt = $evtRef
            $BatchCount++
            $global:TotalAlerts++
            $global:LastTelemetryReceived = [DateTime]::UtcNow

            if ($evt.EventType -eq "MITIGATION") {
                Write-Diag -Message "Active Defense Triggered: $($evt.RawJson)" -Level "WARN" -Tactic "T1485 - Data Destruction / Mitigation" -ProcessName $evt.ProcessName

                <#
                .ARCHITECTURAL_ANCHOR 4: ADVANCED FORENSIC AUTOMATION
                    [FUTURE INTEGRATION ZONE]
                    The Thread Suspension has stabilized the threat. Hook SOAR/Forensic playbooks here.
                    1. Trigger MiniDumpWriteDump on the suspended $evt.ProcessName.
                    2. Invoke Windows Firewall API to drop all non-management outbound sockets (Network Containment).
                    3. Capture the locked file handle into a secure forensic vault.
                #>

                try {
                    $ProcPath = (Get-Process -Name $evt.ProcessName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path -First 1)
                    if ($ProcPath) {
                        $RuleName = "DATA_SENSOR_CONTAIN_$($evt.ProcessName)"
                        New-NetFirewallRule -DisplayName $RuleName -Direction Outbound -Program $ProcPath -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
                        Write-Diag -Message "Process Network Sockets Severed via Firewall API." -Level "INFO"
                        $global:AlertQueue.Enqueue("[*] NETWORK CONTAINMENT ENACTED: Outbound sockets severed for $($evt.ProcessName)")
                    }
                } catch {}

                $global:TotalMitigations++
                $global:AlertQueue.Enqueue("[*] MITIGATION ENACTED: $($evt.RawJson)")
                Add-AlertMessage "MITIGATION ENACTED: $($evt.RawJson)" $cGreen
            }
            elseif ($evt.EventType -eq "DLP_ALERT" -or $evt.EventType -eq "UEBA_ALERT") {
                $ts = (Get-Date).ToString("HH:mm:ss")
                $parsed = $evt.RawJson | ConvertFrom-Json

                <#
                .ARCHITECTURAL_ANCHOR 11: IDENTITY CONTEXT ENRICHMENT
                    [FUTURE INTEGRATION ZONE]
                    Before processing the alert, query the local LSASS or a cached Entra ID/AD token.
                    Map the raw SID/User to a corporate identity matrix.
                #>

                if (-not $global:IdentityCache) { $global:IdentityCache = @{} }
                if ($global:IdentityCache.Count -gt 5000) { $global:IdentityCache.Clear() }

                $Identity = "SYSTEM"
                if ($evt.ProcessName -ne "System" -and $evt.ProcessName -ne "Idle") {
                    if ($global:IdentityCache.ContainsKey($evt.ProcessName)) {
                        $Identity = $global:IdentityCache[$evt.ProcessName]
                    } else {
                        try {
                            $wmiProc = Get-WmiObject Win32_Process -Filter "Name = '$($evt.ProcessName).exe'" -ErrorAction SilentlyContinue | Select-Object -First 1
                            if ($wmiProc) { $Identity = $wmiProc.GetOwner().User; $global:IdentityCache[$evt.ProcessName] = $Identity }
                        } catch {}
                    }
                }

                foreach ($alert in $parsed.alerts) {
                    $CacheKey = "$($alert.alert_type)_$($evt.ProcessName)_$($alert.details)"
                    if ($AlertCache.ContainsKey($CacheKey) -and ($AlertCache[$CacheKey] -gt (Get-Date).AddSeconds(-5))) { continue }
                    $AlertCache[$CacheKey] = Get-Date

                    if ($alert.details -match "CONTAINMENT_REQUIRED") {
                        if ($global:SensorMode -eq "Armed") {
                            try {
                                $ProcPath = (Get-Process -Name $evt.ProcessName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path -First 1)
                                if ($ProcPath) {
                                    $RuleName = "DATA_SENSOR_CONTAIN_$($evt.ProcessName)"
                                    New-NetFirewallRule -DisplayName $RuleName -Direction Outbound -Program $ProcPath -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
                                    Write-Diag -Message "Process Network Sockets Severed via Firewall API." -Level "WARN" -Tactic "T1485 - Data Destruction / Mitigation" -ProcessName $evt.ProcessName
                                    Add-AlertMessage "NETWORK CONTAINMENT ENACTED: Outbound sockets severed for $($evt.ProcessName)" $cRed
                                    $global:TotalMitigations++
                                }
                            } catch {}
                        } else {
                            Write-Diag -Message "Policy Violation Detected. Containment skipped (Sensor is in Monitoring Mode)." -Level "WARN" -Tactic "T1485"
                            Add-AlertMessage "CONTAINMENT RECOMMENDED: Sensor is in Monitoring Mode. Action skipped." $cOrange
                        }
                    }

                    $mitre = if ($alert.mitre_tactic) { $alert.mitre_tactic } else { "T1048" }
                    $contextIndicator = if ($alert.details -match "Velocity|Network_Socket") { "NET" } else { "IO " }

                    $ActionUser = if ($alert.user -and $alert.user -ne "System") { $alert.user } elseif ($evt.UserName) { $evt.UserName } else { $Identity }

                    $LogMsg = "Conviction: $($alert.alert_type) | User: $ActionUser | Confidence: $($alert.confidence) | $($alert.details)"
                    Write-Diag -Message $LogMsg -Level "ALERT" -Tactic $mitre -ProcessName $evt.ProcessName

                    $outMsg = "[$ts] $mitre | $($alert.alert_type) | [$contextIndicator] $ActionUser@$($evt.ProcessName) | $($alert.details)"

                    <#
                    .ARCHITECTURAL_ANCHOR 5: SIEM & DATA LAKE FORWARDING
                        [FUTURE INTEGRATION ZONE]
                        Ship the schematized JSON object to a centralized aggregation tier.
                        Implementation must use a Fire-and-Forget asynchronous HTTPS/gRPC push.
                    #>

                    <#
                    .ARCHITECTURAL_ANCHOR 12: OFFLINE TELEMETRY SPOOLING
                        [FUTURE INTEGRATION ZONE]
                        If the SIEM/XDR endpoint is unreachable (e.g., laptop disconnected),
                        divert the JSON payload into an encrypted local SQLite Spool DB.
                    #>

                    $SiemObject = @{ timestamp = $ts; host = $env:COMPUTERNAME; user = $Identity; process = $evt.ProcessName; alert = $alert } | ConvertTo-Json -Compress
                    $SpoolFile = "C:\ProgramData\DataSensor\Data\OfflineSpool.jsonl"
                    Add-Content -Path $SpoolFile -Value $SiemObject -ErrorAction SilentlyContinue

                    <#
                    .ARCHITECTURAL_ANCHOR 2: NON-BLOCKING EVENT PUSH
                        [FUTURE INTEGRATION ZONE]
                        Drop serialized alert data into a ThreadSafeQueue/ConcurrentQueue here.
                        The core loop MUST NOT wait for the HUD to acknowledge receipt.
                    #>

                    <#
                    .ARCHITECTURAL_ANCHOR 9: WEBPAGE HUD / CONSOLE ALERT ROUTING
                        [FUTURE INTEGRATION ZONE]
                    #>

                    if ($global:AlertQueue.Count -lt 1000) { $global:AlertQueue.Enqueue($outMsg) }

                    $RenderColor = if ($alert.confidence -eq 100) { $cRed } else { $cOrange }
                    Add-AlertMessage "$mitre | $($alert.alert_type) | [$contextIndicator] $ActionUser@$($evt.ProcessName) | $($alert.details)" $RenderColor
                }
            }
            elseif ($evt.EventType -eq "DiagLog") {
                Write-EngineDiag -Message $evt.RawJson -Level "ENGINE"
            }
            elseif ($evt.EventType -eq "ERROR" -or $evt.EventType -eq "FATAL") {
                Write-EngineDiag -Message "SYSTEM FAULT: $($evt.RawJson)" -Level "FATAL"
                Add-AlertMessage "SYSTEM FAULT: $($evt.RawJson)" $cRed
            }
        }

        $global:TotalEvents += $BatchCount

        if (([DateTime]::UtcNow - $global:LastHeartbeat).TotalSeconds -ge 5) {
            $global:LastHeartbeat = [DateTime]::UtcNow
            $MemUsageMB = [math]::Round((Get-Process -Id $PID).WorkingSet64 / 1MB, 2)

            $EtwState = if ($QueueSize -ge 90000) { "Degraded" } else { "Good" }
            $QueueSize = [RealTimeDataSensor]::EventQueue.Count

            Draw-Dashboard -Events $global:TotalEvents -Alerts $global:TotalAlerts -EtwHealth $EtwState -QueueSize $QueueSize

            Draw-AlertWindow
            <#
            .ARCHITECTURAL_ANCHOR 3: AGGREGATED TELEMETRY HEARTBEAT
                [FUTURE INTEGRATION ZONE]
            #>

            $global:SystemMetrics["TotalAlerts"] = $global:TotalAlerts
            $global:SystemMetrics["RAM"] = $MemUsageMB

            <#
            .ARCHITECTURAL_ANCHOR 6: REMOTE POLICY SYNCHRONIZATION
                [FUTURE INTEGRATION ZONE]
            #>

            <#
            .ARCHITECTURAL_ANCHOR 13: OVER-THE-AIR (OTA) BINARY UPDATES
                [FUTURE INTEGRATION ZONE]
            #>

            $EtwState = "Good"
            if ($QueueSize -ge 90000) {
                Write-Diag -Message "UEBA Queue Saturation (90k+). Engine lagging behind ETW firehose." -Level "WARN"
                $EtwState = "Degraded"
            }

            $FaultDetected = $false
            foreach ($log in $global:StartupLogs) {
                if ($log -match "SYSTEM FAULT") { $FaultDetected = $true }
            }

            if ($FaultDetected -and (([DateTime]::UtcNow - $global:LastTelemetryReceived).TotalSeconds -ge 30)) {
                Write-Diag -Message "Pipeline fault correlated with telemetry silence. Initiating Session Recovery." -Level "FATAL"
                Write-Host "`n[!] Sensor Integrity Compromised. Auto-recovering TraceEvent Session..." -ForegroundColor Red

                [RealTimeDataSensor]::RecoverSession()

                $global:LastTelemetryReceived = [DateTime]::UtcNow
                $global:StartupLogs.Clear()
                Write-Diag -Message "TraceEvent Session Auto-Recovered." -Level "INFO"
            }
        }

        if ($global:UiNeedsUpdate -or ($BatchCount -gt 0)) {
            Draw-Dashboard -Events $global:TotalEvents -Alerts $global:TotalAlerts -QueueSize $global:DataQueueSize
            Draw-AlertWindow
            $global:UiNeedsUpdate = $false
        }

        Start-Sleep -Milliseconds 250
    }
} finally {
    Clear-Host
    [Console]::SetCursorPosition(0, 0)

    Write-Host "`n$cGold[*] Initiating Graceful Shutdown...$cReset"
    Write-Diag "Initiating Teardown Sequence..." "INFO"

    <#
    .ARCHITECTURAL_ANCHOR 10: GRACEFUL UI & HUD TEARDOWN
        [FUTURE INTEGRATION ZONE]
    #>

    Write-Host "    [*] Terminating Web HUD Runspace & releasing port bindings..." -ForegroundColor Gray
    try {
        if ($global:HudRunspace) {
            $global:HudRunspace.BeginStop($null, $null) | Out-Null
            $global:HudRunspace.Dispose()
        }
    } catch {}

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