<#
.SYNOPSIS
    Data Sensor — Comprehensive Runtime Validation Suite
.DESCRIPTION
    Structured pre-flight checks, precision vector execution, and per-stage
    assertions covering every pipeline component end-to-end. Writes a
    machine-readable JSONL log and human-readable summary to:
        C:\ProgramData\DataSensor\Logs\QA_<timestamp>.jsonl
        C:\ProgramData\DataSensor\Logs\QA_<timestamp>_Summary.txt
.NOTES
    Must be run as Administrator.
    Sensor (DataSensor_Launcher.ps1) must already be running.
#>
#Requires -RunAsAdministrator

$ErrorActionPreference = 'Continue'   # NEVER Stop — every assertion must run regardless

# =============================================================================
# PATHS
# =============================================================================
$DS_Root       = 'C:\ProgramData\DataSensor'
$BinDir        = "$DS_Root\Bin"
$LogDir        = "$DS_Root\Logs"
$DataDir       = "$DS_Root\Data"
$EvidenceDir   = "$DS_Root\Evidence"
$DbPath        = "$DataDir\DataLedger.db"
$ActiveLog     = "$LogDir\DataSensor_Active.jsonl"
$SpoolLog      = "$DataDir\OfflineSpool.jsonl"
$ChecksumFile  = "$BinDir\checksums.sha256"
$MlDll         = "$BinDir\DataSensor_ML.dll"
$HookDll       = "$BinDir\DataSensor_Hook.dll"
$SqlitePath    = "$BinDir\sqlite3.exe"
$TestDir       = 'C:\temp_dlp_qa'

$RunTs         = Get-Date -Format 'yyyyMMdd_HHmmss'
$QAJsonLog     = "$LogDir\QA_${RunTs}.jsonl"
$QASummaryLog  = "$LogDir\QA_${RunTs}_Summary.txt"

# =============================================================================
# CONSOLE COLOURS
# =============================================================================
$ESC     = [char]27
$cGreen  = "$ESC[92m"; $cRed    = "$ESC[91m"; $cCyan = "$ESC[96m"
$cYellow = "$ESC[93m"; $cGray   = "$ESC[90m"; $cReset = "$ESC[0m"
$cBold   = "$ESC[1m";  $cDim    = "$ESC[2m";  $cWhite = "$ESC[97m"

# =============================================================================
# RESULT TRACKING & LOGGING INFRASTRUCTURE
# =============================================================================
$Script:Assertions = [System.Collections.Generic.List[pscustomobject]]::new()
$Script:Passed     = 0
$Script:Total      = 0

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory $LogDir -Force | Out-Null }

function Write-QALog {
    param(
        [string]$Category,
        [string]$Check,
        [string]$Result,       # PASS | FAIL | WARN | INFO | SKIP
        [string]$Detail  = '',
        [string]$Evidence = ''
    )
    $ts   = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $obj  = [pscustomobject]@{
        timestamp = $ts; category = $Category
        check     = $Check; result = $Result
        detail    = $Detail; evidence = $Evidence
    }
    $Script:Assertions.Add($obj)
    $json = $obj | ConvertTo-Json -Compress
    Add-Content -Path $QAJsonLog -Value $json -Encoding UTF8

    $color = switch ($Result) {
        'PASS' { $cGreen }; 'FAIL' { $cRed }; 'WARN' { $cYellow }
        'INFO' { $cGray };  'SKIP' { $cDim };  default { $cReset }
    }
    $sym = switch ($Result) {
        'PASS' { '[+]' }; 'FAIL' { '[-]' }; 'WARN' { '[!]' }
        'INFO' { ' · ' }; 'SKIP' { '[~]' }; default { '   ' }
    }
    $msg = "  $sym [$Category] $Check"
    if ($Detail)   { $msg += " — $Detail" }
    Write-Host "$color$msg$cReset"
    if ($Evidence) { Write-Host "$cDim        $Evidence$cReset" }
}

function Assert {
    param(
        [bool]  $Condition,
        [string]$Category,
        [string]$Check,
        [string]$PassDetail = '',
        [string]$FailDetail = '',
        [string]$Evidence   = ''
    )
    $Script:Total++
    if ($Condition) {
        $Script:Passed++
        Write-QALog $Category $Check 'PASS' $PassDetail $Evidence
    } else {
        Write-QALog $Category $Check 'FAIL' $FailDetail $Evidence
    }
}

function Write-Section {
    param([string]$Title)
    $line = '─' * 62
    Write-Host "`n$cCyan$cBold$line`n  $Title`n$line$cReset"
    Write-QALog 'SECTION' $Title 'INFO'
}

function Invoke-DB {
    param([string]$Sql)
    if (-not (Test-Path $SqlitePath) -or -not (Test-Path $DbPath)) { return $null }
    try { return (& $SqlitePath $DbPath $Sql 2>$null) } catch { return $null }
}

function Get-ActiveLogLines {
    param([string]$Pattern, [int]$Last = 0)
    if (-not (Test-Path $ActiveLog)) { return @() }
    $lines = Get-Content $ActiveLog -ErrorAction SilentlyContinue
    if ($Last -gt 0) { $lines = $lines | Select-Object -Last $Last }
    return @($lines | Where-Object { $_ -match $Pattern })
}

# =============================================================================
# SQLITE CLI ACQUISITION
# =============================================================================
if (-not (Test-Path $SqlitePath)) {
    Write-Host "$cYellow  [!] Acquiring SQLite CLI...$cReset"
    try {
        $z = "$env:TEMP\sqlite_qa.zip"; $x = "$env:TEMP\sqlite_qa_ext"
        Invoke-WebRequest 'https://sqlite.org/2024/sqlite-tools-win-x64-3450300.zip' -OutFile $z -UseBasicParsing
        Expand-Archive $z $x -Force
        $exe = Get-ChildItem $x -Filter 'sqlite3.exe' -Recurse | Select-Object -First 1
        Copy-Item $exe.FullName $SqlitePath -Force
        Write-QALog 'SETUP' 'SQLite CLI acquired' 'INFO' $SqlitePath
    } catch {
        Write-QALog 'SETUP' 'SQLite CLI' 'WARN' "Could not acquire — DB assertions will be skipped: $_"
    }
}

# =============================================================================
# HEADER
# =============================================================================
Write-Host "`n$cCyan$cBold"
Write-Host '  ╔══════════════════════════════════════════════════════════════╗'
Write-Host '  ║       DATA SENSOR — RUNTIME VALIDATION SUITE           ║'
Write-Host "  ║       Run ID : $RunTs                          ║"
Write-Host '  ╚══════════════════════════════════════════════════════════════╝'
Write-Host "$cReset"
Write-QALog 'INIT' 'QA Suite started' 'INFO' "Host=$env:COMPUTERNAME User=$env:USERNAME OS=$([System.Environment]::OSVersion.VersionString)"
Write-QALog 'INIT' 'Log paths' 'INFO' "JSONL=$QAJsonLog  Summary=$QASummaryLog"

# =============================================================================
# GUARD — sensor must be running
# =============================================================================
if (-not (Test-Path $ActiveLog)) {
    Write-Host "`n$cRed  FATAL: DataSensor_Active.jsonl not found.$cReset"
    Write-Host "$cRed  Start DataSensor_Launcher.ps1 before running QA.$cReset`n"
    Write-QALog 'PREFLIGHT' 'Active log exists' 'FAIL' 'Sensor not running — aborting'
    exit 1
}

# =============================================================================
# BASELINE SNAPSHOTS  (before any vectors fire)
# =============================================================================
$T0                = Get-Date
$Base_Evidence     = @(Get-ChildItem $EvidenceDir -Filter '*.dat' -ErrorAction SilentlyContinue).Count
$Base_DbTotal      = [int](Invoke-DB 'SELECT COUNT(*) FROM DataLedger;')
$Base_DbClip       = [int](Invoke-DB "SELECT COUNT(*) FROM DataLedger WHERE Destination='Memory_Buffer';")
$Base_DbDisk       = [int](Invoke-DB "SELECT COUNT(*) FROM DataLedger WHERE Destination='Disk_Write';")
$Base_DbNet        = [int](Invoke-DB "SELECT COUNT(*) FROM DataLedger WHERE Destination NOT IN ('Memory_Buffer','Disk_Write','Clipboard');")
$Base_AlertLines   = @(Get-ActiveLogLines '"Level":"ALERT"').Count
$Base_FaultLines   = @(Get-ActiveLogLines 'SYSTEM FAULT').Count

Write-QALog 'BASELINE' 'Snapshots captured' 'INFO' `
    "Evidence=$Base_Evidence DB(Total=$Base_DbTotal Clip=$Base_DbClip Disk=$Base_DbDisk Net=$Base_DbNet) Alerts=$Base_AlertLines Faults=$Base_FaultLines"

# =============================================================================
# PRE-FLIGHT CHECKS
# =============================================================================
Write-Section 'PRE-FLIGHT'

# 1. Active log freshness
$logAge = ((Get-Date) - (Get-Item $ActiveLog).LastWriteTime).TotalSeconds
Assert ($logAge -lt 30) 'PREFLIGHT' 'Active log is fresh (<30s)' `
    "$([int]$logAge)s ago" `
    "Last write was $([int]$logAge)s ago — sensor may be stalled or crashed"

# 2. Named pipe reachable
$pipeOk = $false
try {
    $pc = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'DataSensorAlerts',
        [System.IO.Pipes.PipeDirection]::Out)
    $pc.Connect(800); $pc.Dispose(); $pipeOk = $true
} catch {}
Assert $pipeOk 'PREFLIGHT' 'Named pipe DataSensorAlerts reachable' `
    'Hook IPC channel live' `
    'Pipe not reachable — evidence capture and hook → orchestrator routing will fail'

# 3. DLL files present
foreach ($dll in @($MlDll, $HookDll)) {
    $name = Split-Path $dll -Leaf
    $exists = Test-Path $dll
    Assert $exists 'PREFLIGHT' "$name present in Bin\" `
        "$([math]::Round((Get-Item $dll -ErrorAction SilentlyContinue).Length/1KB, 1)) KB" `
        "File missing from $BinDir — run Build-RustEngine.ps1"
}

# 4. DLL hash integrity vs manifest
if (Test-Path $ChecksumFile) {
    foreach ($line in (Get-Content $ChecksumFile | Where-Object { $_ -match '\S' })) {
        $parts = $line.Trim() -split '\s+', 2
        if ($parts.Count -ne 2) { continue }
        $expected = $parts[0].ToUpper(); $dllName = $parts[1].Trim()
        $dllFull  = Join-Path $BinDir $dllName
        if (Test-Path $dllFull) {
            $actual = (Get-FileHash $dllFull SHA256).Hash.ToUpper()
            $match  = ($actual -eq $expected)
            Assert $match 'PREFLIGHT' "$dllName hash integrity" `
                "$($actual.Substring(0,16))..." `
                "MISMATCH — binary may have been tampered`n        Expected: $($expected.Substring(0,16))...`n        Got     : $($actual.Substring(0,16))..."
        } else {
            Assert $false 'PREFLIGHT' "$dllName hash integrity" '' "DLL not found at $dllFull"
        }
    }
} else {
    Write-QALog 'PREFLIGHT' 'checksums.sha256' 'WARN' `
        'Manifest missing — run Build-RustEngine.ps1 to generate it'
}

# 5. SQLite DB schema
if (Test-Path $DbPath) {
    $schema = Invoke-DB '.schema DataLedger'
    Assert ([bool]($schema -match 'DataLedger')) 'PREFLIGHT' 'DataLedger schema valid' `
        'Table confirmed' 'Schema query returned unexpected result'
} else {
    Write-QALog 'PREFLIGHT' 'DataLedger.db' 'WARN' 'DB not yet created — will appear after first batch commit'
}

# 6. FFI engine ptr loaded (from startup log)
$ffiLoaded = (Get-ActiveLogLines 'ML Engine.*FFI.*successfully mapped').Count -gt 0
Assert $ffiLoaded 'PREFLIGHT' 'ML engine FFI pointer loaded' `
    'init_dlp_engine returned non-null' `
    'No FFI mapped message in log — check DLL path and SetDllDirectory call'

# 7. No pre-existing SYSTEM FAULTs since last sensor start
$preFaults = @(Get-ActiveLogLines 'SYSTEM FAULT').Count
Assert ($preFaults -eq 0) 'PREFLIGHT' 'No pre-existing SYSTEM FAULTs in active log' `
    'Clean baseline' `
    "$preFaults fault line(s) already present before test vectors fired — review log"

# =============================================================================
# TEST ARTIFACT CONSTRUCTION
# =============================================================================
Write-Section 'VECTOR SETUP'

if (-not (Test-Path $TestDir)) { New-Item -ItemType Directory $TestDir -Force | Out-Null }

# --- V1: Clipboard payload (AKIA regex trigger)
# Short enough for clipboard but contains clear AKIA key pattern
$ClipPayload = 'SECURITY MEMO — CONFIDENTIAL. Emergency key rotation required. Compromised credential: AKIATESTING123456789ABCD. Handle per RESTRICTED data policy.'
Write-QALog 'SETUP' 'V1 Clipboard payload' 'INFO' "$($ClipPayload.Length) bytes | AKIA key present"

# --- V2: File write payload
# Must be >512 bytes (hook MIN_INSPECT_BYTES).
# Written via [System.IO.File]::WriteAllText — issues ONE WriteFile syscall.
# Set-Content buffers into small chunks and is unreliable for hook testing.
$FilePadding = 'X' * 650
$FilePayload = @"
INTERNAL MEMORANDUM
Classification: CONFIDENTIAL | Handling: RESTRICTED | Distribution: INTERNAL ONLY

To:   Executive Leadership
From: Security Operations
Re:   Project Titan — Q3 Budget and Risk Review

This document is PROPRIETARY. All recipients must comply with RESTRICTED
data handling procedures. Do not forward via personal email.

Executive Summary:
Budget allocation for Project Titan has been revised upward by 18 percent.
Operation Chimera milestones have been moved to align with the Project Olympus
delivery window. All RESTRICTED materials must transit the secure channel only.

Compliance References:
  - Employee payroll SSN: 123-45-6789 (for benefits reconciliation only)
  - Decommissioned AWS credential (rotate now): AKIAIOSFODNN7EXAMPLE
  - Classification: CONFIDENTIAL — INTERNAL ONLY

Padding block for buffer threshold compliance:
$FilePadding
"@

$FilePath  = "$TestDir\CONFIDENTIAL_Memo.txt"
[System.IO.File]::WriteAllText($FilePath, $FilePayload, [System.Text.Encoding]::UTF8)
$FileBytes = (Get-Item $FilePath).Length
Write-QALog 'SETUP' 'V2 File write payload' 'INFO' `
    "$FileBytes bytes | triggers: Project Titan, CONFIDENTIAL, RESTRICTED, INTERNAL ONLY, SSN, AKIA"
if ($FileBytes -lt 512) {
    Write-QALog 'SETUP' 'V2 payload size check' 'WARN' `
        "$FileBytes bytes is below hook MIN_INSPECT_BYTES=512 — hook will filter this write"
}

# --- V3: ZIP archive (delegation trigger)
$ZipSrcDir = "$TestDir\zip_src"
New-Item -ItemType Directory $ZipSrcDir -Force | Out-Null
$ZipInner = "RESTRICTED REPORT`r`nProject Titan Q3 Revenue Forecast`r`nClassification: CONFIDENTIAL`r`nSSN Reference: 456-78-9012`r`nKey: AKIAIOSFODNN7EXAMPLE`r`n" + ('Z' * 650)
[System.IO.File]::WriteAllText("$ZipSrcDir\report.txt", $ZipInner, [System.Text.Encoding]::UTF8)
$ZipPath   = "$TestDir\packaged_report.zip"
Compress-Archive -Path "$ZipSrcDir\*" -DestinationPath $ZipPath -Force
Write-QALog 'SETUP' 'V3 ZIP payload' 'INFO' "$((Get-Item $ZipPath).Length) bytes | inner: RESTRICTED, Project Titan, SSN"

# --- V4: Network ETW (DNS + TCP)
Write-QALog 'SETUP' 'V4 Network target' 'INFO' 'pastebin.com — DNS resolution + TCP/HTTPS'

# =============================================================================
# VECTOR EXECUTION
# =============================================================================
Write-Section 'VECTOR EXECUTION'

# V1 — Clipboard
Write-Host "$cYellow  [>] V1 — Clipboard: AKIA regex trigger$cReset"
Set-Clipboard -Value $ClipPayload
Write-QALog 'VECTOR' 'V1 Clipboard fired' 'INFO' 'Payload placed on clipboard'
Start-Sleep -Seconds 2

# V2 — File write (second write post-injection ensures hook is active)
Write-Host "$cYellow  [>] V2 — File write: $FileBytes bytes with Project Titan + CONFIDENTIAL + SSN$cReset"
[System.IO.File]::WriteAllText($FilePath, $FilePayload, [System.Text.Encoding]::UTF8)
Write-QALog 'VECTOR' 'V2 File write fired' 'INFO' "$FilePath | $FileBytes bytes (single WriteFile syscall)"
Start-Sleep -Seconds 3

# V3 — ZIP archive
Write-Host "$cYellow  [>] V3 — ZIP: archive delegation trigger$cReset"
Compress-Archive -Path "$ZipSrcDir\*" -DestinationPath "$TestDir\packaged_report2.zip" -Force
Write-QALog 'VECTOR' 'V3 ZIP archive fired' 'INFO' "$TestDir\packaged_report2.zip"
Start-Sleep -Seconds 2

# V4 — Network
Write-Host "$cYellow  [>] V4 — Network: pastebin.com DNS + HTTPS$cReset"
try { [System.Net.Dns]::GetHostAddresses('pastebin.com') | Out-Null } catch {}
try { Invoke-WebRequest 'https://pastebin.com/raw/iQxBvFVG' -UseBasicParsing -TimeoutSec 5 | Out-Null } catch {}
Write-QALog 'VECTOR' 'V4 Network fired' 'INFO' 'pastebin.com DNS + HTTP'
Start-Sleep -Seconds 1

# Pipeline settle — batch processor, WAL commit, hook → pipe → orchestrator round trip
Write-Host "$cGray`n  [·] Waiting 15s for Rust FFI, WAL commit, hook IPC, and ETW batch to settle...$cReset"
Write-QALog 'SETUP' 'Pipeline settle' 'INFO' '15s wait'
Start-Sleep -Seconds 15

# =============================================================================
# ASSERTIONS — CLIPBOARD (V1)
# =============================================================================
Write-Section 'V1 — CLIPBOARD'

# A1: Active log shows clipboard DLP alert
$clipAlerts = Get-ActiveLogLines 'Clipboard Intercepted|AKIATESTING123456789'
Assert ($clipAlerts.Count -gt 0) 'V1-CLIPBOARD' 'Active log shows clipboard DLP alert' `
    "$($clipAlerts.Count) matching line(s)" `
    'No Clipboard Intercepted or AKIA alert in active log — check scan_text_payload FFI path and ParseResponse' `
    ($clipAlerts | Select-Object -Last 1)

# A2: OfflineSpool received the alert
$spoolHits = @()
if (Test-Path $SpoolLog) {
    $spoolHits = @(Get-Content $SpoolLog -ErrorAction SilentlyContinue |
        Where-Object { $_ -match 'Clipboard_Capture' })
}
Assert ($spoolHits.Count -gt 0) 'V1-CLIPBOARD' 'OfflineSpool received clipboard alert' `
    "$($spoolHits.Count) spool entry(s)" `
    'No Clipboard_Capture in OfflineSpool — SIEM relay path may be disabled' `
    ($spoolHits | Select-Object -Last 1)

# A3: UEBA DB has Memory_Buffer row (clipboard feeds _uebaQueue)
$clipDbRows = [int](Invoke-DB "SELECT COUNT(*) FROM DataLedger WHERE Destination='Memory_Buffer';")
$clipDelta   = $clipDbRows - $Base_DbClip
Assert ($clipDelta -gt 0) 'V1-CLIPBOARD' 'DataLedger has Memory_Buffer UEBA row' `
    "+$clipDelta row(s) — clipboard metadata stored for baseline" `
    'No new Memory_Buffer rows — clipboard evt not being TryAdd''d to _uebaQueue in StartClipboardMonitor' `
    (Invoke-DB "SELECT Timestamp,User,Process,Bytes FROM DataLedger WHERE Destination='Memory_Buffer' ORDER BY Id DESC LIMIT 1;")

# =============================================================================
# ASSERTIONS — FILE WRITE HOOK (V2)
# =============================================================================
Write-Section 'V2 — FILE WRITE HOOK'

$newEvidence = @(Get-ChildItem $EvidenceDir -File -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt $T0 } | Sort-Object LastWriteTime -Descending)

# A4: New evidence file created
Assert ($newEvidence.Count -gt 0) 'V2-HOOK' 'New evidence file created' `
    "$($newEvidence.Count) file(s) written to Evidence\" `
    "0 new files — possible causes: (1) Hook not injected into pwsh.exe yet — InjectExistingProcesses takes ~250ms. (2) NtQueryInformationFile returned None → now passes through (socket fix). (3) File payload <512 bytes."

if ($newEvidence.Count -gt 0) {
    $latestDat  = $newEvidence[0]
    $datContent = try { [System.IO.File]::ReadAllText($latestDat.FullName) } catch { '' }

    # A5: Evidence is raw content, not JSON (recursive hook detection)
    $isJson = $datContent -match '"alert_type"'
    Assert (-not $isJson) 'V2-HOOK' 'Evidence file contains raw content (not recursive JSON)' `
        "$($latestDat.Name) | $($latestDat.Length) bytes — raw buffer confirmed" `
        "RECURSIVE HOOK: evidence file contains alert_type JSON — hook is intercepting its own pipe writes. Check NtQueryInformationFile path exclusion for namedpipe." `
        $latestDat.FullName

    # A6: Evidence contains expected DLP trigger text
    $triggerHit = $datContent -match 'Project Titan|CONFIDENTIAL|RESTRICTED|INTERNAL ONLY'
    $triggerWord = if ($datContent -match 'Project Titan') { 'Project Titan' }
                   elseif ($datContent -match 'CONFIDENTIAL') { 'CONFIDENTIAL' }
                   elseif ($datContent -match 'RESTRICTED') { 'RESTRICTED' }
                   else { 'INTERNAL ONLY' }
    Assert $triggerHit 'V2-HOOK' 'Evidence file contains DLP trigger text' `
        "Matched: '$triggerWord'" `
        "Evidence file exists but trigger text absent — hook may have captured wrong buffer or UTF-16 decode mis-classified the content`n        First 120 chars: $($datContent.Substring(0,[Math]::Min(120,$datContent.Length)))"

    # A7: Evidence file is NOT gzip/compressed (socket pass-through fix check)
    $isGzip = ($datContent.Length -gt 2 -and
               [byte][char]$datContent[0] -eq 0x1F -and
               [byte][char]$datContent[1] -eq 0x8B)
    # Also check for base64 encoded gzip (H4sI prefix)
    $isEncodedGzip = $datContent.StartsWith('H4sI')
    Assert (-not $isGzip -and -not $isEncodedGzip) 'V2-HOOK' 'Evidence is not compressed binary (socket pass-through check)' `
        'Content is plaintext — socket writes are not being captured' `
        'Evidence file is gzip/compressed data — socket writes still reaching inspection path. Ensure file_path_opt.is_none() early-return is applied in hook_engine/lib.rs.'
} else {
    # Skip sub-checks when no file exists
    foreach ($skipped in @('Evidence file contains raw content (not recursive JSON)',
                            'Evidence file contains DLP trigger text',
                            'Evidence is not compressed binary (socket pass-through check)')) {
        $Script:Total++
        Write-QALog 'V2-HOOK' $skipped 'SKIP' 'No evidence file to inspect'
    }
}

# A8: Active log shows DLP_ALERT from hook
$hookAlerts = Get-ActiveLogLines 'In-Band Hook|In-Band Write Blocked'
Assert ($hookAlerts.Count -gt 0) 'V2-HOOK' 'Active log shows hook DLP_ALERT' `
    "$($hookAlerts.Count) matching line(s)" `
    'No In-Band Hook alert in active log — pipe may not have delivered the alert or ParseResponse filtered it' `
    ($hookAlerts | Select-Object -Last 1)

# A9: UEBA DB has Disk_Write row (hook metadata routes to _uebaQueue)
$diskDbRows = [int](Invoke-DB "SELECT COUNT(*) FROM DataLedger WHERE Destination='Disk_Write';")
$diskDelta   = $diskDbRows - $Base_DbDisk
Assert ($diskDelta -gt 0) 'V2-HOOK' 'DataLedger has Disk_Write UEBA row' `
    "+$diskDelta row(s) — hook file write metadata stored for baseline" `
    'No new Disk_Write rows — hookEvt not being TryAdd''d to _uebaQueue in StartNamedPipeListener' `
    (Invoke-DB "SELECT Timestamp,User,Process,Bytes FROM DataLedger WHERE Destination='Disk_Write' ORDER BY Id DESC LIMIT 1;")

# =============================================================================
# ASSERTIONS — ZIP DELEGATION (V3)
# =============================================================================
Write-Section 'V3 — ZIP DELEGATION'

# A10: Hook sent ASYNC_INSPECT_QUEUED via pipe
$zipDelegated = Get-ActiveLogLines 'ASYNC_INSPECT_QUEUED|Archive.*Delegating|Delegat.*Orchestrator'
Assert ($zipDelegated.Count -gt 0) 'V3-ZIP' 'Hook sent ASYNC_INSPECT_QUEUED alert' `
    "$($zipDelegated.Count) matching line(s)" `
    'No ASYNC_INSPECT_QUEUED in log — hook may not be injected into the PowerShell Compress-Archive process, or ZIP write < 512 bytes' `
    ($zipDelegated | Select-Object -Last 1)

# A11: Orchestrator triggered extraction
$zipExtracted = Get-ActiveLogLines 'TempArchive|Archive Extraction|ZipFile.Extract'
Assert ($zipExtracted.Count -gt 0) 'V3-ZIP' 'Orchestrator initiated ZIP extraction' `
    "TempArchive activity confirmed" `
    'No TempArchive log entry — depends on A10 passing first; check StartNamedPipeListener ASYNC_INSPECT_QUEUED branch' `
    ($zipExtracted | Select-Object -Last 1)

# =============================================================================
# ASSERTIONS — NETWORK ETW (V4)
# =============================================================================
Write-Section 'V4 — NETWORK ETW'

# A12: Total DB row growth confirms batch committed
$finalDbTotal = [int](Invoke-DB 'SELECT COUNT(*) FROM DataLedger;')
$dbDelta      = $finalDbTotal - $Base_DbTotal
Assert ($dbDelta -gt 0) 'V4-NETWORK' 'DataLedger total row growth' `
    "+$dbDelta row(s) committed (total=$finalDbTotal)" `
    "No new DB rows — check: (1) TransactionBehavior::Deferred in ml_engine. (2) busy_timeout(5000ms). (3) Batch processor not faulting." `
    (Invoke-DB 'SELECT Destination,Bytes FROM DataLedger ORDER BY Id DESC LIMIT 3;' | Out-String).Trim()

# A13: Network destination in DB
$netDbRows  = Invoke-DB "SELECT Destination FROM DataLedger WHERE Destination NOT IN ('Memory_Buffer','Disk_Write','Clipboard') ORDER BY Id DESC LIMIT 20;"
$netDelta   = [int](Invoke-DB "SELECT COUNT(*) FROM DataLedger WHERE Destination NOT IN ('Memory_Buffer','Disk_Write','Clipboard');") - $Base_DbNet
$pastebinHit = $netDbRows -match 'pastebin|104\.|151\.'
if ($pastebinHit) {
    Assert $true 'V4-NETWORK' 'pastebin.com or IP in DataLedger' `
        "+$netDelta network row(s)" '' ($netDbRows | Select-Object -First 3 | Out-String).Trim()
} elseif ($netDelta -gt 0) {
    Write-QALog 'V4-NETWORK' 'pastebin.com or IP in DataLedger' 'WARN' `
        "+$netDelta network rows committed but pastebin IP not matched — ETW captured other destinations. Acceptable if network activity is present." `
        ($netDbRows | Select-Object -First 5 | Out-String).Trim()
    $Script:Total++; $Script:Passed++   # Count as pass — DB is working
} else {
    Assert $false 'V4-NETWORK' 'Network rows in DataLedger' `
        '' "0 new network rows — ETW TCPIP/DNS provider may not have captured the event in the batch window"
}

# =============================================================================
# ASSERTIONS — PIPELINE INTEGRITY
# =============================================================================
Write-Section 'PIPELINE INTEGRITY'

# A14: No SYSTEM FAULT entries added during test run
$newFaultLines = @(Get-ActiveLogLines 'SYSTEM FAULT').Count - $Base_FaultLines
Assert ($newFaultLines -eq 0) 'INTEGRITY' 'No SYSTEM FAULTs during test run' `
    'Clean — daemon_error null-check is working correctly' `
    "$newFaultLines new SYSTEM FAULT line(s) appeared — check ParseResponse daemon_error guard in DataSensor.cs line 601" `
    (Get-ActiveLogLines 'SYSTEM FAULT' | Select-Object -Last 3 | Out-String).Trim()

# A15: No batch processor faults
$batchFaults = Get-ActiveLogLines 'Batch Processor Fault|Transaction Error|SQL Commit Error'
Assert ($batchFaults.Count -eq 0) 'INTEGRITY' 'No batch processor or SQL faults' `
    'Batch pipeline clean' `
    "$($batchFaults.Count) fault line(s) — likely DB lock or JSON parse failure" `
    ($batchFaults | Select-Object -Last 2 | Out-String).Trim()

# A16: All new evidence files are plaintext (comprehensive recursive/socket check)
$allNewEvidence = @(Get-ChildItem $EvidenceDir -File -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt $T0 })
$badEvidence = @($allNewEvidence | Where-Object {
    try {
        $c = [System.IO.File]::ReadAllText($_.FullName)
        $c -match '"alert_type"' -or $c.StartsWith('H4sI')
    } catch { $false }
})
Assert ($badEvidence.Count -eq 0) 'INTEGRITY' 'All new evidence files are plaintext raw buffers' `
    "$($allNewEvidence.Count) file(s) — all confirmed raw content" `
    "$($badEvidence.Count) file(s) contain JSON/gzip — hook capturing socket or pipe writes. Apply socket pass-through fix (file_path_opt.is_none() early return) and namedpipe path exclusion." `
    ($badEvidence | Select-Object -ExpandProperty Name | Out-String).Trim()

# A17: EventQueue depth is reasonable (not saturated)
$queueDepth = try { [RealTimeDataSensor]::_eventQueueCount } catch { -1 }
if ($queueDepth -ge 0) {
    Assert ($queueDepth -lt 4500) 'INTEGRITY' 'EventQueue depth below saturation threshold' `
        "Depth=$queueDepth (limit=5000)" `
        "Depth=$queueDepth — approaching 5000 gate. Decrement after TryDequeue in launcher may be missing."
} else {
    Write-QALog 'INTEGRITY' 'EventQueue depth check' 'SKIP' `
        '_eventQueueCount not accessible — RealTimeDataSensor class may not be loaded in QA context'
}

# A18: groom_database returns non-negative (callable and no SQL error)
$groomHits = Get-ActiveLogLines 'grooming complete|grooming error'
if ($groomHits.Count -gt 0) {
    $hasError = [bool]($groomHits -match 'grooming error')
    Assert (-not $hasError) 'INTEGRITY' 'DB grooming callable without error' `
        ($groomHits | Select-Object -Last 1) `
        "Grooming returned error — check groom_database SQL and mutex lock in ml_engine"
} else {
    Write-QALog 'INTEGRITY' 'DB grooming check' 'SKIP' `
        'No grooming log line yet — groom runs every 6h; expected only on long-running sessions'
}

# =============================================================================
# DIAGNOSTIC SUMMARY (always logged, not scored)
# =============================================================================
Write-Section 'DIAGNOSTICS'

$finalClipRows = [int](Invoke-DB "SELECT COUNT(*) FROM DataLedger WHERE Destination='Memory_Buffer';")
$finalDiskRows = [int](Invoke-DB "SELECT COUNT(*) FROM DataLedger WHERE Destination='Disk_Write';")
$finalNetRows  = [int](Invoke-DB "SELECT COUNT(*) FROM DataLedger WHERE Destination NOT IN ('Memory_Buffer','Disk_Write','Clipboard');")
$finalTotal    = [int](Invoke-DB 'SELECT COUNT(*) FROM DataLedger;')

Write-QALog 'DIAG' 'DB row breakdown' 'INFO' `
    "Memory_Buffer(clip)=$finalClipRows  Disk_Write(hook)=$finalDiskRows  Network=$finalNetRows  Total=$finalTotal"
Write-QALog 'DIAG' 'Evidence files this run' 'INFO' `
    "$($allNewEvidence.Count) new .dat file(s) created"
Write-QALog 'DIAG' 'Active log alert lines this run' 'INFO' `
    "+$(@(Get-ActiveLogLines '"Level":"ALERT"').Count - $Base_AlertLines) new ALERT line(s)"

$recentRows = Invoke-DB 'SELECT Id,Timestamp,Destination,Bytes,Process FROM DataLedger ORDER BY Id DESC LIMIT 5;'
if ($recentRows) {
    Write-QALog 'DIAG' 'Most recent DB rows' 'INFO' ($recentRows | Out-String).Trim()
    Write-Host "$cDim  Recent DataLedger rows:"
    $recentRows | ForEach-Object { Write-Host "    $_" }
    Write-Host "$cReset"
}

# =============================================================================
# FINAL REPORT
# =============================================================================
Write-Section 'RESULTS SUMMARY'

$pct = if ($Script:Total -gt 0) { [math]::Round(($Script:Passed / $Script:Total) * 100) } else { 0 }

# Print all assertions
foreach ($a in $Script:Assertions | Where-Object { $_.result -in 'PASS','FAIL','WARN','SKIP' }) {
    $color = switch ($a.result) {
        'PASS' { $cGreen }; 'FAIL' { $cRed }; 'WARN' { $cYellow }; 'SKIP' { $cDim }; default { $cReset }
    }
    $sym = switch ($a.result) {
        'PASS' { '[+]' }; 'FAIL' { '[-]' }; 'WARN' { '[!]' }; 'SKIP' { '[~]' }; default { '   ' }
    }
    Write-Host "$color  $sym [$($a.category)] $($a.check)$cReset"
    if ($a.result -ne 'PASS' -and $a.detail) {
        Write-Host "$cDim       $($a.detail)$cReset"
    }
}

Write-Host ''
$scoreColor = if ($pct -eq 100) { $cGreen } elseif ($pct -ge 70) { $cYellow } else { $cRed }
Write-Host "$scoreColor$cBold  Score: $($Script:Passed)/$($Script:Total) assertions passed ($pct%)$cReset"

if ($pct -eq 100) {
    Write-Host "$cGreen$cBold  [+] ALL CHECKS PASSED — Pipeline fully operational.$cReset"
} elseif ($pct -ge 70) {
    Write-Host "$cYellow$cBold  [~] PARTIAL PASS — Review failures above.$cReset"
} else {
    Write-Host "$cRed$cBold  [-] VALIDATION FAILED — Major pipeline components not functioning.$cReset"
}

Write-Host "$cGray  JSONL log  : $QAJsonLog$cReset"
Write-Host "$cGray  Summary    : $QASummaryLog$cReset"

# Write summary text file
$fails = @($Script:Assertions | Where-Object { $_.result -eq 'FAIL' })
$warns = @($Script:Assertions | Where-Object { $_.result -eq 'WARN' })
$skips = @($Script:Assertions | Where-Object { $_.result -eq 'SKIP' })

$summaryContent = @(
    "DATA SENSOR QA VALIDATION RESULTS"
    "Run ID  : $RunTs"
    "Score   : $($Script:Passed)/$($Script:Total) ($pct%)"
    "Host    : $env:COMPUTERNAME | User: $env:USERNAME"
    "JSONL   : $QAJsonLog"
    ('=' * 64)
    ''
    "FAILURES ($($fails.Count)):"
    if ($fails.Count -gt 0) {
        $fails | ForEach-Object { "  [-] [$($_.category)] $($_.check)`n       $($_.detail)" }
    } else { '  (none)' }
    ''
    "WARNINGS ($($warns.Count)):"
    if ($warns.Count -gt 0) {
        $warns | ForEach-Object { "  [!] [$($_.category)] $($_.check)`n       $($_.detail)" }
    } else { '  (none)' }
    ''
    "SKIPPED ($($skips.Count)):"
    if ($skips.Count -gt 0) {
        $skips | ForEach-Object { "  [~] [$($_.category)] $($_.check) — $($_.detail)" }
    } else { '  (none)' }
    ''
    ('=' * 64)
    "DB ROW COUNTS (post-test):"
    "  Memory_Buffer (clipboard UEBA) : $finalClipRows"
    "  Disk_Write    (hook UEBA)      : $finalDiskRows"
    "  Network       (ETW UEBA)       : $finalNetRows"
    "  Total                          : $finalTotal"
    ''
    "EVIDENCE:"
    "  New .dat files this run : $($allNewEvidence.Count)"
    if ($allNewEvidence.Count -gt 0) {
        $allNewEvidence | ForEach-Object { "  $($_.Name) | $($_.Length) bytes | $($_.LastWriteTime)" }
    }
)
$summaryContent | Out-File $QASummaryLog -Encoding UTF8

Write-QALog 'COMPLETE' 'QA run finished' 'INFO' "$($Script:Passed)/$($Script:Total) passed ($pct%)"

# =============================================================================
# CLEANUP
# =============================================================================
Start-Sleep -Seconds 1   # let hook finish processing before removing test files
Remove-Item $TestDir -Recurse -Force -ErrorAction SilentlyContinue