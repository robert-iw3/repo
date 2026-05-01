<#
.SYNOPSIS
    Sensor Middleware — Full E2E Integration & Validation Test
.DESCRIPTION
    A rigorous, self-contained QA harness for the Telemetry Gateway pipeline.

    What it does:
      1.  Generates an isolated test config.ini that overrides all SIEM
          endpoints to point at local mock HTTP listeners (no real Splunk,
          Elastic, or SQL Server required).
      2.  Compiles the Rust workspace (cargo build --release).
      3.  Validates every compiled binary via SHA-256 and records the hashes.
      4.  Spins up isolated HTTP mock listeners for Splunk (:8088),
          Elastic (:9200), and SQL webhook (:8089) in a background runspace.
      5.  Checks for NATS server; auto-starts it if found on PATH.
      6.  Spawns the ingress and three worker binaries against the test config,
          capturing their stdout/stderr to per-process log files.
      7.  Executes negative auth vectors (wrong token, missing header,
          malformed JSON body).
      8.  Injects a single DeepSensor event, a single DataSensor event, and a
          3-event multi-event batch.
      9.  Polls the egress capture log (rather than sleeping a fixed amount)
          and parses each JSONL record by target.
     10.  Asserts CIM field mappings for Splunk, ECS mappings for Elastic,
          and JSON-array wrapping for SQL — for both sensor types.
     11.  Verifies no daemon process crashed during the run.
     12.  Performs deterministic teardown and prints a summary report.

.NOTES
    Requirements:
      - PowerShell 7.x
      - Rust toolchain (cargo) on PATH
      - nats-server.exe on PATH or in the project root
    Must be run as Administrator (required for HttpListener port binding).
#>
#Requires -RunAsAdministrator
#Requires -Version 7

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ═══════════════════════════════════════════════════════════════════════════════
# 1.  ENVIRONMENT, PATHS & LOGGING
# ═══════════════════════════════════════════════════════════════════════════════
$WorkingDir  = (Get-Item $PSScriptRoot).Parent.FullName
$TestDir     = Join-Path $WorkingDir "tests"
$LogDir      = Join-Path $TestDir    "logs"
$BinDir      = Join-Path $WorkingDir "target\release"
$ScratchDir  = Join-Path $TestDir    "scratch"        # daemons run from here
$TestCfgPath = Join-Path $ScratchDir "config.ini"     # generated test config

foreach ($dir in @($TestDir, $LogDir, $ScratchDir)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

$RunStamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
$QALogFile   = Join-Path $LogDir "QA_Run_$RunStamp.log"
$EgressLog   = Join-Path $LogDir "MockSiem_Egress_$RunStamp.jsonl"

# ANSI colour helpers
$ESC     = [char]27
$cReset  = "$ESC[0m"
$cRed    = "$ESC[91m"
$cGreen  = "$ESC[92m"
$cYellow = "$ESC[93m"
$cCyan   = "$ESC[96m"
$cGray   = "$ESC[90m"
$cBold   = "$ESC[1m"

$global:AssertPass  = 0
$global:AssertFail  = 0
$global:ActiveProcs = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()

function Write-QALog {
    param(
        [string]$Stage,
        [string]$Desc,
        [string]$Detail = ""
    )
    $stamp = "[{0:HH:mm:ss.fff}]" -f (Get-Date)
    $line  = "$cCyan$stamp$cReset $cYellow[$(-join ($Stage.ToUpper().PadRight(8)))]$cReset $Desc"
    Write-Host $line
    if ($Detail) { Write-Host "           $cGray$Detail$cReset" }
    "$stamp [$Stage] $Desc | $Detail" | Out-File $QALogFile -Append -Encoding UTF8
}

function Assert-Check {
    param([bool]$Condition, [string]$Message)
    if ($Condition) {
        $global:AssertPass++
        Write-Host "  $cGreen[PASS]$cReset $Message"
        "  [PASS] $Message" | Out-File $QALogFile -Append -Encoding UTF8
    } else {
        $global:AssertFail++
        Write-Host "  $cRed[FAIL]$cReset $Message"
        "  [FAIL] $Message" | Out-File $QALogFile -Append -Encoding UTF8
    }
}

# Invoke-Api — returns the HTTP status code; never throws.
function Invoke-Api {
    param(
        [string]    $Uri,
        [hashtable] $Headers,
        [string]    $Body,
        [string]    $ContentType = "application/json"
    )
    try {
        $r = Invoke-WebRequest -Uri $Uri -Method Post `
             -Headers $Headers -Body $Body -ContentType $ContentType `
             -ErrorAction Stop -SkipHttpErrorCheck
        return [int]$r.StatusCode
    } catch {
        Write-Host "  $cGray[NET-ERR] $($_.Exception.Message)$cReset"
        return 0
    }
}

# Wait-EgressCondition — polls $EgressLog until $Condition returns $true or timeout.
function Wait-EgressCondition {
    param(
        [scriptblock] $Condition,
        [int]         $TimeoutSeconds  = 20,
        [int]         $PollIntervalMs  = 300
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path $EgressLog) {
            $raw = Get-Content $EgressLog -Raw -ErrorAction SilentlyContinue
            if ($raw -and (& $Condition $raw)) { return $raw }
        }
        Start-Sleep -Milliseconds $PollIntervalMs
    }
    # Return whatever arrived (may be partial) for diagnostic assertions.
    if (Test-Path $EgressLog) { return (Get-Content $EgressLog -Raw -ErrorAction SilentlyContinue) }
    return $null
}

Write-Host ""
Write-Host "$cCyan$cBold╔══════════════════════════════════════════════════════════════╗$cReset"
Write-Host "$cCyan$cBold║   SENSOR MIDDLEWARE — E2E QA PIPELINE  ($RunStamp)  ║$cReset"
Write-Host "$cCyan$cBold╚══════════════════════════════════════════════════════════════╝$cReset"
Write-Host ""

# ═══════════════════════════════════════════════════════════════════════════════
# 2.  GENERATE ISOLATED TEST CONFIG.INI
#     All SIEM endpoints point at localhost mock listeners.
#     SQL uses TestWebhookUrl so the SQL worker posts HTTP instead of TDS.
# ═══════════════════════════════════════════════════════════════════════════════
Write-QALog "CONFIG" "Generating isolated test configuration" $TestCfgPath

@"
[GLOBAL]
NatsEndpoint=127.0.0.1:4222
TelemetryStream=SensorStream
TelemetrySubject=sensor.telemetry
DlqSubjectPrefix=sensor.dlq

[INGRESS]
; Plain HTTP — add axum-server + rustls to enable TLS in production
BindPort=8080
AuthToken=ChangeMe
TlsEnabled=False
TelemetrySubject=sensor.telemetry
TelemetryStream=SensorStream

[SPLUNK]
HecEndpoint=http://127.0.0.1:8088/services/collector/event
HecToken=TestSplunkToken
MaxBatchSize=500
TimeoutSeconds=10
TargetIndex=sensor-alerts
TargetSourceType=sensor:ueba

[ELASTIC]
Endpoint=http://127.0.0.1:9200/_bulk
ApiKey=TestElasticKey
MaxBatchSize=1000
TargetIndex=logs-sensor-alerts

[SQL]
DbHost=127.0.0.1
DbPort=1433
DbName=DataSensor_Telemetry
UseSspi=False
DbUser=
DbPass=
Encryption=Off
TrustServerCert=True
SprocName=EXEC dbo.sp_IngestSensorTelemetry @json = @p1
MaxBatchSize=2000
; Routes SQL batches to the HTTP mock listener during QA (leave empty in prod)
TestWebhookUrl=http://127.0.0.1:8089/sql-ingest
"@ | Out-File $TestCfgPath -Encoding UTF8

Write-QALog "CONFIG" "Test config written" `
    "Ingress :8080 | Splunk :8088 | Elastic :9200 | SQL(webhook) :8089"

# ═══════════════════════════════════════════════════════════════════════════════
# 3.  WORKSPACE COMPILATION & BINARY VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════
Write-QALog "BUILD" "Compiling Rust workspace" "cargo build --release --workspace"

$buildProc = Start-Process -FilePath "cargo" `
    -ArgumentList "build --release --workspace" `
    -WorkingDirectory $WorkingDir `
    -RedirectStandardError (Join-Path $LogDir "cargo_build.err") `
    -Wait -NoNewWindow -PassThru

Assert-Check ($buildProc.ExitCode -eq 0) "Cargo workspace compiled (exit $($buildProc.ExitCode))"
if ($global:AssertFail -gt 0) {
    Write-Host "`n$cRed[CRITICAL] Build failed — see $(Join-Path $LogDir 'cargo_build.err')$cReset"
    Exit 1
}

# Validate binaries and record SHA-256 hashes for traceability.
# NOTE: Binary names match package names in Cargo.toml members, NOT the
# original test concept which incorrectly used "api_ingress.exe".
$ExpectedBins = @(
    "core_ingress.exe",
    "worker_splunk.exe",
    "worker_elastic.exe",
    "worker_sql.exe"
)

foreach ($bin in $ExpectedBins) {
    $path   = Join-Path $BinDir $bin
    $exists = Test-Path $path
    Assert-Check $exists "Binary present: $bin"
    if ($exists) {
        $hash = (Get-FileHash $path -Algorithm SHA256).Hash
        Write-QALog "VERIFY" $bin "SHA256: $hash"
    }
}

if ($global:AssertFail -gt 0) {
    Write-Host "`n$cRed[CRITICAL] Binary validation failed.$cReset"
    Exit 1
}

# ═══════════════════════════════════════════════════════════════════════════════
# 4.  MOCK SIEM HTTP LISTENERS  (isolated background runspace)
#     Every request body is appended to $EgressLog as a single JSONL record:
#       {"target":"SPLUNK","timestamp":"…","payload":"…raw body…"}
# ═══════════════════════════════════════════════════════════════════════════════
Write-QALog "INFRA" "Starting Mock SIEM listeners" ":8088 Splunk | :9200 Elastic | :8089 SQL"

$Runspace = [runspacefactory]::CreateRunspace()
$Runspace.Open()
$Runspace.SessionStateProxy.SetVariable("EgressLog", $EgressLog)

$MockLogic = [scriptblock]::Create({
    $l = [System.Net.HttpListener]::new()
    $l.Prefixes.Add("http://127.0.0.1:8088/")
    $l.Prefixes.Add("http://127.0.0.1:9200/")
    $l.Prefixes.Add("http://127.0.0.1:8089/")
    $l.Start()

    while ($l.IsListening) {
        try {
            $ctx  = $l.GetContext()
            $req  = $ctx.Request
            $sr   = [System.IO.StreamReader]::new($req.InputStream, [System.Text.Encoding]::UTF8)
            $body = $sr.ReadToEnd(); $sr.Close()

            $target = switch ($req.Url.Port) {
                8088 { "SPLUNK"  }
                9200 { "ELASTIC" }
                8089 { "SQL"     }
                default { "UNKNOWN" }
            }

            # Escape the body for embedding in JSON without library dependencies.
            $escaped = $body -replace '\\','\\' -replace '"','\"' `
                             -replace "`r`n",'\n' -replace "`n",'\n' -replace "`t",'\t'

            $record = "{""target"":""$target"",""ts"":""$(Get-Date -Format 'o')"",""payload"":""$escaped""}"
            $record | Out-File -FilePath $EgressLog -Append -Encoding UTF8

            $resp = $ctx.Response
            $resp.StatusCode = 200
            $respBytes = [System.Text.Encoding]::UTF8.GetBytes('{"result":"ok"}')
            $resp.OutputStream.Write($respBytes, 0, $respBytes.Length)
            $resp.Close()
        } catch { <# listener closed or client reset #> }
    }
})

$Pipeline = $Runspace.CreatePipeline()
$Pipeline.Commands.AddScript($MockLogic) | Out-Null
$null = $Pipeline.BeginInvoke()
Start-Sleep -Milliseconds 800   # give listeners time to bind

# ═══════════════════════════════════════════════════════════════════════════════
# 5.  NATS SERVER — CHECK OR AUTO-START
# ═══════════════════════════════════════════════════════════════════════════════
Write-QALog "INFRA" "Checking NATS server" ":4222"

$natsUp = $false
try {
    $tc = [System.Net.Sockets.TcpClient]::new(); $tc.Connect("127.0.0.1", 4222); $tc.Close()
    $natsUp = $true
    Write-QALog "INFRA" "NATS already running on :4222" ""
} catch { }

if (-not $natsUp) {
    Write-QALog "INFRA" "NATS not detected — attempting auto-start" ""
    $natsExe = $null
    foreach ($c in @("nats-server", "nats-server.exe",
                     (Join-Path $WorkingDir "nats-server.exe"),
                     (Join-Path $WorkingDir "nats-server"))) {
        if (Get-Command $c -ErrorAction SilentlyContinue) { $natsExe = $c; break }
        if (Test-Path  $c)                                { $natsExe = $c; break }
    }
    if (-not $natsExe) {
        Write-Host "$cRed[CRITICAL] nats-server not found on PATH or project root. Halting.$cReset"
        Exit 1
    }
    $np = Start-Process -FilePath $natsExe `
          -RedirectStandardOutput (Join-Path $LogDir "nats.log") `
          -WindowStyle Hidden -PassThru
    $global:ActiveProcs.Add($np)
    Start-Sleep -Seconds 2
    Write-QALog "INFRA" "NATS auto-started" "PID $($np.Id)"
}

# ═══════════════════════════════════════════════════════════════════════════════
# 6.  SPAWN MIDDLEWARE DAEMONS
#     Binaries run from $ScratchDir where config.ini is the test config.
# ═══════════════════════════════════════════════════════════════════════════════
Write-QALog "INFRA" "Spawning middleware daemons"

$Daemons = @(
    @{ Name = "core_ingress";   Bin = "core_ingress.exe"   }
    @{ Name = "worker_splunk";  Bin = "worker_splunk.exe"  }
    @{ Name = "worker_elastic"; Bin = "worker_elastic.exe" }
    @{ Name = "worker_sql";     Bin = "worker_sql.exe"     }
)

$DaemonProcs = @{}

foreach ($d in $Daemons) {
    $binPath = Join-Path $BinDir $d.Bin
    $outLog  = Join-Path $LogDir "$($d.Name).stdout.log"
    $errLog  = Join-Path $LogDir "$($d.Name).stderr.log"

    $proc = Start-Process -FilePath $binPath `
            -WorkingDirectory $ScratchDir `
            -RedirectStandardOutput $outLog `
            -RedirectStandardError  $errLog `
            -WindowStyle Hidden -PassThru

    $global:ActiveProcs.Add($proc)
    $DaemonProcs[$d.Name] = $proc
    Write-QALog "SPAWN" $d.Name "PID $($proc.Id)"
}

Write-QALog "INFRA" "Waiting for daemons to initialise" "3 s"
Start-Sleep -Seconds 3

foreach ($d in $Daemons) {
    $p = $DaemonProcs[$d.Name]
    Assert-Check (-not $p.HasExited) "Daemon '$($d.Name)' (PID $($p.Id)) alive after init"
    if ($p.HasExited) {
        $errFile = Join-Path $LogDir "$($d.Name).stderr.log"
        if (Test-Path $errFile) {
            $errTail = Get-Content $errFile -Tail 5 | Out-String
            Write-Host "$cRed[CRASH LOG] $($d.Name):$cReset"
            Write-Host $errTail
        }
        Write-Host "$cRed[CRITICAL] $($d.Name) crashed on start. See $LogDir$cReset"
        Exit 1
    }
}


# ═══════════════════════════════════════════════════════════════════════════════
# 7.  NEGATIVE AUTH VECTORS
# ═══════════════════════════════════════════════════════════════════════════════
$ApiUrl = "http://127.0.0.1:8080/api/v1/telemetry"

Write-QALog "VECTOR" "Negative: Invalid Bearer token" "Expect 401"
$code = Invoke-Api -Uri $ApiUrl `
    -Headers @{ "Authorization" = "Bearer WRONG_TOKEN"; "X-Sensor-Type" = "deepsensor" } `
    -Body "[]"
Assert-Check ($code -eq 401) "API rejects wrong token (HTTP $code, want 401)"

Write-QALog "VECTOR" "Negative: No Authorization header" "Expect 401"
$code = Invoke-Api -Uri $ApiUrl `
    -Headers @{ "X-Sensor-Type" = "deepsensor" } `
    -Body "[]"
Assert-Check ($code -eq 401) "API rejects missing auth header (HTTP $code, want 401)"

Write-QALog "VECTOR" "Negative: Malformed JSON body" "Expect 400"
$code = Invoke-Api -Uri $ApiUrl `
    -Headers @{ "Authorization" = "Bearer ChangeMe"; "X-Sensor-Type" = "deepsensor" } `
    -Body "{ this is not : valid JSON !!!"
Assert-Check ($code -eq 400) "API rejects malformed JSON (HTTP $code, want 400)"

Write-QALog "VECTOR" "Negative: Empty array (zero events)" "Expect 202"
$code = Invoke-Api -Uri $ApiUrl `
    -Headers @{ "Authorization" = "Bearer ChangeMe"; "X-Sensor-Type" = "deepsensor" } `
    -Body "[]"
Assert-Check ($code -eq 202) "API accepts empty array gracefully (HTTP $code, want 202)"

# ═══════════════════════════════════════════════════════════════════════════════
# 8.  POSITIVE TELEMETRY INJECTION
# ═══════════════════════════════════════════════════════════════════════════════
$Ts = (Get-Date -Format 'o')

# ── 8a. Single DeepSensor event ──────────────────────────────────────────────
Write-QALog "VECTOR" "Positive: DeepSensor (single event)" "Behavioral / process injection alert"
$DeepPayload = @"
[
  {
    "timestamp":        "$Ts",
    "host":             "QA-WIN-01",
    "ip":               "10.0.0.50",
    "event_user":       "svc_qa",
    "process":          "rundll32.exe",
    "parent":           "powershell.exe",
    "cmd":              "rundll32.exe payload.dll,EntryPoint",
    "matched_indicator":"T1055 - Process Injection",
    "tactic":           "Defense Evasion",
    "technique":        "T1055",
    "severity":         "CRITICAL",
    "score":            98.5
  }
]
"@
$code = Invoke-Api -Uri $ApiUrl `
    -Headers @{ "Authorization" = "Bearer ChangeMe"; "X-Sensor-Type" = "deepsensor" } `
    -Body $DeepPayload
Assert-Check ($code -eq 202) "API accepted DeepSensor event (HTTP $code, want 202)"

# ── 8b. Single DataSensor event ──────────────────────────────────────────────
Write-QALog "VECTOR" "Positive: DataSensor (single event)" "DLP / network exfil alert"
$DataPayload = @"
[
  {
    "timestamp":  "$Ts",
    "user":       "svc_qa",
    "process":    "chrome.exe",
    "destination":"mega.nz",
    "bytes":      104857600,
    "is_dlp_hit": true,
    "event_type": "Network"
  }
]
"@
$code = Invoke-Api -Uri $ApiUrl `
    -Headers @{ "Authorization" = "Bearer ChangeMe"; "X-Sensor-Type" = "datasensor" } `
    -Body $DataPayload
Assert-Check ($code -eq 202) "API accepted DataSensor event (HTTP $code, want 202)"

# ── 8c. Multi-event DeepSensor batch ─────────────────────────────────────────
Write-QALog "VECTOR" "Positive: DeepSensor multi-event batch (3 events)" "Fan-out stress"
$MultiBatch = @"
[
  {
    "timestamp":"$Ts","host":"QA-WIN-02","ip":"10.0.0.51","event_user":"admin",
    "process":"cmd.exe","parent":"explorer.exe","cmd":"cmd.exe /c whoami",
    "matched_indicator":"T1059 - Command Interpreter","tactic":"Execution",
    "technique":"T1059","severity":"MEDIUM","score":55.0
  },
  {
    "timestamp":"$Ts","host":"QA-WIN-03","ip":"10.0.0.52","event_user":"user1",
    "process":"mshta.exe","parent":"winword.exe","cmd":"mshta.exe vbscript:close(Execute(...))",
    "matched_indicator":"T1218 - Signed Binary Proxy Execution","tactic":"Defense Evasion",
    "technique":"T1218","severity":"HIGH","score":82.0
  },
  {
    "timestamp":"$Ts","host":"QA-WIN-04","ip":"10.0.0.53","event_user":"user2",
    "process":"wscript.exe","parent":"outlook.exe","cmd":"wscript.exe dropper.vbs",
    "matched_indicator":"T1059.005 - VBScript","tactic":"Execution",
    "technique":"T1059.005","severity":"HIGH","score":77.5
  }
]
"@
$code = Invoke-Api -Uri $ApiUrl `
    -Headers @{ "Authorization" = "Bearer ChangeMe"; "X-Sensor-Type" = "deepsensor" } `
    -Body $MultiBatch
Assert-Check ($code -eq 202) "API accepted multi-event DeepSensor batch (HTTP $code)"

# ═══════════════════════════════════════════════════════════════════════════════
# 9.  WAIT FOR EGRESS — POLL UNTIL ALL THREE TARGETS APPEAR
# ═══════════════════════════════════════════════════════════════════════════════
Write-QALog "ASSERT" "Polling egress log for worker deliveries" "Timeout: 20 s"

$RawEgress = Wait-EgressCondition -TimeoutSeconds 20 -Condition {
    param($c)
    ($c -match '"target":"SPLUNK"') -and
    ($c -match '"target":"ELASTIC"') -and
    ($c -match '"target":"SQL"')
}

if (-not $RawEgress) {
    Write-QALog "ASSERT" "WARNING: Timeout — partial or no egress data received" ""
}

Assert-Check ($RawEgress -and $RawEgress.Trim().Length -gt 0) `
    "Egress log is populated"

# Parse JSONL records per target — each line is one HTTP request to a mock.
$SplunkRecs  = [System.Collections.Generic.List[psobject]]::new()
$ElasticRecs = [System.Collections.Generic.List[psobject]]::new()
$SqlRecs     = [System.Collections.Generic.List[psobject]]::new()

if ($RawEgress) {
    foreach ($line in ($RawEgress -split "`n" | Where-Object { $_.Trim() })) {
        try {
            $rec = $line | ConvertFrom-Json -ErrorAction Stop
            switch ($rec.target) {
                "SPLUNK"  { $SplunkRecs.Add($rec)  }
                "ELASTIC" { $ElasticRecs.Add($rec) }
                "SQL"     { $SqlRecs.Add($rec)     }
            }
        } catch { }
    }
}

Write-QALog "ASSERT" "Egress record counts" `
    "Splunk=$($SplunkRecs.Count) | Elastic=$($ElasticRecs.Count) | SQL=$($SqlRecs.Count)"

# Flatten payloads per target for regex assertions
$SA = ($SplunkRecs  | ForEach-Object { $_.payload }) -join "`n"
$EA = ($ElasticRecs | ForEach-Object { $_.payload }) -join "`n"
$QA = ($SqlRecs     | ForEach-Object { $_.payload }) -join "`n"

# ═══════════════════════════════════════════════════════════════════════════════
# 10.  SCHEMA ASSERTIONS
# ═══════════════════════════════════════════════════════════════════════════════

# ── 10a. SPLUNK CIM ──────────────────────────────────────────────────────────
Write-QALog "ASSERT" "Splunk CIM field mapping validation"

Assert-Check ($SplunkRecs.Count -gt 0) `
    "Splunk worker delivered at least one batch"

# DeepSensor mappings
Assert-Check ($SA -match '"app"\s*:\s*"rundll32\.exe"') `
    "Splunk DeepSensor: process → CIM 'app' = 'rundll32.exe'"
Assert-Check ($SA -match '"signature"\s*:\s*"T1055') `
    "Splunk DeepSensor: matched_indicator → CIM 'signature' contains 'T1055'"
Assert-Check ($SA -match '"user"\s*:\s*"svc_qa"') `
    "Splunk DeepSensor: event_user → CIM 'user' = 'svc_qa'"
Assert-Check ($SA -match '"severity"\s*:\s*"CRITICAL"') `
    "Splunk DeepSensor: severity field preserved as 'CRITICAL'"
Assert-Check ($SA -match '"score"\s*:\s*98\.5') `
    "Splunk DeepSensor: score field preserved as 98.5"

# DataSensor mappings
Assert-Check ($SA -match '"dlp_hit"\s*:\s*true') `
    "Splunk DataSensor: is_dlp_hit → 'dlp_hit' = true"
Assert-Check ($SA -match '"app"\s*:\s*"chrome\.exe"') `
    "Splunk DataSensor: process → CIM 'app' = 'chrome.exe'"

# HEC envelope fields
Assert-Check ($SA -match '"index"\s*:\s*"sensor-alerts"') `
    "Splunk: HEC 'index' set to 'sensor-alerts'"
Assert-Check ($SA -match '"sourcetype"') `
    "Splunk: HEC 'sourcetype' field present"
Assert-Check ($SA -match '"time"\s*:') `
    "Splunk: HEC 'time' field present"

# Multi-event fan-out (all 3 hosts from the batch)
Assert-Check ($SA -match 'cmd\.exe') `
    "Splunk multi-batch: cmd.exe event delivered"
Assert-Check ($SA -match 'mshta\.exe') `
    "Splunk multi-batch: mshta.exe event delivered"
Assert-Check ($SA -match 'wscript\.exe') `
    "Splunk multi-batch: wscript.exe event delivered"

# ── 10b. ELASTIC ECS ─────────────────────────────────────────────────────────
Write-QALog "ASSERT" "Elastic ECS field mapping validation"

Assert-Check ($ElasticRecs.Count -gt 0) `
    "Elastic worker delivered at least one batch"

Assert-Check ($EA -match '"_index"\s*:\s*"logs-sensor-alerts"') `
    "Elastic: bulk action targets 'logs-sensor-alerts'"
Assert-Check ($EA -match '"@timestamp"') `
    "Elastic: @timestamp field present"

# DeepSensor ECS
Assert-Check ($EA -match '"name"\s*:\s*"rundll32\.exe"') `
    "Elastic DeepSensor: process → ECS 'process.name' = 'rundll32.exe'"
Assert-Check ($EA -match '"name"\s*:\s*"T1055') `
    "Elastic DeepSensor: matched_indicator → ECS 'rule.name' contains 'T1055'"
Assert-Check ($EA -match '"dataset"\s*:\s*"deepsensor\.behavioral"') `
    "Elastic DeepSensor: event.dataset = 'deepsensor.behavioral'"
Assert-Check ($EA -match '"severity"\s*:\s*"CRITICAL"') `
    "Elastic DeepSensor: severity preserved in deepsensor object"

# DataSensor ECS
Assert-Check ($EA -match '"is_dlp_hit"\s*:\s*true') `
    "Elastic DataSensor: is_dlp_hit present in datasensor object"
Assert-Check ($EA -match '"dataset"\s*:\s*"datasensor\.dlp"') `
    "Elastic DataSensor: event.dataset = 'datasensor.dlp'"

# Bulk NDJSON structure — must NOT contain a comma separator between records
Assert-Check ($EA -notmatch '\}\s*,\s*\{\"index\"') `
    "Elastic NDJSON: no comma between bulk action lines (format integrity)"

# ── 10c. SQL ─────────────────────────────────────────────────────────────────
Write-QALog "ASSERT" "SQL worker delivery validation"

Assert-Check ($SqlRecs.Count -gt 0) `
    "SQL worker delivered at least one batch"

# SQL worker wraps events in a JSON array before calling the sproc
Assert-Check ($QA -match '^\s*\[') `
    "SQL: payload is wrapped in a JSON array '[…]'"

# Raw event fields should be present (SQL worker passes through JSON as-is)
Assert-Check ($QA -match '"matched_indicator"') `
    "SQL: DeepSensor 'matched_indicator' present in JSON payload"
Assert-Check ($QA -match '"is_dlp_hit"') `
    "SQL: DataSensor 'is_dlp_hit' present in JSON payload"
Assert-Check ($QA -match '"sensor_type"') `
    "SQL: sensor_type embedded field present in payload"

# ═══════════════════════════════════════════════════════════════════════════════
# 11.  DAEMON HEALTH CHECK (post-run)
# ═══════════════════════════════════════════════════════════════════════════════
Write-QALog "HEALTH" "Verifying all daemon processes still running after test"

foreach ($d in $Daemons) {
    $p = $DaemonProcs[$d.Name]
    $alive = -not $p.HasExited
    Assert-Check $alive "Daemon '$($d.Name)' (PID $($p.Id)) still running after test"
    if (-not $alive) {
        $errFile = Join-Path $LogDir "$($d.Name).stderr.log"
        if (Test-Path $errFile) {
            Write-Host "$cYellow[CRASH LOG] Last 5 lines of $($d.Name) stderr:$cReset"
            Get-Content $errFile -Tail 5 | ForEach-Object { Write-Host "  $_" }
        }
    }
}


# ═══════════════════════════════════════════════════════════════════════════════
# 12.  DETERMINISTIC TEARDOWN
# ═══════════════════════════════════════════════════════════════════════════════
Write-QALog "TEARDOWN" "Terminating daemon processes"
foreach ($proc in $global:ActiveProcs) {
    try {
        if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    } catch { }
}

try { $Pipeline.Stop()        } catch { }
try { $Runspace.Close()       } catch { }
try { $Runspace.Dispose()     } catch { }

# ═══════════════════════════════════════════════════════════════════════════════
# 13.  SUMMARY REPORT
# ═══════════════════════════════════════════════════════════════════════════════
$Total   = $global:AssertPass + $global:AssertFail
$Colour  = if ($global:AssertFail -eq 0) { $cGreen } else { $cRed }
$Status  = if ($global:AssertFail -eq 0) { "ALL TESTS PASSED" } else { "FAILURES DETECTED" }

Write-Host ""
Write-Host "$Colour$cBold╔══════════════════════════════════════════════════════════════╗$cReset"
Write-Host "$Colour$cBold║  QA SUMMARY  —  $Status$cReset"
Write-Host "$Colour$cBold╠══════════════════════════════════════════════════════════════╣$cReset"
Write-Host "$Colour║$cReset  Total assertions : $Total"
Write-Host "$Colour║$cReset  $cGreen Passed$cReset           : $($global:AssertPass)"
Write-Host "$Colour║$cReset  $cRed Failed$cReset           : $($global:AssertFail)"
Write-Host "$Colour║$cReset  QA log           : $QALogFile"
Write-Host "$Colour║$cReset  Egress capture   : $EgressLog"
Write-Host "$Colour║$cReset  Daemon logs      : $LogDir"
Write-Host "$Colour$cBold╚══════════════════════════════════════════════════════════════╝$cReset"
Write-Host ""

"=== QA SUMMARY === Total:$Total Pass:$($global:AssertPass) Fail:$($global:AssertFail)" |
    Out-File $QALogFile -Append -Encoding UTF8

if ($global:AssertFail -gt 0) {
    Write-Host "$cYellow[!] Check daemon logs in: $LogDir$cReset"
    Exit 1
} else {
    Exit 0
}