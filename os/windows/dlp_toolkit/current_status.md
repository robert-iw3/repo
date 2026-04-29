**NOTE: Alpha Testing Phase On-Going.**

Always take notes, because I'll forget about this...

---

### RESOLVED

The following items are confirmed fixed in code and verified by QA passing:

- IPC newline appended — `format!("{}\n", payload)` confirmed in hook `lib.rs`
- `FILE_INSPECTION` config section correctly scoped in `FILE_EXTENSIONS` lazy_static
- `TRUSTED_PROCESSES` lazy_static reads from `[EXCLUSIONS]` section
- Unknown extension defaults to scan for untrusted processes
- `ARCHIVE_EXTRACTOR_PROCESS` constant defined in FFI engine
- `prepare_cached` SQL column/param count aligned to 9
- `HOOK_DEPTH.set(1)` moved outside sentinel loop
- `DlpConfig` defaults (`15`, `3.0`) match `config.ini`
- Config JSON parse failure now logs explicitly
- `IsDlpHit` column in schema, field in `FfiPlatformEvent`, propagated through batch JSON
- `scan_text_payload` 5th `source_filepath` param wired in both archive and clipboard callers
- `groom_database` retention logic based on `IsDlpHit` not byte count
- `teardown_engine` WAL checkpoint escalation with verification loop
- `ScanTextPayload` P/Invoke points to `DataSensor_ML.dll`
- `hookEvt` sets `is_dlp_hit = true` in pipe listener
- `ForceEjectHooks` writes `Teardown.sig`
- Clipboard worker joined before `teardown_engine` call
- Pipe ACL `AuthenticatedUserSid` Write rule restored
- Archive `RawJson` double-wrap removed
- Archive filepath replacement uses `JsonEscape(file)` → `JsonEscape(evPath)`
- `StartUebaJsonLogger` uses `TryTake(250ms)` instead of `GetConsumingEnumerable`
- Active log staleness — confirmed fresh at 12s in latest QA run (preflight PASS)

---

### QA RUN RESULTS — 20260428_223549

**Score: 22/27 (81%) — Partial Pass**

| Check | Result |
|---|---|
| All PREFLIGHT checks (log freshness, pipe, DLLs, hashes, schema, FFI, faults) | PASS |
| Hook injection confirmed (canary notepad.exe) | **FAIL** |
| V1 Clipboard — active log alert, OfflineSpool, DataLedger Memory_Buffer row | PASS |
| V2 Evidence file created (false positive — clipboard file, not hook write) | PASS* |
| V2 Active log shows hook DLP_ALERT | **FAIL** |
| V2 DataLedger Disk_Write UEBA row | **FAIL** |
| V3 Hook sent ASYNC_INSPECT_QUEUED | **FAIL** |
| V3 Orchestrator ZIP extraction | **FAIL** |
| V4 Network ETW — DB row growth, pastebin destination matched | PASS |
| INTEGRITY — no faults, no SQL errors, evidence plaintext, grooming clean | PASS |

*The V2 evidence assertions (A4–A7) all pass against `1777433759_70c422b2_Clipboard_Capture.dat` — the V1 clipboard file, not a hook write artifact. This is a false positive in the assertion logic. See Issue 4 below.

---

### OUTSTANDING — Issue 1: Hook Injection Failing — ACG on All Test Targets

**Symptom:** Canary `notepad.exe` (PID 15052) not injected after 8s. QA process (PID 4180) not hooked. V2/V3 subprocesses not injected. `Disk_Write` rows remain at 0. No `In-Band Hook` alert in active log.

**Root Cause A — Windows 11 notepad is a Store/UWP app:**
OS is Windows NT 10.0.26200.0 (Windows 11 24H2). On this build, `notepad.exe` is a packaged MSIX app located in `C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_*\`. UWP/MSIX processes run with ACG (`ProhibitDynamicCode`) enabled by default. `IsSafeToInject` correctly returns `false` for them. `CreateRemoteThread` + `LoadLibraryW` injection is impossible against ACG-protected processes regardless of privilege level.

**Root Cause B — QA running under `pwsh.exe`, not `powershell.exe`:**
All DB rows show `Process = pwsh`, confirming the QA script is executing under PowerShell 7 (`pwsh.exe`). `pwsh.exe` enables ACG by default as a .NET 8 app. `Start-Job` under `pwsh` spawns additional `pwsh.exe` child processes — all ACG-protected. Neither the QA process itself nor its V2/V3 subprocesses can be injected. This is the same underlying problem as the previous QA run's child-spawn failure, just expressed differently.

**Root Cause C — `_injectedPids` poisoned on ACG rejection (pre-existing bug):**
`InjectRustHook` calls `_injectedPids.TryAdd(targetPid, 0)` before the `IsSafeToInject` check. When ACG blocks injection, the PID is permanently marked as "injected" without `TryRemove` being called. Any subsequent injection retry (e.g., after a sensor restart without process restart) is silently blocked. The "DLL not found" path correctly calls `TryRemove` — the ACG path does not.

**Fix — `DataSensor.cs`, `InjectRustHook`:** Move `TryAdd` to after the safety check:

```csharp
public static void InjectRustHook(int targetPid) {
    if (_teardownRequested) return;
    if (!File.Exists(_hookDllPath)) return;

    // Check ACG BEFORE claiming the PID slot. If this returns early, the PID
    // must NOT be in _injectedPids — otherwise no retry is ever possible.
    if (!IsSafeToInject(targetPid)) {
        EventQueue.Enqueue(new DataEvent {
            EventType = "WARN",
            RawJson = $"InjectRustHook: ACG (ProhibitDynamicCode) active on PID {targetPid} — injection skipped. Process cannot be hooked."
        });
        return;
    }

    if (!_injectedPids.TryAdd(targetPid, 0)) return;

    // ... rest of method unchanged
}
```

**Fix — `QA-DataSensor.ps1`, canary selection and subprocess spawning:**

1. Canary must be a Win32 process guaranteed to have no ACG. Replace `notepad.exe` with `mshta.exe` — always a Win32 host on all Windows versions, not in any exclusion list, no ACG:

```powershell
$canaryProc = Start-Process 'mshta.exe' -PassThru -ErrorAction Stop
```

2. V2/V3 subprocess writes must use `powershell.exe` (WinPS 5.1) explicitly. Replace `Start-Job` with `Start-Process powershell.exe` using `-EncodedCommand` to pass the payload without shell quoting issues. `Start-Job` under `pwsh` spawns `pwsh` children — the explicit path forces WinPS 5.1 which has no ACG:

```powershell
# V2 — encode the write command and spawn powershell.exe explicitly
$v2Script = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes(
    "Start-Sleep -Seconds 3; " +
    "[System.IO.File]::WriteAllText('$FilePath', " +
    "[System.IO.File]::ReadAllText('${FilePath}_template'), " +
    "[System.Text.Encoding]::UTF8)"
))
# Write payload to a temp template file first (avoids string escaping in encoded cmd)
[System.IO.File]::WriteAllText("${FilePath}_template", $FilePayload, [System.Text.Encoding]::UTF8)
$v2Proc = Start-Process 'powershell.exe' -ArgumentList "-NoProfile -EncodedCommand $v2Script" -PassThru
```

**Fix — `config.ini`, ensure `TrustedProcesses` does NOT include `powershell` or `pwsh`:** Confirmed — config.ini does not list them. This is correct. Do not add them. The injection of WinPS 5.1 subprocesses is the desired behaviour.

---

### OUTSTANDING — Issue 2: Sensor Self-Injection of Launcher Process

**Symptom:** The launcher's own `pwsh`/`powershell.exe` host process is not excluded from the injection sweep. Neither `powershell` nor `pwsh` appears in `_criticalSystemProcs` or in `config.ini` `TrustedProcesses`. This means `InjectExistingProcesses` and the ETW `Kernel-Process/Start` handler will both attempt to inject the launcher's own host process.

**Impact — Two cascading problems:**

1. **Teardown sentinel fires inside the launcher process.** The hook DLL's sentinel thread runs inside the launcher's own `pwsh.exe`. When `Teardown.sig` is written, the sentinel inside the launcher process detects it and signals `HooksDetached` after draining only its own in-flight threads. The C# orchestrator interprets this single signal as confirmation that ALL injected processes have detached — but hooks in other processes (actual user applications) may still have active callbacks. `teardown_engine()` is called prematurely.

2. **`remove_hooks()` trampoline race inside the launcher.** The sentinel calls `remove_hooks()` to patch IAT entries back to originals from within the launcher's own process. Meanwhile the launcher's C# code is executing `Write-Diag → AppendAllText → NtWriteFile`. Patching the NtWriteFile trampoline while C# code is in mid-flight through it causes an access violation, terminating the `pwsh` session. **This is the direct cause of the teardown crash reported.**

**Fix — `DataSensor.cs`, `InjectExistingProcesses` and ETW handler:** Add a self-PID exclusion as the first filter in both injection paths:

```csharp
// At class level:
private static readonly int _selfPid = System.Diagnostics.Process.GetCurrentProcess().Id;

// In InjectExistingProcesses, add before the SessionId check:
if (proc.Id == _selfPid) continue;

// In the ETW Kernel-Process/Start handler, add before the criticalSystemProcs check:
if (targetPid == _selfPid) continue;
```

This is the single most important correctness fix. The sensor must never inject its own host process.

---

### OUTSTANDING — Issue 3: Teardown Crashes Before WAL Commit

**Symptom (user reported):** Teardown terminates the `pwsh` session and does not allow the DB to commit the WAL. Post-teardown, `DataLedger.db` is missing events that were visible in the active log during the session.

**Root Cause Chain:**

The crash and WAL loss share a root cause tree with Issue 2, but there is an additional independent contributor:

**Cause A — Self-injection crash (see Issue 2):** `remove_hooks()` + `FreeLibraryAndExitThread` from within the launcher process. The session crashes before `teardown_engine()` is reached at all. Fix: self-PID exclusion eliminates the sentinel running inside the launcher entirely.

**Cause B — Batch processor not drained before `teardown_engine`:** The launcher's shutdown sequence calls `teardown_engine()` without first waiting for the batch processor's current transaction to commit. The batch processor uses `TryTake(250ms)` and processes items in micro-batches. If a batch transaction is open when `teardown_engine()` calls `PRAGMA wal_checkpoint(FULL)`, SQLite returns `busy != 0` (active writer). The checkpoint escalation loop exhausts all 15 attempts (FULL/RESTART/TRUNCATE × 5 each) and falls back to `PRAGMA journal_mode=DELETE`. Switching journal mode mid-transaction causes the in-progress batch to be rolled back silently. All events in that batch are lost.

**Fix — `DataSensor_Launcher.ps1`, shutdown sequence:** Signal the CTS and wait for the batch processor's done event before calling the teardown FFI. The `_batchProcessorDone` `ManualResetEventSlim` already exists in `DataSensor.cs` for this purpose — it just isn't being awaited:

```powershell
# BEFORE calling [RealTimeDataSensor]::ForceEjectHooks() / teardown_engine:

# 1. Stop accepting new telemetry — signal the blocking collection
[RealTimeDataSensor]::_cts.Cancel()

# 2. Wait for the batch processor to flush its last transaction (10s hard cap)
$flushed = [RealTimeDataSensor]::_batchProcessorDone.Wait(10000)
if (-not $flushed) {
    Write-Diag "Batch processor did not drain within 10s — WAL may be incomplete." "WARN"
}

# 3. NOW it is safe to write Teardown.sig and call teardown_engine
[RealTimeDataSensor]::ForceEjectHooks()
# ... wait for HooksDetached ...
[RealTimeDataSensor]::teardown_engine($enginePtr)
```

**Cause C — `HooksDetached` is a single-fire event, not a quorum:** The sentinel in any ONE injected process can signal `HooksDetached`. If a short-lived process (e.g., a QA subprocess) detaches first, the orchestrator proceeds to `teardown_engine()` while hooks in long-running processes are still active and writing to the DB via the IPC pipe. The pipe listener is still routing events to the batch processor queue, which is now cancelled — those events are dropped.

**Fix — `DataSensor_Launcher.ps1` and `DataSensor.cs`:** After receiving `HooksDetached` and before calling `teardown_engine()`, verify all known injected PIDs have ejected by checking their module lists:

```csharp
// In DataSensor.cs — expose injected PID set for verification
public static IEnumerable<int> GetInjectedPids() => _injectedPids.Keys;
```

```powershell
# After HooksDetached is received, poll until module lists are clean (5s max)
$hookDllName = "DataSensor_Hook.dll"
$deadline = (Get-Date).AddSeconds(5)
while ((Get-Date) -lt $deadline) {
    $stillLoaded = [RealTimeDataSensor]::GetInjectedPids() | Where-Object {
        try {
            (Get-Process -Id $_ -ErrorAction Stop).Modules |
                Where-Object { $_.ModuleName -ieq $hookDllName }
        } catch { $false }
    }
    if (-not $stillLoaded) { break }
    Start-Sleep -Milliseconds 200
}
```

---

### OUTSTANDING — Issue 4: V2 Evidence Assertion False Positive

**Symptom:** A4 through A7 (evidence file created, raw content, trigger text present, not gzip) all PASS. The evidence file they inspect is `1777433759_70c422b2_Clipboard_Capture.dat` — the V1 clipboard capture, not a V2 file write artifact. Because T0 is taken before any vectors fire and the clipboard capture is written after T0, the new-file filter includes it. V2 hook assertions A8 (active log alert) and A9 (Disk_Write row) correctly FAIL, but A4–A7 give a misleading pass, masking the true failure depth.

**Fix — `QA-DataSensor.ps1`, V2 evidence filter:** Exclude `_Clipboard_Capture.dat` from the V2 evidence search. Additionally assert that the evidence file path references a disk write, not a clipboard path:

```powershell
# Replace the existing $newEvidence assignment:
$newEvidence = @(Get-ChildItem $EvidenceDir -File -ErrorAction SilentlyContinue |
    Where-Object {
        $_.LastWriteTime -gt $T0 -and
        $_.Name -notmatch '_Clipboard_Capture\.dat$'
    } | Sort-Object LastWriteTime -Descending)

# Add an explicit assertion that the found file is not a clipboard artifact
if ($newEvidence.Count -gt 0) {
    $isClipboardEvidence = $newEvidence[0].Name -match 'Clipboard'
    Assert (-not $isClipboardEvidence) 'V2-HOOK' 'Evidence file is a hook write artifact (not clipboard)' `
        "$($newEvidence[0].Name) confirmed as file-write evidence" `
        "Evidence file appears to be a clipboard capture misrouted to V2 check — hook write produced no evidence"
}
```

---

### Fix Priority Order

| Priority | Issue | File(s) |
|---|---|---|
| 1 | Self-PID exclusion from injection — eliminates teardown crash | `DataSensor.cs` |
| 2 | Drain batch processor before `teardown_engine` — eliminates WAL loss | `DataSensor_Launcher.ps1` |
| 3 | Move `_injectedPids.TryAdd` after `IsSafeToInject` — fixes retry on ACG rejection | `DataSensor.cs` |
| 4 | QA canary: replace `notepad.exe` with `mshta.exe` — Win32, no ACG, not excluded | `QA-DataSensor.ps1` |
| 5 | QA subprocess: use explicit `powershell.exe` path for V2/V3 writes | `QA-DataSensor.ps1` |
| 6 | QA V2 evidence filter: exclude `_Clipboard_Capture.dat` from hook evidence check | `QA-DataSensor.ps1` |
| 7 | HooksDetached quorum verification before `teardown_engine` call | `DataSensor_Launcher.ps1` |
| 8 | UEBA HUD pane: add `DataSensor_UEBA.jsonl` read to `/api/data` handler | `DataSensor_Launcher.ps1` |

Issues 1 and 2 are blocking — neither V2/V3 nor teardown can pass until they are in. Issues 1–3 are all single-method changes in `DataSensor.cs`. Issues 4–6 are QA-only and do not require a sensor rebuild.