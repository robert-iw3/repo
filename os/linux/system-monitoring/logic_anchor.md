# LINUX SENTINEL — ENGINEERING LOGIC ANCHOR
### v0.2.0 Alpha | Last Updated: 2026-05-03

> **Purpose:** This document is the single source of truth for Linux Sentinel's architecture,
> component contracts, data pipeline, and change-control governance. Read this before touching
> the codebase. Every modification, addition, or deletion is validated against the checklists
> in this document before merge.

---

## PART 1: MISSION & CONSTRAINTS

### 1.1 What This System Is
Linux Sentinel is a zero-fault Extended Detection and Response (EDR) agent for Linux.
It hooks into the kernel via eBPF, streams raw syscall telemetry through a Rust-native
behavioral analysis pipeline, and outputs MITRE ATT&CK-mapped security alerts to a local
SQLite database, JSON artifact files, and an authenticated REST API.

### 1.2 Non-Negotiable Constraints
| Constraint | Rationale |
|---|---|
| **The eBPF poll thread never blocks on I/O, locks, or async.** | A blocked poll thread = total kernel telemetry blackout. Events are dropped by the kernel ring buffer if not drained. |
| **Every engine is independently toggleable via `master.toml`.** | The agent must run in degraded mode (e.g., eBPF off, YARA only) without code changes. |
| **Errors are logged, never swallowed.** | This is a security tool. Silent failures are security failures. |
| **Config struct mirrors TOML exactly.** | A mismatch causes startup crash. No partial boot is acceptable. |
| **The agent must survive container orchestration.** | Kubernetes liveness/readiness probes, OOM kills, and capability restrictions are part of the operating environment. |

---

## PART 2: PROJECT LAYOUT

```
linux-sentinel/
├── src/
│   ├── main.rs                    # Supervisor orchestrator & entry point
│   ├── config.rs                  # master.toml deserialization into MasterConfig
│   ├── api/
│   │   └── server.rs              # Axum REST API (Bearer auth, /api/status, /api/alerts)
│   ├── bpf/
│   │   └── sentinel.bpf.c         # eBPF kernel probes (C, CO-RE/BTF)
│   ├── engine/
│   │   ├── ebpf.rs                # Kernel ring buffer → RawKernelEvent marshalling
│   │   ├── rules.rs               # MITRE ATT&CK rule evaluation engine
│   │   ├── scanner.rs             # 5D UEBA behavioral profiling ("the brain")
│   │   ├── honeypot.rs            # Active deception TCP listeners
│   │   └── yara.rs                # Periodic static file integrity scanning
│   ├── siem/
│   │   ├── models.rs              # SecurityAlert, RuleMatch, AlertLevel, MitreTactic
│   │   └── transmitter.rs         # SQLite WAL writer + JSON artifact output
│   └── utils/
│       └── logging.rs             # tracing-subscriber init (JSON file + stdout)
├── build.rs                       # libbpf-cargo skeleton compilation hook
├── Cargo.toml                     # Dependencies & release profile
├── Dockerfile                     # Multi-stage production container build
├── run.sh                         # Docker/Podman deployment script
├── master.toml                    # Runtime configuration (feature toggles, paths, auth)
├── rules.yara                     # Static threat signatures
├── linux-sentinel.service         # systemd unit
├── linux-sentinel.timer           # systemd hourly run timer
├── linux-sentinel-deployment.yml  # Kubernetes manifest
└── README.md                      # Project documentation & mission statement
```

### 2.1 Module Hierarchy (Rust `mod` tree)
```
crate (main.rs)
├── config                         → config.rs
├── api::server                    → api/server.rs
├── engine::ebpf                   → engine/ebpf.rs
├── engine::rules                  → engine/rules.rs
├── engine::scanner                → engine/scanner.rs
├── engine::honeypot               → engine/honeypot.rs
├── engine::yara                   → engine/yara.rs
├── siem::models                   → siem/models.rs
├── siem::transmitter              → siem/transmitter.rs
└── utils::logging                 → utils/logging.rs
```

---

## PART 3: DATA PIPELINE

### 3.1 Pipeline Topology
```
┌──────────────────────────────────────────────────────────────────────┐
│                        KERNEL SPACE                                  │
│  sentinel.bpf.c                                                      │
│  ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐ ┌────────────┐  │
│  │ execve  │ │ openat   │ │ ptrace   │ │ memfd   │ │ tcp/udp    │  │
│  │ probe   │ │ probe    │ │ probe    │ │ probe   │ │ kprobes    │  │
│  └────┬────┘ └────┬─────┘ └────┬─────┘ └────┬────┘ └─────┬──────┘  │
│       └───────────┴────────────┴─────────────┴────────────┘          │
│                            │                                          │
│                   BPF_MAP_TYPE_RINGBUF (2MB)                         │
│                   + LRU_HASH (10240 entries, PID → last_timestamp)   │
└────────────────────────────┬─────────────────────────────────────────┘
                             │
═══════════════════ KERNEL / USER-SPACE BOUNDARY ═══════════════════════
                             │
┌────────────────────────────▼─────────────────────────────────────────┐
│  EbpfEngine::run()         [BARE OS THREAD — std::thread::spawn]     │
│  • ring_buf.poll(50ms)     blocking, zero CPU when idle              │
│  • Marshals C event_t → Rust RawKernelEvent                         │
│  • raw_tx.try_send()       non-blocking, logs on Full/Closed         │
└────────────────────────────┬─────────────────────────────────────────┘
                             │
                    raw_tx / raw_rx
                    mpsc::channel (cap: 100,000)
                    Payload: RawKernelEvent
                             │
┌────────────────────────────▼─────────────────────────────────────────┐
│  ScannerEngine::run()      [TOKIO TASK — "The Brain"]                │
│  • Consumes raw_rx via tokio::select!                                │
│  • Updates in-memory UEBA profiles (HashMap<String, ProcessProfile>) │
│  • Calculates: Shannon Entropy, Execution Velocity, Path Depth       │
│  • Evaluates RulesEngine::evaluate() for MITRE matches               │
│  • Runs periodic baseline checks (users, memory, rootkits, preload)  │
│  • alert_tx.try_send()     non-blocking                              │
└────────────────────────────┬─────────────────────────────────────────┘
                             │
              ┌──────────────┤ alert_tx / alert_rx
              │              │ mpsc::channel (cap: 100,000)
              │              │ Payload: SecurityAlert
              │              │
┌─────────────┴──┐  ┌───────┴──────┐
│ YaraEngine     │  │ HoneypotEngine│    Additional producers
│ [TOKIO TASK]   │  │ [TOKIO TASK]  │    that also feed alert_tx
│ Periodic scan  │  │ TCP listeners │
│ (300s interval)│  │ ports 21,23,  │
│                │  │ 2222,3389     │
└────────────────┘  └───────────────┘
                             │
┌────────────────────────────▼─────────────────────────────────────────┐
│  TransmissionLayer::spawn_worker()  [TOKIO TASK]                     │
│  • Consumes alert_rx                                                 │
│  • Writes JSON artifact to /var/log/linux-sentinel/Behavior/...      │
│  • INSERT into SQLite events table (WAL mode, busy_timeout=5000)     │
└──────────────────────────────────────────────────────────────────────┘
                             │
┌────────────────────────────▼─────────────────────────────────────────┐
│  ApiServer::run()          [TOKIO TASK]                              │
│  • axum router on 0.0.0.0:8080                                       │
│  • Bearer token auth middleware                                      │
│  • GET /api/status  → engine config readout                          │
│  • GET /api/alerts  → SELECT from SQLite events table                │
└──────────────────────────────────────────────────────────────────────┘
```

### 3.2 Event Type Map (Kernel → User-Space → MITRE)
| Event ID | Syscall / Probe | BPF Program | MITRE Technique | Rules Engine Match |
|---|---|---|---|---|
| 1 `EVENT_EXEC` | `sys_enter_execve` | Tracepoint | T1059 Command & Scripting | `comm == "nc"/"socat"` or target contains `/dev/tcp` |
| 2 `EVENT_OPEN_CRIT` | `sys_enter_openat` | Tracepoint (write/create only) | T1078 Valid Accounts | target starts with `/etc/shadow` or `/etc/sudoers` |
| 3 `EVENT_CONNECT` | `tcp_v4_connect` | Kprobe | T1571 Non-Standard Port | `dest_port == 4444 or 1337` |
| 4 `EVENT_PTRACE` | `sys_enter_ptrace` | Tracepoint | T1055.008 Ptrace Injection | Always triggers |
| 5 `EVENT_MEMFD` | `sys_enter_memfd_create` | Tracepoint | T1620 Reflective Code Loading | Always triggers |
| 6 `EVENT_MODULE` | `sys_enter_init_module` / `finit_module` | Tracepoint | T1547.006 Kernel Modules | Always triggers |
| 7 `EVENT_BPF` | `sys_enter_bpf` | Tracepoint | T1562.001 Impair Defenses | `cmd == PROG_LOAD or MAP_UPDATE` |
| 8 `EVENT_UDP_SEND` | `udp_sendmsg` | Kprobe | T1071.004 DNS Tunneling | Shannon entropy of payload > 4.5 |

### 3.3 Channel Contract Summary
| Channel | Producer(s) | Consumer | Capacity | Backpressure Strategy |
|---|---|---|---|---|
| `raw_tx` → `raw_rx` | `EbpfEngine` (OS thread) | `ScannerEngine` (tokio) | 100,000 | `try_send`: warn log + drop on `Full` |
| `alert_tx` → `alert_rx` | `ScannerEngine`, `YaraEngine`, `HoneypotEngine` | `TransmissionLayer` (tokio) | 100,000 | `try_send`: error log + drop on `Full` |

### 3.4 Shared State Map
| Resource | Owner | Shared Via | Consumers | Mutable? |
|---|---|---|---|---|
| `MasterConfig` | `main.rs` | `Arc<MasterConfig>` | All engines, API server | No (read-only after load) |
| SQLite `Pool<Sqlite>` | `TransmissionLayer` | Pool clone | Transmitter (write), API (read) | Yes (internal pool locking) |
| UEBA Profiles | `ScannerEngine` | Private `HashMap` | `ScannerEngine` only | Yes (single-owner) |
| YARA `Rules` | `YaraEngine` | `Arc<Rules>` | `YaraEngine` only | No (compiled once) |
| Tracing Guard | `main.rs` | `_log_guard` binding | N/A (kept alive for process lifetime) | No |

---

## PART 4: COMPONENT CONTRACTS

### 4.1 sentinel.bpf.c ↔ ebpf.rs (FFI Boundary)

The `event_t` struct is defined in C and read via raw pointer cast in Rust.
**These two definitions must be byte-identical.**

```
C struct event_t                    Rust #[repr(C)] struct event_t
─────────────────                   ──────────────────────────────
u64  ts_ns          (offset 0)      u64  ts_ns
u64  interval_ns    (offset 8)      u64  interval_ns
u32  pid            (offset 16)     u32  pid
u32  ppid           (offset 20)     u32  ppid
u32  uid            (offset 24)     u32  uid
u32  event_type     (offset 28)     u32  event_type
char comm[16]       (offset 32)     [u8; 16]  comm
char target[256]    (offset 48)     [u8; 256] target
u32  daddr          (offset 304)    u32  daddr
u16  dport          (offset 308)    u16  dport
u8   payload[64]    (offset 310)    [u8; 64]  payload
                    (total: 374 + padding)
```

**Rule:** Any field addition, removal, or reordering MUST be mirrored in both files
simultaneously. State byte offsets of changed fields in the blast radius.

### 4.2 master.toml ↔ config.rs (Deserialization Contract)

Every section and key in `master.toml` must have a corresponding field in `MasterConfig`
and its child structs. `toml::from_str` is strict by default — unknown fields will cause
a parse failure at startup.

```
master.toml section     Rust struct              Status
───────────────────     ───────────              ──────
[engine]                EngineConfig             PARTIAL — missing enable_anti_evasion
[monitoring]            (none)                   MISSING from config.rs
[storage]               StorageConfig            OK
[siem]                  SiemConfig               OK
[network]               (none)                   MISSING from config.rs
[process]               (none)                   MISSING from config.rs
[files]                 (none)                   MISSING from config.rs
```

**Rule:** Adding a key to `master.toml` without the matching Rust field = startup crash.
Adding a Rust field without the matching TOML key = startup crash (unless `#[serde(default)]`).

### 4.3 models.rs (Shared Data Schema)

`SecurityAlert` is the universal currency of the alert pipeline.

**Constructor:** `SecurityAlert::from_rule()` — the ONLY constructor.
There is NO `SecurityAlert::new()` method. Any code calling `.new()` will not compile.

**Serialization contract:**
- `AlertLevel`: `#[serde(rename_all = "UPPERCASE")]` — serializes to JSON as `"CRITICAL"`, `"HIGH"`, etc.
- `MitreTactic`: Custom `#[serde(rename = "...")]` per variant — e.g., `"TA0002 Execution"`.
- Neither enum implements `Display`. Calling `.to_string()` produces the `Debug` representation
  (e.g., `"Critical"` not `"CRITICAL"`). If downstream code (SQLite `.bind()`, log output)
  needs the serde-cased string, either implement `Display` to match or serialize via
  `serde_json::to_string()`.

### 4.4 SQLite Schema (transmitter.rs ↔ server.rs)

The `events` table is written by `TransmissionLayer` and read by `ApiServer`.
This is the contract between the two — column changes must update both sides.

```sql
CREATE TABLE events (
    event_id TEXT PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    level TEXT NOT NULL,
    mitre_tactic TEXT NOT NULL,
    mitre_technique TEXT NOT NULL,
    pid INTEGER, ppid INTEGER, uid INTEGER,
    comm TEXT, command_line TEXT,
    target_file TEXT, dest_ip TEXT, dest_port INTEGER,
    shannon_entropy REAL, execution_velocity REAL,
    tuple_rarity REAL, path_depth INTEGER, anomaly_score REAL,
    message TEXT NOT NULL,
    synced BOOLEAN DEFAULT 0
);
-- Indexes: idx_timestamp, idx_comm, idx_dest_ip
```

**Notes:**
- `synced` column exists for future SIEM forwarding but is never updated currently.
- `server.rs` SELECT references columns `id`, `timestamp`, `level`, `message`, `mitre_technique`
  — but the table uses `event_id` not `id`. This is a potential runtime query failure.

---

## PART 5: EXECUTION DOMAINS

The codebase has two distinct execution domains. Crossing the boundary incorrectly
causes deadlocks, panics, or telemetry blackouts.

### 5.1 Bare OS Thread Domain
| Component | Thread Type | Blocking Allowed? | Async Allowed? |
|---|---|---|---|
| `EbpfEngine::run()` | `std::thread::spawn` | YES (`ring_buf.poll` is blocking by design) | **NO** — no `.await`, no `block_on`, no tokio runtime |
| eBPF auto-recovery loop | Same OS thread | YES (`std::thread::sleep` for backoff) | **NO** |

**Communication with async world:** `mpsc::Sender::try_send()` ONLY.
This is the single safe bridge — it never blocks, never touches the tokio runtime.

### 5.2 Tokio Async Domain
| Component | Spawn Method | Blocking Allowed? | Current Violations |
|---|---|---|---|
| `ScannerEngine::run()` | `tokio::spawn` | **NO** | `Command::new("ps")` in `check_hidden_processes` |
| `YaraEngine::run()` | `tokio::spawn` | **NO** | `scanner.scan_file()` is CPU-bound blocking |
| `HoneypotEngine::run()` | `tokio::spawn` | **NO** | Clean |
| `TransmissionLayer worker` | `tokio::spawn` | **NO** | `std::fs::write()` for JSON artifacts |
| `ApiServer::run()` | `tokio::spawn` | **NO** | Clean |

**Rule for new code:** Any blocking operation (file I/O, `Command::new`, CPU-bound loops,
`std::thread::sleep`) inside a tokio task MUST be wrapped in `tokio::task::spawn_blocking`
or offloaded to `rayon`. Failure to do so starves the tokio worker thread pool.

---

## PART 6: CONFIGURATION REFERENCE

### 6.1 master.toml — Complete Section Map

```toml
[engine]
enable_ebpf = true           # Gate: EbpfEngine + raw telemetry pipeline
enable_yara = true           # Gate: YaraEngine periodic file scanning
enable_honeypots = true      # Gate: HoneypotEngine TCP listeners
enable_anti_evasion = true   # Gate: ScannerEngine UEBA profiling
performance_mode = false     # Status API: "High-Throughput" vs "Deep-Inspection"

[monitoring]
monitor_network = true       # (Not yet wired to any engine)
monitor_processes = true
monitor_files = true
monitor_users = true
monitor_rootkits = true
monitor_memory = true

[storage]
central_log_dir = "/var/log/linux-sentinel/diagnostics"
output_dir = "/var/log/linux-sentinel/Behavior/Categories"
sqlite_db_path = "/var/log/linux-sentinel/sentinel.db"

[siem]
middleware_gateway_url = "http://127.0.0.1:8080/api/ingest"
auth_token = "your_auth_token_here"
batch_size = 100

[network]
whitelist_connections = ["127.0.0.1", "::1", ...]

[process]
whitelist_processes = ["firefox", "chrome", "docker", ...]

[files]
exclude_paths = ["/var/lib/docker", "/snap", ...]
critical_paths = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", ...]
```

### 6.2 Feature Toggle → Engine Mapping
| Toggle | Engine(s) Gated | Where Checked | Behavior When Off |
|---|---|---|---|
| `enable_ebpf` | `EbpfEngine` | `main.rs` (spawn guard) | OS thread never spawns, no kernel telemetry |
| `enable_yara` | `YaraEngine` | `main.rs` + `yara.rs` (early return) | No file scanning |
| `enable_honeypots` | `HoneypotEngine` | `main.rs` + `honeypot.rs` (early return) | No deception listeners |
| `enable_anti_evasion` | `ScannerEngine` | `main.rs` + `scanner.rs` (early return) | Raw events accumulate in channel but are never consumed |
| `performance_mode` | Status response only | `server.rs` | String changes in `/api/status` |

### 6.3 Whitelists and Exclusions
The `[network]`, `[process]`, and `[files]` sections define whitelists and exclusions.
Currently, `files.critical_paths` is read by `yara.rs` for scan targets.
The `network.whitelist_connections` and `process.whitelist_processes` are defined in config
but NOT yet wired to any filtering logic in the rules engine or scanner.

---

## PART 7: DEPLOYMENT & INFRASTRUCTURE

### 7.1 Container Build (Dockerfile)

**Builder stage:** `rust:1.73` — compiles the Rust binary via `cargo build --release`.
The `build.rs` script invokes `libbpf-cargo::SkeletonBuilder` to compile `sentinel.bpf.c`
into a Rust skeleton. This requires `libbpf-dev`, `clang`, and kernel headers in the
builder image.

**Runtime stage:** `ubuntu:24.04` — copies binary, `master.toml`, and `rules.yara`.
Requires `libbpf-dev` and `libyara-dev` for shared library linkage at runtime.

**Capabilities required at runtime:**
| Capability | Reason |
|---|---|
| `CAP_BPF` | Load and attach eBPF programs |
| `CAP_PERFMON` | Access perf events for eBPF |
| `CAP_SYS_ADMIN` | eBPF map operations, RLIMIT_MEMLOCK |
| `CAP_NET_ADMIN` | Network namespace visibility, honeypot binding |
| `CAP_SYS_PTRACE` | Process inspection for rootkit detection |
| `CAP_DAC_READ_SEARCH` | Read `/etc/shadow`, `/proc` without ownership |
| `CAP_SYS_RESOURCE` | Set RLIMIT_MEMLOCK to infinity |

### 7.2 Kubernetes (linux-sentinel-deployment.yml)

**Intended deployment model:** DaemonSet (one agent per node).
Current manifest incorrectly uses `Deployment` with `replicas: 1`.

**Volume requirements:**
| Mount | Type | Mode | Purpose |
|---|---|---|---|
| `/var/log/linux-sentinel` | emptyDir | read-write | SQLite DB, JSON artifacts, diagnostic logs |
| `/sys/kernel/debug` | hostPath | read-only | Required for eBPF debugfs access |
| `master.toml` | ConfigMap or hostPath | read-only | Agent configuration |

**Probe configuration:**
- Liveness: `GET /api/status` — `initialDelaySeconds: 20` accounts for eBPF map allocation.
- Readiness: `GET /api/status` — `initialDelaySeconds: 15` accounts for YARA compilation.

### 7.3 systemd

**linux-sentinel.service:**
- `Type=simple` — long-running daemon.
- `Restart=on-failure` — auto-recovery.
- `LimitMEMLOCK=infinity` — required for eBPF.
- Hardened: `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`, `NoNewPrivileges=true`.

**linux-sentinel.timer:**
- Currently configured for hourly runs. This is incorrect for a persistent daemon and is
  under review. The service should use `WantedBy=multi-user.target` directly.

### 7.4 Filesystem Layout (Runtime)
```
/opt/linux-sentinel/
├── linux-sentinel              # Compiled binary
├── master.toml                 # Runtime configuration
└── rules.yara                  # YARA signature rules

/var/log/linux-sentinel/
├── diagnostics/
│   └── sentinel-diagnostics.log   # Rolling JSON logs (tracing-appender, daily)
├── sentinel.db                    # SQLite WAL database (events table)
└── Behavior/
    └── Categories/
        └── {event_id}.json        # Individual SecurityAlert JSON artifacts
```

### 7.5 Graceful Shutdown Sequence (main.rs)

```
1. SIGTERM / Ctrl+C received
2. Drop alert_tx sender → TransmissionLayer worker drains remaining alerts
3. Sleep 3 seconds → SQLite WAL checkpoint flushes to disk
4. Close SQLite pool
5. _log_guard drops → tracing flushes final log entries
6. Process exits
```

**Invariant:** No alert written to the channel before shutdown should be lost.
The 3-second drain window must exceed worst-case SQLite write latency under load.

---

## PART 8: KNOWN ISSUES REGISTER

> This register is maintained across engineering sessions. Issues are never silently
> dropped or silently re-raised. The project owner decides priority.

### 8.1 Compile Blockers (Code will not build)
| # | File | Issue | Root Cause |
|---|------|-------|------------|

### 8.2 Build & Deploy Issues (Build or deploy will fail)
| # | File | Issue | Impact |
|---|------|-------|--------|

### 8.3 Runtime Correctness (Will compile but behave incorrectly)
| # | File | Issue | Impact |
|---|------|-------|--------|

---

## PART 9: CHANGE-CONTROL CHECKLIST

**Every modification** — whether adding, editing, or deleting code — must pass
this checklist before being accepted.

### 9.1 Pre-Flight (Before Writing Code)
- [ ] **Read the target file(s) fresh.** Do not rely on memory, cached context, or
      line numbers from a prior session. Lines shift after every edit.
- [ ] **Identify the execution domain.** Is this code on the OS thread or in a
      tokio task? State it explicitly.
- [ ] **Check cross-file dependencies.** Does this file import from or export to
      other modules? List them.
- [ ] **Check the Known Issues Register (§8).** Does this change address, worsen,
      or interact with any known issue? Update the register accordingly.

### 9.2 Blast Radius (Answer All Before Proposing the Edit)

1. **Will this block the eBPF OS thread?**
   Trace the call path. Flag any sync I/O, file reads, locks, `.await`, `Command::new`,
   or channel operations other than `try_send`.

2. **Will this block a tokio worker thread?**
   Flag any blocking I/O, `std::thread::sleep`, `std::fs` operations, `Command::new`,
   or CPU-bound computation that should use `spawn_blocking`.

3. **Does this introduce a resource leak?**
   If touching the SQLite pool, mpsc channels, file handles, or `Arc` references —
   who owns cleanup? What happens on panic?

4. **Does the config contract hold?**
   If adding/removing a field in the Rust struct, the corresponding TOML key must match.
   If adding/removing a TOML key, the Rust struct must match. State the exact field name
   and type on both sides.

5. **Does the FFI contract hold?**
   If touching `event_t` in C or Rust, both definitions must remain byte-identical.
   State the byte offsets of changed fields.

6. **Does the SQLite schema contract hold?**
   If changing the `events` table, both `transmitter.rs` (INSERT) and `server.rs` (SELECT)
   must be updated simultaneously.

7. **Channel saturation impact?**
   If adding a new producer or changing production rate, state the bounded channel capacity
   and what happens when the channel is full.

8. **Public API surface change?**
   If renaming or changing `pub fn`, `pub struct`, or `pub mod` signatures, list every
   call site that must be updated.

If you cannot answer all eight, the edit is not ready.

### 9.3 Post-Edit Verification
- [ ] **Grep for the same anti-pattern** elsewhere in the same file and in related files.
      The compiler shows one error at a time — don't fix one and leave the next waiting.
- [ ] **Name the verification signal.** Which log line, `cargo check` result, or
      runtime behavior confirms the fix works?
- [ ] **Name the regression signal.** What existing behavior would break if this
      fix is wrong?
- [ ] **Update the Known Issues Register (§8)** if this change resolves or introduces an issue.

### 9.4 Edit Format Rules
- No full-file rewrites unless creating a new file or the change is truly global.
- Show before/after for the smallest meaningful region with enough surrounding context
  to apply the patch unambiguously.
- No silent renames or signature changes to `pub` items.
- No new files, modules, or `pub` items without explicit naming, justification,
  and `mod` declaration in the parent module.

---

## PART 10: ANTI-PATTERNS — HARD STOPS

Stop immediately and reassess if you catch yourself doing any of these:

- Citing line numbers from a previous edit session without re-reading the file.
- Proposing `.await` inside the eBPF OS thread path.
- Proposing blocking I/O inside a tokio task without `spawn_blocking`.
- Proposing `unwrap()` on fallible operations in production code paths.
- Adding a config field in Rust without the corresponding TOML key (or vice versa).
- Modifying `event_t` in C without updating the Rust `#[repr(C)]` mirror (or vice versa).
- Using `sqlx::query!` macro without confirming `DATABASE_URL` is set for compile-time checks.
- Calling `SecurityAlert::new()` — that method does not exist. Use `from_rule()`.
- Assuming a previous edit was applied without verifying the file contents.
- Adding scope (new abstractions, new files, new crates) when removing scope
  (delete dead code, fix the existing call) is the correct fix.
- Swallowing errors with bare `let _ =` without a log statement.
- Guessing at crate API behavior for `libbpf-rs`, `yara-rust`, `sqlx`, or `axum`
  instead of verifying against documentation.
- Hedging with "might" or "could" when the file is right there to verify.