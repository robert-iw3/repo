**Program Increment (PI) Plan: Deep Visibility Sensor Architecture Modernization**

**PI Objectives**
* Transition from a managed-heavy (C#/PowerShell) pipeline to a native, high-performance Rust execution engine.
* Achieve zero-drop kernel telemetry ingestion at >1,000,000 events per minute.
* Eliminate .NET Garbage Collection (GC) pauses during critical Event Tracing for Windows (ETW) evaluations.
* Maintain 100% existing functionality and rule parity throughout the architectural migration.

---

### Epic 1: Engine Architecture & FFI Optimization
Currently, the C# layer executes high-overhead operations (Sigma AST evaluation, string formatting, micro-batching) before passing data to Rust. This epic shifts the computational burden to the unmanaged layer.

* **Migrate Sigma AST to Rust:** Move the Sigma rule parsing and evaluation entirely into `lib.rs`. Rust's pattern matching and AST processing are computationally superior to C#. C# passes the raw ETW struct to Rust, allowing the Rust engine to execute both the Boolean signature checks and the ML heuristics in one unified, memory-safe pass.
* **Zero-Copy Telemetry (Ring Buffers):** Instead of C# serializing telemetry into JSON strings and passing them across the FFI boundary (incurring GC overhead), implement a shared memory ring buffer. C# writes the raw ETW structs (blittable types) directly into the buffer, and Rust reads them natively. This eliminates string allocation entirely and reduces ingestion latency to nanoseconds.

**Feature 1.1: The Unmanaged Memory Contract (Blittable Types)**
Currently, C# allocates .NET `string` objects, formats them into a JSON string, and passes a pointer across the Foreign Function Interface (FFI). Every string allocation creates Garbage Collection pressure.

* **Action Item:** Define a mathematically rigid `struct` that shares the exact same memory layout in both C# and Rust. Dynamic strings are deprecated for high-velocity ETW callbacks.
* **C# Implementation (`[StructLayout(LayoutKind.Sequential)]`):** Utilize `unsafe` code and `fixed` char arrays to define maximum lengths for file paths and command lines (e.g., `fixed char ImagePath[256]`).
* **Rust Implementation (`#[repr(C)]`):** Define the exact mirror of the C# struct.
* **Acceptance Criteria:** The memory layout is identical. C# passes a pointer to the struct; Rust reads the native integers and bytes directly without serialization or deserialization.

**Feature 1.2: The Zero-Copy Ring Buffer**
Instead of executing a function call to Rust for every event (or micro-batching), a massive, lock-free circular buffer (Ring Buffer) is allocated in unmanaged memory utilizing `Marshal.AllocHGlobal` in C#.

* **The Producer (C#):** The ETW thread overwrites the next available struct in the Ring Buffer with incoming OS data and atomically increments a "Write Index." This establishes an $O(1)$ operation executing in <10 nanoseconds.
* **The Consumer (Rust):** A dedicated Rust thread asynchronously polls the "Write Index." Upon detecting new data, the struct is read natively, processed, and the "Read Index" is incremented.
* **Acceptance Criteria:** Implementation achieves zero locks, zero FFI crossing overhead, and zero GC allocations. The ETW kernel thread is mathematically immune to OS buffer overruns.

**Feature 1.3: Rust-Native Sigma Evaluation**
With raw telemetry arriving in Rust instantly, C# is relieved of evaluating the Sigma Abstract Syntax Trees (AST).

* **Pre-Compilation:** During startup, Rust parses the Sigma YAML directory and compiles all `Process_Creation` and `File_Event` rules into a high-speed multi-pattern matching automaton (utilizing libraries such as `aho-corasick`).
* **Native Evaluation:** As the Rust engine pulls the raw ETW struct from the Ring Buffer, the unified automaton executes against the byte arrays. It simultaneously calculates Shannon Entropy, performs UEBA ML updates, and executes Sigma matches within the same hardware CPU cache line.
* **Rust-Native Aggregation:** The `UebaAggregator` is entirely rewritten in Rust utilizing `std::sync::RwLock` or `DashMap`. Rust's strict ownership model inherently prevents concurrency corruption during extreme load.

---

### Epic 2: Core Subsystem Offloading (Rust Migration)
To achieve a "C# = Router, Rust = Brain" architecture, computationally heavy and memory-unsafe tasks currently bottlenecking the managed runtime require offloading to native Rust execution.

**Feature 2.1: Threat Intel Compiler (YAML to Rust)**
* **Current State:** PowerShell recursively parses Sigma YAMLs, fetches intelligence, and dynamically injects arrays into memory.
* **Action Item:** Migrate pre-compilation to Rust utilizing `serde_yaml`. Rust natively handles file I/O, parsing, and caching to construct the multi-pattern search automaton.
* **Acceptance Criteria:** PowerShell memory bloat is eliminated; sensor boot latency is reduced to sub-second initialization.

**Feature 2.2: YARA Memory Scanning**
* **Current State:** C# orchestrates YARA scans, introducing high GC pressure and PInvoke overhead during cross-boundary memory reads.
* **Action Item:** Implement the `windows-rs` crate in Rust to call `ReadProcessMemory` and stream bytes directly into the `yara-rust` engine.
* **Acceptance Criteria:** Zero-allocation, in-place memory scanning is achieved. The operation remains invisible to host memory pressure metrics.

**Feature 2.3: Telemetry Transmission**
* **Current State:** A PowerShell background job polls JSON arrays and dispatches HTTP POSTs via `Invoke-RestMethod` every 500ms.
* **Action Item:** Embed a lightweight `tokio` async runtime within the Rust engine to handle asynchronous network I/O natively.
* **Acceptance Criteria:** Blocky PowerShell execution is offloaded. The subsystem natively handles backpressure without relying on managed queues.

**Feature 2.4: Active Defense Enforcement**
* **Current State:** C# invokes Windows APIs (`SuspendThread`, `MiniDumpWriteDump`, `VirtualProtectEx`) via `DllImport`, risking unhandled exceptions crashing the sensor pipeline.
* **Action Item:** Shift enforcement routines to Rust. Utilize Rust's strict ownership model and `Result` types for failsafe execution of critical OS interactions (e.g., thread suspension and process termination).
* **Acceptance Criteria:** Sensor stability and continuous telemetry flow are mathematically guaranteed, ensuring pipeline resilience even if Active Defense actions fail due to `STATUS_ACCESS_DENIED`.