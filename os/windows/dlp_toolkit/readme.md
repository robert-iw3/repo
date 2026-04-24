### **Project Charter: Data Sensor (DLP & UEBA Engine)**

**Phase:** Early Alpha (Laying the Foundation)

**Lead Developer:** Robert Weber

#### **The Mission**
To engineer, stress-test, and rigorously validate a wire-speed, zero-latency Data Loss Prevention (DLP) sensor utilizing a native FFI architecture. The primary objective is to mathematically prove the stability, accuracy, and memory safety of the Native Rust Machine Learning (UEBA) heuristics and the unmanaged C# ETW listener. The architecture demonstrates execution through surgical threat mitigation and zero-allocation data transmission within a standalone environment, ensuring absolute reliability before integration into the unified .NET 10 orchestration agent.

#### **Core Architectural Objectives (Validation Phase)**

* **Isolated High-Fidelity Observation:**
    * Benchmark the unmanaged C# ETW listener’s ability to monitor continuous `Microsoft-Windows-Kernel-File` and `Microsoft-Windows-Kernel-Network` telemetry.
    * Prove the stability of the micro-batched, memory-mapped SQLite Universal Ledger (WAL mode) by subjecting the FFI boundary to massive exfiltration event loads without inducing I/O blocking or disk contention.
* **Algorithmic Soundness & Multi-Dimensional UEBA:**
    * Stress-test Welford’s Online Algorithm to ensure rolling mathematical baselines adapt to user behavior across dual axes: Volumetric flow and Transfer Velocity.
    * Confirm that variance calculations and Z-Score deviations identify both burst exfiltration and "low-and-slow" anomalies while maintaining a near-zero false positive rate through O(1) trusted-process exclusion.
* **Memory Inspection & FFI Resilience:**
    * Validate the structural integrity of the zero-allocation FFI boundary, utilizing blittable `FfiPlatformEvent` structs to pass telemetry pointers directly to the Native Rust engine.
    * Ensure the in-memory extraction of complex archives (ZIP, Office Open XML) executes with strict memory safety. The Rust engine must enforce hard extraction limits (e.g., 5MB per file) and C# must utilize LOH clamps to prevent process instability or Out-of-Memory (OOM) faults during deep inspection.
* **Deterministic Active Defense & Watchdog Integrity:**
    * Verify surgical thread suspension mechanics via Win32 API hooks (`OpenThread`, `SuspendThread`) to instantly freeze violating threads while preserving primary application state.
    * Validate the ETW Watchdog Canary, ensuring the orchestrator automatically identifies telemetry starvation and executes a sub-second session recovery if kernel buffers are exhausted.

#### **Current State: Hardened Prototype (Standalone)**
The Data Sensor operates as a high-performance, isolated prototype. The Native FFI boundary is fully operational, facilitating zero-latency handoffs between the unmanaged ETW observer and the Rust ML engine. Current efforts prioritize the continuous refinement of the Welford baseline logic against live telemetry, the enforcement of anti-tamper ACLs on the Universal Ledger, and the optimization of the structured JSONL diagnostic engine for SIEM-ready audit trails.

#### **The Intended End State (Readiness for Convergence)**
The successful completion of this phase yields a mathematically proven, resilient, and standalone Data Sensor. Once the UEBA logic, deep inspection routines, and active defense mechanisms demonstrate uncompromising reliability in isolation, the architecture is certified as production-ready. This validated, zero-allocation state serves as the definitive data pipeline for convergence into the larger .NET 10 Unified XDR orchestration agent and the Ring-0 kernel ecosystem.