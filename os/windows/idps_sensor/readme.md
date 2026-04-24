### **Project Charter: IDPS Sensor (Bidirectional Volumetric & Behavioral Engine)**

**Phase:** Version 1.0 (Hardened Standalone Prototype)

**Lead Developer:** Robert Weber

#### **The Mission**
To engineer and validate a wire-speed, zero-latency **Intrusion Detection and Prevention System (IDPS)** utilizing a native FFI architecture. The primary objective is to demonstrate the stability and accuracy of **spatial clustering heuristics** (K-Means and DBSCAN) and unmanaged **ETW collection**. The system provides real-time network observability and automated mitigation through zero-allocation data transmission between a C# orchestrator and a Native Rust behavioral engine.

#### **Core Architectural Objectives**

* **Isolated High-Fidelity Network Observation:**
    * Utilize an unmanaged C# ETW listener to monitor continuous `Microsoft-Windows-TCPIP`, `DNS-Client`, and `Kernel-Network` telemetry.
    * Maintain a stateful **SQLite Universal Ledger** in WAL mode to store raw flow metadata and volumetric history for behavioral analysis.
* **Spatial Clustering & Volumetric Heuristics:**
    * Execute 4D feature matrix analysis using **K-Means and DBSCAN** to identify anomalous network clusters and flow outliers.
    * Apply deterministic heuristics to identify **Ingress/Egress Asymmetry**, **Micro-Bursting**, and high-entropy **DGA DNS queries**.
* **Native FFI Resilience:**
    * Operate a zero-allocation FFI boundary using blittable `IncomingTelemetry` structs to pass telemetry pointers directly from the CLR to Native Rust.
    * Enforce memory safety through strict payload thresholds (1MB) and unmanaged string reclamation to prevent process instability.
* **Active Defense & Observability:**
    * Execute automated mitigation via **process termination** and **dynamic firewall rules** based on high-confidence behavioral alerts.
    * Provide real-time visibility through a **Live Browser HUD** that auto-tails structured JSONL alerts and UEBA baseline logs.

#### **Current State: Hardened Standalone Prototype**
The IDPS Sensor is a fully functional standalone unit featuring a zero-latency FFI bridge and a persistent behavioral state engine. Current logic prioritizes batch-based statistical deviation and spatial clustering to identify network threats.

#### **The Intended End State (Convergence Readiness)**
The successful validation of this architecture yields a resilient, standalone network defense pipeline. Once the spatial clustering and bidirectional routing demonstrate absolute reliability, the system is certified for integration into the larger **.NET 10 Unified XDR agent** and Ring-0 kernel ecosystem.

---

### Deployment Guide: IDPS Sensor

Follow these instructions to deploy the standalone IDPS Sensor prototype. The deployment sequence is managed by the PowerShell orchestrator to ensure cryptographic integrity and environment security.

#### 1. Prerequisites
* **Operating System**: Windows 10/11 or Windows Server 2019+.
* **Permissions**: An elevated PowerShell terminal (Run as Administrator) is required to manage ETW sessions and directory ACLs.
* **Network**: Internet access is required for the initial fetch of the `TraceEvent` library and the synchronization of Suricata/abuse.ch threat intelligence.

#### 2. Initial File Placement
Ensure the following files are present in the installation root directory:
* `IDPSSensor_Launcher.ps1`: The primary PowerShell orchestrator.
* `idpssensor_ml.dll`: The compiled Native Rust behavioral engine.
* `idpssensor_ml.sha256`: The SHA256 integrity hash for the Rust engine.
* `IDPSSensor_Config.ini`: Global configuration for exclusions and AppGuard policies.
* `suricata/`: Directory containing `.rules` or `.list` files for signature-based detection.

#### 3. Automated Provisioning Sequence
When you execute the launcher, the sensor performs the following automated setup:
1.  **Vault Establishment**: Creates `C:\ProgramData\IDPSSensor` and subdirectories (`Bin`, `Data`, `Logs`, `Staging`).
2.  **Anti-Tamper Lockdown**: Applies strict ACLs to the vault, restricting access to `SYSTEM` and `Administrators`.
3.  **Integrity Validation**: Verifies the `idpssensor_ml.dll` hash against the `.sha256` file before relocating it to the secure `\Bin` folder.
4.  **Dependency Injection**: Automatically downloads and RAM-loads the `TraceEvent` library for the local .NET runtime environment.
5.  **Intel Compilation**: Compiles Suricata rules and JA3 fingerprints into O(1) binary search arrays for wire-speed matching.

#### 4. Execution Commands
Run the orchestrator from an elevated terminal using one of the following operational modes:

| Mode | Command | Description |
| :--- | :--- | :--- |
| **Audit** | `.\IDPSSensor_Launcher.ps1` | Standard observation mode; logs anomalies without mitigation. |
| **Armed** | `.\IDPSSensor_Launcher.ps1 -ArmedMode` | Active defense; enables process termination and firewall blocking. |
| **Test** | `.\IDPSSensor_Launcher.ps1 -TestMode` | Bypasses common CDN IP exclusions for validation testing. |
| **Verbose** | `.\IDPSSensor_Launcher.ps1 -EnableDiagnostics` | Enables detailed logging of FFI transitions and ETW events. |

#### 5. Observability & Monitoring
* **Terminal Dashboard**: Provides real-time metrics on events processed, active flows, and engine health.
* **Live Browser HUD**: A local web interface (automatically launched) provides an interactive workbench to inspect structured JSONL alerts and UEBA baseline logs.
* **Log Files**: All telemetry is recorded in `C:\ProgramData\IDPSSensor\Logs` for SIEM ingestion.

#### 6. Termination
To stop the sensor, press **'Ctrl+C'** or **'Q'** in the terminal. The orchestrator will execute a graceful teardown, flushing the SQLite WAL ledger to disk and closing all kernel ETW sessions.