# Linux Sentinel v0.2.0 (Extreme Alpha)

> **⚠️ WARNING:** This project is currently in the **Extreme Alpha** testing stage. It is undergoing high-frequency architectural changes. Do not deploy in mission-critical production environments without thorough verification.

## Project Mission Statement
To deliver a production-grade, zero-fault Extended Detection and Response (EDR) agent that achieves absolute observability over the Linux kernel. Acting as the definitive counterpart to the **Windows DeepSensor** architecture, Linux Sentinel leverages unmanaged eBPF telemetry to capture deep execution lineage, fileless malware, and kernel-level rootkits without taxing the CPU.

By routing raw kernel events through a native Rust-based Machine Learning and UEBA pipeline, Sentinel transforms high-frequency system noise into high-fidelity, **5D mathematical threat models**. It unifies active deception (Honeypots), static integrity (YARA), and dynamic behavioral profiling into a single, self-healing binary.



## Core Features
* **Kernel-Level Observability:** Native eBPF hooks for `execve`, `openat`, `ptrace`, `memfd_create`, and `udp_sendmsg`.
* **5D UEBA Engine:** Real-time calculation of Shannon Entropy, Execution Velocity, and Path Depth.
* **Static Integrity:** Periodic YARA scanning of critical system paths.
* **Active Deception:** Multi-port honeypot listeners for automated scanner detection.
* **Self-Healing Supervisor:** OS-thread isolation for kernel probes with exponential backoff recovery.
* **Hardened API:** Secure REST dashboard with Bearer Token authentication.

---

## Technical Stack
* **Language:** Rust (Edition 2021) after testing validation -> migration to Edition 2024.
* **Kernel Interface:** `libbpf-rs` (CO-RE / BTF)
* **Async Runtime:** `tokio` (Multithreaded)
* **Web Framework:** `axum`
* **Database:** `SQLite` (Write-Ahead Logging enabled)
* **Scanning Engine:** `yara-rust`

---

## Installation & Deployment

### 1. Build Requirements
Ensure `libbpf-dev`, `libyara-dev`, and `clang` are installed on the host system.

```bash
# Clone and build the binary
cargo build --release
```

### 2. Local Docker / Podman Deployment
The included `run.sh` handles capability detection and mounts the required kernel headers.

```bash
sudo chmod +x run.sh
./run.sh
```

### 3. Kubernetes DaemonSet
Deploy the agent across your cluster. **Note:** Privileged mode and specific eBPF capabilities (`CAP_BPF`, `CAP_PERFMON`) are required.

```bash
kubectl apply -f linux-sentinel-deployment.yml

# Access Secure Dashboard
kubectl -n security expose deployment linux-sentinel --type=NodePort --port=8080
```

---

## Configuration (`master.toml`)
All engine behavior is controlled via `/opt/linux-sentinel/master.toml`.

| Section | Toggle | Description |
| :--- | :--- | :--- |
| `[engine]` | `enable_ebpf` | Activates kernel-level telemetry collection. |
| `[engine]` | `enable_yara` | Activates periodic file integrity scanning. |
| `[engine]` | `enable_anti_evasion` | Activates the 5D UEBA and ML routing pipeline. |
| `[engine]` | `enable_honeypots` | Spawns deception nodes on common target ports. |

---

## Accessing the Dashboard
The REST API is secured via Bearer Token. You must provide the `auth_token` defined in your `master.toml` in the Authorization header.

* **Status:** `GET /api/status`
* **Alerts:** `GET /api/alerts`

```bash
curl -H "Authorization: Bearer <your_token>" http://127.0.0.1:8080/api/alerts
```

---

## Logs and Diagnostics
* **Structured Logs (JSON):** `/var/log/linux-sentinel/diagnostics/sentinel-diagnostics.log`
* **SIEM SQLite DB:** `/var/log/linux-sentinel/sentinel.db`
* **Raw Intelligence Artifacts:** `/var/log/linux-sentinel/Behavior/Categories/*.json`

---

## Roadmap (The Horizon)
* **AST Parsing:** Native compilation of Sigma rules into the Rust behavioral engine.
* **Extended TTP Signatures:** Complex multi-event correlation (e.g., detect `memfd_create` followed by `udp_sendmsg`).
* **Process Tree Visualization:** Native graph-based lineage in the dashboard.
* **Automated Response:** Active process killing or network isolation via BPF TC/XDP hooks.