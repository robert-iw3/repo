use crate::config::MasterConfig;
use crate::engine::rules::{RawKernelEvent, RulesEngine};
use crate::siem::models::{AlertLevel, MitreTactic, RuleMatch, SecurityAlert};
use anyhow::Result;
use std::collections::{HashMap, VecDeque};
use std::process::Command;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, trace, warn};

#[derive(Debug, Clone)]
struct ProcessProfile {
    event_count: u64,
    last_seen: u64,
    recent_timestamps: VecDeque<u64>,
    mean_velocity: f64,
    mean_entropy: f64,
}

pub struct ScannerEngine {
    config: Arc<MasterConfig>,
    raw_rx: mpsc::Receiver<RawKernelEvent>,
    alert_tx: mpsc::Sender<SecurityAlert>,
    ueba_profiles: HashMap<String, ProcessProfile>,
}

impl ScannerEngine {
    pub fn new(
        config: Arc<MasterConfig>,
        raw_rx: mpsc::Receiver<RawKernelEvent>,
        alert_tx: mpsc::Sender<SecurityAlert>
    ) -> Self {
        Self { config, raw_rx, alert_tx, ueba_profiles: HashMap::new() }
    }

    pub fn calculate_shannon_entropy(data: &[u8]) -> f64 {
        let mut counts = HashMap::new();
        let mut valid_bytes = 0.0;
        for &byte in data {
            if byte != 0 {
                *counts.entry(byte).or_insert(0) += 1;
                valid_bytes += 1.0;
            }
        }
        if valid_bytes == 0.0 { return 0.0; }
        let mut entropy = 0.0;
        for count in counts.values() {
            let p = *count as f64 / valid_bytes;
            entropy -= p * p.log2();
        }
        entropy
    }

    pub fn calculate_path_depth(path: &str) -> usize {
        path.split('/').filter(|s| !s.is_empty()).count()
    }

    pub async fn run(mut self) {
        if !self.config.engine.enable_anti_evasion {
            info!("Anti-evasion and UEBA scanner explicitly disabled in master.toml.");
            return;
        }

        info!("Starting 5D UEBA & Telemetry Routing Pipeline...");
        let mut scan_interval = interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                Some(raw_event) = self.raw_rx.recv() => {
                    trace!("Pipeline Ingest: Received RawKernelEvent (PID: {})", raw_event.pid);
                    self.process_kernel_event(raw_event).await;
                }
                _ = scan_interval.tick() => {
                    debug!("Initiating periodic system baselining and integrity checks.");
                    self.monitor_users().await;
                    self.monitor_memory().await;
                    self.check_hidden_processes().await;
                    self.check_ld_preload().await;
                    self.prune_ueba_baselines().await;
                    debug!("Periodic system baseline complete.");
                }
            }
        }
    }

    async fn process_kernel_event(&mut self, event: RawKernelEvent) {
        let process_hash = format!("{}|{}", event.pid, event.comm);
        trace!("Processing telemetry for Context Hash: [{}]", process_hash);

        let entropy = Self::calculate_shannon_entropy(&event.payload);
        let path_depth = Self::calculate_path_depth(&event.target);

        // 1. Update In-Memory Mathematical State
        let profile = self.ueba_profiles.entry(process_hash.clone()).or_insert_with(|| {
            debug!("UEBA Memory Allocation: Instantiating new profile for {}", process_hash);
            ProcessProfile {
                event_count: 0, last_seen: event.ts_ns, recent_timestamps: VecDeque::with_capacity(100),
                mean_velocity: 0.0, mean_entropy: 0.0,
            }
        });

        profile.event_count += 1;
        profile.last_seen = event.ts_ns;

        if profile.recent_timestamps.len() >= 100 {
            profile.recent_timestamps.pop_front();
        }
        profile.recent_timestamps.push_back(event.ts_ns);

        let mut velocity = 0.0;
        if profile.recent_timestamps.len() > 1 {
            let first = *profile.recent_timestamps.front().unwrap();
            let last = *profile.recent_timestamps.back().unwrap();
            let time_delta_s = (last - first) as f64 / 1_000_000_000.0; // ns to seconds

            if time_delta_s > 0.0 {
                velocity = (profile.recent_timestamps.len() as f64) / time_delta_s;
                profile.mean_velocity = (profile.mean_velocity * 0.9) + (velocity * 0.1);
                trace!("Velocity updated for {}: {:.2} ev/s", process_hash, velocity);
            }
        }
        profile.mean_entropy = (profile.mean_entropy * 0.9) + (entropy * 0.1);

        // 2. Evaluate against MITRE Rules Engine
        if let Some(rule_match) = RulesEngine::evaluate(&event) {
            info!("Threat Intelligence Triggered: {} by PID {}", rule_match.mitre_technique, event.pid);

            // 3. ENRICHMENT: Single-pass zero-copy memory allocation
            let alert = SecurityAlert::from_rule(
                rule_match,
                event.pid, event.ppid, event.uid, event.comm.clone(), event.target.clone(),
                Some(event.target.clone()), Some(event.dest_ip.clone()), Some(event.dest_port),
                entropy, velocity, 0.0, path_depth, 0.0
            );

            if let Err(e) = self.alert_tx.try_send(alert) {
                error!("SIEM Gateway Disconnect: Failed to route enriched alert down pipeline: {}", e);
            } else {
                debug!("Enriched alert successfully routed to SQLite transmission worker.");
            }
        }

        // 4. Standalone Burst Detection (Zero-Day LotL)
        if velocity > 50.0 && profile.event_count > 100 {
            warn!("UEBA Anomaly: Execution Burst detected for {} (Velocity: {:.2})", process_hash, velocity);

            let burst_rule = RuleMatch {
                level: AlertLevel::Medium,
                mitre_tactic: MitreTactic::Execution,
                mitre_technique: "T1059 Command and Scripting Interpreter".to_string(),
                message: format!("High Execution Velocity Burst: {:.2} events/sec by {}", velocity, process_hash),
            };

            let burst_alert = SecurityAlert::from_rule(
                burst_rule,
                event.pid, event.ppid, event.uid, event.comm.clone(), event.target.clone(),
                None, Some(event.dest_ip.clone()), Some(event.dest_port),
                entropy, velocity, 0.0, path_depth, 0.0
            );

            if let Err(e) = self.alert_tx.try_send(burst_alert) {
                error!("Pipeline Failure: Failed to route UEBA burst alert: {}", e);
            }

            debug!("Resetting UEBA burst window for {}", process_hash);
            profile.recent_timestamps.clear();
        }
    }

    async fn prune_ueba_baselines(&mut self) {
        let current_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64;
        let initial_count = self.ueba_profiles.len();

        trace!("Executing aggressive UEBA memory pruning. Target TTL: 1 hour.");
        // Evict profiles inactive for 1 hour (3.6 trillion nanoseconds)
        self.ueba_profiles.retain(|_, profile| current_time - profile.last_seen < 3_600_000_000_000);

        let pruned = initial_count - self.ueba_profiles.len();
        if pruned > 0 {
            info!("Garbage Collection: Evicted {} stale process models from UEBA memory. Active Models: {}", pruned, self.ueba_profiles.len());
        }
    }

    async fn monitor_users(&self) {
        trace!("Running user integrity check (/etc/passwd)");
        if let Ok(passwd) = tokio::fs::read_to_string("/etc/passwd").await {
            for line in passwd.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() > 2 && parts[0] != "root" && parts[2].parse::<u32>().unwrap_or(9999) == 0 {
                    warn!("Rogue root UID detected: {}", parts[0]);

                    let alert = SecurityAlert::from_rule(
                        RuleMatch {
                            level: AlertLevel::Critical,
                            mitre_tactic: MitreTactic::PrivilegeEscalation,
                            mitre_technique: "T1078 Valid Accounts".to_string(),
                            message: format!("Rogue root UID user detected: {}", parts[0]),
                        },
                        0, 0, 0, "SYSTEM".to_string(), "".to_string(), None, None, None, 0.0, 0.0, 0.0, 0, 0.0
                    );

                    if let Err(e) = self.alert_tx.try_send(alert) {
                        error!("Pipeline Failure: Failed to route rogue user alert: {}", e);
                    }
                }
            }
        }
    }

    async fn monitor_memory(&self) {
        trace!("Running system memory threshold check");
        if let Ok(meminfo) = tokio::fs::read_to_string("/proc/meminfo").await {
            if let Some(total) = meminfo.lines().find(|l| l.starts_with("MemTotal"))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|s| s.parse::<u64>().ok())) {
                if total < 1_000_000 {
                    error!("Critical Memory Starvation: Host OS has less than 1GB RAM remaining.");
                }
            }
        }
    }

    async fn check_hidden_processes(&self) {
        trace!("Running kernel vs user-space PID integrity check");

        // 1. NON-BLOCKING: Async directory iteration
        let mut proc_dir = match tokio::fs::read_dir("/proc").await {
            Ok(dir) => dir,
            Err(e) => {
                error!("Rootkit Check: Failed to read /proc: {}", e);
                return;
            }
        };

        let mut proc_count = 0;
        while let Ok(Some(entry)) = proc_dir.next_entry().await {
            if entry.file_name().to_string_lossy().parse::<u32>().is_ok() {
                proc_count += 1;
            }
        }

        // 2. NON-BLOCKING: Async process execution
        let output = match tokio::process::Command::new("ps")
            .args(["-e", "--no-headers"])
            .output()
            .await
        {
            Ok(out) => out,
            Err(e) => {
                error!("Rootkit Check: Failed to execute 'ps': {}", e);
                return;
            }
        };

        let ps_count = String::from_utf8_lossy(&output.stdout).lines().count();

        // 3. SYNTHETIC ALERT: Uses the convenience constructor
        if proc_count > ps_count + 10 {
            warn!("Rootkit Anomaly: Kernel (/proc) reports {} PIDs, User-space (ps) reports {}", proc_count, ps_count);

            let alert = SecurityAlert::new(
                AlertLevel::Critical,
                format!("Kernel/User-space PID mismatch. /proc: {}, ps: {}", proc_count, ps_count),
                MitreTactic::DefenseEvasion,
                "T1014 Rootkit",
            );

            if let Err(e) = self.alert_tx.try_send(alert) {
                error!("Pipeline Failure: Failed to route rootkit alert: {}", e);
            }
        }
    }

    async fn check_ld_preload(&self) {
        trace!("Checking /etc/ld.so.preload for dynamic linker hijacking");
        if let Ok(contents) = tokio::fs::read_to_string("/etc/ld.so.preload").await {
            if !contents.trim().is_empty() {
                warn!("LD_PRELOAD tampering detected.");

                let alert = SecurityAlert::from_rule(
                    RuleMatch {
                        level: AlertLevel::High,
                        mitre_tactic: MitreTactic::Persistence,
                        mitre_technique: "T1574.006 Dynamic Linker Hijacking".to_string(),
                        message: format!("Suspicious LD_PRELOAD injection: {}", contents.trim()),
                    },
                    0, 0, 0, "SYSTEM".to_string(), "".to_string(), None, None, None, 0.0, 0.0, 0.0, 0, 0.0
                );

                if let Err(e) = self.alert_tx.try_send(alert) {
                    error!("Pipeline Failure: Failed to route LD_PRELOAD alert: {}", e);
                }
            }
        }
    }
}