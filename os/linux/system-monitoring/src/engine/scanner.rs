use crate::config::MasterConfig;
use crate::engine::rules::{RawKernelEvent, RulesEngine};
use crate::siem::models::{AlertLevel, MitreTactic, RuleMatch, SecurityAlert};
use anyhow::Result;
use extended_isolation_forest::{Forest, ForestOptions};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, trace, warn};

#[derive(Debug, Clone)]
struct ProcessProfile {
    event_count: u64,
    last_seen: u64,
    recent_timestamps: VecDeque<u64>,
    recent_event_types: VecDeque<u32>,

    // WELFORD'S ONLINE ALGORITHM: O(1) Memory Temporal Baselining
    mean_delta: f64,
    m2_delta: f64,
    mean_entropy: f64,
    max_velocity: f64,
}

pub struct ScannerEngine {
    config: Arc<MasterConfig>,
    raw_rx: mpsc::Receiver<RawKernelEvent>,
    alert_tx: mpsc::Sender<SecurityAlert>,
    rules_engine: RulesEngine,
    kill_tx: mpsc::UnboundedSender<u32>,

    // ML ENGINE STATE
    ueba_profiles: HashMap<String, ProcessProfile>,
    tuple_freq: HashMap<String, u64>,
    history: VecDeque<[f64; 5]>,
    cached_forest: Arc<RwLock<Option<Forest<f64, 5>>>>,
    is_training: Arc<RwLock<bool>>,
    fit_counter: usize,
}

impl ScannerEngine {
    pub fn new(
        config: Arc<MasterConfig>,
        raw_rx: mpsc::Receiver<RawKernelEvent>,
        alert_tx: mpsc::Sender<SecurityAlert>,
        kill_tx: mpsc::UnboundedSender<u32>
    ) -> Self {
        Self {
            config,
            raw_rx,
            alert_tx,
            kill_tx,
            rules_engine: RulesEngine::new(),
            ueba_profiles: HashMap::new(),
            tuple_freq: HashMap::new(),
            history: VecDeque::with_capacity(5000),
            cached_forest: Arc::new(RwLock::new(None)),
            is_training: Arc::new(RwLock::new(false)),
            fit_counter: 0,
        }
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

        // FEATURE EXTRACT 1 & 2: Entropy and Path Depth
        let entropy = RulesEngine::calculate_shannon_entropy(&event.payload);
        let path_depth = Self::calculate_path_depth(&event.target);

        let current_ts_ns = event.ts_ns;

        // --- 1. MEMORY STATE & WELFORD'S ALGORITHM ---
        let profile = self.ueba_profiles.entry(process_hash.clone()).or_insert_with(|| {
            ProcessProfile {
                event_count: 0, last_seen: current_ts_ns,
                recent_timestamps: VecDeque::with_capacity(100),
                recent_event_types: VecDeque::with_capacity(10),
                mean_delta: 0.0, m2_delta: 0.0, mean_entropy: 0.0, max_velocity: 0.0,
            }
        });

        let delta_t_ns = current_ts_ns.saturating_sub(profile.last_seen);
        let delta_sec = delta_t_ns as f64 / 1_000_000_000.0;

        profile.event_count += 1;
        profile.last_seen = current_ts_ns;

        // Welford's Math for streaming variance
        let count_f = profile.event_count as f64;
        let delta_mean = delta_sec - profile.mean_delta;
        profile.mean_delta += delta_mean / count_f;
        let delta_mean2 = delta_sec - profile.mean_delta;
        profile.m2_delta += delta_mean * delta_mean2;
        profile.mean_entropy += (entropy - profile.mean_entropy) / count_f;

        // Maintain Sliding Windows for TTPs and Velocity
        if profile.recent_timestamps.len() >= 100 {
            profile.recent_timestamps.pop_front();
        }
        if profile.recent_event_types.len() >= 10 {
            profile.recent_event_types.pop_front();
        }
        profile.recent_timestamps.push_back(current_ts_ns);
        profile.recent_event_types.push_back(event.event_type);

        // FEATURE EXTRACT 3 & 4: Velocity
        let mut velocity = if delta_sec > 0.0 { 1.0 / delta_sec } else { 0.0 };
        if profile.recent_timestamps.len() > 1 {
            let first = *profile.recent_timestamps.front().unwrap();
            let time_delta_s = (current_ts_ns - first) as f64 / 1_000_000_000.0;
            if time_delta_s > 0.0 {
                velocity = (profile.recent_timestamps.len() as f64) / time_delta_s;
            }
        }
        if velocity > profile.max_velocity {
            profile.max_velocity = velocity;
        }

        // FEATURE EXTRACT 5: Tuple Rarity (Parent PID -> Child Comm)
        let pc_tuple = format!("{}->{}", event.ppid, event.comm);
        let tuple_count = self.tuple_freq.entry(pc_tuple).or_insert(0);
        *tuple_count += 1;
        let tuple_rarity = 1.0 / (*tuple_count as f64);

        // --- 2. Z-SCORE EVALUATION (LOTL DETECTION) ---
        let variance = if profile.event_count > 1 { profile.m2_delta / (count_f - 1.0) } else { 0.0 };
        let std_dev = variance.sqrt();
        let mut z_score = 0.0;

        // Require 5 baseline events. Trigger if deviating > 4.0 Standard Deviations
        if profile.event_count >= 5 && std_dev > 0.0 {
            z_score = (delta_sec - profile.mean_delta).abs() / std_dev;
        }

        if z_score > 4.0 {
            warn!("LotL Temporal Anomaly: {} broke execution baseline (Z-Score: {:.2})", process_hash, z_score);
        }

        // --- 3. EXTENDED ISOLATION FOREST (UNSUPERVISED ML) ---
        let current_feat = [
            entropy,
            tuple_rarity,
            path_depth as f64,
            velocity,
            profile.max_velocity
        ];

        if self.history.len() >= 5000 {
            self.history.pop_front();
        }
        self.history.push_back(current_feat);
        self.fit_counter += 1;

        // Background Async Training Trigger
        let needs_rebuild = {
            let forest_read = self.cached_forest.read().unwrap();
            self.history.len() > 200
                && (forest_read.is_none() || self.fit_counter > 20000)
                && !*self.is_training.read().unwrap()
        };

        if needs_rebuild {
            let mut is_training = self.is_training.write().unwrap();
            if !*is_training {
                *is_training = true;
                self.fit_counter = 0;

                let history_vec: Vec<[f64; 5]> = self.history.iter().cloned().collect();
                let forest_arc = Arc::clone(&self.cached_forest);
                let training_flag = Arc::clone(&self.is_training);

                // LOGIC ANCHOR MANDATE: Offload CPU-heavy tree building from Tokio worker
                tokio::task::spawn_blocking(move || {
                    let options = ForestOptions {
                        n_trees: 50,
                        sample_size: std::cmp::min(256, history_vec.len()),
                        max_tree_depth: None,
                        extension_level: 2,
                    };

                    if let Ok(forest) = Forest::from_slice(&history_vec, &options) {
                        let mut w_forest = forest_arc.write().unwrap();
                        *w_forest = Some(forest);
                    }
                    *training_flag.write().unwrap() = false;
                });
            }
        }

        // Score current telemetry against the model
        let mut anomaly_score = 0.0;
        if let Some(forest) = &*self.cached_forest.read().unwrap() {
            anomaly_score = forest.score(&current_feat);
        }

        // --- 4. PIPELINE ROUTING ---

        let is_anomaly = anomaly_score > 0.60;
        let mut matched_rule = self.rules_engine.evaluate(&event);

        // If the ML engine flags an anomaly, escalate it even if static rules missed it
        if is_anomaly && matched_rule.is_none() {
            matched_rule = Some(RuleMatch {
                level: if anomaly_score > 0.70 { AlertLevel::High } else { AlertLevel::Medium },
                mitre_tactic: MitreTactic::Unknown,
                mitre_technique: "Behavioral ML Anomaly".to_string(),
                message: format!("Isolation Forest Outlier (Score: {:.2}, Z-Score: {:.2})", anomaly_score, z_score),
            });
        }

        // Single-pass enrichment allocation
        if let Some(rule) = matched_rule {
            let alert = SecurityAlert::from_rule(
                rule, event.pid, event.ppid, event.uid, event.comm.clone(), event.target.clone(),
                Some(event.target.clone()), Some(event.dest_ip.clone()), Some(event.dest_port),
                entropy, velocity, tuple_rarity, path_depth, anomaly_score
            );

            if let Err(e) = self.alert_tx.try_send(alert) {
                error!("SIEM Gateway Disconnect: Failed to route enriched alert down pipeline: {}", e);
            }

            // --- ACTIVE MITIGATION TRIGGER ---
            if self.config.engine.enable_active_mitigation {
                if let Some(rule) = &matched_rule {
                    if rule.level == AlertLevel::Critical || anomaly_score > 0.90 {
                        warn!("Executing Active Mitigation: Sending SIGKILL mandate for highly malicious PID {}", event.pid);
                        let _ = self.kill_tx.send(event.pid); // Unbounded, no backpressure possible
                    }
                }
            }
        }

        // EXTENDED TTP CORRELATION (State Machine)
        // Scenario: Fileless memory allocation (5) followed by an outbound network connection (3 or 8)
        if event.event_type == 8 /* EVENT_UDP_SEND */ || event.event_type == 3 /* EVENT_CONNECT */ {

            if profile.recent_event_types.contains(&5 /* EVENT_MEMFD */) {
                tracing::warn!("Complex TTP Detected: Process {} executed fileless memory allocation followed by network comms.", process_hash);

                let ttp_alert = SecurityAlert::from_rule(
                    RuleMatch {
                        level: AlertLevel::Critical,
                        mitre_tactic: MitreTactic::CommandAndControl,
                        mitre_technique: "T1573 Encrypted Channel (Correlated)".to_string(),
                        message: format!("Correlated TTP: Fileless code execution (memfd) followed immediately by network out in {}", process_hash),
                    },
                    event.pid, event.ppid, event.uid, event.comm.clone(), event.target.clone(),
                    None, Some(event.dest_ip.clone()), Some(event.dest_port),
                    entropy, velocity, 0.0, path_depth, 0.0
                );

                if let Err(e) = self.alert_tx.try_send(ttp_alert) {
                    tracing::error!("Pipeline Failure: Failed to route complex TTP alert: {}", e);
                }

                // Clear the state buffer to prevent duplicate alerts for the same sequence
                profile.recent_event_types.clear();
            }
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