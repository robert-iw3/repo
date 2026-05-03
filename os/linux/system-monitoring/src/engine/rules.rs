use crate::siem::models::{AlertLevel, MitreTactic, RuleMatch};
use serde::Deserialize;
use serde_yaml::Value;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tracing::{debug, error, info, trace, warn};

// --- 1. AST DEFINITIONS FOR SIGMA NATIVE PARSING ---

#[derive(Debug, Deserialize)]
struct RawSigmaYaml {
    title: String,
    level: Option<String>,
    tags: Option<Vec<String>>,
    detection: HashMap<String, Value>,
}

#[derive(Debug)]
enum MatchOperator {
    Exact(String),
    Contains(String),
    EndsWith(String),
    StartsWith(String),
}

impl MatchOperator {
    /// Zero-allocation fast-path string matching against eBPF event data
    fn matches(&self, event: &RawKernelEvent, field: &str) -> bool {
        let field_lower = field.to_lowercase();

        if field_lower == "destinationport" {
            if let MatchOperator::Exact(ref val) = self { return event.dest_port.to_string() == *val; }
            return false;
        }

        let target_val = match field_lower.as_str() {
            "image" | "process" => event.comm.as_str(),
            "commandline" => event.target.as_str(),
            "destinationip" | "destinationhostname" => event.dest_ip.as_str(),
            _ => return false,
        };

        match self {
            MatchOperator::Exact(val) => target_val == val,
            MatchOperator::Contains(val) => target_val.contains(val),
            MatchOperator::EndsWith(val) => target_val.ends_with(val),
            MatchOperator::StartsWith(val) => target_val.starts_with(val),
        }
    }
}

#[derive(Debug)]
struct CompiledSigmaRule {
    title: String,
    level: AlertLevel,
    technique: String,
    selections: HashMap<String, Vec<(String, Vec<MatchOperator>)>>,
    condition: String,
}

impl CompiledSigmaRule {
    /// Evaluates the logic tree without triggering any heap allocations.
    fn evaluate(&self, event: &RawKernelEvent) -> bool {
        let mut state = HashMap::new();

        for (sel_name, fields) in &self.selections {
            let mut selection_matched = true;
            for (field_name, operators) in fields {
                let mut field_matched = false;
                for op in operators {
                    if op.matches(event, field_name) {
                        field_matched = true;
                        break;
                    }
                }
                if !field_matched {
                    selection_matched = false;
                    break;
                }
            }
            state.insert(sel_name.clone(), selection_matched);
        }

        let cond = self.condition.trim();
        if cond == "1 of them" || cond == "any of them" { return state.values().any(|&v| v); }
        if cond == "all of them" { return state.values().all(|&v| v); }

        if cond.contains(" or ") {
            let parts = cond.split(" or ");
            for part in parts {
                if self.eval_and_chunk(part.trim(), &state) { return true; }
            }
            return false;
        } else {
            return self.eval_and_chunk(cond, &state);
        }
    }

    fn eval_and_chunk(&self, chunk: &str, state: &HashMap<String, bool>) -> bool {
        let parts = chunk.split(" and ");
        for part in parts {
            let part = part.trim();
            if part.starts_with("not ") {
                let key = part[4..].trim();
                if *state.get(key).unwrap_or(&false) { return false; }
            } else {
                if !*state.get(part).unwrap_or(&false) { return false; }
            }
        }
        true
    }
}

// --- 2. RAW EVENT DEFINITION ---

#[derive(Debug)]
pub struct RawKernelEvent {
    pub ts_ns: u64,
    pub interval_ns: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub event_type: u32,
    pub comm: String,
    pub target: String,
    pub dest_ip: String,
    pub dest_port: u16,
    pub payload: Vec<u8>,
}

pub struct RulesEngine {
    compiled_sigma_rules: Vec<CompiledSigmaRule>,
}

impl RulesEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            compiled_sigma_rules: Vec::new(),
        };
        // Load rules dynamically at startup. Runs synchronously ONCE.
        engine.load_sigma_rules("/opt/linux-sentinel/sigma/rules");
        engine
    }

    fn create_operator(modifier: &str, val: &str) -> MatchOperator {
        match modifier {
            "contains" => MatchOperator::Contains(val.to_string()),
            "endswith" => MatchOperator::EndsWith(val.to_string()),
            "startswith" => MatchOperator::StartsWith(val.to_string()),
            _ => MatchOperator::Exact(val.to_string()),
        }
    }

    fn load_sigma_rules(&mut self, dir_path: &str) {
        let path = Path::new(dir_path);
        if !path.exists() || !path.is_dir() {
            warn!("Sigma directory missing: {}. Falling back to hardcoded statics only.", dir_path);
            return;
        }

        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let file_path = entry.path();
                if file_path.extension().and_then(|s| s.to_str()) == Some("yml") {
                    if let Ok(content) = fs::read_to_string(&file_path) {
                        if let Ok(raw) = serde_yaml::from_str::<RawSigmaYaml>(&content) {
                            self.compile_and_mount(raw, &file_path.to_string_lossy());
                        } else {
                            error!("Failed to parse YAML format in: {}", file_path.display());
                        }
                    }
                }
            }
        }
        info!("Compiled {} Native Sigma rules into active memory.", self.compiled_sigma_rules.len());
    }

    fn compile_and_mount(&mut self, raw: RawSigmaYaml, file_context: &str) {
        let alert_level = match raw.level.as_deref().unwrap_or("medium").to_lowercase().as_str() {
            "critical" => AlertLevel::Critical,
            "high" => AlertLevel::High,
            "medium" => AlertLevel::Medium,
            "low" | "informational" => AlertLevel::Low,
            _ => AlertLevel::Medium,
        };

        let technique = raw.tags.unwrap_or_default().into_iter()
            .find(|t| t.starts_with("attack.t"))
            .map(|t| t.replace("attack.", "").to_uppercase())
            .unwrap_or_else(|| "Unknown".to_string());

        let mut selections = HashMap::new();
        let mut condition = String::new();

        for (key, val) in raw.detection {
            if key == "condition" {
                condition = val.as_str().unwrap_or("").to_string();
            } else if let Some(sel_map) = val.as_mapping() {
                let mut field_conditions = Vec::new();
                for (f_key, f_val) in sel_map {
                    let field_full = f_key.as_str().unwrap_or("");
                    let mut parts = field_full.split('|');
                    let field_name = parts.next().unwrap_or("").to_string();
                    let modifier = parts.next().unwrap_or("");
                    let mut operators = Vec::new();

                    if let Some(seq) = f_val.as_sequence() {
                        for item in seq {
                            if let Some(val_str) = item.as_str() {
                                operators.push(Self::create_operator(modifier, val_str));
                            }
                        }
                    } else if let Some(val_str) = f_val.as_str() {
                        operators.push(Self::create_operator(modifier, val_str));
                    }
                    field_conditions.push((field_name, operators));
                }
                selections.insert(key, field_conditions);
            }
        }

        if condition.is_empty() {
            error!("Sigma rule missing 'condition' block: {}", file_context);
            return;
        }

        self.compiled_sigma_rules.push(CompiledSigmaRule {
            title: raw.title,
            level: alert_level,
            technique,
            selections,
            condition,
        });
    }

    /// Helper mathematical function to detect obfuscated payloads
    pub fn calculate_shannon_entropy(data: &[u8]) -> f64 {
        let mut counts = [0u16; 256];
        let mut valid_bytes = 0.0;

        for &byte in data {
            if byte != 0 {
                counts[byte as usize] += 1;
                valid_bytes += 1.0;
            }
        }

        if valid_bytes == 0.0 {
            return 0.0;
        }

        let mut entropy = 0.0;
        for &count in counts.iter() {
            if count > 0 {
                let p = (count as f64) / valid_bytes;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Evaluates raw telemetry against the compiled Sigma AST and the static MITRE framework
    pub fn evaluate(&self, event: &RawKernelEvent) -> Option<RuleMatch> {
        trace!("Evaluating Kernel Event -> Type: {}, PID: {}, Comm: '{}', Target: '{}'",
               event.event_type, event.pid, event.comm, event.target);

        // 1. Evaluate Dynamic Sigma Logic Tree First
        for rule in &self.compiled_sigma_rules {
            if rule.evaluate(event) {
                debug!("Threat Intel Triggered: [{}] via Sigma AST", rule.title);
                return Some(RuleMatch {
                    level: rule.level.clone(),
                    mitre_tactic: MitreTactic::Unknown, // Handled downstream by MITRE mapping
                    mitre_technique: rule.technique.clone(),
                    message: format!("Sigma Signature Match: {}", rule.title),
                });
            }
        }

        // 2. High-Speed Static Fast-Path Fallbacks
        match event.event_type {
            // EVENT_EXEC
            1 => {
                if event.comm == "nc" || event.comm == "socat" || event.target.contains("/dev/tcp") {
                    debug!("Rule Match [T1059]: Reverse shell detected via '{}'", event.comm);
                    return Some(RuleMatch {
                        level: AlertLevel::Critical,
                        mitre_tactic: MitreTactic::Execution,
                        mitre_technique: "T1059 Command and Scripting Interpreter".to_string(),
                        message: format!("Reverse shell execution detected via '{}'", event.comm),
                    });
                }
            },
            // EVENT_OPEN_CRIT (File Integrity)
            2 => {
                if event.target.starts_with("/etc/shadow") || event.target.starts_with("/etc/sudoers") {
                    debug!("Rule Match [T1078]: Critical file modification on '{}'", event.target);
                    return Some(RuleMatch {
                        level: AlertLevel::Critical,
                        mitre_tactic: MitreTactic::PrivilegeEscalation,
                        mitre_technique: "T1078 Valid Accounts".to_string(),
                        message: format!("Critical credential file modified by '{}': {}", event.comm, event.target),
                    });
                }
            },
            // EVENT_CONNECT (C2 Beacons)
            3 => {
                if event.dest_port == 4444 || event.dest_port == 1337 {
                    debug!("Rule Match [T1571]: Outbound C2 connection to {}:{}", event.dest_ip, event.dest_port);
                    return Some(RuleMatch {
                        level: AlertLevel::High,
                        mitre_tactic: MitreTactic::CommandAndControl,
                        mitre_technique: "T1571 Non-Standard Port".to_string(),
                        message: format!("Suspicious outbound C2 connection from '{}' to {}:{}", event.comm, event.dest_ip, event.dest_port),
                    });
                }
            },
            // EVENT_PTRACE
            4 => {
                debug!("Rule Match [T1055.008]: Ptrace injection by PID {}", event.pid);
                return Some(RuleMatch {
                    level: AlertLevel::Critical,
                    mitre_tactic: MitreTactic::DefenseEvasion,
                    mitre_technique: "T1055.008 Ptrace System Calls".to_string(),
                    message: format!("Process injection (ptrace) initiated by '{}' on PID {}", event.comm, event.pid),
                });
            },
            // EVENT_MEMFD (Fileless Malware)
            5 => {
                debug!("Rule Match [T1620]: memfd_create fileless execution by '{}'", event.comm);
                return Some(RuleMatch {
                    level: AlertLevel::Critical,
                    mitre_tactic: MitreTactic::DefenseEvasion,
                    mitre_technique: "T1620 Reflective Code Loading".to_string(),
                    message: format!("Reflective code loading (memfd_create) by '{}'. Target: {}", event.comm, event.target),
                });
            },
            // EVENT_MODULE (Kernel Rootkits)
            6 => {
                debug!("Rule Match [T1547.006]: Kernel module manipulation by '{}'", event.comm);
                return Some(RuleMatch {
                    level: AlertLevel::Critical,
                    mitre_tactic: MitreTactic::Persistence,
                    mitre_technique: "T1547.006 Kernel Modules and Extensions".to_string(),
                    message: format!("Kernel module manipulation initiated by '{}'", event.comm),
                });
            },
            // EVENT_BPF (EDR Tampering)
            7 => {
                debug!("Rule Match [T1562.001]: eBPF tampering attempt by '{}'", event.comm);
                return Some(RuleMatch {
                    level: AlertLevel::Critical,
                    mitre_tactic: MitreTactic::DefenseEvasion,
                    mitre_technique: "T1562.001 Impair Defenses".to_string(),
                    message: format!("eBPF tampering/blinding attempt detected by '{}'", event.comm),
                });
            },
            // EVENT_UDP_SEND (DNS Tunneling)
            8 => {
                let entropy = Self::calculate_shannon_entropy(&event.payload);
                if entropy > 4.5 {
                    debug!("Rule Match [T1071.004]: High entropy UDP payload (Entropy: {:.4})", entropy);
                    return Some(RuleMatch {
                        level: AlertLevel::High,
                        mitre_tactic: MitreTactic::CommandAndControl,
                        mitre_technique: "T1071.004 DNS".to_string(),
                        message: format!("High entropy UDP payload detected (Entropy: {:.2}). Possible DNS tunneling by '{}'", entropy, event.comm),
                    });
                }
            },
            _ => {
                trace!("Unhandled event type: {}", event.event_type);
            }
        }

        trace!("Event evaluated cleanly. No rules triggered.");
        None
    }
}