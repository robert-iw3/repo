use crate::siem::models::{AlertLevel, MitreTactic, RuleMatch};
use std::collections::HashMap;
use tracing::{debug, trace};

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

pub struct RulesEngine;

impl RulesEngine {
    /// Helper mathematical function to detect obfuscated payloads
    fn calculate_shannon_entropy(data: &[u8]) -> f64 {
        trace!("Calculating Shannon Entropy for payload of {} bytes", data.len());
        let mut counts = HashMap::new();
        let mut valid_bytes = 0.0;

        for &byte in data {
            if byte != 0 {
                *counts.entry(byte).or_insert(0) += 1;
                valid_bytes += 1.0;
            }
        }

        if valid_bytes == 0.0 {
            trace!("Payload is empty or entirely null bytes. Entropy: 0.0");
            return 0.0;
        }

        let mut entropy = 0.0;
        for count in counts.values() {
            let p = *count as f64 / valid_bytes;
            entropy -= p * p.log2();
        }

        trace!("Shannon Entropy calculated: {:.4}", entropy);
        entropy
    }

    /// Evaluates raw telemetry against the Linux MITRE ATT&CK framework
    pub fn evaluate(event: &RawKernelEvent) -> Option<RuleMatch> {
        trace!("Evaluating Kernel Event -> Type: {}, PID: {}, Comm: '{}', Target: '{}'",
               event.event_type, event.pid, event.comm, event.target);

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