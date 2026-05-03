use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum AlertLevel { Critical, High, Medium, Low, Info }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MitreTactic {
    #[serde(rename = "TA0002 Execution")] Execution,
    #[serde(rename = "TA0003 Persistence")] Persistence,
    #[serde(rename = "TA0004 Privilege Escalation")] PrivilegeEscalation,
    #[serde(rename = "TA0005 Defense Evasion")] DefenseEvasion,
    #[serde(rename = "TA0011 Command and Control")] CommandAndControl,
    #[serde(rename = "TA0010 Exfiltration")] Exfiltration,
    #[serde(rename = "Unknown")] Unknown,
}

pub struct RuleMatch {
    pub level: AlertLevel,
    pub mitre_tactic: MitreTactic,
    pub mitre_technique: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub event_id: String,
    pub timestamp: u64,
    pub level: AlertLevel,
    pub mitre_tactic: MitreTactic,
    pub mitre_technique: String,

    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: String,
    pub command_line: String,

    pub target_file: Option<String>,
    pub dest_ip: Option<String>,
    pub dest_port: Option<u16>,

    pub shannon_entropy: f64,
    pub execution_velocity: f64,
    pub tuple_rarity: f64,
    pub path_depth: usize,
    pub anomaly_score: f64,

    pub message: String,
}

impl std::fmt::Display for AlertLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::fmt::Display for MitreTactic {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            MitreTactic::Execution => "TA0002 Execution",
            MitreTactic::Persistence => "TA0003 Persistence",
            MitreTactic::PrivilegeEscalation => "TA0004 Privilege Escalation",
            MitreTactic::DefenseEvasion => "TA0005 Defense Evasion",
            MitreTactic::CommandAndControl => "TA0011 Command and Control",
            MitreTactic::Exfiltration => "TA0010 Exfiltration",
            MitreTactic::Unknown => "Unknown",
        };
        write!(f, "{}", s)
    }
}

impl SecurityAlert {
    /// constructor 1: HIGH-FIDELITY (from_rule)
    /// Used by the ScannerEngine to achieve single-pass, zero-copy memory allocation
    /// for kernel telemetry enriched with mathematical UEBA features.
    pub fn from_rule(
        rule: RuleMatch,
        pid: u32, ppid: u32, uid: u32, comm: String, command_line: String,
        target_file: Option<String>, dest_ip: Option<String>, dest_port: Option<u16>,
        shannon_entropy: f64, execution_velocity: f64, tuple_rarity: f64, path_depth: usize, anomaly_score: f64,
    ) -> Self {
        Self {
            event_id: Uuid::new_v4().to_string(),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            level: rule.level,
            mitre_tactic: rule.mitre_tactic,
            mitre_technique: rule.mitre_technique,
            message: rule.message,
            pid, ppid, uid, comm, command_line,
            target_file, dest_ip, dest_port,
            shannon_entropy, execution_velocity, tuple_rarity, path_depth, anomaly_score,
        }
    }

    /// constructor 2: SYNTHETIC
    /// A convenience constructor for modules like Honeypots or YARA that do not
    /// originate from raw kernel syscalls and lack 5D mathematical context.
    pub fn new(
        level: AlertLevel,
        message: String,
        mitre_tactic: MitreTactic,
        mitre_technique: &str
    ) -> Self {
        Self {
            event_id: Uuid::new_v4().to_string(),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            level,
            mitre_tactic,
            mitre_technique: mitre_technique.to_string(),
            pid: 0, ppid: 0, uid: 0,
            comm: String::new(),
            command_line: String::new(),
            target_file: None, dest_ip: None, dest_port: None,
            shannon_entropy: 0.0, execution_velocity: 0.0, tuple_rarity: 0.0,
            path_depth: 0, anomaly_score: 0.0,
            message,
        }
    }
}