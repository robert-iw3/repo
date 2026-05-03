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

impl SecurityAlert {
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
}