use serde::Deserialize;
use std::fs;

#[derive(Deserialize, Debug, Clone)]
pub struct MasterConfig {
    pub engine: EngineConfig,
    pub monitoring: MonitoringConfig,
    pub storage: StorageConfig,
    pub siem: SiemConfig,
    pub network: NetworkConfig,
    pub process: ProcessConfig,
    pub files: FilesConfig,
}

#[derive(Deserialize, Debug, Clone)]
pub struct EngineConfig {
    pub enable_ebpf: bool,
    pub enable_yara: bool,
    pub enable_honeypots: bool,
    pub enable_anti_evasion: bool,
    #[serde(default)]
    pub enable_active_mitigation: bool,
    #[serde(default = "default_true")]
    pub enable_api_server: bool,
    pub performance_mode: bool,
}

fn default_true() -> bool { true }

#[derive(Deserialize, Debug, Clone)]
pub struct MonitoringConfig {
    pub monitor_network: bool,
    pub monitor_processes: bool,
    pub monitor_files: bool,
    pub monitor_users: bool,
    pub monitor_rootkits: bool,
    pub monitor_memory: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct StorageConfig {
    pub central_log_dir: String,
    pub output_dir: String,
    pub sqlite_db_path: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SiemConfig {
    pub middleware_gateway_url: String,
    pub auth_token: String,
    pub batch_size: usize,
}

#[derive(Deserialize, Debug, Clone)]
pub struct NetworkConfig {
    pub whitelist_connections: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ProcessConfig {
    pub whitelist_processes: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct FilesConfig {
    pub exclude_paths: Vec<String>,
    pub critical_paths: Vec<String>,
}

pub fn load_master_config(path: &str) -> anyhow::Result<MasterConfig> {
    let config_content = fs::read_to_string(path)?;
    let config: MasterConfig = toml::from_str(&config_content)?;
    Ok(config)
}