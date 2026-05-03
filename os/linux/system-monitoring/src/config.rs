use serde::Deserialize;
use std::fs;

#[derive(Deserialize, Debug, Clone)]
pub struct MasterConfig {
    pub engine: EngineConfig,
    pub storage: StorageConfig,
    pub siem: SiemConfig,
}

#[derive(Deserialize, Debug, Clone)]
pub struct EngineConfig {
    pub enable_ebpf: bool,
    pub enable_yara: bool,
    pub enable_honeypots: bool,
    pub performance_mode: bool,
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

pub fn load_master_config(path: &str) -> anyhow::Result<MasterConfig> {
    let config_content = fs::read_to_string(path)?;
    let config: MasterConfig = toml::from_str(&config_content)?;
    Ok(config)
}