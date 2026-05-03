use crate::config::MasterConfig;
use crate::siem::models::{AlertLevel, MitreTactic, SecurityAlert};
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};
use yara::{Compiler, Rules, Scanner};

pub struct YaraEngine {
    config: Arc<MasterConfig>,
    rules: Arc<Rules>,
    tx: mpsc::Sender<SecurityAlert>,
}

impl YaraEngine {
    pub fn new(
        config: Arc<MasterConfig>,
        rules_path: &str,
        tx: mpsc::Sender<SecurityAlert>,
    ) -> Result<Self> {
        info!("Compiling YARA rules from {}...", rules_path);
        let compiler = Compiler::new().context("Failed to create YARA compiler")?;
        let rules = compiler
            .add_rules_file(rules_path)
            .context("Failed to load YARA rules file")?
            .compile()
            .context("Failed to compile YARA rules")?;

        Ok(Self {
            config,
            rules: Arc::new(rules),
            tx,
        })
    }

    pub async fn run(self) {
        if !self.config.engine.enable_yara {
            info!("YARA scanning engine is disabled in master.toml");
            return;
        }

        info!("YARA scanning engine active. Monitoring critical paths.");

        // Scan every 5 minutes (configurable in future)
        let mut scan_interval = interval(Duration::from_secs(300));

        loop {
            scan_interval.tick().await;
            let mut scanner = self.rules.scanner().unwrap_or_else(|e| {
                error!("Failed to instantiate YARA scanner: {}", e);
                std::process::exit(1);
            });

            for path_str in &self.config.files.critical_paths {
                let path = PathBuf::from(path_str);
                if !path.exists() || !path.is_file() { continue; }

                let rules = self.rules.clone();
                let tx = self.tx.clone();

                tokio::task::spawn_blocking(move || {
                    let mut scanner = rules.scanner().unwrap();
                    if let Ok(results) = scanner.scan_file(&path) {
                        for result in results {
                            let alert = SecurityAlert::new(
                                AlertLevel::Critical,
                                format!("YARA Match: {} on {}", result.identifier, path.display()),
                                MitreTactic::Execution,
                                "T1204 User Execution",
                            );

                            if let Err(e) = tx.try_send(alert) {
                                error!("Pipeline Failure: Failed to route YARA alert for {}: {}", path.display(), e);
                            }
                        }
                    }
                }).await?;
            }
        }
    }
}