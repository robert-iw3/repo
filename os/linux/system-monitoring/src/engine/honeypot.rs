use crate::config::MasterConfig;
use crate::siem::models::{AlertLevel, MitreTactic, SecurityAlert};
use anyhow::Result;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

// Default ports targeted by automated scanners
const TARGET_PORTS: &[u16] = &[21, 23, 2222, 3389];

pub struct HoneypotEngine {
    config: Arc<MasterConfig>,
    tx: mpsc::Sender<SecurityAlert>,
}

impl HoneypotEngine {
    pub fn new(config: Arc<MasterConfig>, tx: mpsc::Sender<SecurityAlert>) -> Self {
        Self { config, tx }
    }

    pub async fn run(self) -> Result<()> {
        if !self.config.engine.enable_honeypots {
            info!("Honeypot engine is disabled in master.toml");
            return Ok(());
        }

        info!("Initializing asynchronous honeypot listeners...");

        for &port in TARGET_PORTS {
            let tx_clone = self.tx.clone();

            tokio::spawn(async move {
                let addr = format!("0.0.0.0:{}", port);
                match TcpListener::bind(&addr).await {
                    Ok(listener) => {
                        info!("Honeypot active on port {}", port);
                        loop {
                            if let Ok((mut socket, peer_addr)) = listener.accept().await {
                                let ip = peer_addr.ip().to_string();

                                // Read initial payload/banner grab attempt
                                let mut buffer = [0; 128];
                                let _ = tokio::time::timeout(
                                    std::time::Duration::from_secs(2),
                                    socket.read(&mut buffer)
                                ).await;

                                let msg = format!("Honeypot connection attempt on port {} from IP: {}", port, ip);
                                warn!("{}", msg);

                                let alert = SecurityAlert::new(
                                    AlertLevel::High,
                                    msg,
                                    MitreTactic::DefenseEvasion, // Or Reconnaissance
                                    "T1046 Network Service Scanning",
                                );

                                let _ = tx_clone.try_send(alert);
                            }
                        }
                    }
                    Err(e) => error!("Failed to bind honeypot to port {}: {}", port, e),
                }
            });
        }

        // Keep the engine alive
        tokio::signal::ctrl_c().await?;
        Ok(())
    }
}