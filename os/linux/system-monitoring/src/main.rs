use crate::api::server::ApiServer;
use crate::config::load_master_config;
use crate::engine::ebpf::EbpfEngine;
use crate::engine::honeypot::HoneypotEngine;
use crate::engine::scanner::ScannerEngine;
use crate::engine::yara::YaraEngine;
use crate::siem::models::SecurityAlert;
use crate::siem::transmitter::TransmissionLayer;
use crate::utils::logging::init_central_logging;

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::signal;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

// Module Registration
mod api { pub mod server; }
mod config;
mod engine {
    pub mod ebpf;
    pub mod honeypot;
    pub mod rules;
    pub mod scanner;
    pub mod yara;
}
mod siem {
    pub mod db;
    pub mod models;
    pub mod transmitter;
}
mod utils { pub mod logging; }

/// Required to allocate massive eBPF Ring Buffers and LRU maps for ML feature tracking.
fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        warn!("Failed to increase RLIMIT_MEMLOCK. Deep eBPF maps may fail on strict kernels.");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Non-Blocking Diagnostics & Master Config
    let _log_guard = init_central_logging("/var/log/linux-sentinel/diagnostics");
    info!("Initializing Linux Sentinel v2.6.0 Enterprise EDR...");

    bump_memlock_rlimit()?;

    let config = Arc::new(load_master_config("/opt/linux-sentinel/master.toml")
        .context("Failed to load master configuration")?);

    // 1. PIPELINE CHANNEL A: Raw Telemetry (eBPF -> UEBA Scanner)
    let (raw_tx, raw_rx) = mpsc::channel::<crate::engine::rules::RawKernelEvent>(100_000);

    // 2. High-Throughput Backpressure Channel (100,000 Event Depth)
    let (alert_tx, alert_rx) = mpsc::channel::<SecurityAlert>(100_000);

    // 3. SIEM Transmission & Local SQLite Storage Worker
    info!("Mounting SQLite Telemetry Engine & SIEM Forwarder...");
    let transmitter = Arc::new(
        TransmissionLayer::new(&config.storage.sqlite_db_path, &config.siem.middleware_gateway_url).await?
    );
    let db_pool = transmitter.get_pool();
    transmitter.spawn_worker(alert_rx);

    let mut async_tasks = vec![];

    // 4. API & Local Dashboard
    if config.engine.enable_api_server {
        let api_config = config.clone();
        let api_pool = db_pool.clone();
        async_tasks.push(tokio::spawn(async move {
            let server = ApiServer::new(api_config, api_pool);
            let _ = server.run(8080).await;
        }));
    }

    // 5. Native 5D UEBA Engine (Consumes Channel A, Produces to Channel B)
    if config.engine.enable_anti_evasion {
        let alert_tx_scan = alert_tx.clone();
        let config_scan = config.clone();
        async_tasks.push(tokio::spawn(async move {
            let engine = ScannerEngine::new(config_scan, raw_rx, alert_tx_scan);
            engine.run().await;
        }));
    }

    // 6. YARA File Integrity Engine
    if config.engine.enable_yara {
        let tx_yara = tx.clone();
        let config_yara = config.clone();
        async_tasks.push(tokio::spawn(async move {
            match YaraEngine::new(config_yara, "/opt/linux-sentinel/rules.yara", tx_yara) {
                Ok(engine) => engine.run().await,
                Err(e) => error!("YARA Engine initialization failed: {}", e),
            }
        }));
    }

    // 7. Active Defense Deception Nodes
    if config.engine.enable_honeypots {
        let tx_honey = tx.clone();
        let config_honey = config.clone();
        async_tasks.push(tokio::spawn(async move {
            let engine = HoneypotEngine::new(config_honey, tx_honey);
            let _ = engine.run().await;
        }));
    }

    // 8. The eBPF Kernel Supervisor (Air-Gapped OS Thread)
    if config.engine.enable_ebpf {
        let raw_tx_ebpf = raw_tx.clone();
        std::thread::spawn(move || {
            let mut backoff = 1;
            let max_retries = 10;
            loop {
                info!("(Re)Starting Native eBPF Telemetry Engine...");
                let engine = EbpfEngine::new(raw_tx_ebpf.clone());

                if let Err(e) = engine.run() {
                    error!("eBPF Engine encountered a critical kernel fault: {}", e);

                    if backoff > max_retries {
                        error!("FATAL: eBPF auto-recovery exhausted. Halting sensor to protect system stability.");
                        std::process::exit(1);
                    }

                    warn!("Auto-recovery initiated. Backing off for {} seconds...", backoff * 2);
                    std::thread::sleep(std::time::Duration::from_secs(backoff * 2));
                    backoff += 1;
                } else {
                    break; // Clean exit triggered by system shutdown
                }
            }
        });
    }

    // 9. Deterministic Graceful Teardown
    match signal::ctrl_c().await {
        Ok(()) => {
            info!("SIGTERM received. Initiating graceful teardown...");

            // Drop the transmission channel, forcing the SQLite worker to drain the queue
            drop(tx);

            // Guarantee 3 seconds for the SQLite Write-Ahead Log (WAL) to checkpoint to disk
            info!("Flushing in-memory telemetry to SQLite (Waiting 3 seconds)...");
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

            db_pool.close().await;
            info!("Sensor shutdown successfully. Zero data loss.");
        }
        Err(err) => warn!("Unable to listen for shutdown signals: {}", err),
    }

    Ok(())
}