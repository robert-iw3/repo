/*=============================================================================================
 * SYSTEM:          Data Sensor - Transmission Layer
 * COMPONENT:       lib.rs (Async Network Pusher)
 * DESCRIPTION:
 * Asynchronously tails the DataLedger.db SQLite WAL and pushes micro-batched
 * data sensor telemetry to the designated middleware endpoint.
 * @RW
 *============================================================================================*/

use ini::Ini;
use reqwest::{Client, header};
use serde::Serialize;
use std::time::Duration;
use tokio::sync::mpsc::Receiver;

#[derive(Serialize, Clone)]
pub struct TransmissionPayload {
    pub timestamp: String,
    pub user: String,
    pub process: String,
    pub destination: String,
    pub bytes: i64,
    pub is_dlp_hit: bool,
    pub event_type: String,
}

pub struct TransmissionConfig {
    pub enable_sync: bool,
    pub endpoint: String,
    pub auth_token: String,
    pub max_batch_size: usize,
}

impl TransmissionConfig {
    pub fn load_from_ini(path: &str) -> Self {
        let conf = Ini::load_from_file(path).unwrap_or_default();
        let section = conf.section(Some("TRANSMISSION"));

        TransmissionConfig {
            enable_sync: section.and_then(|s| s.get("EnableSync")).unwrap_or("False").eq_ignore_ascii_case("true"),
            endpoint: section.and_then(|s| s.get("MiddlewareEndpoint")).unwrap_or("").to_string(),
            auth_token: section.and_then(|s| s.get("AuthToken")).unwrap_or("").to_string(),
            max_batch_size: section.and_then(|s| s.get("MaxBatchSize")).and_then(|v| v.parse().ok()).unwrap_or(1000),
        }
    }
}

pub async fn start_transmission_worker(
    config_path: String,
    mut rx: Receiver<TransmissionPayload>,
    log_diag: impl Fn(&str) + Send + Sync + 'static
) {
    let config = TransmissionConfig::load_from_ini(&config_path);

    if !config.enable_sync || config.endpoint.is_empty() {
        log_diag("[Transmission] Sync disabled. Dropping all channel payloads.");
        // Drain the channel continuously to prevent memory buildup
        while let Some(_) = rx.recv().await {}
        return;
    }

    let mut headers = header::HeaderMap::new();
    headers.insert("Authorization", header::HeaderValue::from_str(&format!("Bearer {}", config.auth_token)).unwrap());

    let client = Client::builder()
        .use_rustls_tls()
        .default_headers(headers)
        .timeout(Duration::from_secs(3))
        .build()
        .expect("Failed to build HTTP client");

    log_diag(&format!("[Transmission] Engine Online. Async Sync to {}", config.endpoint));

    loop {
        let mut batch = Vec::with_capacity(config.max_batch_size);

        // Wait efficiently until at least one item enters the queue
        if let Some(first) = rx.recv().await {
            batch.push(first);

            // Instantly scoop up everything else currently waiting
            while batch.len() < config.max_batch_size {
                if let Ok(next) = rx.try_recv() {
                    batch.push(next);
                } else {
                    break;
                }
            }

            match client.post(&config.endpoint).json(&batch).send().await {
                Ok(resp) if !resp.status().is_success() => {
                    log_diag(&format!("[Transmission] Middleware rejected batch: HTTP {}", resp.status()));
                }
                Err(e) => {
                    log_diag(&format!("[Transmission] Network Fault: {}", e));
                }
                _ => {} // Transmission Success
            }
        } else {
            break; // Channel closed, gracefully terminate worker
        }
    }
}