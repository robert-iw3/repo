/*=============================================================================================
 * SYSTEM:          Universal Telemetry Gateway - Transmission Layer
 * COMPONENT:       lib.rs (Async Network Pusher)
 * DESCRIPTION:
 * Asynchronously tails sensor telemetry and pushes micro-batched data to the
 * designated middleware gateway.
 *============================================================================================*/

use ini::Ini;
use lru::LruCache;
use reqwest::{Client, StatusCode, header};
use serde_json::Value;
use std::fs::OpenOptions;
use std::io::Write;
use std::num::NonZeroUsize;
use std::time::Duration;
use tokio::sync::mpsc::Receiver;
use tokio::time::sleep;

pub struct TransmissionConfig {
    pub enable_sync: bool,
    pub endpoint: String,
    pub auth_token: String,
    pub sensor_type: String,
    pub batch_interval_ms: u64,
    pub max_batch_size: usize,
    pub max_retries: u32,
    pub base_retry_delay_ms: u64,
    pub trust_self_signed: bool,
}

impl TransmissionConfig {
    pub fn load_from_ini(path: &str) -> Self {
        let conf = Ini::load_from_file(path).unwrap_or_default();
        let section = conf.section(Some("TRANSMISSION"));

        TransmissionConfig {
            enable_sync: section
                .and_then(|s| s.get("EnableSync"))
                .unwrap_or("False")
                .eq_ignore_ascii_case("true"),
            endpoint: section
                .and_then(|s| s.get("MiddlewareEndpoint"))
                .unwrap_or("")
                .to_string(),
            auth_token: section
                .and_then(|s| s.get("AuthToken"))
                .unwrap_or("")
                .to_string(),
            sensor_type: section
                .and_then(|s| s.get("SensorType"))
                .unwrap_or("unknown")
                .to_string(),
            batch_interval_ms: section
                .and_then(|s| s.get("BatchIntervalMs"))
                .and_then(|v| v.parse().ok())
                .unwrap_or(500),
            max_batch_size: section
                .and_then(|s| s.get("MaxBatchSize"))
                .and_then(|v| v.parse().ok())
                .unwrap_or(1000),
            max_retries: section
                .and_then(|s| s.get("MaxRetries"))
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            base_retry_delay_ms: section
                .and_then(|s| s.get("BaseRetryDelayMs"))
                .and_then(|v| v.parse().ok())
                .unwrap_or(1000),
            trust_self_signed: section
                .and_then(|s| s.get("TrustSelfSignedCert"))
                .unwrap_or("False")
                .eq_ignore_ascii_case("true"),
        }
    }
}

fn generate_transmission_key(val: &Value) -> String {
    let process = val
        .get("Process")
        .or_else(|| val.get("process"))
        .or_else(|| val.get("Image"))
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");

    let signature = val
        .get("SignatureName")
        .or_else(|| val.get("reason"))
        .or_else(|| val.get("MatchedIndicator"))
        .or_else(|| val.get("action"))
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");

    let score = val.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let category = val
        .get("Category")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if score == -1.0 || score == -2.0 || category == "Suppressed_Rule_Hit" {
        format!("SUPPRESSION_{}_{}", process, signature)
    } else if score <= -3.0 || category == "AggregatedUEBA" {
        format!("UEBA_ROLLUP_{}_{}", process, signature)
    } else {
        format!("ACTIVE_ALERT_{}_{}", process, signature)
    }
}

pub async fn start_transmission_worker(
    config_path: String,
    mut rx: Receiver<Value>,
    log_diag: impl Fn(&str) + Send + Sync + 'static,
) {
    let config = TransmissionConfig::load_from_ini(&config_path);

    if !config.enable_sync || config.endpoint.is_empty() {
        log_diag("[Transmission] Sync disabled. Dropping all channel payloads.");
        while rx.recv().await.is_some() {}
        return;
    }

    let mut dedup_matrix = LruCache::new(NonZeroUsize::new(50_000).unwrap());

    let mut headers = header::HeaderMap::new();
    headers.insert(
        "Authorization",
        header::HeaderValue::from_str(&format!("Bearer {}", config.auth_token)).unwrap(),
    );
    headers.insert(
        "X-Sensor-Type",
        header::HeaderValue::from_str(&config.sensor_type).unwrap(),
    );

    // ── Build the HTTP client ────────────────────────────────────────────────
    // In production with a CA-signed cert, `TrustSelfSignedCert` should be
    // False (or omitted) so the full certificate chain is validated.
    let mut builder = Client::builder()
        .use_rustls_tls()
        .default_headers(headers)
        .timeout(Duration::from_secs(15));

    if config.trust_self_signed {
        log_diag("[Transmission] WARNING: TrustSelfSignedCert=True — certificate validation DISABLED.");
        builder = builder.danger_accept_invalid_certs(true);
    }

    let client = builder.build().expect("Failed to build HTTP client");

    log_diag(&format!(
        "[Transmission] Engine Online. Async Sync to {} [{}]{}",
        config.endpoint,
        config.sensor_type,
        if config.trust_self_signed { " (self-signed OK)" } else { "" }
    ));

    loop {
        let mut batch: Vec<Value> = Vec::with_capacity(config.max_batch_size);

        // Idle at 0% CPU until at least ONE event arrives
        if let Some(first) = rx.recv().await {
            let key = generate_transmission_key(&first);
            if !dedup_matrix.contains(&key) {
                dedup_matrix.put(key, ());
                batch.push(first);
            }

            // Collect more events within the batch interval window
            let timeout = sleep(Duration::from_millis(config.batch_interval_ms));
            tokio::pin!(timeout);

            loop {
                if batch.len() >= config.max_batch_size {
                    break;
                }

                tokio::select! {
                    _ = &mut timeout => {
                        break; // Window expired, flush
                    }
                    msg_opt = rx.recv() => {
                        match msg_opt {
                            Some(next) => {
                                let key = generate_transmission_key(&next);
                                if !dedup_matrix.contains(&key) {
                                    dedup_matrix.put(key, ());
                                    batch.push(next);
                                }
                            }
                            None => return, // Channel closed
                        }
                    }
                }
            }

            if batch.is_empty() {
                continue;
            }

            // ── Auto-Recovery (Exponential Backoff) ──────────────────────────
            let mut retry_count = 0;
            let mut base_delay_ms = config.base_retry_delay_ms;
            let mut transmission_success = false;

            while retry_count <= config.max_retries {
                match client.post(&config.endpoint).json(&batch).send().await {
                    Ok(resp) => {
                        let status = resp.status();
                        if status.is_success() {
                            transmission_success = true;
                            break;
                        } else if status == StatusCode::TOO_MANY_REQUESTS
                            || status.is_server_error()
                        {
                            log_diag(&format!(
                                "[Transmission] Middleware backoff (HTTP {}). Retry {}/{}...",
                                status,
                                retry_count + 1,
                                config.max_retries
                            ));
                        } else {
                            // 4xx (auth, bad request) — retrying won't help
                            log_diag(&format!(
                                "[Transmission] Fatal rejection (HTTP {}). Dropping batch.",
                                status
                            ));
                            break;
                        }
                    }
                    Err(e) => {
                        log_diag(&format!(
                            "[Transmission] Network fault: {}. Retry {}/{}...",
                            e,
                            retry_count + 1,
                            config.max_retries
                        ));
                    }
                }

                retry_count += 1;
                if retry_count <= config.max_retries {
                    sleep(Duration::from_millis(base_delay_ms)).await;
                    base_delay_ms *= 2;
                }
            }

            if !transmission_success {
                log_diag(&format!(
                    "[Transmission] CRITICAL: Exhausted retries. Spooling {} events to DLQ.",
                    batch.len()
                ));

                let dlq_path = if config.sensor_type == "deepsensor" {
                    r"C:\ProgramData\DeepSensor\Logs\Transmission_DLQ.jsonl"
                } else {
                    r"C:\ProgramData\DataSensor\Logs\Transmission_DLQ.jsonl"
                };

                if let Ok(mut file) =
                    OpenOptions::new().create(true).append(true).open(dlq_path)
                {
                    for event in &batch {
                        let _ = writeln!(
                            file,
                            "{}",
                            serde_json::to_string(event).unwrap_or_default()
                        );
                    }
                }
            }
        } else {
            break; // Engine shutting down
        }
    }
}