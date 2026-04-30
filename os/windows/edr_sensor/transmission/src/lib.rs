use ini::Ini;
use reqwest::{Client, StatusCode, header};
use serde_json::Value;
use std::time::Duration;
use tokio::sync::mpsc::Receiver;
use tokio::time::sleep;
use std::collections::HashSet;

pub struct TransmissionConfig {
    pub enable_sync: bool,
    pub endpoint: String,
    pub auth_token: String,
    pub sensor_type: String,
    pub max_batch_size: usize,
    pub max_retries: u32,
    pub base_retry_delay_ms: u64,
}

impl TransmissionConfig {
    pub fn load_from_ini(path: &str) -> Self {
        let conf = Ini::load_from_file(path).unwrap_or_default();
        let section = conf.section(Some("TRANSMISSION"));

        TransmissionConfig {
            enable_sync: section.and_then(|s| s.get("EnableSync")).unwrap_or("False").eq_ignore_ascii_case("true"),
            endpoint: section.and_then(|s| s.get("MiddlewareEndpoint")).unwrap_or("").to_string(),
            auth_token: section.and_then(|s| s.get("AuthToken")).unwrap_or("").to_string(),
            sensor_type: section.and_then(|s| s.get("SensorType")).unwrap_or("deepsensor").to_string(),
            max_batch_size: section.and_then(|s| s.get("MaxBatchSize")).and_then(|v| v.parse().ok()).unwrap_or(1000),
            max_retries: section.and_then(|s| s.get("MaxRetries")).and_then(|v| v.parse().ok()).unwrap_or(5),
            base_retry_delay_ms: section.and_then(|s| s.get("BaseRetryDelayMs")).and_then(|v| v.parse().ok()).unwrap_or(1000),
        }
    }
}

fn generate_transmission_key(val: &Value) -> String {
    let process = val.get("Process")
        .or_else(|| val.get("process"))
        .or_else(|| val.get("Image"))
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");

    let signature = val.get("SignatureName")
        .or_else(|| val.get("reason"))
        .or_else(|| val.get("MatchedIndicator"))
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");

    let score = val.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let category = val.get("Category").and_then(|v| v.as_str()).unwrap_or("");

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
    log_diag: impl Fn(&str) + Send + Sync + 'static
) {
    let config = TransmissionConfig::load_from_ini(&config_path);

    if !config.enable_sync || config.endpoint.is_empty() {
        log_diag("[Transmission] Sync disabled. Dropping all channel payloads.");
        while let Some(_) = rx.recv().await {}
        return;
    }

    let mut historical_transmissions = HashSet::new();
    // Prevent infinite memory growth: clear the hashset if it exceeds 50,000 unique signatures
    const MAX_TRACKED_SIGNATURES: usize = 50_000;

    let mut headers = header::HeaderMap::new();
    headers.insert("Authorization", header::HeaderValue::from_str(&format!("Bearer {}", config.auth_token)).unwrap());
    headers.insert("X-Sensor-Type", header::HeaderValue::from_str(&config.sensor_type).unwrap());

    // Increased timeout to allow for slower enterprise network routes
    let client = Client::builder()
        .use_rustls_tls()
        .default_headers(headers)
        .timeout(Duration::from_secs(15))
        .build()
        .expect("Failed to build HTTP client");

    log_diag(&format!("[Transmission] Engine Online. Async Sync to {} [{}]", config.endpoint, config.sensor_type));

    loop {
        let mut batch: Vec<Value> = Vec::with_capacity(config.max_batch_size);

        if let Some(first) = rx.recv().await {

            // Memory Management for the Gatekeeper
            if historical_transmissions.len() > MAX_TRACKED_SIGNATURES {
                log_diag("[Transmission] Clearing deduplication matrix to preserve memory limits.");
                historical_transmissions.clear();
            }

            let key = generate_transmission_key(&first);
            if historical_transmissions.insert(key) { batch.push(first); }

            while batch.len() < config.max_batch_size {
                if let Ok(next) = rx.try_recv() {
                    let key = generate_transmission_key(&next);
                    if historical_transmissions.insert(key) { batch.push(next); }
                } else {
                    break;
                }
            }

            if batch.is_empty() { continue; }

            // =================================================================
            // AUTO-RECOVERY & THROTTLING LOGIC (Exponential Backoff)
            // =================================================================
            let mut retry_count = 0;
            let max_retries = 5;
            let mut base_delay_ms = 1000;
            let mut transmission_success = false;

            while retry_count <= max_retries {
                match client.post(&config.endpoint).json(&batch).send().await {
                    Ok(resp) => {
                        let status = resp.status();
                        if status.is_success() {
                            transmission_success = true;
                            break;
                        } else if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
                            // HTTP 429 or 5xx: Middleware is telling us to back off
                            log_diag(&format!("[Transmission] Middleware requested backoff (HTTP {}). Retrying {}/{}...", status, retry_count + 1, max_retries));
                        } else {
                            // HTTP 4xx (e.g., 401 Unauthorized, 403 Forbidden, 400 Bad Request)
                            // Retrying will not fix a bad token or malformed JSON. Drop batch.
                            log_diag(&format!("[Transmission] Fatal rejection by Middleware (HTTP {}). Dropping batch of {} events.", status, batch.len()));
                            break;
                        }
                    }
                    Err(e) => {
                        // Network/DNS failure or Timeout
                        log_diag(&format!("[Transmission] Network fault: {}. Retrying {}/{}...", e, retry_count + 1, max_retries));
                    }
                }

                retry_count += 1;
                if retry_count <= max_retries {
                    // Exponential backoff: 1s, 2s, 4s, 8s, 16s
                    sleep(Duration::from_millis(base_delay_ms)).await;
                    base_delay_ms *= 2;
                }
            }

            if !transmission_success {
                log_diag(&format!("[Transmission] CRITICAL: Exhausted all retries. Dropped {} telemetry events.", batch.len()));
                // Data Fidelity Failure Point: Events are dropped from the network pipeline here.
            }
        } else {
            break; // Channel closed, orchestrator shutting down
        }
    }
}