// Elastic Worker for Sensor Middleware
// Consumes telemetry from JetStream, maps it to Elastic Common Schema (ECS),
// and forwards it to an Elasticsearch cluster using the Bulk API.
// worker_elastic/src/main.rs

use async_trait::async_trait;
use ini::Ini;
use lib_siem_template::{SiemAdapter, start_durable_worker};
use reqwest::header;
use serde_json::{json, Value};
use std::time::Duration;
use tracing::{warn, Level};

struct ElasticAdapter {
    client: reqwest::Client,
    endpoint: String,
    api_key: String,
    batch_size: usize,
    target_index: String,
}

#[async_trait]
impl SiemAdapter for ElasticAdapter {
    fn initialize(config_path: &str) -> Self {
        let conf    = Ini::load_from_file(config_path).expect("Failed to read config.ini");
        let section = conf.section(Some("ELASTIC")).expect("ELASTIC section missing");

        ElasticAdapter {
            client: reqwest::Client::builder()
                .use_rustls_tls()
                // Allow self-signed certs on internal Elastic clusters
                .danger_accept_invalid_certs(true)
                .timeout(Duration::from_secs(15))
                .build()
                .expect("Failed to build HTTP client"),
            endpoint: section.get("Endpoint").expect("Endpoint missing").to_string(),
            api_key: section.get("ApiKey").expect("ApiKey missing").to_string(),
            batch_size: section
                .get("MaxBatchSize")
                .unwrap_or("1000")
                .parse()
                .unwrap_or(1000),
            target_index: section
                .get("TargetIndex")
                .unwrap_or("logs-sensor-alerts")
                .to_string(),
        }
    }

    fn batch_size(&self) -> usize {
        self.batch_size
    }

    /// Elastic Bulk API is pure NDJSON.  Each format_event call already appends
    /// two `\n`-terminated lines (action meta + document), so no extra separator.
    fn batch_separator(&self) -> Option<u8> {
        None
    }

    fn format_event(&self, raw_payload: &[u8]) -> Vec<u8> {
        let parsed: Value = match serde_json::from_slice(raw_payload) {
            Ok(v) => v,
            Err(e) => {
                warn!("Elastic: failed to parse event JSON: {}", e);
                return Vec::new();
            }
        };

        // sensor_type is embedded by the ingress as a top-level field.
        let sensor_type = parsed["sensor_type"].as_str().unwrap_or("unknown");

        // Fall back to now() if the event carries no timestamp.
        let timestamp = parsed["timestamp"]
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

        let ecs_doc = match sensor_type {
            "datasensor" => json!({
                "@timestamp": timestamp,
                "event": {
                    "category": parsed["event_type"],
                    "dataset":  "datasensor.dlp"
                },
                "user":        { "name":    parsed["user"] },
                "process":     { "name":    parsed["process"] },
                "destination": { "address": parsed["destination"] },
                "network":     { "bytes":   parsed["bytes"] },
                "datasensor":  { "is_dlp_hit": parsed["is_dlp_hit"] }
            }),
            "deepsensor" => json!({
                "@timestamp": timestamp,
                "event": {
                    // Accept both capitalised and lowercase field names
                    "category": parsed.get("Category")
                        .or_else(|| parsed.get("event_type"))
                        .unwrap_or(&Value::Null),
                    "dataset": "deepsensor.behavioral"
                },
                "host": { "name": parsed["host"] },
                "source": { "ip": parsed["ip"] },
                "process": {
                    "name": parsed.get("process")
                        .or_else(|| parsed.get("Process"))
                        .or_else(|| parsed.get("Image"))
                        .unwrap_or(&Value::Null)
                },
                "rule": {
                    "name": parsed.get("signature_name")
                        .or_else(|| parsed.get("SignatureName"))
                        .or_else(|| parsed.get("matched_indicator"))
                        .or_else(|| parsed.get("MatchedIndicator"))
                        .or_else(|| parsed.get("reason"))
                        .unwrap_or(&Value::Null)
                },
                "deepsensor": {
                    "score":    parsed["score"],
                    "severity": parsed["severity"]
                }
            }),
            other => {
                warn!("Elastic: unknown sensor_type '{}', forwarding raw.", other);
                parsed.clone()
            }
        };

        // Bulk API format: action line + document line, both newline-terminated.
        let action_line = json!({ "index": { "_index": &self.target_index } });
        let mut bulk_lines: Vec<u8> = Vec::new();
        bulk_lines.extend_from_slice(action_line.to_string().as_bytes());
        bulk_lines.push(b'\n');
        bulk_lines.extend_from_slice(ecs_doc.to_string().as_bytes());
        bulk_lines.push(b'\n');
        bulk_lines
    }

    async fn transmit_batch(&self, formatted_batch: Vec<u8>) -> Result<(), String> {
        let res = self
            .client
            .post(&self.endpoint)
            .header(
                header::AUTHORIZATION,
                header::HeaderValue::from_str(&format!("ApiKey {}", self.api_key))
                    .map_err(|e| e.to_string())?,
            )
            .header(header::CONTENT_TYPE, "application/x-ndjson")
            .body(formatted_batch)
            .send()
            .await
            .map_err(|e| format!("Transport failed: {}", e))?;

        if res.status().is_success() {
            Ok(())
        } else {
            Err(format!("Elastic rejected batch: HTTP {}", res.status()))
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .init();

    let conf    = Ini::load_from_file("config.ini").unwrap();
    let global  = conf.section(Some("GLOBAL")).unwrap();
    let nats_url = global.get("NatsEndpoint").unwrap_or("127.0.0.1:4222");
    let stream   = global.get("TelemetryStream").unwrap_or("SensorStream");
    let subject  = global.get("TelemetrySubject").unwrap_or("sensor.telemetry");
    let dlq      = global.get("DlqSubjectPrefix").unwrap_or("sensor.dlq");

    let adapter = ElasticAdapter::initialize("config.ini");
    start_durable_worker(adapter, nats_url, stream, subject, "Elastic_Indexer_Group", dlq).await;
}