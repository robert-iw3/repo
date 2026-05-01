// Splunk Worker for Sensor Middleware
// Consumes telemetry from JetStream, maps it to Splunk CIM format,
// and forwards it to a Splunk HEC endpoint.
// worker_splunk/src/main.rs

use async_trait::async_trait;
use ini::Ini;
use lib_siem_template::{SiemAdapter, start_durable_worker};
use reqwest::header;
use serde_json::{json, Value};
use std::time::Duration;
use tracing::{warn, Level};

struct SplunkAdapter {
    client: reqwest::Client,
    endpoint: String,
    hec_token: String,
    batch_size: usize,
    target_index: String,
    target_sourcetype: String,
}

#[async_trait]
impl SiemAdapter for SplunkAdapter {
    fn initialize(config_path: &str) -> Self {
        let conf    = Ini::load_from_file(config_path).expect("Failed to read config.ini");
        let section = conf.section(Some("SPLUNK")).expect("SPLUNK section missing");

        let timeout_secs = section
            .get("TimeoutSeconds")
            .unwrap_or("15")
            .parse::<u64>()
            .unwrap_or(15);

        SplunkAdapter {
            client: reqwest::Client::builder()
                .use_rustls_tls()
                // Allow self-signed certs on internal Splunk Heavy Forwarders
                .danger_accept_invalid_certs(true)
                .timeout(Duration::from_secs(timeout_secs))
                .build()
                .expect("Failed to build HTTP client"),
            endpoint: section.get("HecEndpoint").expect("HecEndpoint missing").to_string(),
            hec_token: section.get("HecToken").expect("HecToken missing").to_string(),
            batch_size: section
                .get("MaxBatchSize")
                .unwrap_or("500")
                .parse()
                .unwrap_or(500),
            target_index: section.get("TargetIndex").unwrap_or("main").to_string(),
            target_sourcetype: section
                .get("TargetSourceType")
                .unwrap_or("sensor:ueba")
                .to_string(),
        }
    }

    fn batch_size(&self) -> usize {
        self.batch_size
    }

    /// Splunk HEC multi-event format: newline-delimited JSON objects.
    fn batch_separator(&self) -> Option<u8> {
        Some(b'\n')
    }

    fn format_event(&self, raw_payload: &[u8]) -> Vec<u8> {
        let parsed: Value = match serde_json::from_slice(raw_payload) {
            Ok(v) => v,
            Err(e) => {
                warn!("Splunk: failed to parse event JSON: {}", e);
                return Vec::new();
            }
        };

        // sensor_type is embedded by the ingress as a top-level field.
        let sensor_type = parsed["sensor_type"].as_str().unwrap_or("unknown");

        let cim_event = match sensor_type {
            "datasensor" => json!({
                "action": parsed["event_type"],
                "user":   parsed["user"],
                "app":    parsed["process"],
                "dest":   parsed["destination"],
                "bytes":  parsed["bytes"],
                "dlp_hit": parsed["is_dlp_hit"]
            }),
            "deepsensor" => json!({
                "host":       parsed["host"],
                "src_ip":     parsed["ip"],
                "user":       parsed["event_user"],
                "app":        parsed["process"],
                "parent_app": parsed["parent"],
                "command":    parsed["cmd"],
                "dest":       parsed["destination"],
                "dest_port":  parsed["port"],
                // Normalise across different field names used by sensor variants
                "signature": parsed.get("signature_name")
                    .or_else(|| parsed.get("matched_indicator"))
                    .or_else(|| parsed.get("reason"))
                    .unwrap_or(&Value::Null),
                "tactic":    parsed["tactic"],
                "technique": parsed["technique"],
                "severity":  parsed["severity"],
                "score":     parsed["score"]
            }),
            other => {
                warn!("Splunk: unknown sensor_type '{}', forwarding raw.", other);
                parsed.clone()
            }
        };

        // Full HEC event envelope
        let hec_payload = json!({
            "time":       parsed["timestamp"],
            "index":      self.target_index,
            "sourcetype": self.target_sourcetype,
            "event":      cim_event
        });

        hec_payload.to_string().into_bytes()
    }

    async fn transmit_batch(&self, formatted_batch: Vec<u8>) -> Result<(), String> {
        let res = self
            .client
            .post(&self.endpoint)
            .header(
                header::AUTHORIZATION,
                header::HeaderValue::from_str(&format!("Splunk {}", self.hec_token))
                    .map_err(|e| e.to_string())?,
            )
            .header(header::CONTENT_TYPE, "application/json")
            .body(formatted_batch)
            .send()
            .await
            .map_err(|e| format!("Transport failed: {}", e))?;

        if res.status().is_success() {
            Ok(())
        } else {
            Err(format!("Splunk HEC returned HTTP {}", res.status()))
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

    let adapter = SplunkAdapter::initialize("config.ini");

    // The consumer name "Splunk_Indexer_Group" ensures multiple instances of
    // this binary will have NATS load-balance events across all of them.
    start_durable_worker(adapter, nats_url, stream, subject, "Splunk_Indexer_Group", dlq).await;
}