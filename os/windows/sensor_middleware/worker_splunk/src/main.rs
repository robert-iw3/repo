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

fn pick(parsed: &Value, candidates: &[&str]) -> Value {
    for key in candidates {
        if let Some(v) = parsed.get(*key) {
            if !v.is_null() {
                return v.clone();
            }
        }
    }
    Value::Null
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

        let sensor_type = parsed["sensor_type"].as_str().unwrap_or("unknown");

        // ─── CIM Mapping ─────────────────────────────────────────────────
        // Every field uses pick() to try multiple candidate names, handling:
        //   • DeepSensor capitalised names   (Process, SignatureName, ...)
        //   • DataSensor lowercase names     (process, event_type, ...)
        //   • DlpAlert-shaped events         (alert_type, mitre_tactic, ...)

        let cim_event = match sensor_type {
            "datasensor" => json!({
                "action":       pick(&parsed, &["event_type", "action", "alert_type"]),
                "user":         pick(&parsed, &["user", "User"]),
                "app":          pick(&parsed, &["process", "Process", "Image"]),
                "dest":         pick(&parsed, &["destination", "Destination"]),
                "bytes":        pick(&parsed, &["bytes", "Bytes"]),
                "dlp_hit":      pick(&parsed, &["is_dlp_hit", "IsDlpHit"]),
                "confidence":   pick(&parsed, &["confidence"]),
                "mitre_tactic": pick(&parsed, &["mitre_tactic", "tactic"]),
                "filepath":     pick(&parsed, &["filepath", "FilePath"]),
                "details":      pick(&parsed, &["details"])
            }),
            "deepsensor" => json!({
                "host":       pick(&parsed, &["host", "Host", "ComputerName"]),
                "src_ip":     pick(&parsed, &["ip", "SourceIp", "src_ip"]),
                "user":       pick(&parsed, &["event_user", "user", "User", "EventUser"]),
                "app":        pick(&parsed, &["process", "Process", "Image"]),
                "parent_app": pick(&parsed, &["parent", "ParentImage", "parent_process"]),
                "command":    pick(&parsed, &["cmd", "CommandLine", "command_line"]),
                "dest":       pick(&parsed, &["destination", "Destination"]),
                "dest_port":  pick(&parsed, &["port", "DestPort", "dest_port"]),
                "signature":  pick(&parsed, &[
                    "signature_name", "SignatureName",
                    "matched_indicator", "MatchedIndicator",
                    "reason"
                ]),
                "tactic":     pick(&parsed, &["tactic", "mitre_tactic", "Tactic"]),
                "technique":  pick(&parsed, &["technique", "Technique"]),
                "severity":   pick(&parsed, &["severity", "Severity"]),
                "score":      pick(&parsed, &["score", "Score"]),
                "category":   pick(&parsed, &["Category", "category"])
            }),
            other => {
                warn!("Splunk: unknown sensor_type '{}', forwarding raw.", other);
                parsed.clone()
            }
        };

        let timestamp = pick(&parsed, &["timestamp", "Timestamp", "@timestamp"]);

        let hec_payload = json!({
            "time":       timestamp,
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
    start_durable_worker(adapter, nats_url, stream, subject, "Splunk_Indexer_Group", dlq).await;
}