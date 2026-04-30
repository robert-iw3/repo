use async_trait::async_trait;
use ini::Ini;
use lib_siem_template::{SiemAdapter, start_durable_worker};
use reqwest::{Client, header};
use serde_json::{json, Value};
use tracing::{info, Level, warn};

struct ElasticAdapter {
    client: reqwest::Client,
    endpoint: String,
    api_key: String,
    batch_size: usize,
    target_index: String,
    sensor_type: String,
}

#[async_trait]
impl SiemAdapter for ElasticAdapter {
    fn initialize(config_path: &str) -> Self {
        let conf = Ini::load_from_file(config_path).expect("Failed to read config.ini");
        let section = conf.section(Some("ELASTIC")).expect("ELASTIC section missing");

        ElasticAdapter {
            client: reqwest::Client::builder()
                .use_rustls_tls()
                .timeout(Duration::from_secs(15))
                .build()
                .expect("Failed to build reqwest client"),
            endpoint: section.get("Endpoint").expect("Endpoint missing").to_string(),
            api_key: section.get("ApiKey").expect("ApiKey missing").to_string(),
            batch_size: section.get("MaxBatchSize").unwrap_or("1000").parse().unwrap_or(1000),
            target_index: section.get("TargetIndex").unwrap_or("logs-datasensor-alerts").to_string(),
        }
    }

    fn batch_size(&self) -> usize {
        self.batch_size
    }

    fn batch_separator(&self) -> Option<u8> { None }

    fn format_event(&self, raw_payload: &[u8]) -> Vec<u8> {
        let parsed: Value = match serde_json::from_slice(raw_payload) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };

        let ecs_event = match self.sensor_type.as_str() {
            "datasensor" => json!({
                "@timestamp": parsed["timestamp"],
                "event": { "category": parsed["event_type"], "dataset": "datasensor.dlp" },
                "user": { "name": parsed["user"] },
                "process": { "name": parsed["process"] },
                "destination": { "address": parsed["destination"] },
                "network": { "bytes": parsed["bytes"] },
                "datasensor": { "is_dlp_hit": parsed["is_dlp_hit"] }
            }),
            "deepsensor" => json!({
                "@timestamp": chrono::Utc::now().to_rfc3339(),
                "event": {
                    "category": parsed["Category"],
                    "dataset": "deepsensor.behavioral"
                },
                "process": {
                    "name": parsed.get("Process")
                        .or_else(|| parsed.get("Image"))
                        .unwrap_or(&Value::Null)
                },
                "rule": {
                    "name": parsed.get("SignatureName")
                        .or_else(|| parsed.get("MatchedIndicator"))
                        .or_else(|| parsed.get("reason"))
                        .unwrap_or(&Value::Null)
                },
                "deepsensor": { "score": parsed["score"] }
            }),
            _ => parsed.clone(),
        };

        let action_line = json!({ "index": { "_index": self.target_index } });
        let mut bulk_payload = Vec::new();
        bulk_payload.extend_from_slice(action_line.to_string().as_bytes());
        bulk_payload.push(b'\n');
        bulk_payload.extend_from_slice(ecs_event.to_string().as_bytes());
        bulk_payload.push(b'\n');
        bulk_payload
    }

    async fn transmit_batch(&self, formatted_batch: Vec<u8>) -> Result<(), String> {
        let mut headers = header::HeaderMap::new();
        headers.insert("Authorization", header::HeaderValue::from_str(&format!("ApiKey {}", self.api_key)).unwrap());

        let res = self.client.post(&self.endpoint)
            .headers(headers)
            .header("Content-Type", "application/x-ndjson")
            .body(formatted_batch)
            .send().await.map_err(|e| format!("Transport failed: {}", e))?;

        if res.status().is_success() { Ok(()) } else { Err(format!("Elastic rejected batch: HTTP {}", res.status())) }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .init();

    // Load global NATS/JetStream settings from config.ini
    let conf = Ini::load_from_file("config.ini").unwrap();
    let global = conf.section(Some("GLOBAL")).unwrap();
    let nats_url = global.get("NatsEndpoint").unwrap_or("127.0.0.1:4222");
    let stream = global.get("TelemetryStream").unwrap_or("SensorStream");
    let subject = global.get("TelemetrySubject").unwrap_or("sensor.telemetry");

    let adapter = ElasticAdapter::initialize("config.ini");

    // Start the durable consumer loop
    let dlq = global.get("DlqSubjectPrefix").unwrap_or("sensor.dlq");
    start_durable_worker(
        adapter,
        nats_url,
        stream,
        subject,
        "Elastic_Indexer_Group",
        dlq
    ).await;
}