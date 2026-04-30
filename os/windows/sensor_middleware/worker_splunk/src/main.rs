use async_trait::async_trait;
use ini::Ini;
use lib_siem_template::{SiemAdapter, start_durable_worker};
use reqwest::{Client, header};
use serde_json::{json, Value};
use tracing::{info, Level, warn};

struct SplunkAdapter {
    client: reqwest::Client,
    endpoint: String,
    hec_token: String,
    batch_size: usize,
    target_index: String,
    target_sourcetype: String,
    sensor_type: String,
}

#[async_trait]
impl SiemAdapter for SplunkAdapter {
    fn initialize(config_path: &str) -> Self {
        let conf = Ini::load_from_file(config_path).expect("Failed to read config.ini");
        let section = conf.section(Some("SPLUNK")).expect("SPLUNK section missing");

        SplunkAdapter {
            client: reqwest::Client::builder()
                .use_rustls_tls()
                .timeout(Duration::from_secs(15))
                .build()
                .expect("Failed to build reqwest client"),
            endpoint: section.get("HecEndpoint").expect("HecEndpoint missing").to_string(),
            hec_token: section.get("HecToken").expect("HecToken missing").to_string(),
            batch_size: section.get("MaxBatchSize").unwrap_or("1000").parse().unwrap_or(1000),
            target_index: section.get("TargetIndex").unwrap_or("main").to_string(),
            target_sourcetype: section.get("TargetSourceType").unwrap_or("datasensor:ueba").to_string(),
            sensor_type: section.get("SensorType").unwrap_or("unknown").to_string(),
        }
    }

    fn batch_size(&self) -> usize {
        self.batch_size
    }

    fn batch_separator(&self) -> Option<u8> { Some(b'\n') }

    fn format_event(&self, raw_payload: &[u8]) -> Vec<u8> {
        // Deserialize the incoming NATS payload
        let parsed: Value = match serde_json::from_slice(raw_payload) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };

        // Perform conditional CIM mapping
        let cim_event = match self.sensor_type.as_str() {
            "datasensor" => json!({
                "action": parsed["event_type"],
                "user": parsed["user"],
                "app": parsed["process"],
                "dest": parsed["destination"],
                "bytes": parsed["bytes"],
                "dlp_hit": parsed["is_dlp_hit"]
            }),
            "deepsensor" => json!({
                "host": parsed["host"],
                "src_ip": parsed["ip"],
                "user": parsed["event_user"],
                "app": parsed["process"],
                "parent_app": parsed["parent"],
                "command": parsed["cmd"],
                "dest": parsed["destination"],
                "dest_port": parsed["port"],
                "signature": parsed.get("signature_name")
                    .or_else(|| parsed.get("matched_indicator"))
                    .or_else(|| parsed.get("reason"))
                    .unwrap_or(&Value::Null),
                "tactic": parsed["tactic"],
                "technique": parsed["technique"],
                "severity": parsed["severity"],
                "score": parsed["score"]
            }),
            _ => parsed.clone(),
        };

        // Construct the final Splunk HEC payload
        let splunk_hec_payload = json!({
            "time": parsed["timestamp"],
            "event": cim_event
        });

        splunk_hec_payload.to_string().into_bytes()
    }

    async fn transmit_batch(&self, formatted_batch: Vec<u8>) -> Result<(), String> {
        let mut headers = header::HeaderMap::new();
        headers.insert("Authorization", header::HeaderValue::from_str(&format!("Splunk {}", self.hec_token)).unwrap());

        let res = self.client.post(&self.endpoint)
            .headers(headers)
            .body(formatted_batch)
            .send().await.map_err(|e| format!("Network transport failed: {}", e))?;

        if res.status().is_success() { Ok(()) } else { Err(format!("Splunk HEC returned HTTP {}", res.status())) }
    }
}

#[tokio::main]
async fn main() {
    // Initialize high-performance asynchronous logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    // Read global variables
    let conf = Ini::load_from_file("config.ini").unwrap();
    let global = conf.section(Some("GLOBAL")).unwrap();
    let nats_url = global.get("NatsEndpoint").unwrap_or("127.0.0.1:4222");
    let stream = global.get("TelemetryStream").unwrap_or("SensorStream");
    let subject = global.get("TelemetrySubject").unwrap_or("sensor.telemetry");

    let adapter = SplunkAdapter::initialize("config.ini");

    // Execute the durable worker loop.
    // The consumer name "Splunk_Indexer_Group" ensures that if you spin up 5 of these
    // Splunk binaries, NATS will load-balance the events across all 5 automatically.
    let dlq = global.get("DlqSubjectPrefix").unwrap_or("sensor.dlq");
    start_durable_worker(
        adapter,
        nats_url,
        stream,
        subject,
        "Splunk_Indexer_Group",
        dlq
    ).await;
}