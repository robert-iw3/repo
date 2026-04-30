use async_trait::async_trait;
use ini::Ini;
use lib_siem_template::{SiemAdapter, start_durable_worker};
use reqwest::{Client, header};

struct SplunkAdapter {
    endpoint: String,
    hec_token: String,
    batch_size: usize,
}

#[async_trait]
impl SiemAdapter for SplunkAdapter {
    fn initialize(config_path: &str) -> Self {
        let conf = Ini::load_from_file(config_path).expect("Failed to read config.ini");
        let section = conf.section(Some("SPLUNK")).expect("SPLUNK section missing");

        SplunkAdapter {
            endpoint: section.get("HecEndpoint").expect("HecEndpoint missing").to_string(),
            hec_token: section.get("HecToken").expect("HecToken missing").to_string(),
            batch_size: section.get("MaxBatchSize").unwrap_or("500").parse().unwrap_or(500),
        }
    }

    fn batch_size(&self) -> usize {
        self.batch_size
    }

    fn format_event(&self, raw_payload: &[u8]) -> Vec<u8> {
        // Splunk HEC requires data to be nested inside an "event" key.
        // e.g., {"event": {"timestamp":"...", "process":"..."}}
        let mut splunk_event = Vec::with_capacity(raw_payload.len() + 15);
        splunk_event.extend_from_slice(b"{\"event\":");
        splunk_event.extend_from_slice(raw_payload);
        splunk_event.extend_from_slice(b"}");
        splunk_event
    }

    async fn transmit_batch(&self, client: &Client, formatted_batch: Vec<u8>) -> Result<(), String> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            "Authorization",
            header::HeaderValue::from_str(&format!("Splunk {}", self.hec_token)).unwrap(),
        );

        let res = client
            .post(&self.endpoint)
            .headers(headers)
            .body(formatted_batch)
            .send()
            .await
            .map_err(|e| format!("Network transport failed: {}", e))?;

        if res.status().is_success() {
            Ok(())
        } else {
            Err(format!("Splunk HEC returned HTTP {}", res.status()))
        }
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
    start_durable_worker(
        adapter,
        nats_url,
        stream,
        subject,
        "Splunk_Indexer_Group"
    ).await;
}