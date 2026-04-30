use async_trait::async_trait;
use ini::Ini;
use lib_siem_template::{SiemAdapter, start_durable_worker};
use reqwest::{Client, header};
use tracing::{info, Level};

struct ElasticAdapter {
    endpoint: String,
    api_key: String,
    batch_size: usize,
}

#[async_trait]
impl SiemAdapter for ElasticAdapter {
    fn initialize(config_path: &str) -> Self {
        let conf = Ini::load_from_file(config_path).expect("Failed to read config.ini");
        let section = conf.section(Some("ELASTIC")).expect("ELASTIC section missing");

        ElasticAdapter {
            endpoint: section.get("Endpoint").expect("Endpoint missing").to_string(),
            api_key: section.get("ApiKey").expect("ApiKey missing").to_string(),
            batch_size: section.get("MaxBatchSize").unwrap_or("500").parse().unwrap_or(500),
        }
    }

    fn batch_size(&self) -> usize {
        self.batch_size
    }

    fn format_event(&self, raw_payload: &[u8]) -> Vec<u8> {
        // Elastic Bulk API (NDJSON) requires an action line followed by the data
        // {"index": {"_index": "sensor-telemetry"}}
        // {"timestamp": "...", "process": "...", ...}
        let mut bulk_line = Vec::with_capacity(raw_payload.len() + 60);
        bulk_line.extend_from_slice(b"{\"index\":{\"_index\":\"sensor-telemetry\"}}\n");
        bulk_line.extend_from_slice(raw_payload);
        bulk_line
    }

    async fn transmit_batch(&self, client: &Client, formatted_batch: Vec<u8>) -> Result<(), String> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            "Authorization",
            header::HeaderValue::from_str(&format!("ApiKey {}", self.api_key)).unwrap(),
        );

        let res = client
            .post(&self.endpoint)
            .headers(headers)
            .header("Content-Type", "application/x-ndjson")
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
    // Initialize production-grade logging
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
    start_durable_worker(
        adapter,
        nats_url,
        stream,
        subject,
        "Elastic_Indexer_Group"
    ).await;
}