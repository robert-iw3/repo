use async_nats::jetstream::{self, Message};
use async_trait::async_trait;
use futures::StreamExt;
use reqwest::Client;
use std::time::Duration;
use tracing::{error, info, warn};

/// The production contract for any SIEM destination.
#[async_trait]
pub trait SiemAdapter {
    /// Bootstraps the adapter from config.ini
    fn initialize(config_path: &str) -> Self;

    /// Returns the maximum batch size this worker should process at once
    fn batch_size(&self) -> usize;

    /// Formats a raw Data Sensor telemetry JSON byte array into the SIEM's specific format
    fn format_event(&self, raw_payload: &[u8]) -> Vec<u8>;

    /// Executes the bulk HTTP push to the SIEM. Must return Ok(()) ONLY if successful.
    async fn transmit_batch(&self, client: &Client, formatted_batch: Vec<u8>) -> Result<(), String>;
}

/// The core, fault-tolerant JetStream consumer loop.
pub async fn start_durable_worker<T: SiemAdapter>(
    adapter: T,
    nats_url: &str,
    stream_name: &str,
    subject: &str,
    consumer_name: &str
) {
    let client = async_nats::connect(nats_url).await.expect("Failed to connect to NATS");
    let js = jetstream::new(client);

    let stream = js.get_stream(stream_name).await.expect("Failed to bind to JetStream");

    // Ensure the consumer exists. It tracks the offset for this specific SIEM.
    let consumer = stream.get_or_create_consumer(
        consumer_name,
        jetstream::consumer::pull::Config {
            durable_name: Some(consumer_name.to_string()),
            filter_subject: subject.to_string(),
            ack_wait: Duration::from_secs(30), // Time before NATS re-delivers un-acked messages
            ..Default::default()
        },
    ).await.expect("Failed to bind durable consumer");

    let http_client = Client::builder()
        .timeout(Duration::from_secs(15))
        .pool_max_idle_per_host(100)
        .build()
        .unwrap();

    info!("\x1b[38;2;57;255;20m[Worker Online]\x1b[0m Durable queue '{}' tracking stream '{}'", consumer_name, stream_name);

    let mut message_stream = consumer.messages().await.unwrap();
    let batch_limit = adapter.batch_size();

    loop {
        let mut current_batch = Vec::new();
        let mut raw_messages = Vec::new();

        // Pull micro-batches efficiently
        while let Some(Ok(msg)) = tokio::time::timeout(Duration::from_millis(500), message_stream.next()).await {
            current_batch.extend(adapter.format_event(&msg.payload));
            current_batch.push(b'\n'); // NDJSON separation
            raw_messages.push(msg);

            if raw_messages.len() >= batch_limit {
                break;
            }
        }

        if raw_messages.is_empty() {
            continue; // Queue is empty, idle wait
        }

        match adapter.transmit_batch(&http_client, current_batch).await {
            Ok(_) => {
                // Cryptographic/Network success. Acknowledge all messages in the batch to NATS.
                for msg in raw_messages {
                    let _ = msg.ack().await;
                }
                info!("\x1b[38;2;255;215;0m[Transmission]\x1b[0m Successfully flushed {} events to SIEM.", batch_limit);
            }
            Err(e) => {
                error!("\x1b[38;2;255;49;49m[Delivery Fault]\x1b[0m SIEM rejected batch: {}. Messages retained in NATS.", e);
                // We DO NOT ack the messages. JetStream will automatically redeliver them.
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}