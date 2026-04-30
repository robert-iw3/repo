use async_nats::jetstream::{self, Message};
use async_trait::async_trait;
use futures::StreamExt;
use std::time::Duration;
use tracing::{error, info, warn};

#[async_trait]
pub trait SiemAdapter {
    fn initialize(config_path: &str) -> Self;
    fn batch_size(&self) -> usize;
    fn format_event(&self, raw_payload: &[u8]) -> Vec<u8>;
    async fn transmit_batch(&self, client: &Client, formatted_batch: Vec<u8>) -> Result<(), String>;
}

pub async fn start_durable_worker<T: SiemAdapter>(
    adapter: T,
    nats_url: &str,
    stream_name: &str,
    subject: &str,
    consumer_name: &str,
    dlq_prefix: &str
) {
    let client = async_nats::connect(nats_url).await.expect("Failed to connect to NATS");
    let js = jetstream::new(client.clone());

    let stream = js.get_stream(stream_name).await.expect("Failed to bind to JetStream");
    let consumer = stream.get_or_create_consumer(
        consumer_name,
        jetstream::consumer::pull::Config {
            durable_name: Some(consumer_name.to_string()),
            filter_subject: subject.to_string(),
            ack_wait: Duration::from_secs(45),
            max_deliver: 5, // Failsafe delivery mechanism
            ..Default::default()
        },
    ).await.expect("Failed to bind durable consumer");

    info!("\x1b[38;2;57;255;20m[Worker Online]\x1b[0m Durable queue '{}' tracking stream '{}'", consumer_name, stream_name);

    let mut message_stream = consumer.messages().await.unwrap();
    let batch_limit = adapter.batch_size();
    fn batch_separator(&self) -> Option<u8> {
        Some(b',')
    }
    let dlq_subject = format!("{}.{}", dlq_prefix, consumer_name);

    loop {
        let mut current_batch = Vec::new();
        let mut raw_messages = Vec::new();

        while let Some(Ok(msg)) = tokio::time::timeout(Duration::from_millis(500), message_stream.next()).await {
            // Join items with a comma so the SQL/Splunk workers can easily wrap them in a JSON array or NDJSON
            if !current_batch.is_empty() {
                if let Some(sep) = adapter.batch_separator() {
                    current_batch.push(sep);
                }
            }
            current_batch.extend(adapter.format_event(&msg.payload));
            raw_messages.push(msg);

            if raw_messages.len() >= batch_limit { break; }
        }

        if raw_messages.is_empty() { continue; }

        let mut success = false;
        let mut attempt = 1;
        let max_attempts = 5;

        // Exponential Backoff Retry Loop
        while attempt <= max_attempts {
            match adapter.transmit_batch(current_batch.clone()).await {
                Ok(_) => {
                    success = true;
                    for msg in raw_messages.iter() { let _ = msg.ack().await; }
                    info!("\x1b[38;2;255;215;0m[Transmission]\x1b[0m Flushed {} events.", raw_messages.len());
                    break;
                }
                Err(e) => {
                    warn!("\x1b[38;2;255;103;0m[Delivery Fault]\x1b[0m Attempt {}/{} failed: {}", attempt, max_attempts, e);
                    let delay = Duration::from_secs(2_u64.pow(attempt));
                    attempt += 1;
                    if attempt <= max_attempts {
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        // --- DLQ ROUTING ---
        if !success {
            error!("\x1b[38;2;255;49;49m[DLQ Triggered]\x1b[0m Batch failed {} times. Routing to Dead Letter Queue: {}", max_attempts, dlq_subject);

            // Push the failed payload to the DLQ topic so an admin can replay or analyze it later
            let _ = js.publish(dlq_subject.clone(), current_batch.into()).await;

            // Acknowledge the original messages so they don't block the primary pipeline forever
            for msg in raw_messages.iter() { let _ = msg.ack().await; }
        }
    }
}