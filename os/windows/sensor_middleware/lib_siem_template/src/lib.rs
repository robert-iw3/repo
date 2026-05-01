// SIEM Adapter Template for Sensor Middleware
// Provides a reusable framework for building durable workers that consume telemetry
// from JetStream and forward it to various SIEM platforms.
// lib_siem_template/src/lib.rs

use async_nats::jetstream;
use async_trait::async_trait;
use futures::StreamExt;
use std::time::Duration;
use tracing::{error, info, warn};

/// Core trait every SIEM worker must implement.
///
/// `initialize`    — reads config.ini and constructs the adapter.
/// `format_event`  — converts a single raw JSON payload (one event, with
///                   `sensor_type` embedded by the ingress) into the
///                   target-specific wire format.  Return an empty Vec to
///                   silently discard a malformed message.
/// `transmit_batch`— sends the accumulated, formatted batch to the destination.
#[async_trait]
pub trait SiemAdapter: Send + Sync {
    fn initialize(config_path: &str) -> Self
    where
        Self: Sized;

    fn batch_size(&self) -> usize;

    /// Byte inserted *between* events when assembling a batch.
    ///
    /// `Some(b'\n')` — Splunk HEC multi-event format (newline-delimited).
    /// `Some(b',')`  — SQL worker: comma-separated, later wrapped in `[…]`.
    /// `None`         — Elastic Bulk API: each `format_event` already appends
    ///                  `\n`, so no extra separator needed.
    ///
    /// Default is `Some(b',')`.
    fn batch_separator(&self) -> Option<u8> {
        Some(b',')
    }

    fn format_event(&self, raw_payload: &[u8]) -> Vec<u8>;

    async fn transmit_batch(&self, formatted_batch: Vec<u8>) -> Result<(), String>;
}

pub async fn start_durable_worker<T: SiemAdapter>(
    adapter: T,
    nats_url: &str,
    stream_name: &str,
    subject: &str,
    consumer_name: &str,
    dlq_prefix: &str,
) {
    let client = async_nats::connect(nats_url)
        .await
        .expect("Failed to connect to NATS");
    let js = jetstream::new(client.clone());

    // Workers and the ingress may start in any order.  If a worker calls
    // get_stream() before the ingress has created the stream, the worker
    // panics.  get_or_create_stream is idempotent — calling it from
    // multiple processes with the same config is safe and produces exactly
    // one stream.
    let stream = js
        .get_or_create_stream(jetstream::stream::Config {
            name: stream_name.to_string(),
            subjects: vec![subject.to_string()],
            ..Default::default()
        })
        .await
        .expect("Failed to bind to JetStream stream");

    // Ensure a DLQ stream exists so dead-lettered messages are persisted.
    // Without this, js.publish() to a DLQ subject that no stream captures
    // returns "no responders" — and the `let _ =` silently drops the error,
    // losing the dead-letter payload forever.
    let dlq_subject_wildcard = format!("{}.>", dlq_prefix);
    let dlq_stream_name = format!("{}_DLQ", stream_name);
    let _ = js
        .get_or_create_stream(jetstream::stream::Config {
            name: dlq_stream_name.clone(),
            subjects: vec![dlq_subject_wildcard],
            ..Default::default()
        })
        .await;
    // Non-fatal if DLQ stream creation fails (log and continue).
    // The primary pipeline should not be blocked by DLQ infra issues.

    let consumer = stream
        .get_or_create_consumer(
            consumer_name,
            jetstream::consumer::pull::Config {
                durable_name: Some(consumer_name.to_string()),
                filter_subject: subject.to_string(),
                // The exponential backoff retry loop can take up to
                // 2+4+8+16+32 = 62 seconds.  With ack_wait at 45s, NATS
                // would redeliver messages mid-retry, causing duplicates.
                // 90s covers the full retry window plus margin.
                ack_wait: Duration::from_secs(90),
                max_deliver: 5,
                ..Default::default()
            },
        )
        .await
        .expect("Failed to bind durable consumer");

    info!(
        "\x1b[38;2;57;255;20m[Worker Online]\x1b[0m Consumer '{}' tracking stream '{}'",
        consumer_name, stream_name
    );

    let mut message_stream = consumer.messages().await.unwrap();
    let batch_limit = adapter.batch_size();
    let dlq_subject = format!("{}.{}", dlq_prefix, consumer_name);

    loop {
        let mut current_batch: Vec<u8> = Vec::new();
        let mut raw_messages = Vec::new();

        // Drain up to `batch_limit` messages within a 500 ms window.
        while let Ok(Some(Ok(msg))) =
            tokio::time::timeout(Duration::from_millis(500), message_stream.next()).await
        {
            let formatted = adapter.format_event(&msg.payload);

            if formatted.is_empty() {
                // Malformed / unrecognised payload — ack immediately so it does
                // not block the pipeline; the warning is logged inside format_event.
                warn!("[Discard] format_event returned empty; acking malformed message.");
                let _ = msg.ack().await;
                continue;
            }

            if !current_batch.is_empty() {
                if let Some(sep) = adapter.batch_separator() {
                    current_batch.push(sep);
                }
            }
            current_batch.extend(formatted);
            raw_messages.push(msg);

            if raw_messages.len() >= batch_limit {
                break;
            }
        }

        if raw_messages.is_empty() {
            continue;
        }

        // Exponential back-off retry loop.
        let mut success = false;
        let max_attempts: u32 = 5;

        for attempt in 1..=max_attempts {
            match adapter.transmit_batch(current_batch.clone()).await {
                Ok(_) => {
                    success = true;
                    for msg in raw_messages.iter() {
                        let _ = msg.ack().await;
                    }
                    info!(
                        "\x1b[38;2;255;215;0m[Transmission]\x1b[0m Flushed {} events.",
                        raw_messages.len()
                    );
                    break;
                }
                Err(e) => {
                    warn!(
                        "\x1b[38;2;255;103;0m[Delivery Fault]\x1b[0m Attempt {}/{}: {}",
                        attempt, max_attempts, e
                    );
                    if attempt < max_attempts {
                        tokio::time::sleep(Duration::from_secs(2_u64.pow(attempt))).await;
                    }
                }
            }
        }

        // ── DLQ ROUTING ──────────────────────────────────────────────────────
        if !success {
            error!(
                "\x1b[38;2;255;49;49m[DLQ Triggered]\x1b[0m Batch failed {} times. \
                 Routing dead payload to '{}'",
                max_attempts, dlq_subject
            );
            let _ = js
                .publish(dlq_subject.clone(), current_batch.into())
                .await;
            for msg in raw_messages.iter() {
                let _ = msg.ack().await;
            }
        }
    }
}