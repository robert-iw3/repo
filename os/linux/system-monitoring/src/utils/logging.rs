use tracing_subscriber::{fmt, EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
use tracing_appender::non_blocking::WorkerGuard;
use std::fs;

pub fn init_central_logging(log_dir: &str) -> WorkerGuard {
    fs::create_dir_all(log_dir).expect("Failed to create central log directory");

    // Rolling file appender (daily)
    let file_appender = tracing_appender::rolling::daily(log_dir, "sentinel-diagnostics.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let format_layer = fmt::layer()
        .with_target(true)
        .with_thread_ids(true)
        .with_writer(non_blocking)
        .json(); // Structured JSON logging for SIEM ingestion

    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .with(format_layer)
        .with(fmt::layer().with_writer(std::io::stdout)) // Mirror to stdout for container logs
        .init();

    guard // Must be kept alive in main.rs
}