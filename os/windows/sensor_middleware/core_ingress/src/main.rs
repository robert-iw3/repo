// Core Ingress Service for Sensor Middleware
// Listens for incoming telemetry from sensors, validates auth, and publishes
// each event individually to JetStream so workers receive atomic, typed messages.
// core_ingress/src/main.rs
//
// TLS: Controlled by the [INGRESS] config keys TlsEnabled / TlsCertPath /
// TlsKeyPath.  When TlsEnabled=True the ingress terminates HTTPS via rustls;
// when False (default) it binds plain HTTP for testing and development.

use axum::{
    body::Bytes,
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use ini::Ini;
use std::sync::Arc;
use tracing::{error, info, warn, Level};

struct AppState {
    js: async_nats::jetstream::Context,
    auth_token: String,
    subject: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .init();

    let conf    = Ini::load_from_file("config.ini").expect("Failed to read config.ini");
    let global  = conf.section(Some("GLOBAL")).expect("GLOBAL section missing");
    let ingress = conf.section(Some("INGRESS")).expect("INGRESS section missing");

    let nats_url    = global.get("NatsEndpoint").unwrap_or("127.0.0.1:4222");
    let bind_port   = ingress.get("BindPort").unwrap_or("8080");
    let auth_token  = ingress.get("AuthToken").expect("AuthToken missing").to_string();
    let stream_name = ingress.get("TelemetryStream").unwrap_or("SensorStream");
    let subject     = ingress.get("TelemetrySubject").unwrap_or("sensor.telemetry");

    // ── TLS configuration ─────────────────────────────────────────────────────
    let tls_enabled = ingress
        .get("TlsEnabled")
        .unwrap_or("False")
        .eq_ignore_ascii_case("true");

    // ── NATS / JetStream ──────────────────────────────────────────────────────
    let nats_client = async_nats::connect(nats_url)
        .await
        .expect("NATS connection failed");
    let js = async_nats::jetstream::new(nats_client);

    js.get_or_create_stream(async_nats::jetstream::stream::Config {
        name: stream_name.to_string(),
        subjects: vec![subject.to_string()],
        ..Default::default()
    })
    .await
    .expect("Failed to create JetStream stream");

    let state = Arc::new(AppState {
        js,
        auth_token,
        subject: subject.to_string(),
    });

    let app = Router::new()
        .route("/api/v1/telemetry", post(handle_telemetry))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", bind_port);

    // ── Bind with or without TLS ──────────────────────────────────────────────
    if tls_enabled {
        let cert_path = ingress
            .get("TlsCertPath")
            .expect("TlsCertPath required when TlsEnabled=True");
        let key_path = ingress
            .get("TlsKeyPath")
            .expect("TlsKeyPath required when TlsEnabled=True");

        let rustls_config = RustlsConfig::from_pem_file(cert_path, key_path)
            .await
            .expect("Failed to load TLS certificate/key PEM files");

        info!(
            "\x1b[38;2;57;255;20m[Ingress Online]\x1b[0m \
             HTTPS on {} | JetStream '{}' | TLS: ON",
            addr, stream_name
        );

        axum_server::bind_rustls(
            addr.parse().expect("Invalid bind address"),
            rustls_config,
        )
        .serve(app.into_make_service())
        .await
        .unwrap();
    } else {
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .unwrap_or_else(|e| panic!("Failed to bind {}: {}", addr, e));

        info!(
            "\x1b[38;2;57;255;20m[Ingress Online]\x1b[0m \
             HTTP on {} | JetStream '{}' | TLS: OFF",
            addr, stream_name
        );

        axum::serve(listener, app).await.unwrap();
    }
}

async fn handle_telemetry(
    State(state): State<Arc<AppState>>,
    headers: header::HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // ── Authentication ────────────────────────────────────────────────────────
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    if auth_header != Some(&format!("Bearer {}", state.auth_token)) {
        warn!("Unauthorized access attempt.");
        return StatusCode::UNAUTHORIZED;
    }

    // ── Parse body as a JSON array of events ─────────────────────────────────
    let events: Vec<serde_json::Value> = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            warn!("Malformed JSON body from sensor: {}", e);
            return StatusCode::BAD_REQUEST;
        }
    };

    let sensor_type = headers
        .get("X-Sensor-Type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let mut published = 0usize;
    let mut failed    = 0usize;

    for mut event in events {
        if let Some(obj) = event.as_object_mut() {
            obj.insert(
                "sensor_type".to_string(),
                serde_json::Value::String(sensor_type.clone()),
            );
        }

        let msg_bytes = match serde_json::to_vec(&event) {
            Ok(b) => b,
            Err(e) => {
                error!("Failed to re-serialize event: {}", e);
                failed += 1;
                continue;
            }
        };

        match state.js.publish(state.subject.clone(), msg_bytes.into()).await {
            Ok(_)  => published += 1,
            Err(e) => {
                error!("JetStream publish fault: {}", e);
                failed += 1;
            }
        }
    }

    if failed > 0 && published == 0 {
        error!("All {} events failed to publish.", failed);
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        if failed > 0 {
            warn!("Partial publish: {} ok, {} failed.", published, failed);
        }
        info!(
            "Accepted {} event(s) from sensor_type='{}'",
            published, sensor_type
        );
        StatusCode::ACCEPTED
    }
}