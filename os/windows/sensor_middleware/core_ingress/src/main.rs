use ax_extract::State;
use axum::{
    body::Bytes,
    extract as ax_extract,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use ini::Ini;
use std::sync::Arc;
use tracing::{error, info, Level};

struct AppState {
    js: async_nats::jetstream::Context,
    auth_token: String,
    subject: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_max_level(Level::INFO).with_target(false).init();

    let conf = Ini::load_from_file("config.ini").expect("Failed to read config.ini");
    let global = conf.section(Some("GLOBAL")).expect("GLOBAL section missing");
    let ingress = conf.section(Some("INGRESS")).expect("INGRESS section missing");

    let nats_url = global.get("NatsEndpoint").unwrap_or("127.0.0.1:4222");
    let bind_port = ingress.get("BindPort").unwrap_or("8443");
    let auth_token = ingress.get("AuthToken").expect("AuthToken missing").to_string();
    let stream_name = ingress.get("TelemetryStream").unwrap_or("SensorStream");
    let subject = ingress.get("TelemetrySubject").unwrap_or("sensor.telemetry");

    let nats_client = async_nats::connect(nats_url).await.expect("NATS connection failed");
    let js = async_nats::jetstream::new(nats_client);

    js.get_or_create_stream(async_nats::jetstream::stream::Config {
        name: stream_name.to_string(),
        subjects: vec![subject.to_string()],
        ..Default::default()
    })
    .await
    .expect("Failed to create JetStream");

    let state = Arc::new(AppState {
        js,
        auth_token,
        subject: subject.to_string(),
    });

    let app = Router::new()
        .route("/api/v1/telemetry", post(handle_telemetry))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", bind_port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

    info!("\x1b[38;2;57;255;20m[Ingress Online]\x1b[0m Listening on {} | Routing to JetStream '{}'", addr, stream_name);
    axum::serve(listener, app).await.unwrap();
}

async fn handle_telemetry(
    State(state): State<Arc<AppState>>,
    headers: header::HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let auth_header = headers.get(header::AUTHORIZATION).and_then(|h| h.to_str().ok());

    if auth_header != Some(&format!("Bearer {}", state.auth_token)) {
        warn!("Unauthorized access attempt detected.");
        return StatusCode::UNAUTHORIZED;
    }

    // Publish to JetStream to ensure messages are persisted if workers are down
    match state.js.publish(state.subject.clone(), body).await {
        Ok(_) => StatusCode::ACCEPTED,
        Err(e) => {
            error!("JetStream Publish Fault: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}