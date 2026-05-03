use crate::config::MasterConfig;
use anyhow::Result;
use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::get,
    Json, Router,
};
use serde::Serialize;
use sqlx::{Pool, Sqlite};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

struct AppState {
    db_pool: Pool<Sqlite>,
    config: Arc<MasterConfig>,
}

#[derive(Serialize)]
struct StatusResponse {
    status: String,
    version: String,
    engine_mode: String,
    active_modules: Vec<String>,
}

pub struct ApiServer {
    config: Arc<MasterConfig>,
    db_pool: Pool<Sqlite>,
}

impl ApiServer {
    pub fn new(config: Arc<MasterConfig>, db_pool: Pool<Sqlite>) -> Self {
        Self { config, db_pool }
    }

    pub async fn run(self, port: u16) -> Result<()> {
        let shared_state = Arc::new(AppState {
            db_pool: self.db_pool,
            config: self.config.clone(),
        });

        // Apply strict authentication middleware to all routes
        let app = Router::new()
            .route("/api/status", get(status_handler))
            .route("/api/alerts", get(alerts_handler))
            .layer(middleware::from_fn_with_state(shared_state.clone(), auth_middleware))
            .with_state(shared_state);

        let addr = format!("0.0.0.0:{}", port);
        info!("Secure Dashboard API online: http://{}", addr);

        let listener = TcpListener::bind(&addr).await?;
        if let Err(e) = axum::serve(listener, app).await {
            error!("API Server fatal error: {}", e);
        }

        Ok(())
    }
}

/// Constant-time comparison to prevent timing attacks on API authentication.
/// This ensures the comparison time is independent of how many leading bytes match.
fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut res = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        res |= x ^ y;
    }
    res == 0
}

// The Auth Middleware using this secure comparison
async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req.headers().get("Authorization");
    let expected_token = format!("Bearer {}", state.config.siem.auth_token);

    if let Some(header_value) = auth_header {
        let provided_token = header_value.as_bytes();
        // Use secure_compare to validate the Bearer token
        if secure_compare(provided_token, expected_token.as_bytes()) {
            return Ok(next.run(req).await);
        }
    }

    warn!("Unauthorized API access attempt blocked.");
    Err(StatusCode::UNAUTHORIZED)
}

async fn status_handler(axum::extract::State(state): axum::extract::State<Arc<AppState>>) -> Json<StatusResponse> {
    let mut active = Vec::new();
    if state.config.engine.enable_ebpf { active.push("eBPF_Telemetry".to_string()); }
    if state.config.engine.enable_yara { active.push("YARA_Scanner".to_string()); }
    if state.config.engine.enable_anti_evasion { active.push("UEBA_AntiEvasion".to_string()); }
    if state.config.engine.enable_honeypots { active.push("Deception_Nodes".to_string()); }

    Json(StatusResponse {
        status: "Operational".to_string(),
        version: "2.6.0".to_string(),
        engine_mode: if state.config.engine.performance_mode { "High-Throughput".to_string() } else { "Deep-Inspection".to_string() },
        active_modules: active,
    })
}

// GET /api/alerts - Pulls the latest eBPF telemetry directly from SQLite
async fn alerts_handler(axum::extract::State(state): axum::extract::State<Arc<AppState>>) -> Json<serde_json::Value> {
    use sqlx::Row;

    let result = sqlx::query("SELECT event_id as id, timestamp, level, message, mitre_technique FROM events ORDER BY timestamp DESC LIMIT 100")
        .fetch_all(&state.db_pool)
        .await;

    match result {
        Ok(records) => {
            let alerts: Vec<_> = records.into_iter().map(|rec| {
                serde_json::json!({
                    "id": rec.try_get::<String, _>("id").unwrap_or_default(),
                    "timestamp": rec.try_get::<i64, _>("timestamp").unwrap_or_default(),
                    "level": rec.try_get::<String, _>("level").unwrap_or_default(),
                    "message": rec.try_get::<String, _>("message").unwrap_or_default(),
                    "technique": rec.try_get::<String, _>("mitre_technique").unwrap_or_default()
                })
            }).collect();

            Json(serde_json::json!({ "success": true, "count": alerts.len(), "data": alerts }))
        }
        Err(e) => {
            error!("API Database query failed: {}", e);
            Json(serde_json::json!({ "success": false, "error": "Internal Database Error" }))
        }
    }
}