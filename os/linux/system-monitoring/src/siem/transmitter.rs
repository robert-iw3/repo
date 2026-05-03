use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};
use reqwest::Client;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info};
use crate::siem::models::SecurityAlert;

// Retain strict project requirements for threat intel reporting
const BPF_OUTPUT_DIR: &str = "/var/log/linux-sentinel/Behavior/Categories";

pub struct TransmissionLayer {
    db_pool: Pool<Sqlite>,
    client: Client,
    gateway_url: String,
}

impl TransmissionLayer {
    pub async fn new(db_path: &str, gateway_url: &str) -> anyhow::Result<Self> {
        let db_pool = SqlitePoolOptions::new()
            .max_connections(5)
            .idle_timeout(std::time::Duration::from_secs(60))
            .after_connect(|conn, _meta| Box::pin(async move {
                use sqlx::Executor;
                conn.execute("PRAGMA journal_mode=WAL;").await?;
                conn.execute("PRAGMA synchronous=NORMAL;").await?;
                conn.execute("PRAGMA busy_timeout=5000;").await?;
                Ok(())
            }))
            .connect(&format!("sqlite:{}?mode=rwc", db_path))
            .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                level TEXT NOT NULL,
                mitre_tactic TEXT NOT NULL,
                mitre_technique TEXT NOT NULL,
                pid INTEGER,
                ppid INTEGER,
                uid INTEGER,
                comm TEXT,
                command_line TEXT,
                target_file TEXT,
                dest_ip TEXT,
                dest_port INTEGER,
                shannon_entropy REAL,
                execution_velocity REAL,
                tuple_rarity REAL,
                path_depth INTEGER,
                anomaly_score REAL,
                message TEXT NOT NULL,
                synced BOOLEAN DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_comm ON events(comm);
            CREATE INDEX IF NOT EXISTS idx_dest_ip ON events(dest_ip);
            "#
        ).execute(&db_pool).await?;

        std::fs::create_dir_all(BPF_OUTPUT_DIR)?;

        Ok(Self { db_pool, client: Client::new(), gateway_url: gateway_url.to_string() })
    }

    pub fn get_pool(&self) -> Pool<Sqlite> {
        self.db_pool.clone()
    }

    pub fn spawn_worker(self: Arc<Self>, mut rx: mpsc::Receiver<SecurityAlert>) {
        tokio::spawn(async move {
            while let Some(alert) = rx.recv().await {
                let output_path = PathBuf::from(BPF_OUTPUT_DIR).join(format!("{}.json", alert.event_id));
                if let Ok(json) = serde_json::to_string(&alert) {
                    if let Err(e) = tokio::fs::write(&output_path, json).await {
                        error!("Failed to write JSON artifact to {}: {}", output_path.display(), e);
                    }
                }

                let res = sqlx::query(
                    r#"
                    INSERT INTO events (
                        event_id,
                        timestamp,
                        level,
                        mitre_tactic,
                        mitre_technique,
                        pid,
                        ppid,
                        uid,
                        comm,
                        command_line,
                        target_file,
                        dest_ip,
                        dest_port,
                        shannon_entropy,
                        execution_velocity,
                        tuple_rarity,
                        path_depth,
                        anomaly_score,
                        message
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#
                )
                .bind(&alert.event_id).bind(alert.timestamp).bind(&alert.level.to_string())
                .bind(&alert.mitre_tactic.to_string()).bind(&alert.mitre_technique)
                .bind(alert.pid).bind(alert.ppid).bind(alert.uid).bind(&alert.comm)
                .bind(&alert.command_line).bind(&alert.target_file).bind(&alert.dest_ip).bind(alert.dest_port)
                .bind(alert.shannon_entropy).bind(alert.execution_velocity).bind(alert.tuple_rarity)
                .bind(alert.path_depth as i64).bind(alert.anomaly_score).bind(&alert.message)
                .execute(&self.db_pool).await;

                if let Err(e) = res { error!("SIEM DB write failed: {}", e); }
            }
        });
    }
}