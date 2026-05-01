// SQL Worker for Sensor Middleware
// Consumes telemetry from JetStream, wraps events in a JSON array, and
// executes a stored procedure on SQL Server for bulk ingestion.
// worker_sql/src/main.rs
//
// FEATURE: `TestWebhookUrl` config key.  When set, the worker POSTs the JSON
// array to an HTTP endpoint instead of speaking TDS to a SQL Server.  This
// allows the QA harness to capture SQL worker output via a lightweight mock
// listener without requiring a live database.  Leave the key empty (or omit
// it) in production to use the real SQL path.

use async_trait::async_trait;
use ini::Ini;
use lib_siem_template::{SiemAdapter, start_durable_worker};
use tiberius::{AuthMethod, Config, EncryptionLevel};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_util::compat::TokioAsyncWriteCompatExt;
use tracing::{info, warn, Level};

// ── Backend discriminant ──────────────────────────────────────────────────────

enum SqlBackend {
    /// Live TDS connection to SQL Server (production path).
    Live {
        config:      Config,
        sproc_name:  String,
        conn:        Mutex<Option<tiberius::Client<tokio_util::compat::Compat<TcpStream>>>>,
    },
    /// Test/mock path: POST JSON to an HTTP webhook instead of running a sproc.
    TestWebhook {
        client: reqwest::Client,
        url:    String,
    },
}

struct SqlAdapter {
    backend:    SqlBackend,
    batch_size: usize,
}

#[async_trait]
impl SiemAdapter for SqlAdapter {
    fn initialize(config_path: &str) -> Self {
        let conf    = Ini::load_from_file(config_path).expect("Failed to read config.ini");
        let section = conf.section(Some("SQL")).expect("SQL section missing");

        let batch_size = section
            .get("MaxBatchSize")
            .unwrap_or("2000")
            .parse()
            .unwrap_or(2000);

        // ── Test webhook shortcut ─────────────────────────────────────────────
        if let Some(url) = section.get("TestWebhookUrl") {
            if !url.trim().is_empty() {
                info!("[SqlAdapter] TEST MODE: routing batches to webhook '{}'", url);
                return SqlAdapter {
                    backend: SqlBackend::TestWebhook {
                        client: reqwest::Client::builder()
                            .danger_accept_invalid_certs(true)
                            .timeout(std::time::Duration::from_secs(10))
                            .build()
                            .expect("Failed to build HTTP client"),
                        url: url.to_string(),
                    },
                    batch_size,
                };
            }
        }

        // ── Live TDS path ─────────────────────────────────────────────────────
        let mut db_config = Config::new();
        db_config.host(section.get("DbHost").unwrap_or("127.0.0.1"));
        db_config.port(
            section
                .get("DbPort")
                .unwrap_or("1433")
                .parse()
                .unwrap_or(1433),
        );
        db_config.database(section.get("DbName").unwrap_or("DataSensor"));

        match section
            .get("Encryption")
            .unwrap_or("Required")
            .to_lowercase()
            .as_str()
        {
            "off" => db_config.encryption(EncryptionLevel::NotSupported),
            _     => db_config.encryption(EncryptionLevel::Required),
        }

        if section
            .get("TrustServerCert")
            .unwrap_or("False")
            .eq_ignore_ascii_case("true")
        {
            db_config.trust_cert();
        }

        if section
            .get("UseSspi")
            .unwrap_or("False")
            .eq_ignore_ascii_case("true")
        {
            db_config.authentication(AuthMethod::Integrated);
        } else {
            let user = section.get("DbUser").unwrap_or("");
            let pass = section.get("DbPass").unwrap_or("");
            db_config.authentication(AuthMethod::sql_server(user, pass));
        }

        let sproc_name = section
            .get("SprocName")
            .unwrap_or("EXEC dbo.sp_IngestSensorTelemetry @json = @p1")
            .to_string();

        SqlAdapter {
            backend: SqlBackend::Live {
                config:     db_config,
                sproc_name,
                conn:       Mutex::new(None),
            },
            batch_size,
        }
    }

    fn batch_size(&self) -> usize {
        self.batch_size
    }

    /// SQL worker accepts comma-separated events from lib; wraps them in `[…]`
    /// before calling the stored procedure.
    fn batch_separator(&self) -> Option<u8> {
        Some(b',')
    }

    fn format_event(&self, raw_payload: &[u8]) -> Vec<u8> {
        // Validate the payload is well-formed JSON before accepting it into a batch.
        // Corrupt data must not silently break the JSON array wrap in transmit_batch.
        match serde_json::from_slice::<serde_json::Value>(raw_payload) {
            Ok(_) => raw_payload.to_vec(),
            Err(e) => {
                warn!("SQL: dropping malformed event payload: {}", e);
                Vec::new()
            }
        }
    }

    async fn transmit_batch(&self, formatted_batch: Vec<u8>) -> Result<(), String> {
        let json_array = format!("[{}]", String::from_utf8_lossy(&formatted_batch));

        match &self.backend {
            // ── HTTP mock / webhook path (test mode) ──────────────────────────
            SqlBackend::TestWebhook { client, url } => {
                let res = client
                    .post(url)
                    .header("Content-Type", "application/json")
                    .body(json_array)
                    .send()
                    .await
                    .map_err(|e| format!("Webhook transport failed: {}", e))?;

                if res.status().is_success() {
                    Ok(())
                } else {
                    Err(format!("SQL webhook returned HTTP {}", res.status()))
                }
            }

            // ── Live TDS path ─────────────────────────────────────────────────
            SqlBackend::Live { config, sproc_name, conn } => {
                let mut guard = conn.lock().await;

                if guard.is_none() {
                    let tcp = TcpStream::connect(config.get_addr())
                        .await
                        .map_err(|e| e.to_string())?;
                    tcp.set_nodelay(true).unwrap();
                    let client =
                        tiberius::Client::connect(config.clone(), tcp.compat_write())
                            .await
                            .map_err(|e| e.to_string())?;
                    *guard = Some(client);
                }

                let client = guard.as_mut().unwrap();
                match client
                    .execute(sproc_name.as_str(), &[&json_array.as_str()])
                    .await
                {
                    Ok(_) => Ok(()),
                    Err(e) => {
                        // Drop the broken connection; next call will reconnect.
                        *guard = None;
                        Err(format!("SQL execution fault: {}", e))
                    }
                }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .init();

    let conf    = Ini::load_from_file("config.ini").unwrap();
    let global  = conf.section(Some("GLOBAL")).unwrap();
    let nats_url = global.get("NatsEndpoint").unwrap_or("127.0.0.1:4222");
    let stream   = global.get("TelemetryStream").unwrap_or("SensorStream");
    let subject  = global.get("TelemetrySubject").unwrap_or("sensor.telemetry");
    let dlq      = global.get("DlqSubjectPrefix").unwrap_or("sensor.dlq");

    let adapter = SqlAdapter::initialize("config.ini");
    start_durable_worker(adapter, nats_url, stream, subject, "SQL_Ledger_Group", dlq).await;
}