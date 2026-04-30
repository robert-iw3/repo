use async_trait::async_trait;
use ini::Ini;
use lib_siem_template::{SiemAdapter, start_durable_worker};
use tiberius::{AuthMethod, Client, Config, EncryptionLevel};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_util::compat::TokioAsyncWriteCompatExt;
use tracing::{error, info, Level};

struct SqlAdapter {
    config: Config,
    sproc_name: String,
    batch_size: usize,
    conn: Mutex<Option<tiberius::Client<tokio_util::compat::Compat<TcpStream>>>>,
}

#[async_trait]
impl SiemAdapter for SqlAdapter {
    fn initialize(config_path: &str) -> Self {
        let conf = Ini::load_from_file(config_path).expect("Failed to read config.ini");
        let section = conf.section(Some("SQL")).expect("SQL section missing");

        let mut db_config = Config::new();
        db_config.host(section.get("DbHost").unwrap_or("127.0.0.1"));
        db_config.port(section.get("DbPort").unwrap_or("1433").parse().unwrap_or(1433));
        db_config.database(section.get("DbName").unwrap_or("DataSensor"));

        // --- SECURITY ENFORCEMENT ---
        match section.get("Encryption").unwrap_or("Required").to_lowercase().as_str() {
            "required" => db_config.encryption(EncryptionLevel::Required),
            "off" => db_config.encryption(EncryptionLevel::NotSupported),
            _ => db_config.encryption(EncryptionLevel::Required),
        };

        if section.get("TrustServerCert").unwrap_or("False").eq_ignore_ascii_case("true") {
            db_config.trust_cert();
        }

        if section.get("UseSspi").unwrap_or("False").eq_ignore_ascii_case("true") {
            // Natively utilizes Windows Integrated Auth via the OS LSA
            db_config.authentication(AuthMethod::Integrated);
        } else {
            let user = section.get("DbUser").unwrap_or("");
            let pass = section.get("DbPass").unwrap_or("");
            db_config.authentication(AuthMethod::sql_server(user, pass));
        }

        SqlAdapter {
            config: db_config,
            sproc_name: section.get("SprocName").unwrap_or("EXEC sp_Ingest @json = @p1").to_string(),
            batch_size: section.get("MaxBatchSize").unwrap_or("2000").parse().unwrap_or(2000),
        }
    }

    fn batch_size(&self) -> usize {
        self.batch_size
    }

    fn format_event(&self, raw_payload: &[u8]) -> Vec<u8> {
        raw_payload.to_vec()
    }

    async fn transmit_batch(&self, formatted_batch: Vec<u8>) -> Result<(), String> {
        let mut json_array = String::with_capacity(formatted_batch.len() + 2);
        json_array.push('[');
        json_array.push_str(&String::from_utf8_lossy(&formatted_batch));
        json_array.push(']');

        let mut guard = self.conn.lock().await;

        // Reuse existing connection or establish a new one
        if guard.is_none() {
            let tcp = TcpStream::connect(self.config.get_addr()).await.map_err(|e| e.to_string())?;
            tcp.set_nodelay(true).unwrap();
            let client = tiberius::Client::connect(self.config.clone(), tcp.compat_write())
                .await.map_err(|e| e.to_string())?;
            *guard = Some(client);
        }

        let client = guard.as_mut().unwrap();
        match client.execute(self.sproc_name.as_str(), &[&json_array.as_str()]).await {
            Ok(_) => Ok(()),
            Err(e) => {
                *guard = None; // Drop broken connection so next call reconnects
                Err(format!("SQL Execution Fault: {}", e))
            }
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_max_level(Level::INFO).with_target(false).init();

    let conf = Ini::load_from_file("config.ini").unwrap();
    let global = conf.section(Some("GLOBAL")).unwrap();
    let nats_url = global.get("NatsEndpoint").unwrap_or("127.0.0.1:4222");
    let stream = global.get("TelemetryStream").unwrap_or("SensorStream");
    let subject = global.get("TelemetrySubject").unwrap_or("sensor.telemetry");
    let dlq = global.get("DlqSubjectPrefix").unwrap_or("sensor.dlq");

    let adapter = SqlAdapter::initialize("config.ini");

    start_durable_worker(adapter, nats_url, stream, subject, "SQL_Ledger_Group", dlq).await;
}