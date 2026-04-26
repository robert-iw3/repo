/*=============================================================================================
 * SYSTEM:          Data Sensor - Observation & DLP
 * COMPONENT:       lib.rs (High-Performance FFI Engine)
 * DESCRIPTION:
 * Natively compiles as a C-compatible Dynamic Link Library (cdylib).
 * Implements micro-batched transactional logging and memory-mapped SQLite
 * PRAGMAs to handle massive ETW telemetry firehoses without I/O blocking.
 * @RW
 *============================================================================================*/

use rusqlite::{Connection, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io::Read;
use std::os::raw::{c_char};
use std::sync::Mutex;
use std::fs::File;
use regex::RegexSet;
use zip::ZipArchive;

// --- CONFIGURATION & FFI STRUCTURES ---

#[derive(Serialize, Deserialize, Default)]
pub struct DlpConfig {
    pub strict_strings: Vec<String>,
    pub regex_patterns: Vec<String>,
    #[serde(default = "default_min_samples")]
    pub ueba_min_samples: u64,
    #[serde(default = "default_z_score")]
    pub ueba_z_score: f64,
}
fn default_min_samples() -> u64 { 25 }
fn default_z_score() -> f64 { 3.5 }

#[derive(Deserialize)]
pub struct FfiPlatformEvent {
    pub timestamp: String,
    pub user: String,
    pub process: String,
    pub filepath: String,
    pub destination: String,
    pub bytes: i64,
    pub duration_ms: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DlpAlert {
    pub alert_type: String,
    pub details: String,
    pub confidence: i32,
    pub mitre_tactic: String,
    pub user: Option<String>,
    pub process: Option<String>,
    pub filepath: Option<String>,
    pub destination: Option<String>,
}

#[derive(Serialize)]
pub struct EngineResponse {
    pub alerts: Option<Vec<DlpAlert>>,
    pub daemon_error: Option<String>,
}

pub struct UebaBaseline {
    pub count: u64,
    pub mean_bytes: f64,
    pub m2_bytes: f64,
    pub mean_velocity: f64,
    pub m2_velocity: f64,
}

// --- NATIVE ENGINE INITIALIZATION ---

pub struct DlpEngine {
    pub db_conn: Connection,
    pub config: DlpConfig,
    pub user_baselines: HashMap<String, UebaBaseline>,
    pub regex_set: RegexSet,
    pub patterns: Vec<String>,
}

#[no_mangle]
pub extern "C" fn init_dlp_engine(config_json: *const c_char) -> *mut Mutex<DlpEngine> {
    let secure_dir = r"C:\ProgramData\DataSensor\Data";
    let _ = std::fs::create_dir_all(secure_dir);
    let db_path = format!(r"{}\DataLedger.db", secure_dir);

    let conn = Connection::open(&db_path).unwrap_or_else(|_| {
        Connection::open_in_memory().expect("CRITICAL: Failed to initialize SQLite.")
    });

    conn.execute_batch("
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA temp_store = MEMORY;
        PRAGMA mmap_size = 4294967296; /* 4GB Memory Map */
        PRAGMA wal_autocheckpoint = 1000;
    ").expect("Failed to apply high-performance SQLite PRAGMAs.");

    conn.execute(
        "CREATE TABLE IF NOT EXISTS DataLedger (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Timestamp TEXT,
            User TEXT,
            Process TEXT,
            FilePath TEXT,
            Destination TEXT,
            Bytes INTEGER,
            Velocity REAL
        )",
        []
    ).expect("Failed to initialize DataLedger schema.");

    let mut config = DlpConfig::default();
    if !config_json.is_null() {
        let c_str = unsafe { CStr::from_ptr(config_json) };
        if let Ok(json_str) = c_str.to_str() {
            if let Ok(parsed) = serde_json::from_str::<DlpConfig>(json_str) {
                config = parsed;
            }
        }
    }

    let regex_set = RegexSet::new(&config.regex_patterns).unwrap_or_else(|_| RegexSet::empty());
    let patterns = config.regex_patterns.clone();

    let engine = DlpEngine {
        db_conn: conn,
        config,
        user_baselines: HashMap::new(),
        regex_set,
        patterns,
    };

    Box::into_raw(Box::new(Mutex::new(engine)))
}

#[no_mangle]
pub extern "C" fn process_telemetry_batch(
    engine_ptr: *mut Mutex<DlpEngine>,
    batch_json: *const c_char,
) -> *mut c_char {
    if engine_ptr.is_null() || batch_json.is_null() {
        return std::ptr::null_mut();
    }

    let engine_mutex = unsafe { &*engine_ptr };
    let mut engine_guard = match engine_mutex.lock() { Ok(g) => g, Err(p) => p.into_inner() };

    let engine = &mut *engine_guard;

    let json_str = unsafe { CStr::from_ptr(batch_json).to_string_lossy() };
    let events_slice: Vec<FfiPlatformEvent> = serde_json::from_str(&json_str).unwrap_or_default();
    let mut alerts = Vec::new();

    let tx = engine.db_conn.transaction_with_behavior(TransactionBehavior::Immediate).unwrap();
    {
        let mut stmt = match tx.prepare_cached(
            "INSERT INTO DataLedger (Timestamp, User, Process, FilePath, Destination, Bytes, Velocity) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
        ) {
            Ok(s) => s,
            Err(e) => return make_error_response(&format!("SQL Prepare Error: {}", e)),
        };

        for ffi_evt in events_slice {
            let ts = ffi_evt.timestamp.clone();
            let usr = ffi_evt.user.clone();
            let proc = ffi_evt.process.clone();
            let path = ffi_evt.filepath.clone();
            let dest = ffi_evt.destination.clone();
            let bytes = ffi_evt.bytes;

            if dest != "Disk_Write" && dest != "Clipboard" {
                for strict_term in &engine.config.strict_strings {
                    if dest.contains(strict_term) {
                        alerts.push(DlpAlert {
                            alert_type: "NETWORK_INTEL_VIOLATION".to_string(),
                            details: format!("Outbound connection to Threat Intel Indicator: {}", strict_term),
                            user: Some(usr.clone()),
                            process: Some(proc.clone()),
                            filepath: Some(path.clone()),
                            destination: Some(dest.clone()),
                            confidence: 100,
                            mitre_tactic: "T1048 - Exfiltration Over Alternative Protocol".to_string(),
                        });
                        break;
                    }
                }
            }

            let velocity = if ffi_evt.duration_ms > 0 {
                (bytes as f64 / ffi_evt.duration_ms as f64) * 1000.0
            } else {
                bytes as f64
            };

            let _ = stmt.execute(rusqlite::params![ts, usr, proc, path, dest, bytes, velocity]);

            let baseline_key = format!("{}|{}", usr, dest);
            let baseline = engine.user_baselines.entry(baseline_key).or_insert(UebaBaseline {
                count: 0, mean_bytes: 0.0, m2_bytes: 0.0, mean_velocity: 0.0, m2_velocity: 0.0
            });

            baseline.count += 1;
            let n = baseline.count as f64;

            let delta_b = bytes as f64 - baseline.mean_bytes;
            baseline.mean_bytes += delta_b / n;
            baseline.m2_bytes += delta_b * (bytes as f64 - baseline.mean_bytes);

            let delta_v = velocity - baseline.mean_velocity;
            baseline.mean_velocity += delta_v / n;
            baseline.m2_velocity += delta_v * (velocity - baseline.mean_velocity);

            if baseline.count > engine.config.ueba_min_samples {
                let std_dev_b = (baseline.m2_bytes / n).sqrt();
                let std_dev_v = (baseline.m2_velocity / n).sqrt();

                let z_score_b = if std_dev_b > 0.0 { (bytes as f64 - baseline.mean_bytes) / std_dev_b } else { 0.0 };
                let z_score_v = if std_dev_v > 0.0 { (velocity - baseline.mean_velocity) / std_dev_v } else { 0.0 };

                if z_score_b > engine.config.ueba_z_score || z_score_v > engine.config.ueba_z_score {
                    alerts.push(DlpAlert {
                        alert_type: "UEBA_ANOMALY".to_string(),
                        details: format!("Z-Score (Vol: {:.2}, Vel: {:.2}) | Bytes: {} | Velocity: {:.2} B/s", z_score_b, z_score_v, bytes, velocity),
                        user: Some(usr.clone()),
                        process: Some(proc.clone()),
                        filepath: Some(path.clone()),
                        destination: Some(dest.clone()),
                        confidence: 90,
                        mitre_tactic: "T1048 - Exfiltration Over Alternative Protocol".to_string(),
                    });
                }
            }
        }
    }

    if let Err(e) = tx.commit() {
        return make_error_response(&format!("SQL Commit Error: {}", e));
    }

    serialize_response(alerts)
}

#[no_mangle]
pub extern "C" fn inspect_file_content(
    engine_ptr: *mut Mutex<DlpEngine>,
    file_ext: *const c_char,
    filepath: *const c_char,
    process_name: *const c_char,
    user_name: *const c_char,
) -> *mut c_char {
    if engine_ptr.is_null() || filepath.is_null() {
        return std::ptr::null_mut();
    }

    let path_str = unsafe { CStr::from_ptr(filepath).to_string_lossy().into_owned() };
    let ext_str = if file_ext.is_null() { String::new() } else { unsafe { CStr::from_ptr(file_ext).to_string_lossy().to_lowercase() } };
    let proc_str = if process_name.is_null() { "System".to_string() } else { unsafe { CStr::from_ptr(process_name).to_string_lossy().into_owned() } };
    let usr_str = if user_name.is_null() { "System".to_string() } else { unsafe { CStr::from_ptr(user_name).to_string_lossy().into_owned() } };

    let mut file = match File::open(&path_str) {
        Ok(f) => f,
        Err(_) => return std::ptr::null_mut(), // File securely locked by OS, skip cleanly
    };

    let mut extracted_text = String::new();

    if ext_str == ".zip" || ext_str == ".docx" || ext_str == ".xlsx" || ext_str == ".pptx" {
        if let Ok(mut archive) = ZipArchive::new(&mut file) {
            let mut total_extracted_bytes = 0;
            for i in 0..archive.len() {
                if let Ok(archive_file) = archive.by_index(i) {
                    if archive_file.name().ends_with(".xml") || archive_file.name().ends_with(".txt") {
                        let mut contents = String::new();
                        let mut limit_reader = archive_file.take(5 * 1024 * 1024);
                        let bytes_read = limit_reader.read_to_string(&mut contents).unwrap_or(0);
                        extracted_text.push_str(&contents);

                        total_extracted_bytes += bytes_read;
                        if total_extracted_bytes > 25 * 1024 * 1024 {
                            break;
                        }
                    }
                }
            }
        }
    } else {
        let mut limit_reader = file.take(15 * 1024 * 1024);
        let _ = limit_reader.read_to_string(&mut extracted_text);
    }

    let engine_guard = unsafe { &*engine_ptr };
    let engine = match engine_guard.lock() { Ok(g) => g, Err(p) => p.into_inner() };

    let mut alerts = Vec::new();
    let matches: Vec<_> = engine.regex_set.matches(&extracted_text).into_iter().collect();

    for &m in &matches {
        alerts.push(DlpAlert {
            alert_type: "CONTENT_VIOLATION".to_string(),
            details: format!("Matched Signature: {}", engine.patterns[m]),
            user: Some(usr_str.clone()),
            process: Some(proc_str.clone()),
            filepath: Some(path_str.clone()),
            destination: Some("Deep_Inspection".to_string()),
            confidence: 100,
            mitre_tactic: "T1567 - Exfiltration Over Web Service".to_string(),
        });
    }

    for strict_term in &engine.config.strict_strings {
        if extracted_text.contains(strict_term) {
            alerts.push(DlpAlert {
                alert_type: "INTEL_VIOLATION".to_string(),
                details: format!("Matched Exact Term: {}", strict_term),
                user: Some(usr_str.clone()),
                process: Some(proc_str.clone()),
                filepath: Some(path_str.clone()),
                destination: Some("Deep_Inspection".to_string()),
                confidence: 100,
                mitre_tactic: "T1048 - Exfiltration Over Alternative Protocol".to_string(),
            });
        }
    }

    if let Some(trigger) = alerts.iter().find(|a| a.confidence == 100).cloned() {
        let mut final_alerts = alerts;

        let safe_file = trigger.filepath.clone().unwrap_or_else(|| "Unknown_Vector".to_string());
        let safe_dest = trigger.destination.clone().unwrap_or_else(|| "Unknown_Target".to_string());

        final_alerts.push(DlpAlert {
            alert_type: "ACTION_REQUIRED".to_string(),
            details: format!("Auto-Containment Enacted | Trigger: {} | Vector: {} -> {}", trigger.details, safe_file, safe_dest),
            user: trigger.user,
            process: trigger.process,
            filepath: Some(safe_file),
            destination: Some(safe_dest),
            confidence: 100,
            mitre_tactic: "T1485 - Data Destruction / Mitigation".to_string(),
        });
        return serialize_response(final_alerts);
    }

    serialize_response(alerts)
}

fn serialize_response(alerts: Vec<DlpAlert>) -> *mut c_char {
    let response = EngineResponse {
        alerts: if alerts.is_empty() { None } else { Some(alerts) },
        daemon_error: None,
    };
    CString::new(serde_json::to_string(&response).unwrap().replace('\0', "")).unwrap().into_raw()
}

fn make_error_response(msg: &str) -> *mut c_char {
    let response = EngineResponse { alerts: None, daemon_error: Some(msg.to_string()) };
    CString::new(serde_json::to_string(&response).unwrap()).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    if !s.is_null() { unsafe { let _ = CString::from_raw(s); } }
}

#[no_mangle]
pub extern "C" fn teardown_engine(engine_ptr: *mut Mutex<DlpEngine>) {
    if !engine_ptr.is_null() { unsafe { let _ = Box::from_raw(engine_ptr); } }
}