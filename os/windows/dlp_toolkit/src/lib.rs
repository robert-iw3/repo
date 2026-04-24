/*=============================================================================================
 * SYSTEM:          Data Sensor - Observation & DLP
 * COMPONENT:       lib.rs (High-Performance FFI Engine)
 * DESCRIPTION:
 * Natively compiles as a C-compatible Dynamic Link Library (cdylib).
 * Implements micro-batched transactional logging and memory-mapped SQLite
 * PRAGMAs to handle massive ETW telemetry firehoses without I/O blocking.
 *============================================================================================*/

use rusqlite::{Connection, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io::{Cursor, Read};
use std::os::raw::{c_char};
use std::sync::Mutex;
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

#[repr(C)]
pub struct FfiPlatformEvent {
    pub timestamp: *const c_char,
    pub user: *const c_char,
    pub process: *const c_char,
    pub filepath: *const c_char,
    pub destination: *const c_char,
    pub bytes: i64,
    pub duration_ms: i64,
}

#[derive(Serialize)]
pub struct DlpAlert {
    pub alert_type: String,
    pub details: String,
    pub confidence: i32,
    pub mitre_tactic: String,
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

pub struct DlpEngine {
    pub db_conn: Connection,
    pub regex_set: RegexSet,
    pub patterns: Vec<String>,
    pub user_baselines: HashMap<String, UebaBaseline>,
    pub ueba_min_samples: u64,
    pub ueba_z_score: f64,
}

// --- FFI EXPORTS ---

#[no_mangle]
pub extern "C" fn init_dlp_engine(config_json: *const c_char) -> *mut Mutex<DlpEngine> {
    if config_json.is_null() { return std::ptr::null_mut(); }

    let c_str = unsafe { CStr::from_ptr(config_json) };
    let json_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let config: DlpConfig = serde_json::from_str(json_str).unwrap_or_default();

    let mut all_patterns = config.strict_strings.clone();
    all_patterns.extend(config.regex_patterns.clone());
    let regex_set = RegexSet::new(&all_patterns).unwrap();

    let secure_dir = r"C:\ProgramData\DataSensor\Data";
    let _ = std::fs::create_dir_all(secure_dir);
    let db_path = format!(r"{}\DlpLedger.db", secure_dir);

    let conn = Connection::open(&db_path).unwrap_or_else(|_| {
        Connection::open_in_memory().expect("CRITICAL: Failed to initialize SQLite")
    });

    conn.execute_batch("
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA cache_size = -64000;
        PRAGMA mmap_size = 2147483648;
        PRAGMA temp_store = MEMORY;
        PRAGMA wal_autocheckpoint = 1000;

        CREATE TABLE IF NOT EXISTS DataLedger (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Timestamp TEXT,
            Process TEXT,
            FilePath TEXT,
            Destination TEXT,
            Bytes INTEGER,
            Velocity REAL
        );
    ").expect("Failed to apply performance pragmas and schema");

    let engine = DlpEngine {
        db_conn: conn,
        regex_set,
        patterns: all_patterns,
        user_baselines: HashMap::new(),
        ueba_min_samples: config.ueba_min_samples,
        ueba_z_score: config.ueba_z_score,
    };

    Box::into_raw(Box::new(Mutex::new(engine)))
}

#[no_mangle]
pub extern "C" fn process_telemetry_batch(
    engine_ptr: *mut Mutex<DlpEngine>,
    events_ptr: *const FfiPlatformEvent,
    event_count: usize,
) -> *mut c_char {
    let engine_guard = unsafe { &*engine_ptr };
    let mut engine = match engine_guard.lock() { Ok(g) => g, Err(p) => p.into_inner() };

    let events_slice = unsafe { std::slice::from_raw_parts(events_ptr, event_count) };
    let mut alerts = Vec::new();

    let tx = engine.db_conn.transaction_with_behavior(TransactionBehavior::Immediate).unwrap();
    {
        let mut stmt = match tx.prepare_cached(
            "INSERT INTO DataLedger (Timestamp, Process, FilePath, Destination, Bytes, Velocity) VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        ) {
            Ok(s) => s,
            Err(e) => return make_error_response(&format!("SQL Prepare Error: {}", e)),
        };

        for ffi_evt in events_slice {
            let ts = unsafe { CStr::from_ptr(ffi_evt.timestamp).to_string_lossy().into_owned() };
            let usr = unsafe { CStr::from_ptr(ffi_evt.user).to_string_lossy().into_owned() };
            let proc = unsafe { CStr::from_ptr(ffi_evt.process).to_string_lossy().into_owned() };
            let path = unsafe { CStr::from_ptr(ffi_evt.filepath).to_string_lossy().into_owned() };
            let dest = unsafe { CStr::from_ptr(ffi_evt.destination).to_string_lossy().into_owned() };
            let bytes = ffi_evt.bytes;

            let velocity = if ffi_evt.duration_ms > 0 {
                (bytes as f64 / ffi_evt.duration_ms as f64) * 1000.0
            } else {
                bytes as f64
            };

            let _ = stmt.execute(rusqlite::params![ts, proc, path, dest, bytes, velocity]);

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

            if baseline.count > engine.ueba_min_samples {
                let std_dev_b = (baseline.m2_bytes / n).sqrt();
                let std_dev_v = (baseline.m2_velocity / n).sqrt();

                let z_score_b = if std_dev_b > 0.0 { (bytes as f64 - baseline.mean_bytes) / std_dev_b } else { 0.0 };
                let z_score_v = if std_dev_v > 0.0 { (velocity - baseline.mean_velocity) / std_dev_v } else { 0.0 };

                if z_score_b > engine.ueba_z_score || z_score_v > engine.ueba_z_score {
                    alerts.push(DlpAlert {
                        alert_type: "UEBA_ANOMALY".to_string(),
                        details: format!("Z-Score (Vol: {:.2}, Vel: {:.2}) | Bytes: {} | Velocity: {:.2} B/s", z_score_b, z_score_v, bytes, velocity),
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
    file_path: *const c_char,
    file_ext: *const c_char,
    buffer: *const u8,
    buffer_len: usize,
) -> *mut c_char {
    let engine_guard = unsafe { &*engine_ptr };
    let engine = match engine_guard.lock() { Ok(g) => g, Err(p) => p.into_inner() };

    let slice = unsafe { std::slice::from_raw_parts(buffer, buffer_len) };
    let ext_str = unsafe { CStr::from_ptr(file_ext).to_string_lossy().to_lowercase() };

    let mut extracted_text = String::new();

    if ext_str == ".zip" || ext_str == ".docx" || ext_str == ".xlsx" || ext_str == ".pptx" {
        if let Ok(mut archive) = ZipArchive::new(Cursor::new(slice)) {
            for i in 0..archive.len() {
                if let Ok(file) = archive.by_index(i) {
                    if file.name().ends_with(".xml") || file.name().ends_with(".txt") {
                        let mut contents = String::new();
                        let mut limit_reader = file.take(5 * 1024 * 1024);
                        let _ = limit_reader.read_to_string(&mut contents);
                        extracted_text.push_str(&contents);
                    }
                }
            }
        }
    } else {
        extracted_text = String::from_utf8_lossy(slice).into_owned();
    }

    let mut byte_counts = [0usize; 256];
    for &b in slice { byte_counts[b as usize] += 1; }
    let entropy = byte_counts.iter().fold(0.0, |acc, &count| {
        if count == 0 { acc } else {
            let p = count as f64 / buffer_len as f64;
            acc - p * p.log2()
        }
    });

    let mut alerts = Vec::new();
    let matches: Vec<_> = engine.regex_set.matches(&extracted_text).into_iter().collect();

    if !matches.is_empty() {
        for &m in &matches {
            alerts.push(DlpAlert {
                alert_type: "CONTENT_VIOLATION".to_string(),
                details: format!("Matched Signature: {} | File Entropy: {:.2}", engine.patterns[m], entropy),
                confidence: 100,
                mitre_tactic: "T1567 - Exfiltration Over Web Service".to_string(),
            });
        }
    }

    if alerts.iter().any(|a| a.confidence == 100) {
        let mut final_alerts = alerts;
        final_alerts.push(DlpAlert {
            alert_type: "ACTION_REQUIRED".to_string(),
            details: "SUSPEND_THREAD".to_string(),
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