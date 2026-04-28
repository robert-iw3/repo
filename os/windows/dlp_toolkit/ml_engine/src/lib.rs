/*=============================================================================================
 * SYSTEM:          Data Sensor - Observation & DLP
 * COMPONENT:       lib.rs (High-Performance FFI Engine)
 * DESCRIPTION:
 * Natively compiles as a C-compatible Dynamic Link Library (cdylib).
 * Implements micro-batched transactional logging and memory-mapped SQLite
 * PRAGMAs to handle massive ETW telemetry firehoses without I/O blocking.
 * @RW
 *============================================================================================*/

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char};
use std::sync::Mutex;
use regex::RegexSet;

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
    pub strict_set: std::collections::HashSet<String>,
}

#[no_mangle]
pub extern "C" fn init_dlp_engine(config_json: *const c_char) -> *mut Mutex<DlpEngine> {
    let secure_dir = r"C:\ProgramData\DataSensor\Data";
    let _ = std::fs::create_dir_all(secure_dir);
    let db_path = format!(r"{}\DataLedger.db", secure_dir);

    let conn = match Connection::open(&db_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[DataSensor ML] FATAL: Could not open DataLedger.db: {}", e);
            return std::ptr::null_mut();
        }
    };

    let _ = conn.busy_timeout(std::time::Duration::from_millis(5000));

    if conn.execute_batch("
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA temp_store = MEMORY;
        PRAGMA mmap_size = 268435456;
        PRAGMA wal_autocheckpoint = 1000;
    ").is_err() {
        return std::ptr::null_mut();
    }

    if conn.execute(
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
    ).is_err() {
        return std::ptr::null_mut();
    }

    let mut config = DlpConfig::default();
    if !config_json.is_null() {
        let c_str = unsafe { CStr::from_ptr(config_json) };
        if let Ok(json_str) = c_str.to_str() {
            if let Ok(parsed) = serde_json::from_str::<DlpConfig>(json_str) {
                config = parsed;
            }
        }
    }

    config.strict_strings.retain(|s| !s.trim().is_empty());
    config.regex_patterns.retain(|s| !s.trim().is_empty());

    let regex_set = RegexSet::new(&config.regex_patterns).unwrap_or_else(|e| {
        eprintln!("[DataSensor ML] WARNING: Failed to compile RegexSet: {}", e);
        RegexSet::empty()
    });
    let patterns = config.regex_patterns.clone();
    let strict_set: std::collections::HashSet<String> = config.strict_strings.iter().cloned().collect();

    let engine = DlpEngine {
        db_conn: conn,
        config,
        user_baselines: HashMap::new(),
        regex_set,
        patterns,
        strict_set,
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
    let mut engine_guard = match engine_mutex.lock() {
        Ok(g) => g,
        Err(p) => {
            eprintln!("[DataSensor ML] WARNING: Engine mutex was poisoned — recovering. State may be inconsistent.");
            p.into_inner()
        }
    };

    let engine = &mut *engine_guard;

    let json_str = unsafe { CStr::from_ptr(batch_json).to_string_lossy() };
    let events_slice: Vec<FfiPlatformEvent> = match serde_json::from_str(&json_str) {
        Ok(evts) => evts,
        Err(e) => return make_error_response(&format!("JSON Parse Error: {} | Payload: {}", e, json_str)),
    };
    let mut alerts = Vec::new();

    let tx = match engine.db_conn.transaction() {
        Ok(t) => t,
        Err(e) => return make_error_response(&format!("Transaction Error: {}", e)),
    };
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
                let matched_ioc = engine.strict_set.iter().find(|ioc| {
                    dest == ioc.as_str() || dest.ends_with(&format!(".{}", ioc))
                });
                if let Some(ioc) = matched_ioc {
                    alerts.push(DlpAlert {
                        alert_type: "NETWORK_INTEL_VIOLATION".to_string(),
                        details: format!("Outbound connection to Threat Intel Indicator: {}", ioc),
                        user: Some(usr.clone()),
                        process: Some(proc.clone()),
                        filepath: Some(path.clone()),
                        destination: Some(dest.clone()),
                        confidence: 100,
                        mitre_tactic: "T1048 - Exfiltration Over Alternative Protocol".to_string(),
                    });
                }
            }

            let velocity = if ffi_evt.duration_ms > 0 {
                (bytes as f64 / ffi_evt.duration_ms as f64) * 1000.0
            } else {
                bytes as f64
            };

            if let Err(e) = stmt.execute(rusqlite::params![ts, usr, proc, path, dest, bytes, velocity]) {
                return make_error_response(&format!("SQL Insert Error: {}", e));
            }

            if engine.user_baselines.len() > 50_000 {
                engine.user_baselines.clear();
            }

            let baseline_key = format!("{}|{}", usr, dest);
            let baseline = engine.user_baselines.entry(baseline_key).or_insert(UebaBaseline {
                count: 0, mean_bytes: 0.0, m2_bytes: 0.0, mean_velocity: 0.0, m2_velocity: 0.0
            });

            let pre_count = baseline.count;
            let pre_mean_b = baseline.mean_bytes;
            let pre_mean_v = baseline.mean_velocity;
            let pre_std_dev_b = if pre_count > 1 { (baseline.m2_bytes / pre_count as f64).sqrt() } else { 0.0 };
            let pre_std_dev_v = if pre_count > 1 { (baseline.m2_velocity / pre_count as f64).sqrt() } else { 0.0 };

            // Update baseline with the new event (Welford's online algorithm)
            baseline.count += 1;
            let n = baseline.count as f64;

            let delta_b = bytes as f64 - baseline.mean_bytes;
            baseline.mean_bytes += delta_b / n;
            baseline.m2_bytes += delta_b * (bytes as f64 - baseline.mean_bytes);

            let delta_v = velocity - baseline.mean_velocity;
            baseline.mean_velocity += delta_v / n;
            baseline.m2_velocity += delta_v * (velocity - baseline.mean_velocity);

            // Evaluate anomaly against PRE-UPDATE baseline so the current event is scored honestly
            if pre_count > engine.config.ueba_min_samples {
                let z_score_b = if pre_std_dev_b > 0.0 { (bytes as f64 - pre_mean_b) / pre_std_dev_b } else { 0.0 };
                let z_score_v = if pre_std_dev_v > 0.0 { (velocity - pre_mean_v) / pre_std_dev_v } else { 0.0 };

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
pub extern "C" fn scan_text_payload(
    engine_ptr: *mut Mutex<DlpEngine>,
    text_payload: *const c_char,
    source_process: *const c_char,
    user_name: *const c_char,
) -> *mut c_char {
    if engine_ptr.is_null() || text_payload.is_null() { return std::ptr::null_mut(); }

    let engine_mutex = unsafe { &*engine_ptr };

    let mut engine_guard = match engine_mutex.lock() {
        Ok(g) => g,
        Err(p) => {
            eprintln!("[DataSensor ML] WARNING: Engine mutex was poisoned — recovering. State may be inconsistent.");
            p.into_inner()
        }
    };

    let engine = &mut *engine_guard;

    let text = unsafe { CStr::from_ptr(text_payload).to_string_lossy() };
    let process = if source_process.is_null() { "System".to_string() } else { unsafe { CStr::from_ptr(source_process).to_string_lossy().into_owned() } };
    let user = if user_name.is_null() { "System".to_string() } else { unsafe { CStr::from_ptr(user_name).to_string_lossy().into_owned() } };

    let mut matched = false;
    let mut trigger_detail = String::new();

    // 1. Check literal string arrays
    for kw in &engine.config.strict_strings {
        if text.contains(kw) {
            matched = true;
            trigger_detail = format!("Literal Match: {}", kw);
            break;
        }
    }

    // 2. Check compiled regex set
    if !matched && engine.regex_set.is_match(&text) {
        matched = true;
        trigger_detail = "Regex Signature Match".to_string();
    }

    // 3. Return Alert if matched
    if matched {
        let alert = DlpAlert {
            alert_type: "ACTION_REQUIRED".to_string(),
            details: format!("Clipboard Intercepted | {}", trigger_detail),
            confidence: 100,
            mitre_tactic: "T1056 - Collection".to_string(),
            user: Some(user),
            process: Some(process),
            filepath: Some("Clipboard_Capture".to_string()),
            destination: Some("Memory_Buffer".to_string()),
        };
        return serialize_response(vec![alert]);
    }

    std::ptr::null_mut()
}

fn serialize_response(alerts: Vec<DlpAlert>) -> *mut c_char {
    let response = EngineResponse {
        alerts: if alerts.is_empty() { None } else { Some(alerts) },
        daemon_error: None,
    };
    match serde_json::to_string(&response) {
        Ok(s) => match CString::new(s.replace('\0', "")) {
            Ok(cs) => cs.into_raw(),
            Err(_)  => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

fn make_error_response(msg: &str) -> *mut c_char {
    let response = EngineResponse { alerts: None, daemon_error: Some(msg.to_string()) };
    match serde_json::to_string(&response) {
        Ok(s) => match CString::new(s.replace('\0', "")) {
            Ok(cs) => cs.into_raw(),
            Err(_)  => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    if !s.is_null() { unsafe { let _ = CString::from_raw(s); } }
}

#[no_mangle]
pub extern "C" fn teardown_engine(engine_ptr: *mut Mutex<DlpEngine>) {
    if !engine_ptr.is_null() {
        let engine_box = unsafe { Box::from_raw(engine_ptr) };
        let engine = match engine_box.into_inner() {
            Ok(e) => e,
            Err(p) => p.into_inner(),
        };
        let _ = engine.db_conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
    }
}

#[no_mangle]
pub extern "C" fn groom_database(
    engine_ptr: *mut Mutex<DlpEngine>,
    days_to_keep: u32,
) -> i32 {
    if engine_ptr.is_null() { return -1; }

    let engine_mutex = unsafe { &*engine_ptr };
    let engine_guard = match engine_mutex.lock() {
        Ok(g) => g,
        Err(p) => {
            eprintln!("[DataSensor ML] WARNING: Mutex poisoned during grooming.");
            p.into_inner()
        }
    };

    let cutoff_days = days_to_keep.max(1) as i64;

    let result = engine_guard.db_conn.execute(
        "DELETE FROM DataLedger
         WHERE julianday('now') - julianday(Timestamp) > ?1
           AND Destination NOT IN (
               SELECT DISTINCT Destination FROM DataLedger
               WHERE julianday('now') - julianday(Timestamp) <= 3
                 AND (FilePath = 'Clipboard_Capture'
                      OR Bytes > 100000)
           )",
        rusqlite::params![cutoff_days],
    );

    match result {
        Ok(rows_deleted) => rows_deleted as i32,
        Err(e) => {
            eprintln!("[DataSensor ML] Grooming error: {}", e);
            -1
        }
    }
}