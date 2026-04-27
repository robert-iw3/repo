/*=============================================================================================
 * SYSTEM:          Data Sensor - Ring-3 Interceptor
 * COMPONENT:       lib.rs (In-Band API Hook)
 * DESCRIPTION:     Hooks WriteFile, computes SHA256 hashes for validation, inspects buffers,
 * and communicates with the C# Orchestrator via Named Pipes.
 * @RW
 *============================================================================================*/

use serde::Serialize;
use sha2::{Sha256, Digest};
use std::ffi::c_void;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use lazy_static::lazy_static;

thread_local! {
    static IN_HOOK: std::cell::Cell<bool> = std::cell::Cell::new(false);
}

type WriteFileFn = unsafe extern "system" fn(
    *mut c_void,   // HANDLE hFile
    *const c_void, // LPCVOID lpBuffer
    u32,           // DWORD nNumberOfBytesToWrite
    *mut u32,      // LPDWORD lpNumberOfBytesWritten
    *mut c_void,   // LPOVERLAPPED lpOverlapped
) -> i32;          // BOOL

static ORIGINAL_WRITEFILE: std::sync::OnceLock<WriteFileFn> = std::sync::OnceLock::new();

static ALERT_SENDER: OnceLock<std::sync::mpsc::SyncSender<String>> = OnceLock::new();

#[repr(C)]
struct IoStatusBlock {
    status: i32,
    information: usize,
}

#[repr(C)]
struct FileNameInfo {
    file_name_length: u32,
    file_name: [u16; 512],
}

type NtQueryInfoFileFn = unsafe extern "system" fn(
    isize,                  // FileHandle
    *mut IoStatusBlock,     // IoStatusBlock
    *mut c_void,            // FileInformation
    u32,                    // Length
    u32,                    // FileInformationClass
) -> i32;                   // NTSTATUS (0 = success)

const FILE_NAME_INFORMATION_CLASS: u32 = 9;

static NT_QUERY_INFO_FILE: OnceLock<NtQueryInfoFileFn> = OnceLock::new();

#[derive(Serialize)]
struct DlpAlert {
    alert_type: String,
    details: String,
    filepath: String,
    file_hash: String,
    confidence: i32,
    mitre_tactic: String,
}

lazy_static! {
    static ref DLP_LITERALS: Vec<String> = {
        let mut keywords = Vec::new();
        if let Ok(config_data) = std::fs::read_to_string(r"C:\ProgramData\DataSensor\config.ini") {
            for line in config_data.lines() {
                if line.starts_with("Classifications=") || line.starts_with("ProjectNames=") {
                    let parts: Vec<&str> = line.split('=').collect();
                    if parts.len() == 2 {
                        for keyword in parts[1].split(',') {
                            let kw = keyword.trim();
                            if !kw.is_empty() { keywords.push(kw.to_string()); }
                        }
                    }
                }
            }
        }
        if keywords.is_empty() { keywords.push("AKIA".to_string()); }
        keywords
    };

    static ref DLP_PATTERNS: regex::RegexSet = {
        let mut regex_list = Vec::new();
        if let Ok(config_data) = std::fs::read_to_string(r"C:\ProgramData\DataSensor\config.ini") {
            let mut in_regex_section = false;
            for line in config_data.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('[') && trimmed.ends_with(']') {
                    in_regex_section = trimmed == "[DLP_REGEX]";
                    continue;
                }
                if in_regex_section && !trimmed.is_empty() && !trimmed.starts_with(';') {
                            let parts: Vec<&str> = trimmed.splitn(2, '=').collect();
                            if parts.len() == 2 {
                                let val = parts[1].trim();
                                if !val.is_empty() {
                                    regex_list.push(val.to_string());
                                }
                            }
                        }
            }
        }
        if regex_list.is_empty() { regex_list.push(r"AKIA[0-9A-Z]{16}".to_string()); }
        regex::RegexSet::new(&regex_list).unwrap_or_else(|_| regex::RegexSet::new(&[r"AKIA[0-9A-Z]{16}"]).unwrap())
    };
}

#[link(name = "kernel32")]
extern "system" {
    fn GetFileType(hFile: *mut c_void) -> u32;
    fn CreateEventA(lpEventAttributes: *mut c_void, bManualReset: i32, bInitialState: i32, lpName: *const u8) -> *mut c_void;
    fn WaitForSingleObject(hHandle: *mut c_void, dwMilliseconds: u32) -> u32;
    fn CloseHandle(hObject: *mut c_void) -> i32;
}
const FILE_TYPE_DISK: u32 = 0x0001;

unsafe extern "system" fn hooked_write_file(
    h_file: *mut c_void,
    lp_buffer: *const c_void,
    n_bytes: u32,
    lp_bytes_written: *mut u32,
    lp_overlapped: *mut c_void,
) -> i32 {
    if GetFileType(h_file) != FILE_TYPE_DISK {
        return resume_original(h_file, lp_buffer, n_bytes, lp_bytes_written, lp_overlapped);
    }

    if n_bytes == 0 || lp_buffer.is_null() || IN_HOOK.with(|f| f.get()) {
        return resume_original(h_file, lp_buffer, n_bytes, lp_bytes_written, lp_overlapped);
    }
    IN_HOOK.with(|f| f.set(true));

    let mut original_name = "intercepted_payload.dat".to_string();

    let file_path_opt: Option<String> = if let Some(nt_fn) = NT_QUERY_INFO_FILE.get() {
        let mut isb = IoStatusBlock { status: 0, information: 0 };
        let mut name_info = FileNameInfo { file_name_length: 0, file_name: [0u16; 512] };
        let status = nt_fn(h_file as isize, &mut isb, &mut name_info as *mut _ as *mut c_void, std::mem::size_of::<FileNameInfo>() as u32, FILE_NAME_INFORMATION_CLASS);

        if status == 0 || status == 0x80000005u32 as i32 {
            let len = (name_info.file_name_length / 2) as usize;
            let path_str = String::from_utf16_lossy(&name_info.file_name[..len.min(512)]);

            if let Some(idx) = path_str.rfind('\\') {
                original_name = path_str[idx + 1..].to_string();
            } else if let Some(idx) = path_str.rfind('/') {
                original_name = path_str[idx + 1..].to_string();
            } else {
                original_name = path_str.clone();
            }
            Some(path_str.to_lowercase())
        } else { None }
    } else { None };

    if let Some(ref file_path) = file_path_opt {
        let is_own_path = file_path.contains("datasensor")
            || file_path.contains("namedpipe")
            || file_path.ends_with(".jsonl")
            || file_path.ends_with(".log")
            || file_path.contains("afd")
            || file_path.contains("tcp")
            || file_path.contains("udp")
            || file_path.contains("endpoint")
            || file_path.contains("mup");

        if is_own_path {
            IN_HOOK.with(|f| f.set(false));
            return resume_original(h_file, lp_buffer, n_bytes, lp_bytes_written, lp_overlapped);
        }

        if file_path.ends_with(".zip") {
            let alert = DlpAlert {
                alert_type: "ASYNC_INSPECT_QUEUED".to_string(),
                details: "Archive created. Delegating to Orchestrator for deep inspection.".to_string(),
                filepath: file_path.clone(),
                file_hash: String::new(),
                confidence: 50,
                mitre_tactic: "T1560 - Archive Collected Data".to_string(),
            };
            if let Ok(json_payload) = serde_json::to_string(&alert) {
                if let Some(sender) = ALERT_SENDER.get() { let _ = sender.try_send(json_payload); }
            }
            IN_HOOK.with(|f| f.set(false));
            return resume_original(h_file, lp_buffer, n_bytes, lp_bytes_written, lp_overlapped);
        }
    }

    const MIN_INSPECT_BYTES: u32 = 512;
    if n_bytes < MIN_INSPECT_BYTES {
        IN_HOOK.with(|f| f.set(false));
        return resume_original(h_file, lp_buffer, n_bytes, lp_bytes_written, lp_overlapped);
    }

    // 2. CORE BUFFER INSPECTION
    let buffer_slice = std::slice::from_raw_parts(lp_buffer as *const u8, n_bytes as usize);

    let json_keys: &[&[u8]] = &[b"alert_type", b"DurationMs", b"Orchestrator", b"events"];
    let mut is_json_telemetry = false;

    for &key in json_keys {
        if buffer_slice.windows(key.len()).any(|w| w == key) {
            is_json_telemetry = true; break;
        }
        let mut utf16_key = Vec::with_capacity(key.len() * 2);
        for &b in key { utf16_key.push(b); utf16_key.push(0); }

        if buffer_slice.windows(utf16_key.len()).any(|w| w == utf16_key.as_slice()) {
            is_json_telemetry = true; break;
        }
    }

    let is_gzip = buffer_slice.len() > 2 && buffer_slice[0] == 0x1F && buffer_slice[1] == 0x8B;
    if is_gzip || buffer_slice.starts_with(b"H4sI") || is_json_telemetry {
        IN_HOOK.with(|f| f.set(false));
        return resume_original(h_file, lp_buffer, n_bytes, lp_bytes_written, lp_overlapped);
    }

    if buffer_slice.len() >= 4 && buffer_slice[0] == 0x50 && buffer_slice[1] == 0x4B && buffer_slice[2] == 0x03 && buffer_slice[3] == 0x04 {
        let alert = DlpAlert {
            alert_type: "ASYNC_INSPECT_QUEUED".to_string(),
            details: "Archive created. Delegating to Orchestrator for deep inspection.".to_string(),
            filepath: "Encrypted/Compressed Archive".to_string(),
            file_hash: String::new(),
            confidence: 50,
            mitre_tactic: "T1560 - Archive Collected Data".to_string(),
        };
        if let Ok(json_payload) = serde_json::to_string(&alert) {
            if let Some(sender) = ALERT_SENDER.get() { let _ = sender.try_send(json_payload); }
        }
        IN_HOOK.with(|f| f.set(false));
        return resume_original(h_file, lp_buffer, n_bytes, lp_bytes_written, lp_overlapped);
    }

    let content_utf8 = String::from_utf8_lossy(buffer_slice);

    let content_utf16: Option<String> = if buffer_slice.len() >= 4 && buffer_slice.len() % 2 == 0 {
        let has_bom = buffer_slice[0] == 0xFF && buffer_slice[1] == 0xFE;
        let null_odd_bytes = buffer_slice.iter().skip(1).step_by(2).filter(|&&b| b == 0).count();
        let threshold = buffer_slice.len() / 4;
        if has_bom || null_odd_bytes > threshold {
            let start = if has_bom { 2 } else { 0 };
            let words: Vec<u16> = buffer_slice[start..]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            Some(String::from_utf16_lossy(&words).to_string())
        } else {
            None
        }
    } else {
        None
    };

    let is_orchestrator_utf8 = content_utf8.contains("\"alert_type\"")
        || content_utf8.contains("\"events\":[")
        || content_utf8.contains("\"Component\":\"Orchestrator\"")
        || content_utf8.contains("\"DurationMs\":");

    let is_orchestrator_utf16 = content_utf16.as_ref().map_or(false, |s|
        s.contains("\"alert_type\"")
        || s.contains("\"events\":[")
        || s.contains("\"Component\":\"Orchestrator\"")
        || s.contains("\"DurationMs\":")
    );

    if is_orchestrator_utf8 || is_orchestrator_utf16 {
        IN_HOOK.with(|f| f.set(false));
        return resume_original(h_file, lp_buffer, n_bytes, lp_bytes_written, lp_overlapped);
    }

    let mut matched = false;
    let mut trigger_detail = String::new();

    for kw in DLP_LITERALS.iter() {
        let utf8_hit = content_utf8.contains(kw.as_str());
        let utf16_hit = content_utf16.as_ref().map_or(false, |s| s.contains(kw.as_str()));
        if utf8_hit || utf16_hit {
            matched = true;
            trigger_detail = format!("Literal Match: {}", kw);
            break;
        }
    }

    if !matched {
        let utf8_hit = DLP_PATTERNS.is_match(&content_utf8);
        let utf16_hit = content_utf16.as_ref().map_or(false, |s| DLP_PATTERNS.is_match(s));
        if utf8_hit || utf16_hit {
            matched = true;
            trigger_detail = "Regex Signature Match".to_string();
        }
    }

    if matched {
        let mut hasher = Sha256::new();
        hasher.update(buffer_slice);
        let computed_hash = hex::encode(hasher.finalize());

        let evidence_dir = Path::new(r"C:\ProgramData\DataSensor\Evidence");
        let _ = fs::create_dir_all(evidence_dir);
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let evidence_path = evidence_dir.join(
            format!("{}_{}_{}", timestamp, &computed_hash[0..8], original_name)
        );

        if let Ok(mut file) = File::create(&evidence_path) {
            let _ = file.write_all(buffer_slice);
        }

        let alert = DlpAlert {
            alert_type: "ACTION_REQUIRED".to_string(),
            details: format!("In-Band Write Blocked | {}", trigger_detail),
            filepath: evidence_path.display().to_string(),
            file_hash: computed_hash,
            confidence: 100,
            mitre_tactic: "T1485 - Data Destruction / Mitigation".to_string(),
        };
        if let Ok(json_payload) = serde_json::to_string(&alert) {
            if let Some(sender) = ALERT_SENDER.get() { let _ = sender.try_send(json_payload); }
        }

        if !lp_bytes_written.is_null() { *lp_bytes_written = 0; }
        IN_HOOK.with(|f| f.set(false));
        return 0;
    }

    IN_HOOK.with(|f| f.set(false));
    resume_original(h_file, lp_buffer, n_bytes, lp_bytes_written, lp_overlapped)
}

#[inline(always)]
unsafe fn resume_original(
    h_file: *mut c_void,
    lp_buffer: *const c_void,
    n_bytes: u32,
    lp_bytes_written: *mut u32,
    lp_overlapped: *mut c_void,
) -> i32 {
    if let Some(original) = ORIGINAL_WRITEFILE.get() {
        return original(h_file, lp_buffer, n_bytes, lp_bytes_written, lp_overlapped);
    }
    1
}

const DLL_PROCESS_ATTACH: u32 = 1;
const DLL_PROCESS_DETACH: u32 = 0;

#[no_mangle]
pub extern "system" fn DllMain(_hinst_dll: *mut c_void, fdw_reason: u32, _lpv_reserved: *mut c_void) -> i32 {
    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            unsafe {
                std::thread::spawn(move || {
                    let shutdown_file = std::path::Path::new(r"C:\ProgramData\DataSensor\Teardown.sig");
                    loop {
                        if shutdown_file.exists() {
                            unsafe {
                                minhook_sys::MH_DisableHook(std::ptr::null_mut()); // Safely detach
                                minhook_sys::MH_Uninitialize();
                            }
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                    }
                });

                let kernel32 = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(
                    b"kernelbase.dll\0".as_ptr()
                );
                if kernel32 == 0 { return 1; }

                let write_file_addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                    kernel32, b"WriteFile\0".as_ptr()
                );

                let (tx, rx) = std::sync::mpsc::sync_channel::<String>(1024);
                let _ = ALERT_SENDER.set(tx);
                let ntdll = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(
                    b"ntdll.dll\0".as_ptr()
                );
                if ntdll != 0 {
                    if let Some(fn_addr) = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                        ntdll, b"NtQueryInformationFile\0".as_ptr()
                    ) {
                        let _ = NT_QUERY_INFO_FILE.set(std::mem::transmute(fn_addr));
                    }
                }

                std::thread::spawn(move || {
                    IN_HOOK.with(|f| f.set(true));

                    for payload in rx {
                        let mut retries = 0;
                        while retries < 15 {
                            if let Ok(mut pipe) = OpenOptions::new().write(true).open(r"\\.\pipe\DataSensorAlerts") {
                                let _ = pipe.write_all(payload.as_bytes());
                                break;
                            }
                            std::thread::sleep(std::time::Duration::from_millis(20));
                            retries += 1;
                        }
                    }
                });

                if let Some(addr) = write_file_addr {
                    let addr_ptr = addr as *mut c_void;

                    if minhook_sys::MH_Initialize() != 0 { return 1; }

                    let mut original: *mut c_void = std::ptr::null_mut();
                    if minhook_sys::MH_CreateHook(addr_ptr, hooked_write_file as *mut c_void, &mut original) == 0 {
                        let _ = ORIGINAL_WRITEFILE.set(std::mem::transmute(original));
                        let _ = minhook_sys::MH_EnableHook(addr_ptr);
                    }
                }
            }
        }
        DLL_PROCESS_DETACH => {
            unsafe {
                let _ = minhook_sys::MH_DisableHook(std::ptr::null_mut()); // Disable all hooks
                let _ = minhook_sys::MH_Uninitialize();
            }
        }
        _ => {}
    }
    1
}