/*=============================================================================================
 * SYSTEM:          Data Sensor - Observation & DLP
 * COMPONENT:       hook_teardown.rs (Ring-3 Hook DLL — Teardown & Re-entrancy Module)
 * DESCRIPTION:
 * 1. SENTINEL WATCHER   — A dedicated 64KB background thread monitors for the Teardown.sig
 * file at 250ms intervals. Upon detection, it invokes
 * FreeLibraryAndExitThread to facilitate a safe, self-directed
 * module ejection. Utilizing a file-based signal ensures reliable
 * communication across all session boundaries and privilege levels.
 *
 * 2. RE-ENTRANCY GUARD  — A thread-local depth counter prevents recursive hook invocation.
 * Because lower-level OS components (such as NTFS filter drivers or
 * the TCP/IP stack) may trigger WriteFile() during their own I/O
 * completions, this guard is strictly required to prevent infinite
 * recursion and subsequent stack exhaustion.
 *
 * 3. TEARDOWN GATE      — The is_teardown_requested() validation serves as the mandatory
 * initial check within every intercepted callback. When asserted,
 * the hook immediately delegates execution to the original API,
 * ensuring all in-flight I/O operations resolve safely before the
 * sentinel thread unmaps the library from memory.
 *
 * @RW
 *============================================================================================*/

use std::cell::Cell;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::LibraryLoader::FreeLibraryAndExitThread;

// ── FILE-SENTINEL CONFIGURATION ─────────────────────────────────────────────

const TEARDOWN_SIG_PATH: &str = r"C:\ProgramData\DataSensor\Teardown.sig";
const POLL_INTERVAL_MS: u64 = 250;

// ── GLOBAL STATE ─────────────────────────────────────────────────────────────

static TEARDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
static MODULE_HANDLE: OnceLock<usize> = OnceLock::new();
static IN_FLIGHT_THREADS: AtomicUsize = AtomicUsize::new(0);

// ── THREAD-LOCAL RE-ENTRANCY COUNTER ─────────────────────────────────────────

thread_local! {
    static HOOK_DEPTH: Cell<u32> = const { Cell::new(0) };
}

// ── PUBLIC API ────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub fn on_attach(h_module: usize) {
    let _ = MODULE_HANDLE.set(h_module);
    start_sentinel_watcher();
    log_diag("INFO", "Teardown sentinel watcher started (File-Sentinel mode).");
}

pub fn on_detach() {
    TEARDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

#[inline(always)]
pub fn is_teardown_requested() -> bool {
    TEARDOWN_REQUESTED.load(Ordering::Relaxed)
}

#[inline(always)]
pub fn enter_hook() -> bool {
    if TEARDOWN_REQUESTED.load(Ordering::Relaxed) {
        return false;
    }

    HOOK_DEPTH.with(|depth| {
        if depth.get() > 0 {
            return false;
        }
        depth.set(1);
        IN_FLIGHT_THREADS.fetch_add(1, Ordering::SeqCst);
        true
    })
}

#[inline(always)]
pub fn exit_hook() {
    HOOK_DEPTH.with(|depth| depth.set(0));
    IN_FLIGHT_THREADS.fetch_sub(1, Ordering::SeqCst);
}

pub struct HookGuard;

impl HookGuard {
    #[inline(always)]
    pub fn acquire() -> Option<Self> {
        if enter_hook() { Some(HookGuard) } else { None }
    }
}

impl Drop for HookGuard {
    #[inline(always)]
    fn drop(&mut self) {
        exit_hook();
    }
}

// ── INTERNAL — SENTINEL WATCHER ───────────────────────────────────────────────

fn start_sentinel_watcher() {
    let result = thread::Builder::new()
        .name("DS-Sentinel".to_string())
        .stack_size(64 * 1024)
        .spawn(sentinel_loop);

    if let Err(e) = result {
        log_diag("ERROR", &format!("Sentinel thread spawn failed: {}. Manual teardown only.", e));
    }
}

fn sentinel_loop() {
    loop {
        thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
        if Path::new(TEARDOWN_SIG_PATH).exists() {
            TEARDOWN_REQUESTED.store(true, Ordering::SeqCst);
            log_diag("WARN", "Teardown signal detected. Closing entrance gate.");
            crate::remove_hooks();
            let mut wait_cycles = 0;
            loop {
                let active = IN_FLIGHT_THREADS.load(Ordering::SeqCst);
                if active == 0 {
                    log_diag("INFO", "In-flight threads reached 0. Safe to eject.");
                    break;
                }
                wait_cycles += 1;
                if wait_cycles % 10 == 0 {
                    log_diag("WARN", &format!("Ejection paused. {} threads still in-flight.", active));
                }
                thread::sleep(Duration::from_millis(50));
            }
            eject_self();
            return;
        }
    }
}

fn eject_self() {
    #[cfg(target_os = "windows")]
    {
        if let Some(&h_module_usize) = MODULE_HANDLE.get() {
            unsafe {
                FreeLibraryAndExitThread(h_module_usize as isize, 0);
            }
        } else {
            log_diag("ERROR", "MODULE_HANDLE not set. DLL will be inert but not ejected.");
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        log_diag("INFO", "[STUB] eject_self() — non-Windows build.");
    }
}

// ── DIAGNOSTIC HELPER ─────────────────────────────────────────────────────────

fn log_diag(level: &str, message: &str) {
    use std::io::Write;

    let log_path = r"C:\ProgramData\DataSensor\Logs\DataSensor_Diagnostic.log";
    let timestamp = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("epoch+{}s", secs)
    };

    let line = format!("[{}] [{}] [DS-Hook] {}\n", timestamp, level, message);

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        let _ = file.write_all(line.as_bytes());
    }
}