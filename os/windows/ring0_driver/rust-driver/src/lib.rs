// Endpoint Monitor Driver — lib.rs
//
// A KMDF minifilter with process/thread/object/registry/network telemetry.
//
// @RW

#![no_std]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use wdk_sys::*;
use wdk_sys::ntddk::*;
use wdk_sys::ntifs::*;
use wdk_alloc::WdkAllocator;
use wdk_panic;
use fsfilter_rs::*;

#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

extern "system" {
    // Required to safely read user-mode memory without __try/__except SEH blocks
    fn MmCopyVirtualMemory(
        SourceProcess: PEPROCESS,
        SourceAddress: PVOID,
        TargetProcess: PEPROCESS,
        TargetAddress: PVOID,
        BufferSize: SIZE_T,
        PreviousMode: i8, // KPROCESSOR_MODE (UserMode = 1, KernelMode = 0)
        ReturnSize: *mut SIZE_T,
    ) -> NTSTATUS;
}

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Power-of-two ring-buffer capacity.  Doubled from 512 for burst headroom.
const MAX_EVENTS: usize = 1024;

const TAG_CONTEXT: u32 = u32::from_le_bytes(*b"monC");

/// IOCTL codes: CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, fn, METHOD_BUFFERED=0, FILE_READ_ACCESS=1)
///   0x002220xx = (0x22 << 16) | (1 << 14) | (fn << 2) | 0
const IOCTL_GET_EVENTS: u32 = 0x00224000; // fn=0x800
const IOCTL_GET_STATS:  u32 = 0x00224004; // fn=0x801

// ETW provider GUID  {12345678-ABCD-EF01-2345-6789ABCDEF01}
// Replace with a freshly generated GUID before shipping.
const PROVIDER_GUID: GUID = GUID {
    data1: 0x12345678,
    data2: 0xABCD,
    data3: 0xEF01,
    data4: [0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01],
};

// ─────────────────────────────────────────────────────────────────────────────
// Multiplexed Event Structures
// ─────────────────────────────────────────────────────────────────────────────

/// Discriminator for the User-Mode Orchestrator to route to the correct ML Sensor
#[repr(u16)]
#[derive(Clone, Copy, PartialEq)]
pub enum EventCategory {
    ProcessCreate = 1,
    ProcessExit   = 2,
    NetworkFlow   = 3,  // For IDPSSensor & C2Sensor
    FileIo        = 4,  // For OsSensor & DataSensor
    MemoryPatch   = 5,  // VirtualAlloc/Protect RWX
    NamedPipe     = 6,  // Lateral Movement (C2Sensor)
    ImageLoad     = 7,  // For DLL loads
}

/// The universal header attached to EVERY event in the byte stream.
/// Ensures alignment is strictly 8 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TelemetryHeader {
    pub timestamp:  LARGE_INTEGER, // 8 B - QPC Tick
    pub event_id:   u64,           // 8 B - Monotonic sequence
    pub pid:        u32,           // 4 B - Subject Process
    pub tid:        u32,           // 4 B - Subject Thread
    pub total_size: u16,           // 2 B - Total bytes: Header + Payload + Variable Data
    pub category:   u16,           // 2 B - EventCategory
    pub _reserved:  u32,           // 4 B - Explicit padding for 8-byte alignment
}

// ── Payloads ─────────────────────────────────────────────────────────────────
// Payloads contain NO pointers. Variable length data (like strings) is appended
// directly after the payload in the byte buffer.

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessCreatePayload {
    pub parent_pid:        u32,
    pub is_wow64:          u8,
    pub _pad:              [u8; 3],
    pub image_path_bytes:  u16,  // Length of the WCHAR string appended after payload
    pub cmdline_bytes:     u16,  // Length of the WCHAR string appended after image_path
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ImageLoadPayload {
    pub base_address: u64,
    pub image_size:   u32,
    pub is_kernel:    u8,
    pub _pad:         [u8; 1],
    pub path_bytes:   u16,  // Length of the WCHAR string appended after payload
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkFlowPayload {
    pub src_ip:     u32,   // IPv4
    pub dest_ip:    u32,
    pub src_port:   u16,
    pub dest_port:  u16,
    pub protocol:   u8,    // 6 = TCP, 17 = UDP
    pub direction:  u8,    // 0 = Ingress, 1 = Egress
    pub _pad:       u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemoryPatchPayload {
    pub target_pid:     u32,
    pub desired_access: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileIoPayload {
    pub operation:  u32,  // IRP_MJ_CREATE, IRP_MJ_WRITE, etc.
    pub path_bytes: u16,  // Length of the appended WCHAR string
    pub is_pipe:    u8,   // 1 if named pipe, 0 otherwise
    pub _pad:       u8,   // Explicit padding to maintain 8-byte alignment
}

/// Statistics exported via IOCTL_GET_STATS.
#[repr(C)]
pub struct DriverStats {
    pub events_logged:  u64,
    pub events_dropped: u64,
    pub queue_depth:    u32,
    pub queue_capacity: u32,
}

/// Per-stream file-path cache allocated with FltAllocateContext.
#[repr(C)]
pub struct MonitorStreamContext {
    pub name_len: u16,
    pub name:     [WCHAR; 260],
}

// ─────────────────────────────────────────────────────────────────────────────
// Global state: Variable-Length Byte Stream Ring Buffer
// ─────────────────────────────────────────────────────────────────────────────

const RING_BUFFER_SIZE: usize = 2 * 1024 * 1024;

/// Wrapper to guarantee 8-byte alignment for safe pointer casting.
/// Prevents EXCEPTION_DATATYPE_MISALIGNMENT BSODs.
#[repr(C, align(8))]
struct AlignedRingBuffer([u8; RING_BUFFER_SIZE]);

static mut BYTE_RING_BUFFER: AlignedRingBuffer = AlignedRingBuffer([0; RING_BUFFER_SIZE]);

static mut QUEUE_HEAD: usize = 0;
static mut QUEUE_TAIL: usize = 0;

static EVENTS_LOGGED:  AtomicU64 = AtomicU64::new(0);
static EVENTS_DROPPED: AtomicU64 = AtomicU64::new(0);
/// Monotonically increasing event sequence number.
static EVENT_ID_SEQ:   AtomicU64 = AtomicU64::new(0);

static mut QUEUE_LOCK:             KSPIN_LOCK   = 0;
static mut FILTER_HANDLE:          PFLT_FILTER  = core::ptr::null_mut();
static mut ETW_REG_HANDLE:         REGHANDLE    = 0;
static mut REG_COOKIE:             EX_COOKIE    = 0;
static mut OBJECT_CALLBACK_HANDLE: PVOID        = core::ptr::null_mut();
static mut DEVICE_OBJECT:          PDEVICE_OBJECT = core::ptr::null_mut();
static mut CURRENT_ACTIVITY_ID:    GUID = GUID { data1: 0, data2: 0, data3: 0, data4: [0; 8] };

/// Initialised by KeInitializeEvent before any callbacks fire.
static mut AGENT_EVENT: KEVENT = unsafe { core::mem::zeroed() };

/// Registered WFP callout ID; 0 means not registered.
#[cfg(feature = "network")]
static WFP_CALLOUT_ID: AtomicU32 = AtomicU32::new(0);

#[cfg(feature = "network")]
static WFP_STREAM_CALLOUT_ID: AtomicU32 = AtomicU32::new(0);

// ─────────────────────────────────────────────────────────────────────────────
// Byte-Stream Ring-Buffer Serialization
// ─────────────────────────────────────────────────────────────────────────────

/// Enqueue a variable-length event safely.
/// **MUST** be called with `QUEUE_LOCK` held (IRQL = DISPATCH_LEVEL).
/// Safely handles wrap-around. Drops event if the queue is full.

unsafe fn enqueue_byte_stream(
    header: &TelemetryHeader,
    payload_ptr: *const u8,
    payload_size: usize,
    var_data_ptr: *const u8,
    var_data_size: usize,
) -> bool {
    let total_size = header.total_size as usize;
    if total_size > RING_BUFFER_SIZE / 4 { return false; }

    let mut tail = QUEUE_TAIL;
    let head = QUEUE_HEAD;

    if tail >= head {
        if tail + total_size > RING_BUFFER_SIZE {
            let remaining = RING_BUFFER_SIZE - tail;
            if remaining >= head { return false; } // Not enough room to wrap

            // This takes O(1) time and eliminates DPC latency spikes.
            if remaining >= core::mem::size_of::<TelemetryHeader>() {
                let wrap_header = TelemetryHeader {
                    timestamp: LARGE_INTEGER { QuadPart: 0 },
                    event_id: 0,
                    pid: 0,
                    tid: 0,
                    total_size: remaining as u16,
                    category: 0xFFFF, // EventCategory::QueueWrap
                    _reserved: 0,
                };
                core::ptr::copy_nonoverlapping(
                    &wrap_header as *const _ as *const u8,
                    BYTE_RING_BUFFER.0.as_mut_ptr().add(tail),
                    core::mem::size_of::<TelemetryHeader>()
                );
            }
            tail = 0;
        }
    } else {
        if tail + total_size >= head { return false; }
    }

    // ── Safe Serialization ───────────────────────────────────────────────────
    let dest = BYTE_RING_BUFFER.0.as_mut_ptr().add(tail);

    core::ptr::copy_nonoverlapping(
        header as *const _ as *const u8,
        dest,
        core::mem::size_of::<TelemetryHeader>()
    );

    if payload_size > 0 && !payload_ptr.is_null() {
        core::ptr::copy_nonoverlapping(
            payload_ptr,
            dest.add(core::mem::size_of::<TelemetryHeader>()),
            payload_size
        );
    }

    if var_data_size > 0 && !var_data_ptr.is_null() {
        core::ptr::copy_nonoverlapping(
            var_data_ptr,
            dest.add(core::mem::size_of::<TelemetryHeader>() + payload_size),
            var_data_size
        );
    }

    QUEUE_TAIL = (tail + total_size + 7) & !7;
    true
}

/// Dequeue byte stream to User-Mode buffer via IOCTL.
/// Acquires/releases `QUEUE_LOCK` internally. Returns bytes written.
unsafe fn dequeue_byte_stream(out_buf: *mut u8, out_max_size: usize) -> usize {
    // Cap the maximum bytes copied under a spinlock to 128KB.
    // If the orchestrator asks for 2MB, only give 128KB. It will simply
    // call the IOCTL again in a loop. This keeps kernel latency exceptionally low.
    let safe_max_size = out_max_size.min(128 * 1024);

    let mut irql: KIRQL = 0;
    KeAcquireSpinLock(&mut QUEUE_LOCK, &mut irql);

    let mut bytes_read = 0;

    while QUEUE_HEAD != QUEUE_TAIL && bytes_read < safe_max_size {
        let header_ptr = BYTE_RING_BUFFER.0.as_ptr().add(QUEUE_HEAD) as *const TelemetryHeader;
        let event_size = (*header_ptr).total_size as usize;
        let category = (*header_ptr).category;

        // Failsafe against corrupt memory loops
        if event_size == 0 {
            QUEUE_HEAD = 0;
            QUEUE_TAIL = 0;
            break;
        }

        // Handle the O(1) Wrap header
        if category == 0xFFFF {
            QUEUE_HEAD = 0;
            continue;
        }

        if bytes_read + event_size > safe_max_size { break; }

        core::ptr::copy_nonoverlapping(
            BYTE_RING_BUFFER.0.as_ptr().add(QUEUE_HEAD),
            out_buf.add(bytes_read),
            event_size
        );

        bytes_read += event_size;
        QUEUE_HEAD = (QUEUE_HEAD + event_size + 7) & !7;
    }

    if QUEUE_HEAD == QUEUE_TAIL {
        QUEUE_HEAD = 0;
        QUEUE_TAIL = 0;
    }

    KeReleaseSpinLock(&mut QUEUE_LOCK, irql);
    bytes_read
}

// ─────────────────────────────────────────────────────────────────────────────
// Activity ID generation
// ─────────────────────────────────────────────────────────────────────────────

/// Return (or lazily generate) the current ETW activity correlation GUID.
/// Uses `ExGenRandom` (Win8+) for cryptographic-quality entropy.
/// Falls back to a zero GUID if entropy is unavailable; that is safe — the
/// event is still recorded, just without correlation.
unsafe fn get_current_activity_id() -> GUID {
    // Fast path: already generated.
    if CURRENT_ACTIVITY_ID.data1 != 0 || CURRENT_ACTIVITY_ID.data4[0] != 0 {
        return CURRENT_ACTIVITY_ID;
    }

    let mut id: GUID = core::mem::zeroed();
    // ExGenRandom fills an arbitrary-length byte array with kernel PRNG data.
    let status = ExGenRandom(
        &mut id as *mut GUID as *mut u8,
        core::mem::size_of::<GUID>() as ULONG,
    );
    if NT_SUCCESS(status) {
        // Set RFC 4122 version 4 / variant 1 bits.
        id.data3 = (id.data3 & 0x0FFF) | 0x4000;
        id.data4[0] = (id.data4[0] & 0x3F) | 0x80;
        CURRENT_ACTIVITY_ID = id;
    } else {
        DbgPrint!("EM: ExGenRandom failed 0x%08X — using zero GUID\0".as_ptr(), status);
    }
    id
}

// ─────────────────────────────────────────────────────────────────────────────
// ETW tracing
// ─────────────────────────────────────────────────────────────────────────────

/// Emits the multiplexed byte-stream to ETW via dynamic descriptors.
///
/// Safe at IRQL ≤ DISPATCH_LEVEL. Non-fatal: write failures occur when no
/// consumer is listening and do not affect ring-buffer enqueue.
unsafe fn trace_etw_event(
    header: &TelemetryHeader,
    payload_ptr: *const u8,
    payload_size: usize,
    var_data_ptr: *const u8,
    var_data_size: usize,
) {
    if ETW_REG_HANDLE == 0 { return; }

    // Build an array of descriptors to push the variable-length pieces
    // to ETW sequentially without requiring an extra memory allocation.
    let mut desc: [EVENT_DATA_DESCRIPTOR; 3] = core::mem::zeroed();
    let mut desc_count = 1;

    EventDataDescCreate(
        &mut desc[0],
        header as *const _ as *const core::ffi::c_void,
        core::mem::size_of::<TelemetryHeader>() as ULONG,
    );

    if payload_size > 0 && !payload_ptr.is_null() {
        EventDataDescCreate(
            &mut desc[1],
            payload_ptr as *const core::ffi::c_void,
            payload_size as ULONG,
        );
        desc_count += 1;
    }

    if var_data_size > 0 && !var_data_ptr.is_null() {
        EventDataDescCreate(
            &mut desc[2],
            var_data_ptr as *const core::ffi::c_void,
            var_data_size as ULONG,
        );
        desc_count += 1;
    }

    let s = EventWrite(ETW_REG_HANDLE, core::ptr::null(), desc_count, desc.as_mut_ptr());
    if !NT_SUCCESS(s) {
        DbgPrint!("EM: EventWrite 0x%08X\0".as_ptr(), s);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Core event logger
// ─────────────────────────────────────────────────────────────────────────────

/// Transitional bridge logger.
/// Maps the legacy `log_event` signature to the new byte-stream buffer
/// to keep existing callbacks compiling. (To be replaced with specific loggers in Step 2).
unsafe fn log_event(
    event_type: u32,
    pid:        HANDLE,
    parent_pid: HANDLE,
    path:       *const WCHAR,
    path_bytes: u16,
    _score:     u32,
) {
    let id = EVENT_ID_SEQ.fetch_add(1, Ordering::Relaxed);
    let current_tid = PsGetCurrentThreadId() as u32;
    let proc_id = pid as u32;

    // Map legacy event_type to new EventCategory to satisfy Orchestrator logic
    let category = match event_type {
        0 => EventCategory::ProcessCreate,
        7 => EventCategory::ProcessExit,
        8 => EventCategory::MemoryPatch,
        6 => EventCategory::NetworkFlow,
        _ => EventCategory::FileIo,
    } as u16;

    let mut header = TelemetryHeader {
        timestamp:  LARGE_INTEGER { QuadPart: KeQueryPerformanceCounter(core::ptr::null_mut()).QuadPart },
        event_id:   id,
        pid:        proc_id,
        tid:        current_tid,
        total_size: core::mem::size_of::<TelemetryHeader>() as u16,
        category,
        _reserved:  0,
    };

    // Pack the old arguments into a generic payload container
    // just to fulfill the serialization contract.
    let payload = ProcessCreatePayload {
        parent_pid: parent_pid as u32,
        is_wow64: 0,
        _pad: [0; 3],
        image_path_bytes: path_bytes,
        cmdline_bytes: 0,
    };

    let payload_size = core::mem::size_of::<ProcessCreatePayload>();

    // Total size cap check to prevent u16 overflow on malformed strings
    let total_calc = header.total_size as u32 + payload_size as u32 + path_bytes as u32;
    if total_calc > 0xFFFF { return; } // Drop excessively large legacy events

    header.total_size = total_calc as u16;

    // ── ETW emit (Caller's IRQL) ────────────────────────────────────────────
    trace_etw_event(
        &header,
        &payload as *const _ as *const u8,
        payload_size,
        path as *const u8,
        path_bytes as usize
    );

    // ── Ring-buffer enqueue (DISPATCH_LEVEL) ────────────────────────────────
    let mut irql: KIRQL = 0;
    KeAcquireSpinLock(&mut QUEUE_LOCK, &mut irql);

    let enqueued = enqueue_byte_stream(
        &header,
        &payload as *const _ as *const u8,
        payload_size,
        path as *const u8,
        path_bytes as usize,
    );

    KeReleaseSpinLock(&mut QUEUE_LOCK, irql);

    if enqueued {
        EVENTS_LOGGED.fetch_add(1, Ordering::Relaxed);
        #[cfg(feature = "ai_agent")]
        KeSetEvent(&mut AGENT_EVENT, 0, FALSE);
    } else {
        let dropped = EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
        if dropped.is_power_of_two() {
            DbgPrint!("EM: ring-buffer overflow — total dropped=%llu\0".as_ptr(), dropped);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Callbacks
// ─────────────────────────────────────────────────────────────────────────────

/// Safely copies memory from a user-mode process into a kernel buffer.
/// Safe to call at PASSIVE_LEVEL. Prevents Page Fault BSODs.
unsafe fn safe_read_user_string(
    source_process: PEPROCESS,
    unicode_str: *const UNICODE_STRING,
    dest_buffer: &mut [u8],
) -> u16 {
    if unicode_str.is_null() { return 0; }

    let source_len = (*unicode_str).Length as usize;
    let source_ptr = (*unicode_str).Buffer as PVOID;

    if source_len == 0 || source_ptr.is_null() { return 0; }

    // Cap the copy to our destination buffer size to prevent overflows
    let copy_size = source_len.min(dest_buffer.len());
    let mut bytes_copied: SIZE_T = 0;

    let status = MmCopyVirtualMemory(
        source_process,
        source_ptr,
        PsGetCurrentProcess(),
        dest_buffer.as_mut_ptr() as PVOID,
        copy_size as SIZE_T,
        1, // UserMode
        &mut bytes_copied,
    );

    if NT_SUCCESS(status) {
        bytes_copied as u16
    } else {
        0
    }
}

/// Process creation/termination notification.
unsafe extern "system" fn process_notify_callback(
    process: PEPROCESS,
    pid:     HANDLE,
    info:    *mut PS_CREATE_NOTIFY_INFO,
) {
    let current_tid = PsGetCurrentThreadId() as u32;
    let proc_id = pid as u32;

    if info.is_null() {
        // Process Exit
        let header = TelemetryHeader {
            timestamp: LARGE_INTEGER { QuadPart: KeQueryPerformanceCounter(core::ptr::null_mut()).QuadPart },
            event_id: EVENT_ID_SEQ.fetch_add(1, Ordering::Relaxed),
            pid: proc_id,
            tid: current_tid,
            total_size: core::mem::size_of::<TelemetryHeader>() as u16,
            category: EventCategory::ProcessExit as u16,
            _reserved: 0,
        };

        let mut irql = 0;
        KeAcquireSpinLock(&mut QUEUE_LOCK, &mut irql);
        enqueue_byte_stream(&header, core::ptr::null(), 0, core::ptr::null(), 0);
        KeReleaseSpinLock(&mut QUEUE_LOCK, irql);
        return;
    }

    // Process Create (info is NOT null)
    let parent_pid = (*info).ParentProcessId as u32;
    let creator_process = PsGetCurrentProcess(); // Process triggering the creation

    // Stack buffers for strings. Max 1024 bytes per string to prevent kernel stack overflow.
    let mut image_buf = [0u8; 1024];
    let mut cmd_buf = [0u8; 1024];

    // Safely extract strings
    let image_bytes = safe_read_user_string(creator_process, (*info).ImageFileName, &mut image_buf);
    let cmd_bytes = safe_read_user_string(creator_process, (*info).CommandLine, &mut cmd_buf);

    // Combine variable data tightly into one buffer for enqueueing
    let total_var_size = (image_bytes + cmd_bytes) as usize;
    let mut var_data = [0u8; 2048];
    if image_bytes > 0 {
        core::ptr::copy_nonoverlapping(image_buf.as_ptr(), var_data.as_mut_ptr(), image_bytes as usize);
    }
    if cmd_bytes > 0 {
        core::ptr::copy_nonoverlapping(cmd_buf.as_ptr(), var_data.as_mut_ptr().add(image_bytes as usize), cmd_bytes as usize);
    }

    let payload = ProcessCreatePayload {
        parent_pid,
        is_wow64: 0, // Can extract from info->Flags if needed
        _pad: [0; 3],
        image_path_bytes: image_bytes,
        cmdline_bytes: cmd_bytes,
    };

    let payload_size = core::mem::size_of::<ProcessCreatePayload>();
    let total_size = core::mem::size_of::<TelemetryHeader>() + payload_size + total_var_size;

    let header = TelemetryHeader {
        timestamp: LARGE_INTEGER { QuadPart: KeQueryPerformanceCounter(core::ptr::null_mut()).QuadPart },
        event_id: EVENT_ID_SEQ.fetch_add(1, Ordering::Relaxed),
        pid: proc_id,
        tid: current_tid,
        total_size: total_size as u16,
        category: EventCategory::ProcessCreate as u16,
        _reserved: 0,
    };

    let mut irql = 0;
    KeAcquireSpinLock(&mut QUEUE_LOCK, &mut irql);

    let enqueued = enqueue_byte_stream(
        &header,
        &payload as *const _ as *const u8,
        payload_size,
        if total_var_size > 0 { var_data.as_ptr() } else { core::ptr::null() },
        total_var_size,
    );

    KeReleaseSpinLock(&mut QUEUE_LOCK, irql);

    if enqueued {
        EVENTS_LOGGED.fetch_add(1, Ordering::Relaxed);
    } else {
        EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

// DLL Load Notification
unsafe extern "system" fn image_load_notify_callback(
    full_image_name: PUNICODE_STRING,
    process_id: HANDLE,
    image_info: PIMAGE_INFO,
) {
    if full_image_name.is_null() || image_info.is_null() { return; }

    let proc_id = process_id as u32;
    // Exclude system/kernel space image loads to save immense IO Overhead
    if proc_id == 0 || (*image_info).SystemModeImage != 0 { return; }

    let mut path_buf = [0u8; 1024];
    // Since Image loads happen in the context of the loading process, can copy safely
    let path_bytes = safe_read_user_string(PsGetCurrentProcess(), full_image_name, &mut path_buf);

    let payload = ImageLoadPayload {
        base_address: (*image_info).ImageBase as u64,
        image_size: (*image_info).ImageSize as u32,
        is_kernel: (*image_info).SystemModeImage as u8,
        _pad: [0; 1],
        path_bytes,
    };

    let payload_size = core::mem::size_of::<ImageLoadPayload>();
    let total_size = core::mem::size_of::<TelemetryHeader>() + payload_size + path_bytes as usize;

    let header = TelemetryHeader {
        timestamp: LARGE_INTEGER { QuadPart: KeQueryPerformanceCounter(core::ptr::null_mut()).QuadPart },
        event_id: EVENT_ID_SEQ.fetch_add(1, Ordering::Relaxed),
        pid: proc_id,
        tid: PsGetCurrentThreadId() as u32,
        total_size: total_size as u16,
        category: EventCategory::ImageLoad as u16,
        _reserved: 0,
    };

    let mut irql = 0;
    KeAcquireSpinLock(&mut QUEUE_LOCK, &mut irql);
    let enqueued = enqueue_byte_stream(&header, &payload as *const _ as *const u8, payload_size, path_buf.as_ptr(), path_bytes as usize);
    KeReleaseSpinLock(&mut QUEUE_LOCK, irql);

    if enqueued { EVENTS_LOGGED.fetch_add(1, Ordering::Relaxed); }
}

/// Thread creation notification.
#[cfg(feature = "threads")]
unsafe extern "system" fn thread_notify_callback(
    pid:    HANDLE,
    tid:    HANDLE,
    create: BOOLEAN,
) {
    if create == 0 { return; }
    // Cross-process thread creation is a strong injection indicator.
    let score = if PsGetCurrentProcessId() != pid { 900 } else { 0 };
    log_event(7, pid, tid, core::ptr::null(), 0, score);
}

/// Internal helper to serialize file events to the byte stream securely.
/// Safe at APC_LEVEL. Performs zero-allocation substring checks.
#[inline]
unsafe fn emit_file_telemetry(op: u32, path_ptr: *const WCHAR, path_bytes: u16) {
    if path_ptr.is_null() || path_bytes == 0 { return; }

    let wchars = (path_bytes / 2) as usize;
    let path_slice = core::slice::from_raw_parts(path_ptr, wchars);
    let mut is_pipe = 0;

    // Fast-path heuristic: Scan for "pipe" (case-insensitive).
    // The bitwise OR with 0x0020 safely converts ASCII uppercase to lowercase
    // without branching, keeping the CPU pipeline fully saturated.
    if wchars >= 4 {
        for i in 0..=(wchars - 4) {
            if (path_slice[i]   | 0x0020) == 0x0070 && // 'p'
               (path_slice[i+1] | 0x0020) == 0x0069 && // 'i'
               (path_slice[i+2] | 0x0020) == 0x0070 && // 'p'
               (path_slice[i+3] | 0x0020) == 0x0065    // 'e'
            {
                is_pipe = 1;
                break;
            }
        }
    }

    let category = if is_pipe == 1 { EventCategory::NamedPipe as u16 } else { EventCategory::FileIo as u16 };

    let payload = FileIoPayload {
        operation: op,
        path_bytes,
        is_pipe,
        _pad: 0,
    };

    let payload_size = core::mem::size_of::<FileIoPayload>();

    // Cap maximum path size to 2048 bytes to prevent ring-buffer starvation
    // from maliciously crafted, infinitely long directory paths.
    let safe_path_bytes = path_bytes.min(2048);
    let total_size = core::mem::size_of::<TelemetryHeader>() + payload_size + safe_path_bytes as usize;

    let header = TelemetryHeader {
        timestamp: LARGE_INTEGER { QuadPart: KeQueryPerformanceCounter(core::ptr::null_mut()).QuadPart },
        event_id: EVENT_ID_SEQ.fetch_add(1, Ordering::Relaxed),
        pid: PsGetCurrentProcessId() as u32,
        tid: PsGetCurrentThreadId() as u32,
        total_size: total_size as u16,
        category,
        _reserved: 0,
    };

    let mut irql = 0;
    KeAcquireSpinLock(&mut QUEUE_LOCK, &mut irql);
    let enqueued = enqueue_byte_stream(
        &header,
        &payload as *const _ as *const u8,
        payload_size,
        path_ptr as *const u8,
        safe_path_bytes as usize
    );
    KeReleaseSpinLock(&mut QUEUE_LOCK, irql);

    if enqueued { EVENTS_LOGGED.fetch_add(1, Ordering::Relaxed); }
}

/// Minifilter pre-operation for CREATE / READ / WRITE / CLEANUP.
unsafe extern "system" fn pre_operation_callback(
    data: *mut FLT_CALLBACK_DATA,
    obj:  PFLT_RELATED_OBJECTS,
    _:    *mut PVOID,
) -> FLT_PREOP_CALLBACK_STATUS {
    if data.is_null() || obj.is_null() { return FLT_PREOP_SUCCESS_NO_CALLBACK; }
    if (*obj).FileObject.is_null()     { return FLT_PREOP_SUCCESS_NO_CALLBACK; }

    let op = (*(*data).Iopb).MajorFunction as u32;
    let mut ctx: PFLT_CONTEXT = core::ptr::null_mut();

    let status = FltGetStreamContext((*obj).Instance, (*obj).FileObject, &mut ctx);
    if NT_SUCCESS(status) {
        // Fast path: context already cached from a prior IRP_MJ_CREATE.
        let sctx = ctx as *mut MonitorStreamContext;
        emit_file_telemetry(op, (*sctx).name.as_ptr(), (*sctx).name_len * 2);
        FltReleaseContext(ctx);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Slow path: only on IRP_MJ_CREATE — fetch name, cache it, and emit.
    if op != IRP_MJ_CREATE { return FLT_PREOP_SUCCESS_NO_CALLBACK; }

    let mut name_ptr: PFLT_FILE_NAME_INFORMATION = core::ptr::null_mut();
    let name_status = FltGetFileNameInformation(
        data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &mut name_ptr,
    );

    if !NT_SUCCESS(name_status) || name_ptr.is_null() {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    let parse_status = FltParseFileNameInformation(name_ptr);
    if NT_SUCCESS(parse_status) {

        emit_file_telemetry(op, (*name_ptr).Name.Buffer, (*name_ptr).Name.Length);

        // Allocate and populate a stream context for future READ/WRITE callbacks.
        let mut new_ctx: PFLT_CONTEXT = core::ptr::null_mut();
        let alloc_status = FltAllocateContext(
            FILTER_HANDLE,
            FLT_STREAM_CONTEXT,
            core::mem::size_of::<MonitorStreamContext>() as SIZE_T,
            NonPagedPoolNx,
            &mut new_ctx,
        );

        if NT_SUCCESS(alloc_status) && !new_ctx.is_null() {
            let sctx = new_ctx as *mut MonitorStreamContext;
            let wchars = ((*name_ptr).Name.Length / 2).min(260);
            (*sctx).name_len = wchars;

            core::ptr::copy_nonoverlapping(
                (*name_ptr).Name.Buffer,
                (*sctx).name.as_mut_ptr(),
                wchars as usize,
            );

            let set_status = FltSetStreamContext(
                (*obj).Instance,
                (*obj).FileObject,
                FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                new_ctx,
                core::ptr::null_mut(),
            );

            FltReleaseContext(new_ctx);
            if !NT_SUCCESS(set_status) && set_status != STATUS_FLT_CONTEXT_ALREADY_DEFINED {
                DbgPrint!("EM: FltSetStreamContext 0x%08X\0".as_ptr(), set_status);
            }
        }
    }

    FltReleaseFileNameInformation(name_ptr);
    FLT_PREOP_SUCCESS_NO_CALLBACK
}

/// Stream context cleanup callback (no heap members — nothing to free).
unsafe extern "system" fn context_cleanup_callback(
    _context: PFLT_CONTEXT,
    _type:    FLT_CONTEXT_TYPE,
) {}

/// Object callback — detects cross-process memory injection and handle manipulation.
#[cfg(feature = "objects")]
unsafe extern "system" fn object_callback(
    _:        PVOID,
    pre_info: *mut OB_PRE_OPERATION_INFORMATION,
) -> OB_PREOP_CALLBACK_STATUS {
    if pre_info.is_null() || (*pre_info).Object.is_null() { return OB_PREOP_SUCCESS; }

    // Strictly registered for PsProcessType
    if (*pre_info).ObjectType != *PsProcessType { return OB_PREOP_SUCCESS; }

    // Retrieve the original access mask requested by the thread
    let access = if (*pre_info).Operation == OB_OPERATION_HANDLE_CREATE {
        (*pre_info).Parameters.CreateHandleInformation.OriginalDesiredAccess
    } else {
        (*pre_info).Parameters.DuplicateHandleInformation.OriginalDesiredAccess
    };

    // 0x0020 (PROCESS_VM_WRITE) | 0x0008 (PROCESS_VM_OPERATION)
    // This exact combination is the classic indicator of remote thread injection,
    // process hollowing, and credential dumping toolkits (e.g., Mimikatz).
    let is_injection_access = (access & 0x0028) == 0x0028;

    if is_injection_access {
        let target_pid = PsGetProcessId((*pre_info).Object as PEPROCESS) as u32;
        let caller_pid = PsGetCurrentProcessId() as u32;

        // Filter out self-modification (processes are allowed to write to their own memory)
        if caller_pid != target_pid {

            // NOTE: Future Self-Defense Mechanism Placeholder.
            // If `target_pid` matches the user-mode C2Sensor/OsSensor PID, then
            // actively strip the access rights here to prevent termination or blinding.
            // e.g., (*pre_info).Parameters.CreateHandleInformation.DesiredAccess &= !0x0029;

            // Serialize and Enqueue Telemetry
            let payload = MemoryPatchPayload {
                target_pid,
                desired_access: access,
            };

            let payload_size = core::mem::size_of::<MemoryPatchPayload>();
            let total_size = core::mem::size_of::<TelemetryHeader>() + payload_size;

            let header = TelemetryHeader {
                timestamp: LARGE_INTEGER { QuadPart: KeQueryPerformanceCounter(core::ptr::null_mut()).QuadPart },
                event_id: EVENT_ID_SEQ.fetch_add(1, Ordering::Relaxed),
                pid: caller_pid, // The actor requesting the handle
                tid: PsGetCurrentThreadId() as u32,
                total_size: total_size as u16,
                category: EventCategory::MemoryPatch as u16,
                _reserved: 0,
            };

            let mut irql = 0;
            KeAcquireSpinLock(&mut QUEUE_LOCK, &mut irql);
            let enqueued = enqueue_byte_stream(&header, &payload as *const _ as *const u8, payload_size, core::ptr::null(), 0);
            KeReleaseSpinLock(&mut QUEUE_LOCK, irql);

            if enqueued { EVENTS_LOGGED.fetch_add(1, Ordering::Relaxed); }
        }
    }

    OB_PREOP_SUCCESS
}

/// Registry operation callback.
#[cfg(feature = "registry")]
unsafe extern "system" fn registry_callback(
    _context:  PVOID,
    _reg_type: PVOID,
    reg_info:  PVOID,
) -> NTSTATUS {
    // reg_info is a raw C pointer — a Rust `if let Some()` on a raw pointer
    // does NOT null-check it.  Check explicitly.
    if reg_info.is_null() { return STATUS_SUCCESS; }

    let info = reg_info as *const REG_NOTIFY_INFORMATION;
    if (*info).Object.is_null() { return STATUS_SUCCESS; }

    // Retrieve the kernel object's key path via the registered cookie.
    // CmCallbackGetKeyObjectIDEx is available since Windows 8.
    let mut key_name: *mut UNICODE_STRING = core::ptr::null_mut();
    let name_status = CmCallbackGetKeyObjectIDEx(
        &REG_COOKIE,
        (*info).Object,
        core::ptr::null_mut(),
        &mut key_name,
        0,
    );

    if NT_SUCCESS(name_status) && !key_name.is_null() && !(*key_name).Buffer.is_null() {
        let len = (*key_name).Length.min(520); // ≤ 260 WCHARs
        log_event(5, PsGetCurrentProcessId(), core::ptr::null_mut(), (*key_name).Buffer, len, 0);
        CmCallbackReleaseKeyObjectIDEx(key_name as PVOID);
    } else {
        // Non-fatal: log the pid/timestamp at least, path will be empty.
        log_event(5, PsGetCurrentProcessId(), core::ptr::null_mut(), core::ptr::null(), 0, 0);
    }
    STATUS_SUCCESS
}

// ─────────────────────────────────────────────────────────────────────────────
// WFP Network Telemetry (ALE Layer)
// ─────────────────────────────────────────────────────────────────────────────

// WFP Constants mapped manually to avoid wdk-sys binding bloat
const FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS: isize = 0;
const FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS: isize = 1;
const FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT: isize = 2;
const FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT: isize = 3;
const FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL: isize = 4;
const FWPS_METADATA_FIELD_PROCESS_ID: u64 = 0x00000020;
const FWP_ACTION_PERMIT: u32 = 0x00000001;

#[cfg(feature = "network")]
unsafe extern "system" fn ale_auth_connect_v4_callout(
    in_fixed_values: *const FWPS_INCOMING_VALUES0,
    in_meta_values:  *const FWPS_INCOMING_METADATA_VALUES0,
    _layer_data:     *mut core::ffi::c_void,
    _classify_ctx:   *const core::ffi::c_void,
    _filter:         *const FWPS_FILTER0,
    _flow_context:   u64,
    classify_out:    *mut FWPS_CLASSIFY_OUT0,
) {
    // Defensively check pointers (WFP can occasionally pass null contexts during teardown)
    if in_fixed_values.is_null() || in_meta_values.is_null() || classify_out.is_null() {
        return;
    }

    // Permit Traffic by Default (Fail-Open to prevent network bricking)
    // Explicitly set this, otherwise the packet is dropped.
    (*classify_out).actionType = FWP_ACTION_PERMIT;

    // Extract 5-Tuple (WFP stores IPv4 as Host Byte Order uint32)
    let values_ptr = (*in_fixed_values).incomingValue;

    // Bounds check to ensure WFP passed the expected number of fields for this layer
    if (*in_fixed_values).valueCount <= FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL as u32 {
        return;
    }

    // (Adjust union field `.uint32` below if the wdk-sys bindgen uses `__bindgen_anon_1.uint32`)
    let src_ip   = (*values_ptr.offset(FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS)).value.uint32;
    let dest_ip  = (*values_ptr.offset(FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS)).value.uint32;
    let src_port = (*values_ptr.offset(FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT)).value.uint16;
    let dest_port= (*values_ptr.offset(FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT)).value.uint16;
    let protocol = (*values_ptr.offset(FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL)).value.uint8;

    // Drop internal loopback traffic early to save Ring Buffer space (127.0.0.1)
    if dest_ip == 0x7F000001 { return; }

    // Extract High-Fidelity PID directly from the networking stack
    let mut pid = 0;
    if ((*in_meta_values).currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) != 0 {
        pid = (*in_meta_values).processId as u32;
    }

    // Serialize and Enqueue
    let payload = NetworkFlowPayload {
        src_ip,
        dest_ip,
        src_port,
        dest_port,
        protocol,
        direction: 1, // 1 = Egress (Connect implies outbound)
        _pad: 0,
    };

    let payload_size = core::mem::size_of::<NetworkFlowPayload>();
    let total_size = core::mem::size_of::<TelemetryHeader>() + payload_size;

    let header = TelemetryHeader {
        timestamp: LARGE_INTEGER { QuadPart: KeQueryPerformanceCounter(core::ptr::null_mut()).QuadPart },
        event_id: EVENT_ID_SEQ.fetch_add(1, Ordering::Relaxed),
        pid,
        tid: PsGetCurrentThreadId() as u32,
        total_size: total_size as u16,
        category: EventCategory::NetworkFlow as u16,
        _reserved: 0,
    };

    let mut irql = 0;
    KeAcquireSpinLock(&mut QUEUE_LOCK, &mut irql);
    let enqueued = enqueue_byte_stream(&header, &payload as *const _ as *const u8, payload_size, core::ptr::null(), 0);
    KeReleaseSpinLock(&mut QUEUE_LOCK, irql);

    if enqueued { EVENTS_LOGGED.fetch_add(1, Ordering::Relaxed); }
}

// WFP Stream Constants
const FWPS_FIELD_STREAM_V4_IP_LOCAL_ADDRESS: isize = 0;
const FWPS_FIELD_STREAM_V4_IP_REMOTE_ADDRESS: isize = 1;
const FWPS_FIELD_STREAM_V4_IP_LOCAL_PORT: isize = 2;
const FWPS_FIELD_STREAM_V4_IP_REMOTE_PORT: isize = 3;
const FWPS_STREAM_FLAG_RECEIVE: u32 = 0x00000001;
const FWPS_STREAM_FLAG_SEND: u32 = 0x00000002;

extern "system" {
    fn FwpsCopyStreamDataToBuffer0(
        streamData: *const FWPS_STREAM_DATA0,
        buffer: *mut core::ffi::c_void,
        bufferLength: SIZE_T,
        bytesCopied: *mut SIZE_T,
    );
}

#[cfg(feature = "network")]
unsafe extern "system" fn stream_v4_callout(
    in_fixed_values: *const FWPS_INCOMING_VALUES0,
    in_meta_values:  *const FWPS_INCOMING_METADATA_VALUES0,
    layer_data:      *mut core::ffi::c_void,
    _classify_ctx:   *const core::ffi::c_void,
    _filter:         *const FWPS_FILTER0,
    _flow_context:   u64,
    classify_out:    *mut FWPS_CLASSIFY_OUT0,
) {
    if in_fixed_values.is_null() || classify_out.is_null() || layer_data.is_null() {
        return;
    }

    // Fail-Open: Always permit the traffic immediately to prevent network halting
    (*classify_out).actionType = FWP_ACTION_PERMIT;

    let stream_data = layer_data as *const FWPS_STREAM_DATA0;
    if (*stream_data).dataLength == 0 { return; }

    // Extract 5-Tuple
    let values_ptr = (*in_fixed_values).incomingValue;
    if (*in_fixed_values).valueCount <= FWPS_FIELD_STREAM_V4_IP_REMOTE_PORT as u32 { return; }

    let src_ip   = (*values_ptr.offset(FWPS_FIELD_STREAM_V4_IP_LOCAL_ADDRESS)).value.uint32;
    let dest_ip  = (*values_ptr.offset(FWPS_FIELD_STREAM_V4_IP_REMOTE_ADDRESS)).value.uint32;
    let src_port = (*values_ptr.offset(FWPS_FIELD_STREAM_V4_IP_LOCAL_PORT)).value.uint16;
    let dest_port= (*values_ptr.offset(FWPS_FIELD_STREAM_V4_IP_REMOTE_PORT)).value.uint16;

    // Drop internal loopback
    if dest_ip == 0x7F000001 || src_ip == 0x7F000001 { return; }

    // Determine Direction
    let direction = if ((*stream_data).flags & FWPS_STREAM_FLAG_SEND) != 0 { 1 } else { 0 };

    // Safe Extraction: Cap at 256 bytes to prevent queue starvation.
    // 256 bytes is precisely enough to capture TLS Client Hello (JA3) and DNS queries.
    let copy_len = (*stream_data).dataLength.min(256);
    let mut payload_buffer = [0u8; 256];
    let mut bytes_copied: SIZE_T = 0;

    FwpsCopyStreamDataToBuffer0(
        stream_data,
        payload_buffer.as_mut_ptr() as *mut _,
        copy_len as SIZE_T,
        &mut bytes_copied
    );

    if bytes_copied == 0 { return; }

    let mut pid = 0;
    if !in_meta_values.is_null() && ((*in_meta_values).currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) != 0 {
        pid = (*in_meta_values).processId as u32;
    }

    // Serialize and Enqueue
    let payload = NetworkFlowPayload {
        src_ip,
        dest_ip,
        src_port,
        dest_port,
        protocol: 6, // FWPS_LAYER_STREAM_V4 is exclusively TCP
        direction,
        _pad: 0,
    };

    let payload_size = core::mem::size_of::<NetworkFlowPayload>();
    let total_size = core::mem::size_of::<TelemetryHeader>() + payload_size + bytes_copied as usize;

    let header = TelemetryHeader {
        timestamp: LARGE_INTEGER { QuadPart: KeQueryPerformanceCounter(core::ptr::null_mut()).QuadPart },
        event_id: EVENT_ID_SEQ.fetch_add(1, Ordering::Relaxed),
        pid,
        tid: PsGetCurrentThreadId() as u32,
        total_size: total_size as u16,
        category: EventCategory::NetworkFlow as u16,
        _reserved: 0,
    };

    let mut irql = 0;
    KeAcquireSpinLock(&mut QUEUE_LOCK, &mut irql);
    let enqueued = enqueue_byte_stream(
        &header,
        &payload as *const _ as *const u8,
        payload_size,
        payload_buffer.as_ptr(),
        bytes_copied as usize
    );
    KeReleaseSpinLock(&mut QUEUE_LOCK, irql);

    if enqueued { EVENTS_LOGGED.fetch_add(1, Ordering::Relaxed); }
}

// ─────────────────────────────────────────────────────────────────────────────
// Device-object dispatch helpers
// ─────────────────────────────────────────────────────────────────────────────

/// IRP completion helper — fills IoStatus and calls IofCompleteRequest.
#[inline]
unsafe fn complete_irp(irp: PIRP, status: NTSTATUS, info: usize) -> NTSTATUS {
    (*irp).IoStatus.__bindgen_anon_1.Status = status;
    (*irp).IoStatus.Information = info;
    IofCompleteRequest(irp, IO_NO_INCREMENT as i8);
    status
}

/// IRP_MJ_CREATE / IRP_MJ_CLOSE — succeed silently so usermode can open the device.
unsafe extern "system" fn create_close_handler(
    _device: PDEVICE_OBJECT,
    irp: PIRP,
) -> NTSTATUS {
    complete_irp(irp, STATUS_SUCCESS, 0)
}

/// IRP_MJ_DEVICE_CONTROL — exposes ring-buffer data and statistics.
unsafe extern "system" fn ioctl_handler(
    _device: PDEVICE_OBJECT,
    irp:     PIRP,
) -> NTSTATUS {
    let stack   = IoGetCurrentIrpStackLocation(irp);
    let code    = (*stack).Parameters.DeviceIoControl.IoControlCode;
    let out_len = (*stack).Parameters.DeviceIoControl.OutputBufferLength as usize;

    match code {
        IOCTL_GET_EVENTS => {
            if out_len == 0 {
                return complete_irp(irp, STATUS_BUFFER_TOO_SMALL, 0);
            }
            let buf = (*irp).AssociatedIrp.SystemBuffer as *mut u8;
            if buf.is_null() {
                return complete_irp(irp, STATUS_INVALID_PARAMETER, 0);
            }
            // Fetch as many raw bytes as will fit into the user's buffer
            let bytes_copied = dequeue_byte_stream(buf, out_len);
            complete_irp(irp, STATUS_SUCCESS, bytes_copied)
        }

        IOCTL_GET_STATS => {
            if out_len < core::mem::size_of::<DriverStats>() {
                return complete_irp(irp, STATUS_BUFFER_TOO_SMALL, 0);
            }
            let buf = (*irp).AssociatedIrp.SystemBuffer as *mut DriverStats;
            if buf.is_null() {
                return complete_irp(irp, STATUS_INVALID_PARAMETER, 0);
            }
            let head  = QUEUE_HEAD.load(Ordering::Relaxed);
            let tail  = QUEUE_TAIL.load(Ordering::Relaxed);
            let depth = if tail >= head { tail - head } else { MAX_EVENTS - head + tail };
            *buf = DriverStats {
                events_logged:  EVENTS_LOGGED.load(Ordering::Relaxed),
                events_dropped: EVENTS_DROPPED.load(Ordering::Relaxed),
                queue_depth:    depth as u32,
                queue_capacity: MAX_EVENTS as u32,
            };
            complete_irp(irp, STATUS_SUCCESS, core::mem::size_of::<DriverStats>())
        }

        _ => complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST, 0),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Filter/callback registration tables
// ─────────────────────────────────────────────────────────────────────────────

static OP_REG: [FLT_OPERATION_REGISTRATION; 5] = [
    FLT_OPERATION_REGISTRATION {
        MajorFunction: IRP_MJ_CREATE,
        Flags: 0,
        PreOperation:  Some(pre_operation_callback),
        PostOperation: None,
        Reserved1: 0,
    },
    FLT_OPERATION_REGISTRATION {
        MajorFunction: IRP_MJ_READ,
        // Skip paging-I/O reads to avoid excessive DISPATCH-level callbacks.
        // System paging traffic is very high volume with near-zero security value.
        Flags: FLTFL_OPERATION_REGISTRATION_SKIP_CACHED_IO
             | FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
        PreOperation:  Some(pre_operation_callback),
        PostOperation: None,
        Reserved1: 0,
    },
    FLT_OPERATION_REGISTRATION {
        MajorFunction: IRP_MJ_WRITE,
        Flags: FLTFL_OPERATION_REGISTRATION_SKIP_CACHED_IO
             | FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
        PreOperation:  Some(pre_operation_callback),
        PostOperation: None,
        Reserved1: 0,
    },
    FLT_OPERATION_REGISTRATION {
        // IRP_MJ_CLEANUP: file object is about to be closed.
        // Registering here ensures stream contexts are released promptly and
        // no context reference is held past the last file-handle close.
        MajorFunction: IRP_MJ_CLEANUP,
        Flags: 0,
        PreOperation:  Some(pre_operation_callback),
        PostOperation: None,
        Reserved1: 0,
    },
    FLT_OPERATION_REGISTRATION {
        MajorFunction: IRP_MJ_OPERATION_END,
        Flags: 0,
        PreOperation:  None,
        PostOperation: None,
        Reserved1: 0,
    },
];

static CONTEXT_REG: [FLT_CONTEXT_REGISTRATION; 2] = [
    FLT_CONTEXT_REGISTRATION {
        ContextType: FLT_STREAM_CONTEXT,
        Flags: 0,
        ContextCleanupCallback: Some(context_cleanup_callback),
        Size: core::mem::size_of::<MonitorStreamContext>(),
        PoolTag: TAG_CONTEXT,
    },
    FLT_CONTEXT_REGISTRATION {
        ContextType: FLT_CONTEXT_END,
        Flags: 0,
        ContextCleanupCallback: None,
        Size: 0,
        PoolTag: 0,
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// DriverEntry cleanup helper
// ─────────────────────────────────────────────────────────────────────────────

/// Unwind all registrations that succeeded before `FltRegisterFilter`.
/// Called from early-return failure paths in `driver_entry`.
unsafe fn cleanup_pre_filter() {
    #[cfg(feature = "objects")]
    if !OBJECT_CALLBACK_HANDLE.is_null() {
        // ObUnRegisterCallbacks returns VOID — do NOT check a return value.
        ObUnRegisterCallbacks(OBJECT_CALLBACK_HANDLE);
        OBJECT_CALLBACK_HANDLE = core::ptr::null_mut();
    }
    #[cfg(feature = "threads")]
    { PsRemoveCreateThreadNotifyRoutine(Some(thread_notify_callback)); }

    // Unregister Image Load Callback
    PsRemoveLoadImageNotifyRoutine(Some(image_load_notify_callback));

    // Unregister Process Callback
    PsSetCreateProcessNotifyRoutineEx(Some(process_notify_callback), TRUE);
}

// ─────────────────────────────────────────────────────────────────────────────
// DriverEntry
// ─────────────────────────────────────────────────────────────────────────────

#[export_name = "DriverEntry"]
pub unsafe extern "system" fn driver_entry(
    driver:    PDRIVER_OBJECT,
    _registry: PCUNICODE_STRING,
) -> NTSTATUS {

    KeInitializeSpinLock(&mut QUEUE_LOCK);

    #[cfg(feature = "ai_agent")]
    KeInitializeEvent(&mut AGENT_EVENT, NotificationEvent, FALSE);

    // ── Process notification ─────────────────────────────────────────────────
    let mut s = PsSetCreateProcessNotifyRoutineEx(Some(process_notify_callback), FALSE);
    if !NT_SUCCESS(s) {
        DbgPrint!("EM: PsSetCreateProcessNotifyRoutineEx 0x%08X\0".as_ptr(), s);
        return s;
    }

    // ── Image Load notification ──────────────────────────────────────────────
    s = PsSetLoadImageNotifyRoutine(Some(image_load_notify_callback));
    if !NT_SUCCESS(s) {
        DbgPrint!("EM: PsSetLoadImageNotifyRoutine 0x%08X\0".as_ptr(), s);
        // Not strictly fatal, but standard practice is to abort if blind.
        PsSetCreateProcessNotifyRoutineEx(Some(process_notify_callback), TRUE);
        return s;
    }

    // ── Thread notification ──────────────────────────────────────────────────
    #[cfg(feature = "threads")]
    {
        s = PsSetCreateThreadNotifyRoutine(Some(thread_notify_callback));
        if !NT_SUCCESS(s) {
            DbgPrint!("EM: PsSetCreateThreadNotifyRoutine 0x%08X\0".as_ptr(), s);
            PsSetCreateProcessNotifyRoutineEx(Some(process_notify_callback), TRUE);
            return s;
        }
    }

    // ── Object callbacks ─────────────────────────────────────────────────────
    #[cfg(feature = "objects")]
    {
        let mut obj_op = OB_OPERATION_REGISTRATION {
            ObjectType: PsProcessType,
            Operations: OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
            PreOperation:  Some(object_callback),
            PostOperation: None,
        };
        // Use a distinct altitude from the minifilter (320000) to avoid conflicts.
        let alt_str = RtlInitUnicodeString("321000\0");
        let mut cb_reg = OB_CALLBACK_REGISTRATION {
            Version: OB_FLT_REGISTRATION_VERSION,
            OperationRegistrationCount: 1,
            Altitude: alt_str,
            RegistrationContext: core::ptr::null_mut(),
            OperationRegistration: &mut obj_op,
        };
        s = ObRegisterCallbacks(&cb_reg, &mut OBJECT_CALLBACK_HANDLE);
        if !NT_SUCCESS(s) {
            DbgPrint!("EM: ObRegisterCallbacks 0x%08X\0".as_ptr(), s);
            #[cfg(feature = "threads")]
            PsRemoveCreateThreadNotifyRoutine(Some(thread_notify_callback));
            PsSetCreateProcessNotifyRoutineEx(Some(process_notify_callback), TRUE);
            return s;
        }
    }

    // ── Minifilter ───────────────────────────────────────────────────────────
    let mut reg: FLT_REGISTRATION = core::mem::zeroed();
    reg.Size                  = core::mem::size_of::<FLT_REGISTRATION>() as USHORT;
    reg.Version               = FLT_REGISTRATION_VERSION;
    reg.OperationRegistration = OP_REG.as_ptr();
    reg.FilterUnloadCallback  = Some(unload_callback);
    reg.ContextRegistration   = CONTEXT_REG.as_ptr();

    s = FltRegisterFilter(driver, &reg, &mut FILTER_HANDLE);
    if !NT_SUCCESS(s) {
        DbgPrint!("EM: FltRegisterFilter 0x%08X\0".as_ptr(), s);
        cleanup_pre_filter();
        return s;
    }

    s = FltStartFiltering(FILTER_HANDLE);
    if !NT_SUCCESS(s) {
        DbgPrint!("EM: FltStartFiltering 0x%08X\0".as_ptr(), s);
        FltUnregisterFilter(FILTER_HANDLE);
        FILTER_HANDLE = core::ptr::null_mut();
        cleanup_pre_filter();
        return s;
    }

    // ── ETW (non-fatal — driver still operates without it) ──────────────────
    s = EtwRegister(&PROVIDER_GUID, None, core::ptr::null_mut(), &mut ETW_REG_HANDLE);
    if !NT_SUCCESS(s) {
        DbgPrint!("EM: EtwRegister 0x%08X (non-fatal)\0".as_ptr(), s);
    }

    // ── Registry callback (non-fatal) ────────────────────────────────────────
    #[cfg(feature = "registry")]
    {
        let mut altitude = RtlInitUnicodeString("320000\0");
        s = CmRegisterCallbackEx(
            Some(registry_callback),
            &altitude,
            driver as PVOID,
            core::ptr::null_mut(),
            &mut REG_COOKIE,
            core::ptr::null_mut(),
        );
        if !NT_SUCCESS(s) {
            DbgPrint!("EM: CmRegisterCallbackEx 0x%08X (non-fatal)\0".as_ptr(), s);
        }
    }

    // ── WFP callout (non-fatal) ──────────────────────────────────────────────
    #[cfg(feature = "network")]
    {
        // Register ALE Auth Connect Callout
        let mut ale_callout: FWPS_CALLOUT0 = core::mem::zeroed();
        ale_callout.calloutKey = GUID {
            data1: 0x87654321, data2: 0xDCBA, data3: 0x10FE,
            data4: [0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x10],
        };
        ale_callout.classifyFn = Some(core::mem::transmute(ale_auth_connect_v4_callout as *const ()));

        let mut ale_id: u32 = 0;
        let s1 = FwpsCalloutRegister0(DEVICE_OBJECT as *mut _, &ale_callout, &mut ale_id);
        if NT_SUCCESS(s1) { WFP_CALLOUT_ID.store(ale_id, Ordering::SeqCst); }
        else { DbgPrint!("EM: FwpsCalloutRegister0 (ALE) 0x%08X\0".as_ptr(), s1); }

        // Register Stream Callout
        let mut stream_callout: FWPS_CALLOUT0 = core::mem::zeroed();
        stream_callout.calloutKey = GUID {
            data1: 0x12345678, data2: 0x90AB, data3: 0xCDEF,
            data4: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        };
        stream_callout.classifyFn = Some(core::mem::transmute(stream_v4_callout as *const ()));

        let mut stream_id: u32 = 0;
        let s2 = FwpsCalloutRegister0(DEVICE_OBJECT as *mut _, &stream_callout, &mut stream_id);
        if NT_SUCCESS(s2) { WFP_STREAM_CALLOUT_ID.store(stream_id, Ordering::SeqCst); }
        else { DbgPrint!("EM: FwpsCalloutRegister0 (Stream) 0x%08X\0".as_ptr(), s2); }
    }

    // ── Device object + symbolic link ────────────────────────────────────────
    // FILE_DEVICE_SECURE_OPEN ensures the device ACL is applied to all
    // open requests, preventing unprivileged usermode access to event data.
    let mut dev_name = RtlInitUnicodeString("\\Device\\EndpointMonitor\0");
    s = IoCreateDevice(
        driver,
        0,
        &mut dev_name,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &mut DEVICE_OBJECT,
    );
    if NT_SUCCESS(s) {
        // Register dispatch routines — IRP_MJ_CREATE/CLOSE must succeed for
        // usermode to open the device handle at all.
        (*driver).MajorFunction[IRP_MJ_CREATE as usize]         = Some(create_close_handler);
        (*driver).MajorFunction[IRP_MJ_CLOSE as usize]          = Some(create_close_handler);
        (*driver).MajorFunction[IRP_MJ_DEVICE_CONTROL as usize] = Some(ioctl_handler);

        let mut symlink = RtlInitUnicodeString("\\DosDevices\\EndpointMonitor\0");
        let sym_s = IoCreateSymbolicLink(&mut symlink, &mut dev_name);
        if !NT_SUCCESS(sym_s) {
            DbgPrint!("EM: IoCreateSymbolicLink 0x%08X\0".as_ptr(), sym_s);
        }
    } else {
        DbgPrint!("EM: IoCreateDevice 0x%08X (non-fatal)\0".as_ptr(), s);
        DEVICE_OBJECT = core::ptr::null_mut();
    }

    DbgPrint!("EM: loaded v0.7.0\0".as_ptr());
    STATUS_SUCCESS
}

// ─────────────────────────────────────────────────────────────────────────────
// Unload callback
// ─────────────────────────────────────────────────────────────────────────────

/// Called by Filter Manager when the filter is being unloaded.
///
/// **Ordering matters** — callbacks that can still enqueue events must be
/// removed before tear down of the structures they write into.  The correct
/// order is:
///   1. Process / thread / object callbacks (stop new events)
///   2. Registry / network callbacks
///   3. ETW (drains pending writes synchronously)
///   4. Device object / symbolic link (stop IOCTL traffic)
///   5. Return SUCCESS — Filter Manager calls FltUnregisterFilter for us;
///      do NOT call it here or throws a double-unregister bug.
unsafe extern "system" fn unload_callback(_flags: FLT_REGISTRATION_FLAGS) -> NTSTATUS {

    // 1 ── Stop event sources ─────────────────────────────────────────────────

    // Unregister Image Load Callback
    PsRemoveLoadImageNotifyRoutine(Some(image_load_notify_callback));

    // Unregister Process Callback
    PsSetCreateProcessNotifyRoutineEx(Some(process_notify_callback), TRUE);

    #[cfg(feature = "threads")]
    PsRemoveCreateThreadNotifyRoutine(Some(thread_notify_callback));

    #[cfg(feature = "objects")]
    if !OBJECT_CALLBACK_HANDLE.is_null() {
        // ObUnRegisterCallbacks is VOID — no return value to check.
        ObUnRegisterCallbacks(OBJECT_CALLBACK_HANDLE);
        OBJECT_CALLBACK_HANDLE = core::ptr::null_mut();
    }

    // 2 ── Stop registry / network monitoring ─────────────────────────────────
    #[cfg(feature = "registry")]
    if REG_COOKIE != 0 {
        let s = CmUnRegisterCallback(REG_COOKIE);
        if !NT_SUCCESS(s) { DbgPrint!("EM: CmUnRegisterCallback 0x%08X\0".as_ptr(), s); }
        REG_COOKIE = 0;
    }

    #[cfg(feature = "network")]
    {
        let ale_id = WFP_CALLOUT_ID.swap(0, Ordering::SeqCst);
        if ale_id != 0 {
            let s = FwpsCalloutUnregisterById0(ale_id);
            if !NT_SUCCESS(s) { DbgPrint!("EM: FwpsCalloutUnregisterById0 (ALE) 0x%08X\0".as_ptr(), s); }
        }

        let stream_id = WFP_STREAM_CALLOUT_ID.swap(0, Ordering::SeqCst);
        if stream_id != 0 {
            let s = FwpsCalloutUnregisterById0(stream_id);
            if !NT_SUCCESS(s) { DbgPrint!("EM: FwpsCalloutUnregisterById0 (Stream) 0x%08X\0".as_ptr(), s); }
        }
    }

    // 3 ── ETW flush ──────────────────────────────────────────────────────────
    if ETW_REG_HANDLE != 0 {
        // EtwUnregister waits for all in-flight EventWrite calls to complete.
        EtwUnregister(ETW_REG_HANDLE);
        ETW_REG_HANDLE = 0;
    }

    // 4 ── Device object teardown ─────────────────────────────────────────────
    if !DEVICE_OBJECT.is_null() {
        let mut symlink = RtlInitUnicodeString("\\DosDevices\\EndpointMonitor\0");
        IoDeleteSymbolicLink(&mut symlink);
        IoDeleteDevice(DEVICE_OBJECT);
        DEVICE_OBJECT = core::ptr::null_mut();
    }

    #[cfg(feature = "ai_agent")]
    KeClearEvent(&mut AGENT_EVENT);

    DbgPrint!("EM: unloaded. logged=%llu dropped=%llu\0".as_ptr(),
        EVENTS_LOGGED.load(Ordering::Relaxed),
        EVENTS_DROPPED.load(Ordering::Relaxed));

    STATUS_SUCCESS
    // 5 ── Filter Manager calls FltUnregisterFilter after this returns. ───────
}