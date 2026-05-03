use crate::engine::rules::RawKernelEvent;
use anyhow::{Context, Result};
use libbpf_rs::RingBufferBuilder;
use std::net::Ipv4Addr;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

mod sentinel_skel {
    include!(concat!(env!("OUT_DIR"), "/sentinel.skel.rs"));
}
use sentinel_skel::SentinelSkelBuilder;

#[repr(C)]
struct event_t {
    ts_ns: u64,
    interval_ns: u64,
    pid: u32,
    ppid: u32,
    uid: u32,
    event_type: u32,
    comm: [u8; 16],
    target: [u8; 512],
    daddr: u32,
    dport: u16,
    payload: [u8; 64],
}

pub struct EbpfEngine {
    raw_tx: mpsc::Sender<RawKernelEvent>,
    kill_rx: mpsc::UnboundedReceiver<u32>,
}

impl EbpfEngine {
    pub fn new(raw_tx: mpsc::Sender<RawKernelEvent>, kill_rx: mpsc::UnboundedReceiver<u32>) -> Self {
        Self { raw_tx, kill_rx }
    }

    pub fn run(mut self) -> Result<()> {
        info!("Loading Native eBPF CO-RE skeleton...");
        let skel_builder = SentinelSkelBuilder::default();
        let open_skel = skel_builder.open().context("Failed to open BPF skeleton")?;
        let mut skel = open_skel.load().context("Failed to load BPF skeleton")?;
        skel.attach().context("Failed to attach BPF programs")?;

        let mut builder = RingBufferBuilder::new();
        let tx_clone = self.raw_tx.clone();

        builder.add(skel.maps().events(), move |data| {
            if data.len() < std::mem::size_of::<event_t>() { return 0; }
            let c_event = unsafe { &*(data.as_ptr() as *const event_t) };

            let raw_event = RawKernelEvent {
                ts_ns: c_event.ts_ns,
                interval_ns: c_event.interval_ns,
                pid: c_event.pid,
                ppid: c_event.ppid,
                uid: c_event.uid,
                event_type: c_event.event_type,
                comm: String::from_utf8_lossy(&c_event.comm).trim_matches(char::from(0)).to_string(),
                target: String::from_utf8_lossy(&c_event.target).trim_matches(char::from(0)).to_string(),
                dest_ip: Ipv4Addr::from(u32::from_be(c_event.daddr)).to_string(),
                dest_port: u16::from_be(c_event.dport),
                payload: c_event.payload.to_vec(),
            };

            // PIPELINE SHIFT: We strictly route the raw telemetry to the UEBA Scanner.
            // Absolutely no rule evaluation happens here in the kernel-bound OS thread.
            match tx_clone.try_send(raw_event) {
                Ok(_) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    warn!("SYSTEM OVERLOAD: Kernel event dropped due to UEBA pipeline backpressure.");
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    error!("FATAL: UEBA telemetry routing channel closed unexpectedly.");
                }
            }
            0
        })?;

        let ring_buf = builder.build().context("Failed to build ring buffer")?;
        info!("eBPF engine active. Streaming raw telemetry to UEBA Pipeline at 50ms intervals.");

        loop {
            // Unmanaged OS thread blocking poll; yields to kernel, consumes 0% CPU while idle
            ring_buf.poll(std::time::Duration::from_millis(50))?;

            // NON-BLOCKING MAP UPDATE: Safely update kernel maps across the FFI boundary
            while let Ok(pid) = self.kill_rx.try_recv() {
                let pid_bytes = pid.to_ne_bytes();
                let flag_bytes = 1u32.to_ne_bytes();
                if let Err(e) = skel.maps_mut().kill_list().update(&pid_bytes, &flag_bytes, libbpf_rs::MapFlags::ANY) {
                    error!("FATAL: Failed to update eBPF kill_list map for PID {}: {}", pid, e);
                } else {
                    info!("ACTIVE MITIGATION ARMED: PID {} added to kernel kill list.", pid);
                }
            }
        }
    }
}