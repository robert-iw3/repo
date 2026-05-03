#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_FILENAME 256
#define MAX_PAYLOAD 64

// Linux Event Mapping
enum event_id {
    EVENT_EXEC          = 1, // T1059 Command and Scripting Interpreter
    EVENT_OPEN_CRIT     = 2, // T1083 / T1005 (File/Cred Access)
    EVENT_CONNECT       = 3, // T1071 / T1571 (C2)
    EVENT_PTRACE        = 4, // T1055 Process Injection
    EVENT_MEMFD         = 5, // T1620 Payload Execution (Fileless)
    EVENT_MODULE        = 6, // T1547.006 Kernel Modules / Rootkits
    EVENT_BPF           = 7, // T1562.001 Impair Defenses (eBPF Blinding)
    EVENT_UDP_SEND      = 8, // T1573 Encrypted Channel / DNS C2
};

// Unified, tightly packed payload for Rust FFI and ML feature extraction
struct event_t {
    u64 ts_ns;
    u64 interval_ns;         // Critical for Execution Velocity (ML)
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 event_type;
    char comm[TASK_COMM_LEN];
    char target[MAX_FILENAME];
    u32 daddr;
    u16 dport;
    u8 payload[MAX_PAYLOAD]; // Critical for Shannon Entropy (ML)
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 * 1024 * 1024); // 2MB buffer for deep inspection loads
} events SEC(".maps");

// BPF Map to track process timing for velocity calculations (in-kernel ML prep)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);   // PID
    __type(value, u64); // Last Timestamp
} proc_timestamps SEC(".maps");

#define POPULATE_CORE(evt, e_type) do { \
    evt->ts_ns = bpf_ktime_get_ns(); \
    evt->pid = bpf_get_current_pid_tgid() >> 32; \
    evt->uid = bpf_get_current_uid_gid(); \
    evt->event_type = e_type; \
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm)); \
    struct task_struct *task = (struct task_struct *)bpf_get_current_task(); \
    BPF_CORE_READ_INTO(&evt->ppid, task, real_parent, tgid); \
    u64 *last_ts = bpf_map_lookup_elem(&proc_timestamps, &evt->pid); \
    if (last_ts) { \
        evt->interval_ns = evt->ts_ns - *last_ts; \
    } else { \
        evt->interval_ns = 0; \
    } \
    bpf_map_update_elem(&proc_timestamps, &evt->pid, &evt->ts_ns, BPF_ANY); \
} while(0)


// 1. Process Execution (TA0002)
SEC("tracepoint/syscalls/sys_enter_execve")
int tp__sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_EXEC);
    const char *argp = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&evt->target, sizeof(evt->target), argp);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// 2. High-Risk File Access (DLP, Credential Access, Persistence)
SEC("tracepoint/syscalls/sys_enter_openat")
int tp__sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    int flags = ctx->args[2];

    // Only capture writes, appends, and creations to drop read-only noise
    if ((flags & O_WRONLY) || (flags & O_RDWR) || (flags & O_CREAT)) {
        struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
        if (!evt) return 0;

        POPULATE_CORE(evt, EVENT_OPEN_CRIT);
        const char *argp = (const char *)ctx->args[1];
        bpf_probe_read_user_str(&evt->target, sizeof(evt->target), argp);

        bpf_ringbuf_submit(evt, 0);
    }
    return 0;
}

// 3. Fileless Malware Execution (T1620)
SEC("tracepoint/syscalls/sys_enter_memfd_create")
int tp__sys_enter_memfd_create(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_MEMFD);
    const char *argp = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&evt->target, sizeof(evt->target), argp);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// 4. Defense Evasion - Impair Defenses (T1562.001) / eBPF Tampering
SEC("tracepoint/syscalls/sys_enter_bpf")
int tp__sys_enter_bpf(struct trace_event_raw_sys_enter *ctx) {
    int cmd = ctx->args[0];
    // Alert on processes trying to load new BPF programs or modify maps
    if (cmd == BPF_PROG_LOAD || cmd == BPF_MAP_UPDATE_ELEM) {
        struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
        if (!evt) return 0;

        POPULATE_CORE(evt, EVENT_BPF);
        bpf_ringbuf_submit(evt, 0);
    }
    return 0;
}

// 5. Persistence - Kernel Modules / Rootkits (T1547.006)
SEC("tracepoint/syscalls/sys_enter_init_module")
int tp__sys_enter_init_module(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_MODULE);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int tp__sys_enter_finit_module(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_MODULE);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// 6. Process Injection (T1055)
SEC("tracepoint/syscalls/sys_enter_ptrace")
int tp__sys_enter_ptrace(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_PTRACE);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// 7. C2 & Exfiltration (Outbound TCP)
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk) {
    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_CONNECT);
    BPF_CORE_READ_INTO(&evt->daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&evt->dport, sk, __sk_common.skc_dport);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// 8. DNS Tunneling & UDP Exfiltration (T1573)
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(trace_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    POPULATE_CORE(evt, EVENT_UDP_SEND);

    BPF_CORE_READ_INTO(&evt->daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&evt->dport, sk, __sk_common.skc_dport);

    struct iovec iov = {};
    const void *iov_ptr = BPF_CORE_READ(msg, msg_iter.__iov);
    if (iov_ptr && bpf_probe_read_kernel(&iov, sizeof(iov), iov_ptr) == 0) {
        bpf_probe_read_user(&evt->payload, sizeof(evt->payload), iov.iov_base);
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}