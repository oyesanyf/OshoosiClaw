// +build ignore
/*
 * OshoosiClaw Linux eBPF Ring-Buffer Probes & LSM Parity
 * 
 * Provides kernel-space telemetry via BPF RingBuffer (process exec/exit, connect)
 * and hardware-speed pre-operation process execution blocking via Linux Security Module (LSM)
 * BPF hook bprm_check_security.
 */

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../include/osoosi_ebpf_types.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define EPERM 1

// Process Ring Buffer Map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} process_ring SEC(".maps");

// Network Ring Buffer Map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} network_ring SEC(".maps");

// Blocked Binary Paths Map for LSM Enforced Blocking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[OSOOSI_PATH_LEN]);
    __type(value, uint32_t);
} blocked_paths SEC(".maps");

// Linux tracepoint sched_process_exec context definition
struct trace_event_raw_sched_process_exec {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __data_loc_filename;
    int pid;
    int old_pid;
};

// Linux tracepoint sched_process_exit context definition
struct trace_event_raw_sched_process_exit {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    char comm[16];
    int pid;
    int prio;
};

// Linux syscall sys_enter_connect context definition
struct trace_event_raw_sys_enter_connect {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long int id;
    unsigned long int fd;
    void *uservaddr;
    unsigned long int addrlen;
};

// Hook 1: Process Execution Tracepoint
SEC("tp/sched/sched_process_exec")
int handle_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct ebpf_process_event *event;

    event = bpf_ringbuf_reserve(&process_ring, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint64_t uid_gid = bpf_get_current_uid_gid();

    event->pid = (uint32_t)(pid_tgid >> 32);
    event->ppid = 0; // Filled from task_struct in full CO-RE environment
    event->uid = (uint32_t)uid_gid;
    event->gid = (uint32_t)(uid_gid >> 32);
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = OSOOSI_EBPF_EVENT_EXEC;
    event->_pad = 0;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Read executable path from dynamic offset in tracepoint
    unsigned short filename_offset = (unsigned short)(ctx->__data_loc_filename & 0xFFFF);
    const char *filename_ptr = (const char *)ctx + filename_offset;
    bpf_probe_read_str(&event->filename, sizeof(event->filename), filename_ptr);

    // Read process command line / args placeholder
    event->args[0] = '\0';

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Hook 2: Process Exit Tracepoint
SEC("tp/sched/sched_process_exit")
int handle_process_exit(struct trace_event_raw_sched_process_exit *ctx) {
    struct ebpf_process_event *event;

    event = bpf_ringbuf_reserve(&process_ring, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint64_t uid_gid = bpf_get_current_uid_gid();

    event->pid = (uint32_t)(pid_tgid >> 32);
    event->ppid = 0;
    event->uid = (uint32_t)uid_gid;
    event->gid = (uint32_t)(uid_gid >> 32);
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = OSOOSI_EBPF_EVENT_EXIT;
    event->_pad = 0;

    bpf_probe_read_kernel_str(&event->comm, sizeof(event->comm), ctx->comm);
    event->filename[0] = '\0';
    event->args[0] = '\0';

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Hook 3: Network Connect Syscall Tracepoint
SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter_connect *ctx) {
    struct ebpf_network_event *event;
    void *sockaddr_ptr = ctx->uservaddr;
    if (!sockaddr_ptr || ctx->addrlen < 8) {
        return 0;
    }

    uint16_t family = 0;
    bpf_probe_read_user(&family, sizeof(family), sockaddr_ptr);

    // Support AF_INET (IPv4) and AF_INET6 (IPv6)
    if (family != 2 && family != 10) {
        return 0;
    }

    event = bpf_ringbuf_reserve(&network_ring, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    event->pid = (uint32_t)(pid_tgid >> 32);
    event->family = family;
    event->sport = 0;
    event->_pad = 0;
    event->timestamp_ns = bpf_ktime_get_ns();

    if (family == 2) { // AF_INET
        // sockaddr_in: sin_port at offset 2, sin_addr at offset 4
        bpf_probe_read_user(&event->dport, sizeof(event->dport), (const char *)sockaddr_ptr + 2);
        bpf_probe_read_user(&event->daddr, 4, (const char *)sockaddr_ptr + 4);
    } else { // AF_INET6
        // sockaddr_in6: sin6_port at offset 2, sin6_addr at offset 8
        bpf_probe_read_user(&event->dport, sizeof(event->dport), (const char *)sockaddr_ptr + 2);
        bpf_probe_read_user(&event->daddr, 16, (const char *)sockaddr_ptr + 8);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Minimal linux_binprm representation for LSM hook
struct linux_binprm {
    char buf[128];
    void *file;
    const char *filename;
    const char *interp;
};

// Hook 4: Linux Security Module (LSM) Pre-Operation Execution Block
// Intercepts binary launch and returns -EPERM before the process can execute!
SEC("lsm/bprm_check_security")
int BPF_PROG(test_bprm_check, struct linux_binprm *bprm) {
    char filename[OSOOSI_PATH_LEN] = {0};

    if (!bprm) {
        return 0;
    }

    // Read target binary filename from bprm
    const char *fn_ptr = BPF_CORE_READ(bprm, filename);
    if (!fn_ptr) {
        return 0;
    }

    bpf_probe_read_kernel_str(filename, sizeof(filename), fn_ptr);

    // Look up path in kernel blocked_paths map
    uint32_t *rule_val = bpf_map_lookup_elem(&blocked_paths, filename);
    if (rule_val && *rule_val != 0) {
        // Enforce Ring-0 execution block on Linux!
        // Also emit block event into process_ring for EDR audit trail
        struct ebpf_process_event *event = bpf_ringbuf_reserve(&process_ring, sizeof(*event), 0);
        if (event) {
            uint64_t pid_tgid = bpf_get_current_pid_tgid();
            uint64_t uid_gid = bpf_get_current_uid_gid();
            event->pid = (uint32_t)(pid_tgid >> 32);
            event->ppid = 0;
            event->uid = (uint32_t)uid_gid;
            event->gid = (uint32_t)(uid_gid >> 32);
            event->timestamp_ns = bpf_ktime_get_ns();
            event->event_type = OSOOSI_EBPF_EVENT_LSM_BLOCK;
            event->_pad = 0;
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            bpf_probe_read_kernel_str(&event->filename, sizeof(event->filename), filename);
            event->args[0] = '\0';
            bpf_ringbuf_submit(event, 0);
        }

        bpf_printk("OshoosiClaw LSM: BLOCKED execution of binary %s\n", filename);
        return -EPERM;
    }

    return 0;
}
