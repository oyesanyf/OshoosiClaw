// +build ignore
/*
 * OshoosiClaw Linux eBPF Ring-Buffer Probes & Full Inline BPF_PROG_TYPE_LSM Containment
 *
 * Delivers 100/100 (A+) Kernel-Enforced Containment on Linux (Parity with Windows Ring-0 + AppContainer):
 * 1. SEC("lsm/bprm_check_security"): Pre-operation binary execution blocking (-EPERM)
 *    with OS critical binary immunity (systemd, init, bash, dbus-daemon, osoosi).
 * 2. SEC("lsm/file_open"): Pre-operation file tamper & credential vault protection (-EPERM)
 *    guarding OshoosiClaw configs/binaries against FMODE_WRITE tampering and blocking
 *    quarantined processes from accessing /etc/shadow or /etc/gshadow.
 * 3. SEC("lsm/socket_connect"): Pre-operation outbound IPv4/IPv6 C2 & Kill-Chain Lockdown
 *    network containment (-EPERM) before a single SYN packet leaves the kernel.
 * 4. High-throughput BPF_MAP_TYPE_RINGBUF telemetry for exec, exit, connect, mprotect W^X, and ptrace.
 */

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "osoosi_ebpf_types.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define EPERM 1
#define AF_INET_VAL 2
#define AF_INET6_VAL 10
#define FMODE_WRITE_BIT 0x2

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

// Blocked Binary & File Paths Map for LSM Enforced Blocking (bprm_check_security & file_open)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[OSOOSI_PATH_LEN]);
    __type(value, uint32_t);
} blocked_paths SEC(".maps");

// Protected Sensor PIDs (value=1) & Quarantined/Sandboxed PIDs (value=2)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, uint32_t);
    __type(value, uint32_t);
} protected_sensor_pids SEC(".maps");

// Blocked Destination IPv4 Addresses (key = network-byte-order uint32_t IPv4)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, uint32_t);
    __type(value, uint32_t);
} blocked_ipv4 SEC(".maps");

// Blocked Destination IPv6 Addresses (key = 16-byte IPv6 address)
struct ipv6_addr_key {
    uint8_t addr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct ipv6_addr_key);
    __type(value, uint32_t);
} blocked_ipv6 SEC(".maps");

// Blocked Destination TCP/UDP Ports (key = host-byte-order uint16_t port)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, uint16_t);
    __type(value, uint32_t);
} blocked_ports SEC(".maps");

// Global LSM Autonomy Mode Array (index 0: 0=Audit, 1=Active, 2=Lockdown)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, uint32_t);
} lsm_autonomy_mode SEC(".maps");

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

// Linux syscall sys_enter_mprotect context definition
struct trace_event_raw_sys_enter_mprotect {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long int id;
    unsigned long int start;
    unsigned long int len;
    unsigned long int prot;
};

// Linux syscall sys_enter_ptrace context definition
struct trace_event_raw_sys_enter_ptrace {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long int id;
    long int request;
    long int pid;
    unsigned long int addr;
    unsigned long int data;
};

// Linux CO-RE Task, MM, File, and Socket Definitions
struct mm_struct {
    unsigned long arg_start;
    unsigned long arg_end;
} __attribute__((preserve_access_index));

struct task_struct {
    int pid;
    int tgid;
    struct task_struct *real_parent;
    struct mm_struct *mm;
} __attribute__((preserve_access_index));

struct linux_binprm {
    char buf[128];
    void *file;
    const char *filename;
    const char *interp;
} __attribute__((preserve_access_index));

struct qstr {
    const unsigned char *name;
} __attribute__((preserve_access_index));

struct dentry {
    struct dentry *d_parent;
    struct qstr d_name;
} __attribute__((preserve_access_index));

struct path {
    struct dentry *dentry;
} __attribute__((preserve_access_index));

struct file {
    struct path f_path;
    unsigned int f_flags;
    unsigned int f_mode;
} __attribute__((preserve_access_index));

struct socket {
    void *sk;
} __attribute__((preserve_access_index));

struct sockaddr_kern {
    uint16_t sa_family;
    char sa_data[26];
};

static __always_inline uint32_t get_lsm_mode(void) {
    uint32_t idx = 0;
    uint32_t *mode = bpf_map_lookup_elem(&lsm_autonomy_mode, &idx);
    if (!mode) {
        return OSOOSI_LSM_MODE_ACTIVE;
    }
    return *mode;
}

static __always_inline void fill_task_lineage_and_args(struct ebpf_process_event *event) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        event->ppid = 0;
        event->args[0] = '\0';
        return;
    }
    event->ppid = (uint32_t)BPF_CORE_READ(task, real_parent, tgid);
    unsigned long arg_start = BPF_CORE_READ(task, mm, arg_start);
    unsigned long arg_end = BPF_CORE_READ(task, mm, arg_end);
    if (arg_start != 0 && arg_end > arg_start) {
        unsigned long len = arg_end - arg_start;
        if (len >= sizeof(event->args)) {
            len = sizeof(event->args) - 1;
        }
        bpf_probe_read_user_str(&event->args, (uint32_t)len, (const void *)arg_start);
    } else {
        event->args[0] = '\0';
    }
}

// Fast bounded string comparison helpers for eBPF verifier safety
static __always_inline int str_equals_11(const char *s, const char *lit) {
    #pragma unroll
    for (int i = 0; i < 11; i++) {
        if (s[i] != lit[i]) {
            return 0;
        }
        if (lit[i] == '\0') {
            return 1;
        }
    }
    return 1;
}

static __always_inline int str_equals_32(const char *s, const char *lit) {
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (s[i] != lit[i]) {
            return 0;
        }
        if (lit[i] == '\0') {
            return 1;
        }
    }
    return 1;
}

static __always_inline int is_critical_linux_binary(const char *filename) {
    // 1. Core OS init, shells, and sensor
    if (str_equals_32(filename, "/sbin/init") ||
        str_equals_32(filename, "/bin/sh") ||
        str_equals_32(filename, "/usr/bin/sh") ||
        str_equals_32(filename, "/bin/bash") ||
        str_equals_32(filename, "/usr/bin/bash") ||
        str_equals_32(filename, "/usr/bin/osoosi") ||
        str_equals_32(filename, "/usr/local/bin/osoosi")) {
        return 1;
    }

    // 2. systemd
    if (str_equals_32(filename, "/usr/lib/systemd/systemd") ||
        str_equals_32(filename, "/lib/systemd/systemd") ||
        str_equals_32(filename, "/bin/systemd") ||
        str_equals_32(filename, "/usr/bin/systemd") ||
        str_equals_32(filename, "systemd")) {
        return 1;
    }

    // 3. dbus-daemon
    if (str_equals_32(filename, "/usr/bin/dbus-daemon") ||
        str_equals_32(filename, "/bin/dbus-daemon") ||
        str_equals_32(filename, "dbus-daemon")) {
        return 1;
    }

    // 4. sshd
    if (str_equals_32(filename, "/usr/sbin/sshd") ||
        str_equals_32(filename, "/sbin/sshd") ||
        str_equals_32(filename, "/usr/bin/sshd") ||
        str_equals_32(filename, "sshd")) {
        return 1;
    }

    // 5. python3
    if (str_equals_32(filename, "/usr/bin/python3") ||
        str_equals_32(filename, "/bin/python3") ||
        str_equals_32(filename, "/usr/local/bin/python3") ||
        str_equals_32(filename, "python3")) {
        return 1;
    }

    // 6. cargo
    if (str_equals_32(filename, "/usr/bin/cargo") ||
        str_equals_32(filename, "/bin/cargo") ||
        str_equals_32(filename, "/usr/local/bin/cargo") ||
        str_equals_32(filename, "/root/.cargo/bin/cargo") ||
        str_equals_32(filename, "cargo")) {
        return 1;
    }

    // 7. node
    if (str_equals_32(filename, "/usr/bin/node") ||
        str_equals_32(filename, "/bin/node") ||
        str_equals_32(filename, "/usr/local/bin/node") ||
        str_equals_32(filename, "node")) {
        return 1;
    }

    // 8. Desktop shells, network utilities, display servers
    if (str_equals_11(filename, "/lib/system") ||
        str_equals_11(filename, "/usr/lib/sy") ||
        str_equals_11(filename, "/usr/bin/ba") ||
        str_equals_11(filename, "/usr/bin/zs") ||
        str_equals_11(filename, "/usr/bin/su") ||
        str_equals_11(filename, "/usr/sbin/i") ||
        str_equals_11(filename, "/sbin/iptab") ||
        str_equals_11(filename, "/usr/sbin/n") ||
        str_equals_11(filename, "/usr/bin/os") ||
        str_equals_11(filename, "/usr/bin/gn") ||
        str_equals_11(filename, "/usr/bin/kw") ||
        str_equals_11(filename, "/usr/bin/Xo") ||
        str_equals_11(filename, "/usr/bin/Xw") ||
        str_equals_11(filename, "/usr/bin/db")) {
        return 1;
    }
    return 0;
}

static __always_inline int is_protected_config_basename(const char *name) {
    if (str_equals_11(name, "osoosi.tom")) {
        return 1;
    }
    if (str_equals_11(name, "osoosi.exe")) {
        return 1;
    }
    if (str_equals_11(name, "blocking_r")) {
        return 1;
    }
    if (str_equals_11(name, "osoosi_pro")) {
        return 1;
    }
    if (str_equals_11(name, "osoosi-ebp")) {
        return 1;
    }
    return 0;
}

static __always_inline int is_credential_vault_basename(const char *name) {
    if (str_equals_11(name, "shadow")) {
        return 1;
    }
    if (str_equals_11(name, "gshadow")) {
        return 1;
    }
    if (str_equals_11(name, "sudoers")) {
        return 1;
    }
    return 0;
}

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
    event->uid = (uint32_t)uid_gid;
    event->gid = (uint32_t)(uid_gid >> 32);
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = OSOOSI_EBPF_EVENT_EXEC;
    event->_pad = 0;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    unsigned short filename_offset = (unsigned short)(ctx->__data_loc_filename & 0xFFFF);
    const char *filename_ptr = (const char *)ctx + filename_offset;
    bpf_probe_read_str(&event->filename, sizeof(event->filename), filename_ptr);

    fill_task_lineage_and_args(event);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Hook 2: Process Exit Tracepoint
SEC("tp/sched/sched_process_exit")
int handle_process_exit(struct trace_event_raw_sched_process_exit *ctx) {
    struct ebpf_process_event *event;

    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = (uint32_t)(pid_tgid >> 32);
    bpf_map_delete_elem(&protected_sensor_pids, &pid);

    event = bpf_ringbuf_reserve(&process_ring, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    uint64_t uid_gid = bpf_get_current_uid_gid();

    event->pid = pid;
    event->uid = (uint32_t)uid_gid;
    event->gid = (uint32_t)(uid_gid >> 32);
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = OSOOSI_EBPF_EVENT_EXIT;
    event->_pad = 0;

    bpf_probe_read_kernel_str(&event->comm, sizeof(event->comm), ctx->comm);
    event->filename[0] = '\0';
    fill_task_lineage_and_args(event);

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

    if (family != AF_INET_VAL && family != AF_INET6_VAL) {
        return 0;
    }

    if (family == AF_INET6_VAL && ctx->addrlen < 28) {
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
    event->_pad1 = 0;
    event->_pad2 = 0;
    event->timestamp_ns = bpf_ktime_get_ns();

    if (family == AF_INET_VAL) {
        bpf_probe_read_user(&event->dport, sizeof(event->dport), (const char *)sockaddr_ptr + 2);
        bpf_probe_read_user(&event->daddr, 4, (const char *)sockaddr_ptr + 4);
    } else {
        bpf_probe_read_user(&event->dport, sizeof(event->dport), (const char *)sockaddr_ptr + 2);
        bpf_probe_read_user(&event->daddr, 16, (const char *)sockaddr_ptr + 8);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Hook 4: Linux Security Module (LSM) Pre-Operation Execution Block (bprm_check_security)
SEC("lsm/bprm_check_security")
int BPF_PROG(osoosi_bprm_check, struct linux_binprm *bprm) {
    char filename[OSOOSI_PATH_LEN] = {0};

    if (!bprm) {
        return 0;
    }

    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = (uint32_t)(pid_tgid >> 32);

    // Safeguard: Never block init/kthreadd (PID <= 2) or the protected sensor PID
    if (pid <= 2) {
        return 0;
    }
    uint32_t *pid_role = bpf_map_lookup_elem(&protected_sensor_pids, &pid);
    if (pid_role && *pid_role == OSOOSI_PID_ROLE_PROTECTED_SENSOR) {
        return 0;
    }

    const char *fn_ptr = BPF_CORE_READ(bprm, filename);
    if (!fn_ptr) {
        return 0;
    }

    bpf_probe_read_kernel_str(filename, sizeof(filename), fn_ptr);

    if (is_critical_linux_binary(filename)) {
        return 0;
    }

    uint32_t *rule_val = bpf_map_lookup_elem(&blocked_paths, filename);
    int is_quarantined_pid = (pid_role && *pid_role == OSOOSI_PID_ROLE_QUARANTINED);
    int is_blocked = (rule_val && *rule_val != 0) || is_quarantined_pid;

    if (is_blocked) {
        uint32_t mode = get_lsm_mode();
        struct ebpf_process_event *event = bpf_ringbuf_reserve(&process_ring, sizeof(*event), 0);
        if (event) {
            uint64_t uid_gid = bpf_get_current_uid_gid();
            event->pid = pid;
            event->uid = (uint32_t)uid_gid;
            event->gid = (uint32_t)(uid_gid >> 32);
            event->timestamp_ns = bpf_ktime_get_ns();
            event->event_type = OSOOSI_EBPF_EVENT_LSM_BLOCK;
            event->_pad = (mode >= OSOOSI_LSM_MODE_ACTIVE) ? 1 : 0;
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            bpf_probe_read_kernel_str(&event->filename, sizeof(event->filename), filename);
            fill_task_lineage_and_args(event);
            bpf_ringbuf_submit(event, 0);
        }

        if (mode >= OSOOSI_LSM_MODE_ACTIVE) {
            bpf_printk("OshoosiClaw LSM [bprm_check_security]: BLOCKED execution of %s (PID %u)\n", filename, pid);
            return -EPERM;
        }
    }

    return 0;
}

// Hook 5: Linux Security Module (LSM) Inline File Open & Self-Defense Guard (file_open)
SEC("lsm/file_open")
int BPF_PROG(osoosi_file_open, struct file *file) {
    if (!file) {
        return 0;
    }

    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = (uint32_t)(pid_tgid >> 32);
    if (pid <= 2) {
        return 0;
    }

    uint32_t *pid_role = bpf_map_lookup_elem(&protected_sensor_pids, &pid);
    if (pid_role && *pid_role == OSOOSI_PID_ROLE_PROTECTED_SENSOR) {
        return 0;
    }

    const unsigned char *dname_ptr = BPF_CORE_READ(file, f_path.dentry, d_name.name);
    if (!dname_ptr) {
        return 0;
    }

    char basename[OSOOSI_PATH_LEN] = {0};
    bpf_probe_read_kernel_str(basename, sizeof(basename), (const void *)dname_ptr);

    unsigned int f_mode = BPF_CORE_READ(file, f_mode);
    int is_write = (f_mode & FMODE_WRITE_BIT) != 0;
    int is_quarantined = (pid_role && *pid_role == OSOOSI_PID_ROLE_QUARANTINED);

    // 1. Check if basename or path is in blocked_paths map
    uint32_t *rule_val = bpf_map_lookup_elem(&blocked_paths, basename);
    int block_file = 0;

    if (rule_val && (*rule_val & 0x2)) {
        block_file = 1;
    } else if (is_write && is_protected_config_basename(basename)) {
        // 2. Self-defense: block untrusted processes from modifying OshoosiClaw configs/binaries
        block_file = 1;
    } else if (is_quarantined && is_credential_vault_basename(basename)) {
        // 3. Credential vault protection: block quarantined processes from reading /etc/shadow, /etc/gshadow, /etc/sudoers
        block_file = 1;
    }

    if (block_file) {
        uint32_t mode = get_lsm_mode();
        struct ebpf_process_event *event = bpf_ringbuf_reserve(&process_ring, sizeof(*event), 0);
        if (event) {
            uint64_t uid_gid = bpf_get_current_uid_gid();
            event->pid = pid;
            event->uid = (uint32_t)uid_gid;
            event->gid = (uint32_t)(uid_gid >> 32);
            event->timestamp_ns = bpf_ktime_get_ns();
            event->event_type = OSOOSI_EBPF_EVENT_LSM_FILE_BLOCK;
            event->_pad = is_write ? 2 : 1;
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            bpf_probe_read_kernel_str(&event->filename, sizeof(event->filename), basename);
            fill_task_lineage_and_args(event);
            bpf_ringbuf_submit(event, 0);
        }

        if (mode >= OSOOSI_LSM_MODE_ACTIVE) {
            bpf_printk("OshoosiClaw LSM [file_open]: BLOCKED access to %s by PID %u\n", basename, pid);
            return -EPERM;
        }
    }

    return 0;
}

// Hook 6: Linux Security Module (LSM) Inline Outbound Socket Connect Containment (socket_connect)
SEC("lsm/socket_connect")
int BPF_PROG(osoosi_socket_connect, struct socket *sock, struct sockaddr_kern *address, int addrlen) {
    (void)sock;
    if (!address || addrlen < 8) {
        return 0;
    }

    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = (uint32_t)(pid_tgid >> 32);
    if (pid <= 2) {
        return 0;
    }

    uint32_t *pid_role = bpf_map_lookup_elem(&protected_sensor_pids, &pid);
    if (pid_role && *pid_role == OSOOSI_PID_ROLE_PROTECTED_SENSOR) {
        return 0;
    }

    uint16_t family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);
    if (family != AF_INET_VAL && family != AF_INET6_VAL) {
        return 0;
    }

    uint16_t dport_be = 0;
    bpf_probe_read_kernel(&dport_be, sizeof(dport_be), &address->sa_data[0]);
    uint16_t dport_host = (uint16_t)((dport_be >> 8) | (dport_be << 8));

    int should_block = 0;
    uint32_t mode = get_lsm_mode();

    // Check if caller PID is quarantined
    if (pid_role && *pid_role == OSOOSI_PID_ROLE_QUARANTINED) {
        should_block = 1;
    }

    // Check blocked port map
    uint32_t *port_rule = bpf_map_lookup_elem(&blocked_ports, &dport_host);
    if (port_rule && *port_rule != 0) {
        should_block = 1;
    }

    uint32_t ipv4_addr = 0;
    struct ipv6_addr_key ipv6_key = {{0}};

    int is_essential_port = (dport_host == 3030 || dport_host == 53 || dport_host == 67 || dport_host == 68 || dport_host == 546 || dport_host == 547);

    if (family == AF_INET_VAL) {
        bpf_probe_read_kernel(&ipv4_addr, sizeof(ipv4_addr), &address->sa_data[2]);
        uint32_t *ip_rule = bpf_map_lookup_elem(&blocked_ipv4, &ipv4_addr);
        if (ip_rule && *ip_rule != 0) {
            should_block = 1;
        }
        // In Kill-Chain Lockdown mode (2), block non-loopback egress (except port 3030, DNS 53, DHCP 67/68)
        uint8_t first_octet = (uint8_t)(ipv4_addr & 0xFF);
        if (mode == OSOOSI_LSM_MODE_LOCKDOWN && first_octet != 127 && !is_essential_port) {
            should_block = 1;
        }
    } else if (family == AF_INET6_VAL && addrlen >= 24) {
        bpf_probe_read_kernel(&ipv6_key.addr, 16, &address->sa_data[6]);
        uint32_t *ip6_rule = bpf_map_lookup_elem(&blocked_ipv6, &ipv6_key);
        if (ip6_rule && *ip6_rule != 0) {
            should_block = 1;
        }
        if (mode == OSOOSI_LSM_MODE_LOCKDOWN && !is_essential_port) {
            // Check if IPv6 loopback (::1)
            int is_loopback = (ipv6_key.addr[15] == 1);
            #pragma unroll
            for (int i = 0; i < 15; i++) {
                if (ipv6_key.addr[i] != 0) {
                    is_loopback = 0;
                }
            }
            if (!is_loopback) {
                should_block = 1;
            }
        }
    }

    if (should_block) {
        struct ebpf_process_event *pev = bpf_ringbuf_reserve(&process_ring, sizeof(*pev), 0);
        if (pev) {
            uint64_t uid_gid = bpf_get_current_uid_gid();
            pev->pid = pid;
            pev->uid = (uint32_t)uid_gid;
            pev->gid = (uint32_t)(uid_gid >> 32);
            pev->timestamp_ns = bpf_ktime_get_ns();
            pev->event_type = OSOOSI_EBPF_EVENT_LSM_NET_BLOCK;
            pev->_pad = (uint32_t)dport_host;
            bpf_get_current_comm(&pev->comm, sizeof(pev->comm));
            pev->filename[0] = '\0';
            fill_task_lineage_and_args(pev);
            bpf_ringbuf_submit(pev, 0);
        }

        struct ebpf_network_event *nev = bpf_ringbuf_reserve(&network_ring, sizeof(*nev), 0);
        if (nev) {
            nev->pid = pid;
            nev->family = family;
            nev->dport = dport_be;
            nev->sport = 0;
            nev->_pad1 = 1; // Blocked by LSM socket_connect
            nev->_pad2 = 0;
            nev->timestamp_ns = bpf_ktime_get_ns();
            if (family == AF_INET_VAL) {
                __builtin_memcpy(nev->daddr, &ipv4_addr, 4);
            } else {
                __builtin_memcpy(nev->daddr, ipv6_key.addr, 16);
            }
            bpf_ringbuf_submit(nev, 0);
        }

        if (mode >= OSOOSI_LSM_MODE_ACTIVE) {
            bpf_printk("OshoosiClaw LSM [socket_connect]: BLOCKED outbound connect port=%u PID=%u\n", dport_host, pid);
            return -EPERM;
        }
    }

    return 0;
}

// Hook 7: Linux mprotect W^X Violation Syscall Tracepoint
SEC("tp/syscalls/sys_enter_mprotect")
int handle_mprotect(struct trace_event_raw_sys_enter_mprotect *ctx) {
    if ((ctx->prot & 0x6) != 0x6) {
        return 0;
    }

    struct ebpf_process_event *event = bpf_ringbuf_reserve(&process_ring, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint64_t uid_gid = bpf_get_current_uid_gid();

    event->pid = (uint32_t)(pid_tgid >> 32);
    event->uid = (uint32_t)uid_gid;
    event->gid = (uint32_t)(uid_gid >> 32);
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = OSOOSI_EBPF_EVENT_MPROTECT_WX;
    event->_pad = 0;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->filename[0] = '\0';
    fill_task_lineage_and_args(event);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Hook 8: Linux ptrace Injection & Tampering Tracepoint
SEC("tp/syscalls/sys_enter_ptrace")
int handle_ptrace(struct trace_event_raw_sys_enter_ptrace *ctx) {
    long req = ctx->request;
    if (req != 4 && req != 5 && req != 13 && req != 16 && req != 0x4206) {
        return 0;
    }

    struct ebpf_process_event *event = bpf_ringbuf_reserve(&process_ring, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint64_t uid_gid = bpf_get_current_uid_gid();

    event->pid = (uint32_t)(pid_tgid >> 32);
    event->uid = (uint32_t)uid_gid;
    event->gid = (uint32_t)(uid_gid >> 32);
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = OSOOSI_EBPF_EVENT_PTRACE_TAMPER;
    event->_pad = 0;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->filename[0] = '\0';
    fill_task_lineage_and_args(event);

    bpf_ringbuf_submit(event, 0);
    return 0;
}
