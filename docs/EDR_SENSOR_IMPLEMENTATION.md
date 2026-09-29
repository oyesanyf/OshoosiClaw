# Cross-Platform EDR Sensor Implementation in Rust

To build a cross-platform EDR sensor in Rust, you generally need to separate your Kernel-Interaction Logic (which is platform-specific) from your Telemetry Logic (which is shared).

Below are the boilerplate implementations for each. Note that for a production EDR, these would usually be separate crates in a workspace, as they require different dependencies and compilation targets (especially Linux eBPF).

## 1. Windows: Native Ring-0 Kernel Driver & WFP Network Filtering

In production, OpenỌ̀ṣọ́ọ̀sì combines a **Ring-0 Kernel Filter Driver** (`driver/windows/src/osoosi_driver.c`) for pre-operation process execution blocking with the **Windows Filtering Platform (WFP)** for real-time network layer inspection.

### 1.1 Native Ring-0 Kernel Driver (`driver/windows/src/osoosi_driver.c`)

The Windows Ring-0 driver intercepts process creation synchronously in kernel space before the Process Environment Block (PEB) or primary thread is instantiated.

#### Architecture Highlights:
- **Synchronous Process Interception**: Registered via `PsSetCreateProcessNotifyRoutineEx(OsoosiCreateProcessNotifyRoutine, FALSE)`. When process creation is initiated, `CreateInfo->CreationStatus = STATUS_ACCESS_DENIED` (`0xC0000022`) aborts process creation immediately in the kernel.
- **Pre-Event 1 Execution Blocking**: Prevents malicious binaries from executing any instructions in user space, rendering direct syscall bypasses (`SysWhispers`, `Hell's Gate`) and DLL unhooking completely ineffective.
- **Kernel BSOD Prevention & Memory Safety**: Implements `OsoosiContainsSubstrInsensitive`, performing length-bounded, case-insensitive substring comparisons. Standard null-terminated string functions cause kernel bugchecks (BSOD) when encountering non-null-terminated kernel `UNICODE_STRING` buffers.
- **Path Normalization**: Automatically strips DOS drive prefixes (`[A-Za-z]:`) to ensure exact substring matching against kernel NT device paths (`\Device\HarddiskVolumeX\...`).
- **Core OS Immunity & Self-Defense**: Hardcoded kernel protection exempting critical system processes (PIDs 0, 4) and infrastructure images (`smss.exe`, `csrss.exe`, `wininit.exe`, `services.exe`, `lsass.exe`, `sysmon64.exe`, `sysmon.exe`, `msmpeng.exe`, `osoosi.exe`).
- **Fast Spinlock Circular Queue**: Intercepted events are buffered into a 256-slot non-paged circular ring queue protected by `KeAcquireInStackQueuedSpinLock` and drained via `IOCTL_OSOOSI_POLL_INTERCEPTIONS`.

#### Kernel Driver Implementation Snippet (`driver/windows/src/osoosi_driver.c`):
```c
VOID OsoosiCreateProcessNotifyRoutine(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    UNREFERENCED_PARAMETER(Process);
    KLOCK_QUEUE_HANDLE lockHandle;

    if (CreateInfo == NULL) {
        return; // Process exit notification
    }

    ULONG pid = HandleToULong(ProcessId);
    ULONG parentPid = HandleToULong(CreateInfo->ParentProcessId);

    // Safeguard: Never block core infrastructure or system PIDs
    if (pid <= 4 || parentPid == 0 || OsoosiIsCriticalSystemImage(CreateInfo->ImageFileName)) {
        return;
    }

    KeAcquireInStackQueuedSpinLock(&g_State.Lock, &lockHandle);

    BOOLEAN isBlockedPath = OsoosiIsPathBlockedLocked(CreateInfo->ImageFileName);
    BOOLEAN shouldBlock = isBlockedPath && (g_State.Mode >= OSOOSI_MODE_ACTIVE);

    if (shouldBlock) {
        g_State.BlockedCount++;
        // Pre-operation execution block: stops the process before thread creation!
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED; // 0xC0000022
        KdPrint(("OsoosiDriver: BLOCKED process creation: PID=%lu, Image=%wZ\n", pid, CreateInfo->ImageFileName));
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
}
```

#### User-Mode Orchestrator Client (`crates/osoosi-runtime/src/kernel_driver.rs`):
```rust
let client = KernelDriverClient::open();
if let Some(drv) = client {
    // Dynamically set driver mode: Audit (0), Active (1), Lockdown (2)
    drv.set_mode(DriverAutonomyMode::Active)?;
    
    // Synchronize file path block rules to kernel memory
    drv.add_block_path(r"C:\Users\Public\mimikatz.exe")?;
    
    // Poll intercepted events from kernel ring buffer
    let events = drv.poll_interceptions()?;
}
```

### 1.2 Windows Filtering Platform (WFP Network Monitoring)
For outbound network traffic, WFP subscribes to `FWPM_LAYER_ALE_AUTH_CONNECT_V4` to inspect connections and enforce dynamic egress tarpitting:

```rust
use wfp::{FilterEngineBuilder, FilterBuilder, ActionType, Layer, Transaction};
use std::io;

fn main() -> io::Result<()> {
    let mut engine = FilterEngineBuilder::default().dynamic().open()?;
    let transaction = Transaction::new(&mut engine)?;

    FilterBuilder::default()
        .name("EDR Network Monitor")
        .description("Observing all outbound IPv4 traffic")
        .action(ActionType::Permit)
        .layer(Layer::ConnectV4)
        .add(&transaction)?;

    transaction.commit()?;
    println!("Windows WFP Sensor Active. Monitoring network layer...");
    std::thread::park();
    Ok(())
}
```

## 2. macOS: Endpoint Security (Using endpoint-sec)
On macOS, you must use the System Extension framework. This code requires the `com.apple.developer.endpoint-security.client` entitlement to run.

### Cargo.toml
```toml
[target.'cfg(target_os = "macos")'.dependencies]
endpoint-sec = "0.5.1"
```

### main.rs
```rust
#[cfg(target_os = "macos")]
use endpoint_sec::{Client, Event};

fn main() {
    #[cfg(target_os = "macos")]
    {
        // 1. Create the ES Client with a handler callback
        let client = Client::new(|_client, message| {
            match message.event() {
                Event::Open(ev) => {
                    println!("File Open Detected: {}", ev.file().path());
                }
                Event::Connect(ev) => {
                    println!("Network Connection: Destination {}", ev.address());
                }
                _ => (),
            }
        }).expect("Failed to create ES Client. Are you running with proper entitlements?");

        // 2. Subscribe to the events we want to monitor
        client.subscribe(&[Event::Connect]).unwrap();
        
        println!("macOS Endpoint Security Sensor Active.");
        loop { std::thread::sleep(std::time::Duration::from_secs(1)); }
    }
}
```

## 3. Linux: Production eBPF Ring Buffers & LSM Pre-Execution Blocking

On Linux edge nodes, OpenỌ̀ṣọ́ọ̀sì implements native kernel instrumentation and hardware-speed pre-operation execution blocking through **eBPF Ring Buffers** and the **BPF Linux Security Module (LSM)** (`ebpf/src/osoosi_probe.bpf.c` and `crates/osoosi-telemetry/src/linux_ebpf.rs`).

### 3.1 Kernel eBPF Probe & LSM Blocking (`ebpf/src/osoosi_probe.bpf.c`)

Unlike legacy kprobes or tracepoint-only telemetry collectors that detect malicious binaries after process execution has already begun, OpenỌ̀ṣọ́ọ̀sì hooks `lsm/bprm_check_security` for hardware-enforced pre-operation blocking.

#### Architecture Highlights:
- **LSM Pre-Execution Blocking (`osoosi_bprm_check`)**: Hooks `bprm_check_security` within the Linux kernel. When `execve()` or `execveat()` is called, the kernel passes `struct linux_binprm`. The probe checks the kernel-space `blocked_paths` hash map (`BPF_MAP_TYPE_HASH`). If the executable path matches, it emits an `OSOOSI_EBPF_EVENT_LSM_BLOCK` telemetry event and returns `-EPERM` (`-EACCES`), immediately terminating execution before ELF binary headers or pages are mapped into memory.
- **Zero-Drop Ring Buffer Maps**: Utilizes `BPF_MAP_TYPE_RINGBUF` (256 KB each for `process_ring` and `network_ring`), replacing high-overhead perf buffers with atomic memory pages shared between kernel and user space.
- **Tracepoint Hooks**:
  - `tp/sched/sched_process_exec`: Process launch telemetry (PID, PPID, UID, GID, comm, executable filename, args).
  - `tp/sched/sched_process_exit`: Process termination and exit metrics.
  - `tp/syscalls/sys_enter_connect`: Outbound socket connection telemetry for IPv4 (`AF_INET`) and IPv6 (`AF_INET6`), capturing destination IP, port, and PID.

#### Kernel Probe Snippet (`ebpf/src/osoosi_probe.bpf.c`):
```c
// Blocked binary paths hash map for LSM enforcement
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[OSOOSI_PATH_LEN]);
    __type(value, uint32_t);
} blocked_paths SEC(".maps");

// LSM Pre-Operation Execution Block
SEC("lsm/bprm_check_security")
int BPF_PROG(osoosi_bprm_check, struct linux_binprm *bprm) {
    char filename[OSOOSI_PATH_LEN] = {0};
    if (!bprm) return 0;

    const char *fn_ptr = BPF_CORE_READ(bprm, filename);
    if (!fn_ptr) return 0;
    bpf_probe_read_kernel_str(filename, sizeof(filename), fn_ptr);

    // Look up path in kernel blocked_paths map
    uint32_t *rule_val = bpf_map_lookup_elem(&blocked_paths, filename);
    if (rule_val && *rule_val != 0) {
        // Enforce Ring-0 execution block on Linux!
        bpf_printk("OshoosiClaw LSM: BLOCKED execution of binary %s\n", filename);
        return -EPERM; // -EACCES
    }
    return 0;
}
```

### 3.2 User-Space Telemetry Engine (`crates/osoosi-telemetry/src/linux_ebpf.rs`)

The Linux telemetry engine loads and attaches the compiled eBPF bytecode using the pure-Rust Aya framework, streaming events asynchronously over Tokio channels.

#### Architecture Highlights:
- **Panic-Free Multi-Path Discovery**: Dynamically resolves eBPF object bytecode across:
  1. `$env:OSOOSI_EBPF_OBJECT` (Custom override)
  2. `osoosi-ebpf.o` (Working directory)
  3. `ebpf/bin/osoosi-ebpf.o` (Development tree)
  4. `/usr/lib/osoosi/osoosi-ebpf.o` (Standard FHS package path)
  5. `/etc/osoosi/osoosi-ebpf.o` (Configuration path)
  If the kernel lacks BPF LSM or BTF support, error propagation is completely non-fatal and falls back to user-mode monitoring.
- **Asynchronous Tokio AsyncFd Polling**: Uses `tokio::io::unix::AsyncFd` on the ring buffer file descriptors to await readability, draining events with zero CPU spinning.
- **Event Normalization**: Parses kernel memory structs (`EbpfProcessEvent`, `EbpfNetworkEvent`) into standard `HostSecurityEvent` records for consumption by the detection engine.

#### Rust Engine Snippet (`crates/osoosi-telemetry/src/linux_ebpf.rs`):
```rust
let mut bpf = Ebpf::load(&bytes)?;

// Attach tracepoints
self.attach_tracepoint(&mut bpf, "handle_process_exec", "sched", "sched_process_exec")?;
self.attach_tracepoint(&mut bpf, "handle_process_exit", "sched", "sched_process_exit")?;
self.attach_tracepoint(&mut bpf, "handle_connect", "syscalls", "sys_enter_connect")?;

// Wrap ring buffers in async descriptors
let process_ring: RingBuf<MapData> = RingBuf::try_from(bpf.take_map("process_ring").unwrap())?;
let mut process_fd = tokio::io::unix::AsyncFd::new(process_ring)?;

tokio::spawn(async move {
    loop {
        if let Ok(mut guard) = process_fd.readable_mut().await {
            let rb = guard.get_inner_mut();
            while let Some(item) = rb.next() {
                if let Some(ev) = parse_process_event(&item) {
                    let _ = tx.send(ev).await;
                }
            }
            guard.clear_ready();
        }
    }
});
```

## Summary of Implementation Logic
### How to manage this "Unified" code:
To keep your project clean, use Conditional Compilation (`#[cfg(target_os = "...")])` or create a Trait that abstracts the "Start Monitoring" function:
- **Trait Sensor**: Defines `fn start_monitoring(&self)`.
- **Impl for Windows**: Uses `wfp-rs`.
- **Impl for macOS**: Uses `endpoint-sec`.
- **Impl for Linux**: Uses `aya`.

### A Crucial Warning on Privileges:
- **Windows**: Must run as Administrator (and eventually as a PPL service).
- **macOS**: Must be signed with an Endpoint Security Entitlement from Apple and run as root.
- **Linux**: Requires `CAP_BPF` or root privileges to load eBPF programs into the kernel.
