# OshoosiClaw Linux eBPF Ring-Buffer Probes & LSM Parity

This directory provides native Linux kernel instrumentation using modern **eBPF Ring Buffers** and the **BPF Linux Security Module (LSM)** interface.

This architecture achieves parity with the Windows Ring-0 Driver:
- **Zero-Drop Telemetry**: High-throughput kernel ring buffers (`BPF_MAP_TYPE_RINGBUF`) for process execution (`sched_process_exec`), exit (`sched_process_exit`), and network outbound connects (`sys_enter_connect`).
- **Hardware-Speed Pre-Operation Blocking**: Uses `SEC("lsm/bprm_check_security")` to intercept binary launch and return `-EPERM`, aborting execution **before process memory is mapped and before the process starts**.

---

## Architecture Overview

1. **`process_ring` (`BPF_MAP_TYPE_RINGBUF`)**:
   Emits `struct ebpf_process_event` containing PID, PPID, UID, GID, comm, executable path, and timestamp.
   Decoded into `HostSecurityEvent` with:
   - Event 1: Process Creation
   - Event 5: Process Exit
   - Event 25: Process Tampering / LSM Block

2. **`network_ring` (`BPF_MAP_TYPE_RINGBUF`)**:
   Emits `struct ebpf_network_event` containing PID, IP family (AF_INET/AF_INET6), destination port, source port, and destination IP address.
   Decoded into `HostSecurityEvent` Event 3 (Network Connection).

3. **`blocked_paths` (`BPF_MAP_TYPE_HASH`)**:
   In-kernel hashtable populated by the Oshoosi orchestrator during quarantine or threat mitigation.
   When `bprm_check_security` executes, it performs a lookup against this map and instantly returns `-EPERM` if matched.

---

## Kernel Requirements

- **Linux Kernel**: Version >= 5.8 (for `BPF_MAP_TYPE_RINGBUF`) and >= 5.7 (for BPF LSM).
- **Kernel Config**:
  - `CONFIG_BPF=y`
  - `CONFIG_BPF_SYSCALL=y`
  - `CONFIG_BPF_LSM=y`
  - `CONFIG_DEBUG_INFO_BTF=y`
- **Boot Parameters**:
  Ensure `bpf` is included in the active LSM list:
  ```bash
  cat /sys/kernel/security/lsm
  # Should output: capability,landlock,lockdown,yama,bpf
  ```
  If `bpf` is missing, append `lsm=capability,landlock,lockdown,yama,bpf` to `/etc/default/grub` (`GRUB_CMDLINE_LINUX`) and run `update-grub`.

---

## Building eBPF Bytecode

```bash
make
# Outputs bin/osoosi-ebpf.o
```

---

## User-Space Loading (Aya)

The compiled bytecode is loaded and attached automatically by `osoosi-telemetry` using the Aya eBPF library.
Set the environment variable `OSOOSI_EBPF_OBJECT=/path/to/osoosi-ebpf.o` or place it alongside the binary.
