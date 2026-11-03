//! OS Kernel TCP Socket Table Loopback Peer-PID Anti-Spoofing Resolver.
//!
//! Authenticates the owning OS process ID (`PID`) of an inbound loopback TCP socket
//! by querying the kernel TCP connection table directly (`GetExtendedTcpTable` on Windows
//! for both `AF_INET` and `AF_INET6`, `/proc/net/tcp*` + `/proc/<pid>/fd` on Linux).
//! Fails closed when no active non-zero owner PID matches `(peer_addr, bound_port)`.

use std::net::{IpAddr, SocketAddr};

/// Resolves the authenticated OS process ID (`PID`) owning the client half of a loopback
/// TCP connection `(peer_addr -> 127.0.0.1:bound_port / [::1]:bound_port)`.
pub fn resolve_loopback_peer_pid(peer_addr: SocketAddr, bound_port: u16) -> anyhow::Result<u32> {
    if !peer_addr.ip().is_loopback() && !is_ipv4_mapped_loopback(&peer_addr.ip()) {
        anyhow::bail!(
            "Refusing peer-PID lookup for non-loopback address {}",
            peer_addr
        );
    }

    #[cfg(windows)]
    {
        resolve_loopback_peer_pid_windows(peer_addr, bound_port)
    }

    #[cfg(target_os = "linux")]
    {
        resolve_loopback_peer_pid_linux(peer_addr, bound_port)
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = bound_port;
        anyhow::bail!(
            "OS kernel TCP socket table owner-PID resolution is unsupported on this platform"
        )
    }
}

fn is_ipv4_mapped_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
    }
}

#[cfg(windows)]
fn resolve_loopback_peer_pid_windows(
    peer_addr: SocketAddr,
    bound_port: u16,
) -> anyhow::Result<u32> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;
    const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct MibTcpRowOwnerPid {
        dw_state: u32,
        dw_local_addr: u32,
        dw_local_port: u32,
        dw_remote_addr: u32,
        dw_remote_port: u32,
        dw_owning_pid: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct MibTcp6RowOwnerPid {
        uc_local_addr: [u8; 16],
        dw_local_scope_id: u32,
        dw_local_port: u32,
        uc_remote_addr: [u8; 16],
        dw_remote_scope_id: u32,
        dw_remote_port: u32,
        dw_state: u32,
        dw_owning_pid: u32,
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetExtendedTcpTable(
            p_tcp_table: *mut u8,
            pdw_size: *mut u32,
            b_order: i32,
            ul_af: u32,
            table_class: u32,
            reserved: u32,
        ) -> u32;
    }

    fn fetch_table(af: u32) -> anyhow::Result<Vec<u8>> {
        let mut size: u32 = 0;
        // SAFETY: First call with null buffer queries required byte count into `size`.
        let rc = unsafe {
            GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut size,
                0,
                af,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if rc != ERROR_INSUFFICIENT_BUFFER && rc != 0 {
            anyhow::bail!("GetExtendedTcpTable(af={}) size query failed: {}", af, rc);
        }
        let mut alloc_size = size.max(4096);
        for _ in 0..4 {
            let mut buf = vec![0u8; alloc_size as usize];
            let mut actual_size = alloc_size;
            // SAFETY: `buf` has length `actual_size` bytes and is valid for writes.
            let rc2 = unsafe {
                GetExtendedTcpTable(
                    buf.as_mut_ptr(),
                    &mut actual_size,
                    0,
                    af,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            };
            if rc2 == 0 {
                buf.truncate(actual_size as usize);
                return Ok(buf);
            }
            if rc2 == ERROR_INSUFFICIENT_BUFFER {
                alloc_size = actual_size.saturating_add(4096);
                continue;
            }
            anyhow::bail!("GetExtendedTcpTable(af={}) failed with error {}", af, rc2);
        }
        anyhow::bail!("GetExtendedTcpTable(af={}) exhausted buffer retries", af)
    }

    let peer_port = peer_addr.port();
    let normalized_v4: Option<Ipv4Addr> = match peer_addr.ip() {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    };

    // 1. Check IPv4 TCP table when peer address is IPv4 or IPv4-mapped IPv6.
    if let Some(target_v4) = normalized_v4 {
        let buf = fetch_table(AF_INET)?;
        if buf.len() >= 4 {
            let num_entries = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            let row_size = std::mem::size_of::<MibTcpRowOwnerPid>();
            let max_rows = (buf.len().saturating_sub(4)) / row_size;
            let count = num_entries.min(max_rows);
            for idx in 0..count {
                let offset = 4 + idx * row_size;
                // SAFETY: Bounds checked via `max_rows` above; `read_unaligned` handles 4-byte offset alignment.
                let row = unsafe {
                    std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const MibTcpRowOwnerPid)
                };
                let local_port = u16::from_be((row.dw_local_port & 0xFFFF) as u16);
                let remote_port = u16::from_be((row.dw_remote_port & 0xFFFF) as u16);
                let local_ip = Ipv4Addr::from(u32::from_be(row.dw_local_addr));
                let remote_ip = Ipv4Addr::from(u32::from_be(row.dw_remote_addr));
                // Client row: client's local = (target_v4, peer_port) -> server's (loopback, bound_port)
                if local_port == peer_port
                    && remote_port == bound_port
                    && local_ip == target_v4
                    && remote_ip.is_loopback()
                    && row.dw_owning_pid != 0
                {
                    return Ok(row.dw_owning_pid);
                }
            }
        }
    }

    // 2. Check IPv6 TCP table (handles native ::1 and dual-stack ::ffff:127.0.0.1 sockets).
    if let Ok(buf6) = fetch_table(AF_INET6) {
        if buf6.len() >= 4 {
            let num_entries = u32::from_ne_bytes([buf6[0], buf6[1], buf6[2], buf6[3]]) as usize;
            let row_size = std::mem::size_of::<MibTcp6RowOwnerPid>();
            let max_rows = (buf6.len().saturating_sub(4)) / row_size;
            let count = num_entries.min(max_rows);
            for idx in 0..count {
                let offset = 4 + idx * row_size;
                // SAFETY: Bounds checked via `max_rows` above; `read_unaligned` handles 4-byte offset alignment.
                let row = unsafe {
                    std::ptr::read_unaligned(buf6.as_ptr().add(offset) as *const MibTcp6RowOwnerPid)
                };
                let local_port = u16::from_be((row.dw_local_port & 0xFFFF) as u16);
                let remote_port = u16::from_be((row.dw_remote_port & 0xFFFF) as u16);
                if local_port != peer_port || remote_port != bound_port || row.dw_owning_pid == 0 {
                    continue;
                }
                let local_v6 = Ipv6Addr::from(row.uc_local_addr);
                let remote_v6 = Ipv6Addr::from(row.uc_remote_addr);
                let remote_ok = remote_v6.is_loopback()
                    || remote_v6
                        .to_ipv4_mapped()
                        .is_some_and(|v4| v4.is_loopback());
                let local_ok = match peer_addr.ip() {
                    IpAddr::V6(v6) => {
                        local_v6 == v6
                            || (v6.to_ipv4_mapped().is_some()
                                && local_v6.to_ipv4_mapped() == v6.to_ipv4_mapped())
                    }
                    IpAddr::V4(v4) => local_v6.to_ipv4_mapped() == Some(v4),
                };
                if local_ok && remote_ok {
                    return Ok(row.dw_owning_pid);
                }
            }
        }
    }

    anyhow::bail!(
        "No active loopback TCP client socket found in OS kernel table for {} -> port {}",
        peer_addr,
        bound_port
    )
}

#[cfg(target_os = "linux")]
fn resolve_loopback_peer_pid_linux(peer_addr: SocketAddr, bound_port: u16) -> anyhow::Result<u32> {
    let peer_port = peer_addr.port();
    let mut target_inode: Option<u64> = None;

    for proc_file in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(contents) = std::fs::read_to_string(proc_file) else {
            continue;
        };
        for line in contents.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 10 {
                continue;
            }
            let Some((_, lport_hex)) = cols[1].split_once(':') else {
                continue;
            };
            let Some((_, rport_hex)) = cols[2].split_once(':') else {
                continue;
            };
            let Ok(lport) = u16::from_str_radix(lport_hex, 16) else {
                continue;
            };
            let Ok(rport) = u16::from_str_radix(rport_hex, 16) else {
                continue;
            };
            if lport == peer_port && rport == bound_port {
                if let Ok(inode) = cols[9].parse::<u64>() {
                    if inode > 0 {
                        target_inode = Some(inode);
                        break;
                    }
                }
            }
        }
        if target_inode.is_some() {
            break;
        }
    }

    let inode = target_inode.ok_or_else(|| {
        anyhow::anyhow!(
            "No active loopback TCP socket inode found for {} -> port {}",
            peer_addr,
            bound_port
        )
    })?;
    let needle = format!("socket:[{}]", inode);

    for entry in std::fs::read_dir("/proc")?.flatten() {
        let file_name = entry.file_name();
        let Some(pid_str) = file_name.to_str() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        if pid == 0 {
            continue;
        }
        let fd_dir = entry.path().join("fd");
        let Ok(fds) = std::fs::read_dir(fd_dir) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(link) = std::fs::read_link(fd.path()) {
                if link.to_string_lossy() == needle {
                    return Ok(pid);
                }
            }
        }
    }

    anyhow::bail!(
        "Could not correlate socket inode {} to a live /proc/<pid>/fd owner",
        inode
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_loopback_peer_pid_self() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind v4 loopback");
        let bound_port = listener.local_addr().expect("local_addr").port();
        let client =
            std::net::TcpStream::connect(("127.0.0.1", bound_port)).expect("connect v4 loopback");
        let client_addr = client.local_addr().expect("client local_addr");
        let (_accepted, peer_addr) = listener.accept().expect("accept");
        assert_eq!(client_addr, peer_addr);

        let resolved_pid =
            resolve_loopback_peer_pid(peer_addr, bound_port).expect("resolve v4 peer pid");
        assert_eq!(resolved_pid, std::process::id());

        if let Ok(listener6) = std::net::TcpListener::bind("[::1]:0") {
            let port6 = listener6.local_addr().expect("v6 local_addr").port();
            if let Ok(client6) = std::net::TcpStream::connect(("::1", port6)) {
                let (_acc6, peer6) = listener6.accept().expect("accept v6");
                let _ = client6;
                let pid6 = resolve_loopback_peer_pid(peer6, port6).expect("resolve v6 peer pid");
                assert_eq!(pid6, std::process::id());
            }
        }
    }
}
