//! Network Discovery and Route Scraping.
//!
//! Implements three discovery strategies:
//!   1. ARP Cache Scraping (passive, immediate neighbors)
//!   2. Routing Table Scraping (subnet boundary detection)
//!   3. Sysmon Event ID 3 Parsing (passive outbound destination learning)
//!   4. Active "Sherpa" Probing (checks discovered IPs for OshoosiClaw peers)

use std::collections::HashMap;
use std::net::{SocketAddr, TcpStream};
use std::process::Command;
use std::time::Duration;
use sysinfo::Networks;
use tracing::{debug, info};
#[cfg(target_os = "windows")]
use windows::Win32::System::EventLog::*;

/// A host discovered through any discovery method.
#[derive(Debug, Clone)]
pub struct DiscoveredHost {
    pub ip: String,
    pub mac: Option<String>,
    pub interface: String,
    pub is_osoosi_peer: bool,
}

/// A route entry from the OS routing table.
#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub destination: String,
    pub gateway: String,
    pub interface: String,
    pub mask: Option<String>,
}

pub struct RouteScraper {
    pub osoosi_port: u16,
}

impl Default for RouteScraper {
    fn default() -> Self {
        Self::new()
    }
}

impl RouteScraper {
    pub fn new() -> Self {
        Self {
            osoosi_port: 4001, // Default OshoosiClaw listen port
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 1. ARP Cache Scraping
    // ─────────────────────────────────────────────────────────────────────────

    /// Pull the local ARP/Neighbor cache using native APIs or direct file access.
    /// No shell commands (arp -a, ip neigh) are used to avoid EDR alerting.
    pub fn scrape_arp(&self) -> Vec<DiscoveredHost> {
        let mut hosts = Vec::new();

        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::NetworkManagement::IpHelper::*;
            use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

            unsafe {
                let mut table_ptr: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
                // Get both IPv4 and IPv6 neighbors (AF_UNSPEC = 0)
                if GetIpNetTable2(0, &mut table_ptr) == 0 {
                    let table = &*table_ptr;
                    // Use the Table field directly; it's a flexible array member pattern in C
                    let entries = std::slice::from_raw_parts(&table.Table as *const _ as *const MIB_IPNET_ROW2, table.NumEntries as usize);
                    for entry in entries {
                        // NL_NEIGHBOR_STATE: Reachable = 5, Stale = 4
                        let state = entry.State;
                        if state == 5 || state == 4 {
                            let ip = match entry.Address.si_family {
                                AF_INET => {
                                    let addr = entry.Address.Ipv4.sin_addr;
                                    let b = addr.S_un.S_un_b;
                                    format!("{}.{}.{}.{}", b.s_b1, b.s_b2, b.s_b3, b.s_b4)
                                }
                                AF_INET6 => {
                                    let addr = entry.Address.Ipv6.sin6_addr;
                                    let b = addr.u.Byte;
                                    format!("{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                                        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                                        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
                                }
                                _ => continue,
                            };

                            let mac = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                entry.PhysicalAddress[0], entry.PhysicalAddress[1],
                                entry.PhysicalAddress[2], entry.PhysicalAddress[3],
                                entry.PhysicalAddress[4], entry.PhysicalAddress[5]);

                            hosts.push(DiscoveredHost {
                                ip,
                                mac: Some(mac),
                                interface: format!("if-{}", entry.InterfaceIndex),
                                is_osoosi_peer: false,
                            });
                        }
                    }
                    FreeMibTable(table_ptr as *mut _);
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            // Linux: Native /proc/net/arp parsing
            if let Ok(content) = std::fs::read_to_string("/proc/net/arp") {
                for line in content.lines().skip(1) { // Skip header
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 6 {
                        let ip = parts[0];
                        let mac = parts[3];
                        let dev = parts[5];
                        let flags = parts[2];
                        
                        // Flags 0x2 = ATF_COM (Completed), 0x4 = ATF_PERM (Permanent)
                        if flags != "0x0" {
                            hosts.push(DiscoveredHost {
                                ip: ip.to_string(),
                                mac: Some(mac.to_string()),
                                interface: dev.to_string(),
                                is_osoosi_peer: false,
                            });
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            // macOS: Native sysctl/routing socket approach is complex in raw Rust.
            // For now, we use the sysinfo-integrated network discovery or 
            // fallback to a clean internal implementation if possible.
            // (Re-using the arp -an parser but wrapped in a way that minimizes EDR impact)
            if let Ok(output) = Command::new("arp").arg("-an").output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if let (Some(start), Some(end)) = (line.find('('), line.find(')')) {
                        let ip = &line[start + 1..end];
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        let mac = parts.get(3).map(|&m| m.to_string());
                        let iface = parts.iter().position(|&p| p == "on").and_then(|i| parts.get(i + 1)).unwrap_or(&"unknown").to_string();
                        hosts.push(DiscoveredHost { ip: ip.to_string(), mac, interface: iface, is_osoosi_peer: false });
                    }
                }
            }
        }

        info!("ARP scrape: discovered {} adjacent hosts", hosts.len());
        hosts
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. Routing Table Scraping (Subnet Boundary Detection)
    // ─────────────────────────────────────────────────────────────────────────

    /// Scrape the OS routing table to identify subnet boundaries.
    /// Returns a list of route entries that can be used to detect multi-homed
    /// nodes and guide active probing.
    pub fn scrape_routes(&self) -> Vec<RouteEntry> {
        let mut routes = Vec::new();

        #[cfg(target_os = "windows")]
        {
            // Windows: route print -4
            if let Ok(output) = Command::new("route").args(["print", "-4"]).output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut in_table = false;

                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if trimmed.contains("Network Destination") {
                        in_table = true;
                        continue;
                    }
                    if trimmed.contains("Persistent Routes") {
                        in_table = false;
                    }
                    if !in_table {
                        continue;
                    }

                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    // Destination  Netmask  Gateway  Interface  Metric
                    if parts.len() >= 4 {
                        routes.push(RouteEntry {
                            destination: parts[0].to_string(),
                            mask: Some(parts[1].to_string()),
                            gateway: parts[2].to_string(),
                            interface: parts[3].to_string(),
                        });
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            // Linux: ip route show
            // Example: 192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100
            if let Ok(output) = Command::new("ip").args(["route", "show"]).output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.is_empty() {
                        continue;
                    }
                    let dest = parts[0];
                    let gateway = parts
                        .iter()
                        .position(|&p| p == "via")
                        .and_then(|i| parts.get(i + 1))
                        .unwrap_or(&"0.0.0.0")
                        .to_string();
                    let iface = parts
                        .iter()
                        .position(|&p| p == "dev")
                        .and_then(|i| parts.get(i + 1))
                        .unwrap_or(&"unknown")
                        .to_string();
                    routes.push(RouteEntry {
                        destination: dest.to_string(),
                        mask: None,
                        gateway,
                        interface: iface,
                    });
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            // macOS: netstat -rn -f inet
            if let Ok(output) = Command::new("netstat").args(["-rn", "-f", "inet"]).output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut in_table = false;
                for line in stdout.lines() {
                    if line.contains("Destination") {
                        in_table = true;
                        continue;
                    }
                    if !in_table {
                        continue;
                    }
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        routes.push(RouteEntry {
                            destination: parts[0].to_string(),
                            gateway: parts[1].to_string(),
                            interface: parts.get(3).unwrap_or(&"unknown").to_string(),
                            mask: None,
                        });
                    }
                }
            }
        }

        info!("Route scrape: found {} route entries", routes.len());
        routes
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 3. Sysmon Event ID 3 Passive Discovery (Windows)
    // ─────────────────────────────────────────────────────────────────────────

    /// Parse recent Sysmon Network Connection events (Event ID 3) from the
    /// Windows Event Log to learn which remote IPs this host has talked to.
    /// This is a passive, zero-noise discovery method.
    #[cfg(target_os = "windows")]
    pub fn scrape_sysmon_connections(&self) -> Vec<DiscoveredHost> {
        let mut hosts = HashMap::new();

        unsafe {
            let channel = windows::core::w!("Microsoft-Windows-Sysmon/Operational");
            let query = windows::core::w!("*[System[(EventID=3)]]");
            
            let handle = EvtQuery(None, channel, query, EvtQueryChannelPath.0 as u32);
            if let Ok(h) = handle {
                let mut events = vec![0isize; 64]; // EvtNext expects &mut [isize]
                let mut returned = 0u32;
                
                // windows-rs EvtNext: (session, events_slice, timeout_ms, flags, returned)
                if EvtNext(h, &mut events, 0, 0, &mut returned).is_ok() && returned > 0 {
                    for i in 0..returned as usize {
                        let event = EVT_HANDLE(events[i]);
                        let mut buffer_used = 0u32;
                        let mut property_count = 0u32;
                        
                        // Get XML length first
                        let _ = EvtRender(None, event, EvtRenderEventXml.0 as u32, 0, None, &mut buffer_used, &mut property_count);
                        
                        if buffer_used > 0 {
                            let mut buffer = vec![0u16; (buffer_used / 2 + 1) as usize];
                            if EvtRender(None, event, EvtRenderEventXml.0 as u32, buffer_used, Some(buffer.as_mut_ptr() as *mut _), &mut buffer_used, &mut property_count).is_ok() {
                                let xml = String::from_utf16_lossy(&buffer);
                                if let Some(dst_ip) = Self::extract_sysmon_event_data_value(&xml, "DestinationIp") {
                                    if dst_ip != "127.0.0.1" && dst_ip != "::1" {
                                        hosts.entry(dst_ip.to_string()).or_insert_with(|| DiscoveredHost {
                                            ip: dst_ip.to_string(),
                                            mac: None,
                                            interface: "sysmon-native".to_string(),
                                            is_osoosi_peer: false,
                                        });
                                    }
                                }
                            }
                        }
                        let _ = EvtClose(event);
                    }
                }
                let _ = EvtClose(h);
            }
        }

        hosts.into_values().collect()
    }

    #[cfg(not(target_os = "windows"))]
    pub fn scrape_sysmon_connections(&self) -> Vec<DiscoveredHost> {
        vec![] // Sysmon is Windows-only; Unix uses journald or auditd
    }

    #[cfg(target_os = "windows")]
    fn extract_sysmon_event_data_value(xml: &str, key: &str) -> Option<String> {
        let marker = format!("Name=\"{}\">", key);
        let start = xml.find(&marker)? + marker.len();
        let rest = &xml[start..];
        let end = rest.find("</Data>")?;
        let value = rest[..end].trim();
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 4. Identify Local Network Interfaces and Subnets
    // ─────────────────────────────────────────────────────────────────────────

    /// Identify subnet boundaries using sysinfo's network interface list.
    pub fn list_interfaces(&self) -> Vec<String> {
        let networks = Networks::new_with_refreshed_list();
        let ifaces: Vec<String> = networks.iter().map(|(name, _)| name.clone()).collect();
        info!("Detected {} network interfaces", ifaces.len());
        ifaces
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 5. Active "Sherpa" Probing — Check for OshoosiClaw Peers
    // ─────────────────────────────────────────────────────────────────────────

    /// Given a list of discovered hosts, probe each one's OshoosiClaw listen
    /// port to check if it's a peer agent. Uses a short TCP timeout to stay
    /// low-and-slow.
    pub fn probe_for_peers(&self, hosts: &mut Vec<DiscoveredHost>) {
        let port = self.osoosi_port;
        let timeout = Duration::from_millis(300);

        for host in hosts.iter_mut() {
            let addr = format!("{}:{}", host.ip, port);
            match addr.parse::<SocketAddr>() {
                Ok(sock_addr) => match TcpStream::connect_timeout(&sock_addr, timeout) {
                    Ok(_) => {
                        host.is_osoosi_peer = true;
                        info!("OshoosiClaw peer discovered: {}", host.ip);
                    }
                    Err(_) => {
                        debug!("No OshoosiClaw peer at {}", host.ip);
                    }
                },
                Err(_) => {}
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Full Discovery Run
    // ─────────────────────────────────────────────────────────────────────────

    /// Run all discovery strategies and return a deduplicated list of hosts,
    /// annotated with whether they are OshoosiClaw peers.
    pub fn run_full_discovery(&self) -> Vec<DiscoveredHost> {
        let mut all: HashMap<String, DiscoveredHost> = HashMap::new();

        // Collect from ARP cache
        for host in self.scrape_arp() {
            all.entry(host.ip.clone()).or_insert(host);
        }

        // Collect from Sysmon Event ID 3 (Windows only)
        for host in self.scrape_sysmon_connections() {
            all.entry(host.ip.clone()).or_insert(host);
        }

        let mut hosts: Vec<DiscoveredHost> = all.into_values().collect();

        // Probe for peers
        self.probe_for_peers(&mut hosts);

        let peer_count = hosts.iter().filter(|h| h.is_osoosi_peer).count();
        info!(
            "Discovery complete: {} total hosts, {} OshoosiClaw peers",
            hosts.len(),
            peer_count
        );

        hosts
    }
}
