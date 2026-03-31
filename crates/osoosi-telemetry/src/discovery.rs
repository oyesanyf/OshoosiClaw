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
use tracing::{info, debug};

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
            osoosi_port: 9876, // Default OshoosiClaw listen port
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 1. ARP Cache Scraping
    // ─────────────────────────────────────────────────────────────────────────

    /// Pull the local ARP cache using system commands.
    /// Supports Windows (`arp -a`), Linux (`ip neigh`), and macOS (`arp -an`).
    pub fn scrape_arp(&self) -> Vec<DiscoveredHost> {
        let mut hosts = Vec::new();

        #[cfg(target_os = "windows")]
        {
            // Windows: arp -a
            // Interface: 192.168.1.10 --- 0x2
            //   Internet Address      Physical Address      Type
            //   192.168.1.1           00-11-22-33-44-55     dynamic
            if let Ok(output) = Command::new("arp").arg("-a").output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut current_interface = "unknown".to_string();

                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() { continue; }

                    if trimmed.starts_with("Interface:") {
                        current_interface = trimmed
                            .replace("Interface:", "")
                            .trim()
                            .split_whitespace()
                            .next()
                            .unwrap_or("unknown")
                            .to_string();
                        continue;
                    }

                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 3 {
                        let ip = parts[0];
                        let mac = parts[1];
                        let entry_type = parts[2];

                        if (ip.starts_with("192.") || ip.starts_with("10.") || ip.starts_with("172."))
                            && (entry_type.eq_ignore_ascii_case("dynamic")
                                || entry_type.eq_ignore_ascii_case("static"))
                        {
                            hosts.push(DiscoveredHost {
                                ip: ip.to_string(),
                                mac: Some(mac.replace('-', ":").to_lowercase()),
                                interface: current_interface.clone(),
                                is_osoosi_peer: false,
                            });
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            // Linux: ip neigh show
            // Example: 192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
            if let Ok(output) = Command::new("ip").args(["neigh", "show"]).output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 5 {
                        let ip = parts[0];
                        let dev = if parts.len() > 2 { parts[2] } else { "unknown" };
                        let mac = if parts.len() > 4 { parts[4] } else { "unknown" };
                        let state = parts.last().unwrap_or(&"UNKNOWN");
                        if !state.eq_ignore_ascii_case("FAILED") && !state.eq_ignore_ascii_case("INCOMPLETE") {
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
            // macOS: arp -an
            // (192.168.1.1) at 00:11:22:33:44:55 on en0 ifscope [ethernet]
            if let Ok(output) = Command::new("arp").arg("-an").output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if let (Some(start), Some(end)) = (line.find('('), line.find(')')) {
                        let ip = &line[start + 1..end];
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        let mac = parts.get(3).map(|&m| m.to_string());
                        // Interface is typically after "on"
                        let iface = parts.iter()
                            .position(|&p| p == "on")
                            .and_then(|i| parts.get(i + 1))
                            .unwrap_or(&"unknown")
                            .to_string();
                        hosts.push(DiscoveredHost {
                            ip: ip.to_string(),
                            mac,
                            interface: iface,
                            is_osoosi_peer: false,
                        });
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
                    if !in_table { continue; }

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
                    if parts.is_empty() { continue; }
                    let dest = parts[0];
                    let gateway = parts.iter()
                        .position(|&p| p == "via")
                        .and_then(|i| parts.get(i + 1))
                        .unwrap_or(&"0.0.0.0")
                        .to_string();
                    let iface = parts.iter()
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
                    if line.contains("Destination") { in_table = true; continue; }
                    if !in_table { continue; }
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

        // Query Sysmon Event ID 3 (NetworkConnect) from last 24h
        let ps_cmd = r#"
            $since = (Get-Date).AddHours(-24)
            Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-Sysmon/Operational'
                Id = 3
                StartTime = $since
            } -ErrorAction SilentlyContinue |
            ForEach-Object {
                $xml = [xml]$_.ToXml()
                $data = $xml.Event.EventData.Data
                $dst = ($data | Where-Object { $_.Name -eq 'DestinationIp' }).'#text'
                if ($dst) { Write-Output $dst }
            } | Sort-Object -Unique
        "#;

        if let Ok(output) = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", ps_cmd])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let ip = line.trim();
                if ip.is_empty() || ip == "127.0.0.1" || ip == "::1" { continue; }
                hosts.entry(ip.to_string()).or_insert_with(|| DiscoveredHost {
                    ip: ip.to_string(),
                    mac: None,
                    interface: "sysmon-event3".to_string(),
                    is_osoosi_peer: false,
                });
            }
        }

        let result: Vec<DiscoveredHost> = hosts.into_values().collect();
        info!("Sysmon Event ID 3 passive discovery: {} unique remote IPs", result.len());
        result
    }

    #[cfg(not(target_os = "windows"))]
    pub fn scrape_sysmon_connections(&self) -> Vec<DiscoveredHost> {
        vec![] // Sysmon is Windows-only; Unix uses journald or auditd
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
                Ok(sock_addr) => {
                    match TcpStream::connect_timeout(&sock_addr, timeout) {
                        Ok(_) => {
                            host.is_osoosi_peer = true;
                            info!("OshoosiClaw peer discovered: {}", host.ip);
                        }
                        Err(_) => {
                            debug!("No OshoosiClaw peer at {}", host.ip);
                        }
                    }
                }
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
