//! Network Discovery and Route Scraping.
//!
//! Periodic scraping of the local ARP cache and routing table to identify 
//! adjacent hosts and subnet boundaries. Used for dynamic peer discovery.

use std::process::Command;
use sysinfo::{Networks, System};
use tracing::info;

#[derive(Debug, Clone)]
pub struct DiscoveredHost {
    pub ip: String,
    pub mac: Option<String>,
    pub interface: String,
}

pub struct RouteScraper {
    system: System,
}

impl RouteScraper {
    pub fn new() -> Self {
        Self {
            system: System::new_all(),
        }
    }

    /// Pull the local ARP cache using system commands.
    /// Supports Windows (arp -a), Linux (ip neigh), and macOS (arp -an).
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
                        current_interface = trimmed.replace("Interface:", "").trim().split(" ").next().unwrap_or("unknown").to_string();
                        continue;
                    }

                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 3 {
                        let ip = parts[0];
                        let mac = parts[1];
                        let entry_type = parts[2];

                        // Filter for common LAN IPs and dynamic/static entries (skip multicast)
                        if (ip.starts_with("192.") || ip.starts_with("10.") || ip.starts_with("172.")) 
                           && (entry_type.to_lowercase() == "dynamic" || entry_type.to_lowercase() == "static") {
                            hosts.push(DiscoveredHost {
                                ip: ip.to_string(),
                                mac: Some(mac.replace("-", ":").to_lowercase()),
                                interface: current_interface.clone(),
                            });
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            // Linux: ip neigh show
            if let Ok(output) = Command::new("ip").args(["neigh", "show"]).output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    // Example: 192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
                    if parts.len() >= 5 {
                        let ip = parts[0];
                        let dev = parts[2];
                        let mac = parts[4];
                        hosts.push(DiscoveredHost {
                            ip: ip.to_string(),
                            mac: Some(mac.to_string()),
                            interface: dev.to_string(),
                        });
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            // macOS: arp -an
            if let Ok(output) = Command::new("arp").arg("-an").output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    // (192.168.1.1) at 00:11:22:33:44:55 on en0
                    if let Some(start) = line.find('(') {
                        if let Some(end) = line.find(')') {
                            let ip = &line[start + 1..end];
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            // parts[parts.len()-1] is usually the interface
                            hosts.push(DiscoveredHost {
                                ip: ip.to_string(),
                                mac: parts.get(3).map(|&m| m.to_string()),
                                interface: parts.last().unwrap_or(&"unknown").to_string(),
                            });
                        }
                    }
                }
            }
        }

        info!("Scraped {} hosts from ARP cache", hosts.len());
        hosts
    }

    /// Identify subnet boundaries using sysinfo.
    pub fn list_subnets(&mut self) -> Vec<String> {
        let networks = Networks::new_with_refreshed_list();
        let mut subnets = Vec::new();

        for (name, _data) in &networks {
            info!("Network Interface: {}", name);
            // In sysinfo 0.30, IP discovery is platform-specific or handled differently.
            // For now, we list the interfaces.
            subnets.push(name.clone());
        }
        subnets
    }
}
