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
            if let Ok(output) = Command::new("arp").arg("-a").output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        let ip = parts[0];
                        let mac = parts[1];
                        if ip.starts_with("192.") || ip.starts_with("10.") || ip.starts_with("172.") {
                            hosts.push(DiscoveredHost {
                                ip: ip.to_string(),
                                mac: Some(mac.to_string()),
                                interface: "unknown".to_string(),
                            });
                        }
                    }
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            // Simplified Linux/macOS fallback
            if let Ok(output) = Command::new("arp").arg("-an").output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    // (192.168.1.1) at 00:11:22:33:44:55 on en0
                    if let Some(start) = line.find('(') {
                        if let Some(end) = line.find(')') {
                            let ip = &line[start + 1..end];
                            hosts.push(DiscoveredHost {
                                ip: ip.to_string(),
                                mac: None,
                                interface: "unknown".to_string(),
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
