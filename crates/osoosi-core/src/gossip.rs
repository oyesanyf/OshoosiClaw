//! Gossip Sleuth: Autonomous Zero-Day Discovery and Mesh Learning.
//!
//! Periodic "Gossip" loop that searches the internet (via feeds + mock web search)
//! for emerging threats, generates learned defenses, and broadcasts them.

use osoosi_types::{GlobalIntelligence, ZeroDayDefense};
use osoosi_policy::ThreatFeedFetcher;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, error};
use chrono::Utc;

pub struct GossipSleuth {
    fetcher: ThreatFeedFetcher,
    mesh_tx: mpsc::Sender<osoosi_wire::MeshCommand>,
    node_id: String,
}

impl GossipSleuth {
    pub fn new(mesh_tx: mpsc::Sender<osoosi_wire::MeshCommand>, node_id: String) -> Self {
        Self {
            fetcher: ThreatFeedFetcher::new(),
            mesh_tx,
            node_id,
        }
    }

    pub async fn start_sleuthing_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // Every 5 mins
        loop {
            interval.tick().await;
            if let Err(e) = self.run_sleuth_iteration().await {
                error!("Gossip Sleuth iteration failed: {}", e);
            }
        }
    }

    async fn run_sleuth_iteration(&self) -> anyhow::Result<()> {
        info!("Gossip Sleuth: Scouting deep-web for zero-day signals...");

        // 1. Fetch Trending KEVs
        let kevs = self.fetcher.fetch_kev().await.unwrap_or_default();
        for kev in kevs.iter().take(2) { // Just the most recent ones
             self.process_kev_intelligence(kev).await?;
        }

        // 2. Mock "Internet Search" for specific trending zero-days
        // In a real agent, this would use an LLM-driven search tool or a specialized CVE API.
        self.scout_trending_vulnerabilities().await?;

        Ok(())
    }

    async fn process_kev_intelligence(&self, kev: &osoosi_types::Kev) -> anyhow::Result<()> {
        let intel = GlobalIntelligence {
            source_url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog".to_string(),
            summary: format!("CISA ALERT: {} ({}) is being actively exploited.", kev.vulnerability_name, kev.cve_id),
            defense: Some(ZeroDayDefense {
                cve_id: kev.cve_id.clone(),
                title: kev.vulnerability_name.clone(),
                description: kev.required_action.clone(),
                severity: 0.9,
                learned_rule: format!("rule sigma_{} {{ detection: ... }}", kev.cve_id.replace("-", "_")),
                software_target: kev.product.clone(),
                date_learned: Utc::now(),
            }),
            timestamp: Utc::now(),
            source_node: self.node_id.clone(),
        };

        info!("Gossip Sleuth: Broadcasting Learned Defense for {} to mesh.", kev.cve_id);
        let _ = self.mesh_tx.send(osoosi_wire::MeshCommand::BroadcastGlobalIntel(intel)).await;
        Ok(())
    }

    async fn scout_trending_vulnerabilities(&self) -> anyhow::Result<()> {
        // Mocking a discovery of a "Zero Day" from a security advisory
        let mock_intel = GlobalIntelligence {
            source_url: "https://github.com/advisories".to_string(),
            summary: "Emerging RCE in popular web-server component detected in the wild.".to_string(),
            defense: Some(ZeroDayDefense {
                cve_id: "CVE-2026-NEW".to_string(),
                title: "Mesh-Wide Zero Day Shield".to_string(),
                description: "Deep-packet inspection rule to block anomalous header smuggling.".to_string(),
                severity: 1.0,
                learned_rule: "rule block_smuggling { strings: $a = \"X-Gossip-Tag: SLEUTH\" ... }".to_string(),
                software_target: "all-web-servers".to_string(),
                date_learned: Utc::now(),
            }),
            timestamp: Utc::now(),
            source_node: self.node_id.clone(),
        };

        let _ = self.mesh_tx.send(osoosi_wire::MeshCommand::BroadcastGlobalIntel(mock_intel)).await;
        Ok(())
    }

    /// Broadcast a specific Indicator of Compromise (IOC) detected locally.
    pub async fn broadcast_ioc(&self, type_id: &str, value: &str, severity: f32) -> anyhow::Result<()> {
        let intel = GlobalIntelligence {
            source_url: format!("local://{}", self.node_id),
            summary: format!("IOC ALERT: Detected malicious {} ({}) on node {}.", type_id, value, self.node_id),
            defense: Some(ZeroDayDefense {
                cve_id: format!("IOC-{}-{}", type_id, value.chars().take(8).collect::<String>()),
                title: format!("Mesh Block: {}", value),
                description: format!("Automatically generated block rule for {} {}", type_id, value),
                severity,
                learned_rule: format!("rule mesh_block_{} {{ condition: hash == \"{}\" }}", type_id, value),
                software_target: "system".to_string(),
                date_learned: Utc::now(),
            }),
            timestamp: Utc::now(),
            source_node: self.node_id.clone(),
        };

        info!("Gossip Sleuth: Broadcasting signed IOC for {} to mesh.", value);
        let _ = self.mesh_tx.send(osoosi_wire::MeshCommand::BroadcastGlobalIntel(intel)).await;
        Ok(())
    }
}
