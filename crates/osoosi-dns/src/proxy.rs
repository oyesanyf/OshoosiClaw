//! DNS Shield Proxy
//!
//! A local DNS proxy that listens on 127.0.0.1:5353 (non-privileged port),
//! intercepts queries, analyzes them, and forwards clean ones upstream.
//! Uses hickory-resolver for upstream resolution.
//!
//! Cross-platform: Windows, Linux, macOS.

use crate::analysis::{self, DnsVerdict};
use crate::blocklist::DnsBlocklist;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{error, info, warn};
use hickory_proto::op::{Message, MessageType, ResponseCode, Header};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use dashmap::DashMap;

/// Telemetry event emitted by the DNS Shield for consumption by the consensus engine.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DnsEvent {
    pub domain: String,
    pub query_type: String,
    pub verdict: String,
    pub entropy: f64,
    pub reason: String,
    pub source_ip: String,
    pub blocked: bool,
}

/// The DNS Shield proxy server.
pub struct DnsShield {
    blocklist: Arc<DnsBlocklist>,
    /// Channel to send DNS events to the orchestrator for voting
    event_tx: tokio::sync::mpsc::Sender<DnsEvent>,
    /// Cache of recent lookups to avoid redundant upstream queries
    cache: Arc<DashMap<String, Vec<u8>>>,
    /// Upstream DNS server (default: Cloudflare 1.1.1.1)
    upstream: SocketAddr,
    /// Listen address (default: 127.0.0.1:5353)
    listen_addr: SocketAddr,
}

impl DnsShield {
    pub fn new(
        blocklist: Arc<DnsBlocklist>,
        event_tx: tokio::sync::mpsc::Sender<DnsEvent>,
    ) -> Self {
        Self {
            blocklist,
            event_tx,
            cache: Arc::new(DashMap::new()),
            upstream: "1.1.1.1:53".parse().unwrap(),
            listen_addr: "127.0.0.1:5353".parse().unwrap(),
        }
    }

    /// Set the upstream DNS resolver (e.g., "8.8.8.8:53" or "1.0.0.1:53")
    pub fn with_upstream(mut self, addr: SocketAddr) -> Self {
        self.upstream = addr;
        self
    }

    /// Set the listen address (default: 127.0.0.1:5353)
    pub fn with_listen_addr(mut self, addr: SocketAddr) -> Self {
        self.listen_addr = addr;
        self
    }

    /// Start the DNS proxy server. This runs forever.
    pub async fn run(&self) -> anyhow::Result<()> {
        let socket = UdpSocket::bind(self.listen_addr).await?;
        info!(
            "🛡️ DNS Shield active on {} → upstream {}",
            self.listen_addr, self.upstream
        );
        info!(
            "🛡️ Blocklist loaded with {} entries",
            self.blocklist.len()
        );

        let mut buf = vec![0u8; 4096];

        loop {
            let (len, src) = match socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    error!("DNS recv error: {}", e);
                    continue;
                }
            };

            let query_data = buf[..len].to_vec();
            let socket_ref = &socket;
            let blocklist = self.blocklist.clone();
            let event_tx = self.event_tx.clone();
            let cache = self.cache.clone();
            let upstream = self.upstream;

            // Parse the DNS query
            let message = match Message::from_bytes(&query_data) {
                Ok(m) => m,
                Err(e) => {
                    warn!("Malformed DNS query from {}: {}", src, e);
                    continue;
                }
            };

            let query_id = message.id();
            let queries = message.queries().to_vec();

            if queries.is_empty() {
                continue;
            }

            let domain = queries[0].name().to_string();
            let qtype = queries[0].query_type();

            // --- 1. Check blocklist ---
            if let Some(block_reason) = blocklist.is_blocked(&domain) {
                info!("🚫 DNS BLOCKED: {} ({})", domain, block_reason);

                // Send sinkhole response (0.0.0.0)
                let response = build_sinkhole_response(query_id, &domain, qtype);
                if let Ok(bytes) = response.to_bytes() {
                    let _ = socket_ref.send_to(&bytes, src).await;
                }

                // Emit telemetry event
                let _ = event_tx.try_send(DnsEvent {
                    domain: domain.clone(),
                    query_type: format!("{:?}", qtype),
                    verdict: "BLOCKED".to_string(),
                    entropy: 0.0,
                    reason: block_reason,
                    source_ip: src.to_string(),
                    blocked: true,
                });

                continue;
            }

            // --- 2. Analyze domain (DGA, tunneling, entropy) ---
            let analysis = analysis::analyze_domain(&domain);

            if analysis.verdict == DnsVerdict::Block {
                info!("🚫 DNS BLOCKED (analysis): {} — {}", domain, analysis.reason);

                let response = build_sinkhole_response(query_id, &domain, qtype);
                if let Ok(bytes) = response.to_bytes() {
                    let _ = socket_ref.send_to(&bytes, src).await;
                }

                let _ = event_tx.try_send(DnsEvent {
                    domain: domain.clone(),
                    query_type: format!("{:?}", qtype),
                    verdict: "BLOCKED".to_string(),
                    entropy: analysis.entropy,
                    reason: analysis.reason,
                    source_ip: src.to_string(),
                    blocked: true,
                });

                continue;
            }

            // --- 3. Emit suspicious telemetry (but still forward) ---
            if analysis.verdict == DnsVerdict::Suspicious {
                warn!("⚠️ DNS SUSPICIOUS: {} — {}", domain, analysis.reason);
                let _ = event_tx.try_send(DnsEvent {
                    domain: domain.clone(),
                    query_type: format!("{:?}", qtype),
                    verdict: "SUSPICIOUS".to_string(),
                    entropy: analysis.entropy,
                    reason: analysis.reason,
                    source_ip: src.to_string(),
                    blocked: false,
                });
            }

            // --- 4. Check cache ---
            let cache_key = format!("{}:{:?}", domain, qtype);
            if let Some(cached) = cache.get(&cache_key) {
                // Patch the ID to match the current query
                let mut cached_bytes = cached.value().clone();
                if cached_bytes.len() >= 2 {
                    cached_bytes[0] = (query_id >> 8) as u8;
                    cached_bytes[1] = (query_id & 0xFF) as u8;
                }
                let _ = socket_ref.send_to(&cached_bytes, src).await;
                continue;
            }

            // --- 5. Forward to upstream ---
            let upstream_socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to create upstream socket: {}", e);
                    continue;
                }
            };

            if let Err(e) = upstream_socket.send_to(&query_data, upstream).await {
                error!("Failed to forward query to upstream: {}", e);
                continue;
            }

            let mut upstream_buf = vec![0u8; 4096];
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                upstream_socket.recv_from(&mut upstream_buf),
            )
            .await
            {
                Ok(Ok((len, _))) => {
                    let response_data = &upstream_buf[..len];

                    // Cache the response (with a simple TTL-less cache; production would honor DNS TTL)
                    cache.insert(cache_key, response_data.to_vec());

                    // Forward response back to client
                    let _ = socket_ref.send_to(response_data, src).await;
                }
                Ok(Err(e)) => {
                    error!("Upstream DNS error: {}", e);
                }
                Err(_) => {
                    warn!("Upstream DNS timeout for {}", domain);
                }
            }
        }
    }
}

/// Build a DNS response that sinkhole the domain to 0.0.0.0
fn build_sinkhole_response(id: u16, domain: &str, qtype: RecordType) -> Message {
    let mut response = Message::new();
    let mut header = Header::new();
    header.set_id(id);
    header.set_message_type(MessageType::Response);
    header.set_response_code(ResponseCode::NoError);
    header.set_recursion_desired(true);
    header.set_recursion_available(true);
    response.set_header(header);

    // Add a sinkhole A record pointing to 0.0.0.0
    if qtype == RecordType::A || qtype == RecordType::AAAA {
        if let Ok(name) = Name::parse(domain, None) {
            let rdata = if qtype == RecordType::A {
                RData::A(hickory_proto::rr::rdata::A(std::net::Ipv4Addr::new(0, 0, 0, 0)))
            } else {
                RData::AAAA(hickory_proto::rr::rdata::AAAA(std::net::Ipv6Addr::UNSPECIFIED))
            };

            let record = Record::from_rdata(name, 300, rdata);
            response.add_answer(record);
        }
    }

    response
}
