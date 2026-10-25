//! Empirical Adversarial Challenge Suite: Provenance Laundering & SSRF Normalization (Milestone 1)
//!
//! Author: Challenger 2 (M1 Adversarial Challenger: Provenance Laundering & SSRF)
//!
//! Objectives:
//! 1. Provenance Laundering Stress-Test:
//!    - Construct a multi-hop relay chain starting from an `Untrusted` arm (`UntrustedDocIngest`)
//!      passing through 3+ intermediate `Worker` arms (`VulnerabilityResearch`, `AnomalyDetection`,
//!      `EvolutionaryOptimizer`), targeting `AccountingLedgerWrite` (PrivilegedSink).
//!    - Verify that `LAW1_STICKY_TAINT_VETO` deterministically halts transmission and prevents authority laundering.
//!    - Test active tamper attacks (stripping provenance, forging taint_floor) and ensure cryptographic HMAC vetoes.
//!    - Test homological exactness and proxy laundering detection via `HomologicalBoundaryAuditor` and `MeshGuard`.
//!    - Verify benign worker-to-worker and clean privileged sink transmissions succeed (zero false positives).
//! 2. SSRF Normalization Stress-Test:
//!    - Non-standard IP encodings: decimal integer, hex, octal, shortened dotted-quad, trailing-dot FQDN.
//!    - IPv6 ranges: NAT64, 6to4, IPv4-mapped, IPv4-compatible, unique local, link-local, loopback, unspecified.
//!    - Verify `validate_agent_egress_url`, `breakout_defense::validate_agent_egress_url`, and `resolve_and_pin`.
//!    - Verify DNS pinning succeeds on legitimate public HTTPS targets and produces valid `PinnedEgress` and `--resolve` flags.

use osoosi_agent_anomaly::breakout_defense::validate_agent_egress_url as validate_egress_url_breakout;
use osoosi_agent_anomaly::containment_ring::{
    ArmContainmentRing, MessageKind, ProvenanceHop, MAX_RELAY_HOPS,
};
use osoosi_agent_anomaly::egress_proxy::{
    is_non_standard_ip_host_encoding, is_restricted_rebinding_ip, resolve_and_pin,
    validate_agent_egress_url,
};
use osoosi_agent_anomaly::mesh_guard::{HomologicalBoundaryAuditor, MeshGuard};
use osoosi_types::arm_role::{ArmRole, TrustTier};
use osoosi_types::OctopusSecurityError;
use std::net::IpAddr;

// ================================================================================================
// PART 1: PROVENANCE LAUNDERING STRESS TESTS
// ================================================================================================

/// Test 1.1: Multi-Hop Relay Chain with 3+ Intermediate Worker Arms
/// UntrustedDocIngest -> VulnerabilityResearch -> AnomalyDetection -> EvolutionaryOptimizer -> AccountingLedgerWrite
/// Deterministically halts at AccountingLedgerWrite with LAW1_STICKY_TAINT_VETO.
#[tokio::test]
async fn challenge_provenance_laundering_multihop_3_intermediate_workers_vetoed() {
    let seed = b"challenger2_provenance_seed_32_bytes";

    // Instantiate arms
    let untrusted_arm = ArmContainmentRing::new(1, ArmRole::UntrustedDocIngest, 1, seed);
    let worker_vuln = ArmContainmentRing::new(2, ArmRole::VulnerabilityResearch, 1, seed);
    let worker_anomaly = ArmContainmentRing::new(3, ArmRole::AnomalyDetection, 1, seed);
    let worker_evo = ArmContainmentRing::new(4, ArmRole::EvolutionaryOptimizer, 1, seed);
    let ledger_sink = ArmContainmentRing::new(5, ArmRole::AccountingLedgerWrite, 1, seed);

    // Verify initial trust tiers
    assert_eq!(untrusted_arm.role.trust_tier(), TrustTier::Untrusted);
    assert_eq!(worker_vuln.role.trust_tier(), TrustTier::Worker);
    assert_eq!(worker_anomaly.role.trust_tier(), TrustTier::Worker);
    assert_eq!(worker_evo.role.trust_tier(), TrustTier::Worker);
    assert_eq!(ledger_sink.role.trust_tier(), TrustTier::PrivilegedSink);

    // Hop 1: UntrustedDocIngest (1) -> VulnerabilityResearch (2)
    let hop1_msg = untrusted_arm
        .sign_mesh_message(
            2,
            1,
            MessageKind::Finding,
            "corr-hop1",
            "malicious-invoice-buffer-overflow",
        )
        .await
        .expect("Hop 1 signing must succeed");
    assert_eq!(hop1_msg.taint_floor, TrustTier::Untrusted);
    assert!(hop1_msg.provenance.is_empty());

    let hop1_verified = worker_vuln
        .verify_incoming_message(&hop1_msg)
        .await
        .expect("Untrusted -> Worker hop 1 is permitted");
    assert_eq!(hop1_verified.effective_taint_floor(), TrustTier::Untrusted);

    // Hop 2: VulnerabilityResearch (2) -> AnomalyDetection (3)
    let hop2_msg = worker_vuln
        .sign_mesh_message(
            3,
            1,
            MessageKind::ThreatMapping,
            "corr-hop2",
            "forwarded-cve-threat-profile",
        )
        .await
        .expect("Hop 2 signing must succeed");
    // Sticky taint floor MUST remain Untrusted even though sender is Worker
    assert_eq!(
        hop2_msg.taint_floor,
        TrustTier::Untrusted,
        "Worker 1 must inherit sticky Untrusted taint floor from tainted state"
    );
    assert_eq!(hop2_msg.provenance.len(), 1);
    assert_eq!(hop2_msg.provenance[0].arm_id, 1);
    assert_eq!(hop2_msg.provenance[0].role, ArmRole::UntrustedDocIngest);

    let hop2_verified = worker_anomaly
        .verify_incoming_message(&hop2_msg)
        .await
        .expect("Worker -> Worker hop 2 is permitted");
    assert_eq!(hop2_verified.effective_taint_floor(), TrustTier::Untrusted);

    // Hop 3: AnomalyDetection (3) -> EvolutionaryOptimizer (4)
    let hop3_msg = worker_anomaly
        .sign_mesh_message(
            4,
            1,
            MessageKind::ChainCandidate,
            "corr-hop3",
            "derived-heuristic-mutation",
        )
        .await
        .expect("Hop 3 signing must succeed");
    assert_eq!(
        hop3_msg.taint_floor,
        TrustTier::Untrusted,
        "Worker 2 must inherit sticky Untrusted taint floor"
    );
    assert_eq!(hop3_msg.provenance.len(), 2);
    assert_eq!(hop3_msg.provenance[0].arm_id, 1);
    assert_eq!(hop3_msg.provenance[1].arm_id, 2);

    let hop3_verified = worker_evo
        .verify_incoming_message(&hop3_msg)
        .await
        .expect("Worker -> Worker hop 3 is permitted");
    assert_eq!(hop3_verified.effective_taint_floor(), TrustTier::Untrusted);

    // Hop 4: EvolutionaryOptimizer (4) -> AccountingLedgerWrite (5) [PrivilegedSink]
    // The attacker attempts to reach PrivilegedSink via 3 intermediate workers!
    let hop4_msg = worker_evo
        .sign_mesh_message(
            5,
            1,
            MessageKind::Alert,
            "corr-hop4-exfil",
            "disburse_funds_to_offshore_account_99999",
        )
        .await
        .expect("Hop 4 signing must succeed");
    assert_eq!(
        hop4_msg.taint_floor,
        TrustTier::Untrusted,
        "Worker 3 must inherit sticky Untrusted taint floor"
    );
    assert_eq!(hop4_msg.provenance.len(), 3);

    // PrivilegedSink verification MUST deterministically halt with LAW1_STICKY_TAINT_VETO
    let sink_verdict = ledger_sink.verify_incoming_message(&hop4_msg).await;
    assert!(
        sink_verdict.is_err(),
        "AccountingLedgerWrite MUST reject multi-hop relay originating from UntrustedDocIngest"
    );

    match sink_verdict {
        Err(OctopusSecurityError::DelegationScopeViolation(err_msg)) => {
            assert!(
                err_msg.contains("LAW1_STICKY_TAINT_VETO")
                    || err_msg.contains("LAW1_PROXY_LAUNDERING_VETO"),
                "Error message must specify Law 1 taint/proxy laundering veto, got: {}",
                err_msg
            );
            assert!(
                err_msg.contains("AccountingLedgerWrite"),
                "Error message must cite recipient sink, got: {}",
                err_msg
            );
        }
        other => panic!(
            "Expected DelegationScopeViolation for sticky taint veto, got: {:?}",
            other
        ),
    }
}

/// Test 1.2: Adversarial Provenance Stripping and Forgery Attack
/// A rogue intermediate worker attempts to forge a clean `taint_floor = Worker` or wipe `provenance`.
/// Verified: Cryptographic HMAC check detects tampering and fails closed with IdentitySpoofingDetected.
#[tokio::test]
async fn challenge_adversarial_provenance_tamper_forgery_fails_closed() {
    let seed = b"challenger2_provenance_seed_32_bytes";
    let worker_vuln = ArmContainmentRing::new(2, ArmRole::VulnerabilityResearch, 1, seed);
    let ledger_sink = ArmContainmentRing::new(5, ArmRole::AccountingLedgerWrite, 1, seed);

    // Create a legitimately signed message
    let mut msg = worker_vuln
        .sign_mesh_message(
            5,
            1,
            MessageKind::Alert,
            "corr-attack",
            "adversarial_forged_payload",
        )
        .await
        .unwrap();

    // Adversarial modification 1: Tamper with taint_floor (change to PrivilegedSink to bypass)
    msg.taint_floor = TrustTier::PrivilegedSink;
    let res1 = ledger_sink.verify_incoming_message(&msg).await;
    assert!(res1.is_err(), "Tampered taint_floor must fail verification");
    match res1 {
        Err(OctopusSecurityError::IdentitySpoofingDetected(msg)) => {
            assert!(
                msg.contains("Mesh taint floor") || msg.contains("signature mismatch"),
                "Must detect taint floor spoofing or HMAC mismatch, got: {}",
                msg
            );
        }
        other => panic!("Expected IdentitySpoofingDetected, got: {:?}", other),
    }

    // Adversarial modification 2: Strip provenance hops on a message that had them
    let mut msg2 = worker_vuln
        .sign_mesh_message(
            5,
            1,
            MessageKind::Alert,
            "corr-attack-2",
            "adversarial_stripped_hops",
        )
        .await
        .unwrap();
    // Simulate attacker injecting fake provenance or stripping signature
    msg2.provenance.push(ProvenanceHop {
        arm_id: 99,
        role: ArmRole::UntrustedDocIngest,
        generation: 1,
    });
    let res2 = ledger_sink.verify_incoming_message(&msg2).await;
    assert!(res2.is_err(), "Modified provenance must fail HMAC check");
    match res2 {
        Err(OctopusSecurityError::IdentitySpoofingDetected(msg)) => {
            assert!(
                msg.contains("signature mismatch"),
                "Must detect HMAC mismatch, got: {}",
                msg
            );
        }
        other => panic!("Expected IdentitySpoofingDetected, got: {:?}", other),
    }
}

/// Test 1.3: Direct and Homological Relay Laundering Defense
/// Direct check via `HomologicalBoundaryAuditor::audit_role_chain` and `MeshGuard::validate_message`
#[tokio::test]
async fn challenge_homological_auditor_and_mesh_guard_proxy_laundering_veto() {
    // 1. Direct Untrusted -> PrivilegedSink (2-simplex boundary veto)
    let direct_chain = [ArmRole::UntrustedDocIngest, ArmRole::AccountingLedgerWrite];
    let report_direct = HomologicalBoundaryAuditor::audit_role_chain(&direct_chain);
    assert!(!report_direct.allowed);
    assert!(report_direct.proxy_laundering_detected);
    assert!(report_direct.reason.contains("LAW1_DIRECT_BOUNDARY_VETO"));

    // 2. 5-hop relay chain: UntrustedDocIngest -> VulnerabilityResearch -> AnomalyDetection -> EvolutionaryOptimizer -> AccountingLedgerWrite
    let relay_chain = [
        ArmRole::UntrustedDocIngest,
        ArmRole::VulnerabilityResearch,
        ArmRole::AnomalyDetection,
        ArmRole::EvolutionaryOptimizer,
        ArmRole::AccountingLedgerWrite,
    ];
    let report_relay = HomologicalBoundaryAuditor::audit_role_chain(&relay_chain);
    assert!(!report_relay.allowed);
    assert!(report_relay.proxy_laundering_detected);
    assert!(report_relay.reason.contains("LAW1_PROXY_LAUNDERING_VETO"));

    // 3. Chain length limit (> MAX_RELAY_HOPS + 1)
    let too_long_chain: Vec<ArmRole> = std::iter::repeat(ArmRole::AnomalyDetection)
        .take(MAX_RELAY_HOPS + 3)
        .collect();
    let report_long = HomologicalBoundaryAuditor::audit_role_chain(&too_long_chain);
    assert!(!report_long.allowed);
    assert!(report_long.reason.contains("LAW1_CHAIN_LENGTH_VETO"));

    // 4. MeshGuard enforcement
    let mesh_guard = MeshGuard::new();
    // Allow route (1 -> 2)
    mesh_guard
        .allow_route(1, 2, Some(MessageKind::Finding))
        .await;

    let seed = b"challenger2_provenance_seed_32_bytes";
    let untrusted_arm = ArmContainmentRing::new(1, ArmRole::UntrustedDocIngest, 1, seed);
    let worker_vuln = ArmContainmentRing::new(2, ArmRole::VulnerabilityResearch, 1, seed);

    let msg1 = untrusted_arm
        .sign_mesh_message(2, 1, MessageKind::Finding, "corr-mesh-1", "doc")
        .await
        .unwrap();
    let verified1 = worker_vuln.verify_incoming_message(&msg1).await.unwrap();

    // Permitted route passes MeshGuard
    let mg_report = mesh_guard.validate_message(&verified1).await;
    assert!(
        mg_report.is_ok(),
        "Authorized Untrusted -> Worker route must pass MeshGuard"
    );

    // Unauthorized route fails MeshGuard (even if role chain is clean)
    let unauth_worker = ArmContainmentRing::new(9, ArmRole::AnomalyDetection, 1, seed);
    let msg_unauth = worker_vuln
        .sign_mesh_message(9, 1, MessageKind::Finding, "corr-unauth", "hello")
        .await
        .unwrap();
    let verified_unauth = unauth_worker.verify_incoming_message(&msg_unauth).await.unwrap();
    let mg_unauth = mesh_guard.validate_message(&verified_unauth).await;
    assert!(
        mg_unauth.is_err(),
        "Unauthorized route must fail MeshGuard route veto"
    );
}

/// Test 1.4: Clean Provenance Chain into Privileged Sink (Zero False Positives)
/// Verify that a clean Worker with NO untrusted ancestry can legitimately send findings to PrivilegedSink.
#[tokio::test]
async fn challenge_clean_provenance_privileged_sink_permitted() {
    let seed = b"challenger2_provenance_seed_32_bytes";

    let worker_clean = ArmContainmentRing::new(10, ArmRole::VulnerabilityResearch, 1, seed);
    let ledger_sink = ArmContainmentRing::new(11, ArmRole::AccountingLedgerWrite, 1, seed);

    // Clean worker message (no prior untrusted taint)
    let clean_msg = worker_clean
        .sign_mesh_message(
            11,
            1,
            MessageKind::Finding,
            "corr-clean-1",
            "cve-audit-complete",
        )
        .await
        .unwrap();
    assert_eq!(clean_msg.taint_floor, TrustTier::Worker);
    assert!(clean_msg.provenance.is_empty());

    let verified = ledger_sink.verify_incoming_message(&clean_msg).await;
    assert!(
        verified.is_ok(),
        "Clean worker message without untrusted taint must be permitted: {:?}",
        verified.err()
    );
}

// ================================================================================================
// PART 2: SSRF NORMALIZATION & RESTRICTED IP ENCODING STRESS TESTS
// ================================================================================================

/// Test 2.1: Non-Standard IP Encodings (Decimal, Hex, Octal, Shortened Quad, Trailing Dot)
#[test]
fn challenge_ssrf_non_standard_ip_host_encodings() {
    // 1. Decimal integer representations
    let decimal_hosts = [
        "2130706433", // 127.0.0.1
        "3232235521", // 192.168.0.1
        "2886729729", // 172.16.0.1
        "167772161",  // 10.0.0.1
        "2852039166", // 169.254.169.254
        "0",          // 0.0.0.0
    ];
    for host in decimal_hosts {
        assert!(
            is_non_standard_ip_host_encoding(host),
            "Decimal host '{}' must be detected as non-standard IP encoding",
            host
        );
    }

    // 2. Hex representations
    let hex_hosts = [
        "0x7f000001",   // 127.0.0.1
        "0x7f.0x0.0x0.0x1",
        "0x7f.1",
        "0x0a000001",   // 10.0.0.1
        "0xa9fea9fe",   // 169.254.169.254
        "0xc0a80001",   // 192.168.0.1
    ];
    for host in hex_hosts {
        assert!(
            is_non_standard_ip_host_encoding(host),
            "Hex host '{}' must be detected as non-standard IP encoding",
            host
        );
    }

    // 3. Octal representations
    let octal_hosts = [
        "0177.0.0.1",
        "0177.000.0000.0001",
        "0177.0.0.01",
        "0012.0.0.1",   // 10.0.0.1
        "0251.0376.0251.0376", // 169.254.169.254
    ];
    for host in octal_hosts {
        assert!(
            is_non_standard_ip_host_encoding(host),
            "Octal host '{}' must be detected as non-standard IP encoding",
            host
        );
    }

    // 4. Shortened dotted quad
    let shortened_quads = [
        "127.1",      // 127.0.0.1
        "10.1",       // 10.0.0.1
        "192.168.1",  // 192.168.0.1
        "172.16.1",   // 172.16.0.1
    ];
    for host in shortened_quads {
        assert!(
            is_non_standard_ip_host_encoding(host),
            "Shortened quad '{}' must be detected as non-standard IP encoding",
            host
        );
    }

    // 5. Standard domains and standard IPs must NOT trigger non-standard flag
    assert!(!is_non_standard_ip_host_encoding("google.com"));
    assert!(!is_non_standard_ip_host_encoding("api.github.com"));
    assert!(!is_non_standard_ip_host_encoding("127.0.0.1"));
    assert!(!is_non_standard_ip_host_encoding("192.168.1.1"));
}

/// Test 2.2: Comprehensive IPv4/IPv6 Mathematical Range Checks
#[test]
fn challenge_ssrf_restricted_ip_mathematical_ranges() {
    let restricted_ips: &[&str] = &[
        // Loopback
        "127.0.0.1",
        "127.0.0.2",
        "127.255.255.254",
        "::1",
        // RFC 1918 Private
        "10.0.0.1",
        "10.254.254.254",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.0.1",
        "192.168.254.254",
        // Cloud Metadata & Link-Local
        "169.254.169.254",
        "169.254.1.1",
        "fe80::1",
        "fe80::dead:beef",
        // CGNAT
        "100.64.0.1",
        "100.127.255.254",
        // Unique Local IPv6 (fc00::/7)
        "fc00::1",
        "fd00::1",
        "fd12:3456:789a::1",
        // Unspecified & Broadcast
        "0.0.0.0",
        "255.255.255.255",
        "::",
        // Benchmarking & Class E & IETF protocol
        "198.18.0.1",
        "198.19.255.254",
        "240.0.0.1",
        "250.1.2.3",
        "192.0.0.1",
        // IPv6 NAT64 (64:ff9b::/96 and 64:ff9b:1::/48)
        "64:ff9b::127.0.0.1",
        "64:ff9b::169.254.169.254",
        "64:ff9b::10.0.0.1",
        "64:ff9b:1::127.0.0.1",
        // IPv6 6to4 (2002::/16)
        "2002:7f00:1::",
        "2002:a00::1",
        "2002:a9fe:a9fe::1",
        // IPv4-mapped IPv6 (::ffff:0:0/96)
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "::ffff:10.0.0.1",
        // IPv4-compatible IPv6 (::0:0/96)
        "::127.0.0.1",
        "::169.254.169.254",
        // Teredo & Documentation
        "2001:0000::1",
        "2001:db8::1",
    ];

    for ip_str in restricted_ips {
        let parsed: IpAddr = ip_str
            .parse()
            .unwrap_or_else(|e| panic!("Failed to parse test IP '{}': {}", ip_str, e));
        assert!(
            is_restricted_rebinding_ip(&parsed),
            "IP '{}' MUST be identified as restricted rebinding IP",
            ip_str
        );
    }

    // Public IPs must NOT be restricted
    let public_ips: &[&str] = &[
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
    ];
    for ip_str in public_ips {
        let parsed: IpAddr = ip_str.parse().unwrap();
        assert!(
            !is_restricted_rebinding_ip(&parsed),
            "Public IP '{}' must NOT be classified as restricted",
            ip_str
        );
    }
}

/// Test 2.3: End-to-End URL Validation & Trailing-Dot FQDN Blocking via egress_proxy
#[test]
fn challenge_ssrf_url_validation_and_trailing_dot_veto() {
    let allowed_domains = vec![
        "google.com".to_string(),
        "example.com".to_string(),
        "github.com".to_string(),
    ];

    let attack_urls = [
        // Non-standard decimal, hex, octal, shortened quad
        "https://2130706433/sensitive-data",
        "https://0x7f000001/admin",
        "https://0x7f.1/admin",
        "https://0177.0.0.1/config",
        "https://127.1/secret",
        // Trailing-dot FQDN loopback evasion
        "https://localhost./evil",
        "https://attacker.localhost./evil",
        "https://sub.local./evil",
        "https://metadata.google.internal./computeMetadata/v1/",
        // Embedded credentials (userinfo)
        "https://admin:password@google.com/search",
        // Non-HTTPS transport
        "http://google.com/search",
        "ftp://google.com/search",
        // Non-443 port
        "https://google.com:8443/search",
        "https://google.com:80/search",
        // IPv6 bracketed restricted targets
        "https://[::1]/secret",
        "https://[fc00::1]/secret",
        "https://[fe80::1]/secret",
        "https://[64:ff9b::7f00:1]/secret",
        "https://[2002:7f00::1]/secret",
        "https://[::ffff:7f00:1]/secret",
        // Raw decimal in domain form
        "https://2130706433:443/secret",
    ];

    for url in attack_urls {
        // Must fail egress_proxy::validate_agent_egress_url
        let res1 = validate_agent_egress_url(url, &allowed_domains);
        assert!(
            res1.is_err(),
            "egress_proxy::validate_agent_egress_url must reject attack URL: {}",
            url
        );

        // Must fail resolve_and_pin
        let res3 = resolve_and_pin(url, &allowed_domains);
        assert!(
            res3.is_err(),
            "resolve_and_pin must reject attack URL: {}",
            url
        );
    }

    // breakout_defense::validate_agent_egress_url blocks decimal, hex, octal, shortened quad, and localhost.
    let breakout_blocked_urls = [
        "https://2130706433/sensitive-data",
        "https://0x7f000001/admin",
        "https://0x7f.1/admin",
        "https://0177.0.0.1/config",
        "https://127.1/secret",
        "https://localhost./evil",
        "https://attacker.localhost./evil",
        "https://[::1]/secret",
        "https://[64:ff9b::7f00:1]/secret",
        "https://[2002:7f00::1]/secret",
        "https://[::ffff:7f00:1]/secret",
    ];
    for url in breakout_blocked_urls {
        let res2 = validate_egress_url_breakout(url, false);
        assert!(
            res2.is_err(),
            "validate_egress_url_breakout must reject attack URL: {}",
            url
        );
    }
}

/// Test 2.4: Empirical Disparity: Legacy breakout_defense vs Hardened egress_proxy
/// Demonstrates that egress_proxy correctly blocks cloud metadata / internal FQDNs
/// (.internal, .local, metadata.google.internal) while legacy breakout_defense omits them.
#[test]
fn challenge_ssrf_disparity_internal_fqdn_bypass_in_legacy_breakout_defense() {
    let internal_urls = [
        "https://metadata.google.internal/computeMetadata/v1/",
        "https://sub.local/secret",
        "https://sub.local./secret",
        "https://service.internal/api",
    ];

    for url in internal_urls {
        // egress_proxy properly BLOCKS internal and cloud metadata hostnames
        assert!(
            validate_agent_egress_url(url, &[]).is_err(),
            "Hardened egress_proxy MUST block internal FQDN: {}",
            url
        );

        // Empirical proof: Legacy breakout_defense currently fails to block these internal FQDNs
        // (documenting the necessity of migrating containment_ring.rs to egress_proxy).
        let legacy_res = validate_egress_url_breakout(url, false);
        assert!(
            legacy_res.is_ok(),
            "Empirical finding: legacy breakout_defense fails to block internal FQDN '{}'",
            url
        );
    }
}

/// Test 2.4: Legitimate DNS Pinning and `--resolve` Flag Formatting
#[test]
fn challenge_dns_pinning_and_curl_resolve_generation() {
    let allowed_domains = vec!["google.com".to_string(), "example.com".to_string()];

    // Test with real public host
    let pinned_res = resolve_and_pin("https://google.com/search?q=test", &allowed_domains);
    assert!(
        pinned_res.is_ok(),
        "resolve_and_pin on https://google.com must succeed: {:?}",
        pinned_res.err()
    );

    let pinned = pinned_res.unwrap();
    assert_eq!(pinned.host, "google.com");
    assert_eq!(pinned.port, 443);
    assert!(!pinned.pinned_addrs.is_empty(), "Must resolve at least 1 IP address");

    // All resolved IPs must be public, non-restricted
    for ip in &pinned.pinned_addrs {
        assert!(
            !is_restricted_rebinding_ip(ip),
            "Resolved IP '{}' for google.com must NOT be in restricted range",
            ip
        );
    }

    // Verify curl_resolve_arg formatting
    let resolve_arg = pinned.curl_resolve_arg();
    assert!(
        resolve_arg.starts_with("google.com:443:"),
        "curl_resolve_arg must start with 'google.com:443:', got: {}",
        resolve_arg
    );
    assert!(
        resolve_arg.contains('.'),
        "curl_resolve_arg must contain valid IP octets"
    );
}
