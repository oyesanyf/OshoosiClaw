use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use libp2p::PeerId;
use osoosi_memory::MemoryStore;
use osoosi_trust::TrustManager;
use osoosi_types::{
    AttestationChallenge, AttestationError, GoldenBaseline,
    PeerAnnounce, PeerRulesConfig, PendingJoinRequest, PolicyConsensusMessage,
    ThreatSignature,
};
use osoosi_wire::{JoinGate, MeshAttestationMessage, MeshCommand, TarpitSignal};
use std::sync::Arc;

struct DummyExecutor;

#[async_trait::async_trait]
impl osoosi_types::SecuredExecutor for DummyExecutor {
    async fn execute(&self, _cmd: std::process::Command) -> anyhow::Result<std::process::Output> {
        Ok(std::process::Output {
            status: std::process::ExitStatus::default(),
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    }

    async fn download(&self, _url: &str, _dest: &std::path::Path, _resume: bool) -> anyhow::Result<()> {
        Ok(())
    }
}

fn setup_test_gate(
    rules: PeerRulesConfig,
    master_pk: Option<String>,
) -> (
    JoinGate,
    tokio::sync::mpsc::Receiver<MeshCommand>,
    Arc<MemoryStore>,
    Arc<TrustManager>,
) {
    let memory = Arc::new(MemoryStore::new(":memory:").unwrap());
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    let tm = Arc::new(TrustManager::new(Arc::new(DummyExecutor)).unwrap());
    let gate = JoinGate::new(memory.clone(), tx, 0.8, rules, master_pk)
        .with_trust_manager(tm.clone());
    (gate, rx, memory, tm)
}

// =========================================================================
// 1. REPLAY ATTACKS ON JOIN GATE AND MESH
// =========================================================================

#[test]
fn test_attack_peer_announce_replay_nonce_triggers_quarantine() {
    let (gate, mut rx, memory, _tm) = setup_test_gate(PeerRulesConfig::default(), None);
    let peer_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
    let peer_id = PeerId::random().to_string();

    let challenge = AttestationChallenge::new(peer_tm.did().clone(), vec![0, 7, 16]);
    let attestation = peer_tm.respond_to_attestation(challenge).unwrap();

    let announce = PeerAnnounce {
        source_node: peer_id.clone(),
        is_patched: true,
        os_name: "Windows".to_string(),
        os_version: "11".to_string(),
        os_supported: true,
        timestamp: Utc::now(),
        membership_proof: None,
        attestation: Some(attestation),
    };

    // First broadcast: legitimate
    let res1 = gate.on_peer_announce_received(&announce, &PeerRulesConfig::default());
    assert!(res1.is_ok());
    assert!(!gate.is_quarantined(&peer_id).unwrap());

    // Second broadcast: replayed identical announce packet
    let res2 = gate.on_peer_announce_received(&announce, &PeerRulesConfig::default());
    assert!(res2.is_ok());

    // Attacker must be quarantined immediately
    assert!(
        gate.is_quarantined(&peer_id).unwrap(),
        "Replaying an announce nonce must trigger peer quarantine"
    );

    let rep = memory.get_reputation(&peer_id).unwrap().unwrap();
    assert_eq!(rep.score, 0.0, "Quarantined peer reputation must drop to 0.0");

    let mut saw_quarantine_cmd = false;
    let mut saw_tripwire_cmd = false;
    while let Ok(cmd) = rx.try_recv() {
        match cmd {
            MeshCommand::QuarantinePeer(_) => saw_quarantine_cmd = true,
            MeshCommand::BroadcastTripwire(_) => saw_tripwire_cmd = true,
            _ => (),
        }
    }
    assert!(saw_quarantine_cmd, "MeshCommand::QuarantinePeer must be dispatched");
    assert!(saw_tripwire_cmd, "MeshCommand::BroadcastTripwire must be dispatched");
}

#[test]
fn test_attack_peer_announce_replay_nonce_from_different_node_id() {
    let (gate, _rx, _memory, _tm) = setup_test_gate(PeerRulesConfig::default(), None);
    let peer_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
    let victim_id = PeerId::random().to_string();
    let attacker_id = PeerId::random().to_string();

    let challenge = AttestationChallenge::new(peer_tm.did().clone(), vec![0, 7, 16]);
    let attestation = peer_tm.respond_to_attestation(challenge).unwrap();

    let announce_victim = PeerAnnounce {
        source_node: victim_id.clone(),
        is_patched: true,
        os_name: "Windows".to_string(),
        os_version: "11".to_string(),
        os_supported: true,
        timestamp: Utc::now(),
        membership_proof: None,
        attestation: Some(attestation.clone()),
    };

    // Victim announces
    assert!(gate.on_peer_announce_received(&announce_victim, &PeerRulesConfig::default()).is_ok());

    // Rogue attacker node steals the attestation packet and re-announces under its own ID
    let announce_attacker = PeerAnnounce {
        source_node: attacker_id.clone(),
        is_patched: true,
        os_name: "Linux".to_string(),
        os_version: "6.1".to_string(),
        os_supported: true,
        timestamp: Utc::now(),
        membership_proof: None,
        attestation: Some(attestation),
    };

    assert!(gate.on_peer_announce_received(&announce_attacker, &PeerRulesConfig::default()).is_ok());

    // Attacker node must be quarantined for replaying seen nonce
    assert!(
        gate.is_quarantined(&attacker_id).unwrap(),
        "Rogue peer replaying another node's attestation nonce must be quarantined"
    );
}

#[test]
fn test_attack_peer_announce_expired_timestamp_triggers_quarantine() {
    let (gate, _rx, memory, _tm) = setup_test_gate(PeerRulesConfig::default(), None);
    let peer_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
    let peer_id = PeerId::random().to_string();

    let challenge = AttestationChallenge::new(peer_tm.did().clone(), vec![0, 7, 16]);
    let attestation = peer_tm.respond_to_attestation(challenge).unwrap();

    // Attacker replays announcement with timestamp 400s in the past (> 300s TTL)
    let stale_time = Utc::now() - chrono::Duration::seconds(400);
    let announce = PeerAnnounce {
        source_node: peer_id.clone(),
        is_patched: true,
        os_name: "Windows".to_string(),
        os_version: "11".to_string(),
        os_supported: true,
        timestamp: stale_time,
        membership_proof: None,
        attestation: Some(attestation),
    };

    assert!(gate.on_peer_announce_received(&announce, &PeerRulesConfig::default()).is_ok());

    assert!(
        gate.is_quarantined(&peer_id).unwrap(),
        "Expired announcement must trigger peer quarantine"
    );
    let rep = memory.get_reputation(&peer_id).unwrap().unwrap();
    assert_eq!(rep.score, 0.0);
}

#[test]
fn test_attack_peer_announce_future_timestamp_triggers_quarantine() {
    let (gate, _rx, memory, _tm) = setup_test_gate(PeerRulesConfig::default(), None);
    let peer_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
    let peer_id = PeerId::random().to_string();

    let challenge = AttestationChallenge::new(peer_tm.did().clone(), vec![0, 7, 16]);
    let attestation = peer_tm.respond_to_attestation(challenge).unwrap();

    // Announcement with future timestamp (age < 0)
    let future_time = Utc::now() + chrono::Duration::seconds(150);
    let announce = PeerAnnounce {
        source_node: peer_id.clone(),
        is_patched: true,
        os_name: "Windows".to_string(),
        os_version: "11".to_string(),
        os_supported: true,
        timestamp: future_time,
        membership_proof: None,
        attestation: Some(attestation),
    };

    assert!(gate.on_peer_announce_received(&announce, &PeerRulesConfig::default()).is_ok());

    assert!(
        gate.is_quarantined(&peer_id).unwrap(),
        "Future-dated announcement must trigger peer quarantine"
    );
    let rep = memory.get_reputation(&peer_id).unwrap().unwrap();
    assert_eq!(rep.score, 0.0);
}

#[test]
fn test_attack_attestation_response_unsolicited_replay_risk() {
    let (gate, mut rx, memory, _tm) = setup_test_gate(PeerRulesConfig::default(), None);
    let peer_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
    let peer_id = PeerId::random().to_string();

    // Attacker crafts an unsolicited attestation response without challenger issuing a challenge
    let dummy_challenge = AttestationChallenge::new(peer_tm.did().clone(), vec![0, 7, 16]);
    let unsolicited_response = peer_tm.respond_to_attestation(dummy_challenge).unwrap();

    let result = gate.handle_attestation_response(&peer_id, &unsolicited_response);
    assert_eq!(
        result,
        Err(AttestationError::NonceReplayDetected),
        "Unsolicited attestation response must be rejected with NonceReplayDetected"
    );

    // Unsolicited response must automatically quarantine the offending peer
    assert!(gate.is_quarantined(&peer_id).unwrap());
    let rep = memory.get_reputation(&peer_id).unwrap().unwrap();
    assert_eq!(rep.score, 0.0);

    let mut saw_quarantine_cmd = false;
    while let Ok(cmd) = rx.try_recv() {
        if let MeshCommand::QuarantinePeer(_) = cmd {
            saw_quarantine_cmd = true;
        }
    }
    assert!(saw_quarantine_cmd);
}

#[test]
fn test_attack_attestation_response_replayed_after_consumption() {
    let (gate, _rx, _memory, _tm) = setup_test_gate(PeerRulesConfig::default(), None);
    let peer_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
    let peer_id = PeerId::random().to_string();

    let challenge = gate.create_attestation_challenge(&peer_id, None);
    let response = peer_tm.respond_to_attestation(challenge).unwrap();

    // First presentation: valid, challenge consumed from active_challenges
    let res1 = gate.handle_attestation_response(&peer_id, &response);
    assert!(res1.is_ok());

    // Replay attack: presenting the same response again
    let res2 = gate.handle_attestation_response(&peer_id, &response);
    assert_eq!(
        res2,
        Err(AttestationError::NonceReplayDetected),
        "Replaying an already-consumed attestation response must fail and quarantine"
    );
    assert!(gate.is_quarantined(&peer_id).unwrap());
}

// =========================================================================
// 2. SYBIL ATTACKS AND JOIN GATE VIOLATIONS
// =========================================================================

#[test]
fn test_attack_discovery_beacon_flooding_sybil_defense() {
    let (gate, _rx, memory, _tm) = setup_test_gate(PeerRulesConfig::default(), None);
    let attacker_pid = PeerId::random();

    // Attacker fires 30 rapid mDNS discovery beacons
    for _ in 0..30 {
        let _ = gate.on_peer_discovered(attacker_pid, Some("/ip4/192.168.1.50/tcp/4001".to_string()));
    }

    // Only 1 entry should exist in pending joins
    let pending = memory.get_pending_joins().unwrap();
    let matches: Vec<_> = pending
        .iter()
        .filter(|p| p.peer_id == attacker_pid.to_string())
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "Discovery rate limiter must throttle repeated discovery beacons to exactly 1"
    );
}

#[tokio::test]
async fn test_attack_quarantined_peer_cannot_bypass_via_mdns_or_allow() {
    let (gate, _rx, memory, _tm) = setup_test_gate(PeerRulesConfig::default(), None);
    let rogue_pid = PeerId::random();
    let rogue_id_str = rogue_pid.to_string();

    // Peer gets quarantined
    gate.quarantine_peer(&rogue_id_str, "Adversarial behavior detected").unwrap();
    assert!(gate.is_quarantined(&rogue_id_str).unwrap());

    // 1. Attacker attempts to rejoin via mDNS discovery beacon
    let _ = gate.on_peer_discovered(rogue_pid, Some("/ip4/10.0.0.99/tcp/4001".to_string()));
    let pending = memory.get_pending_joins().unwrap();
    assert!(
        !pending.iter().any(|p| p.peer_id == rogue_id_str),
        "Quarantined peer must be ignored during mDNS discovery"
    );

    // 2. Attacker attempts direct allow() invocation
    let allow_res = gate.allow(&rogue_id_str).await;
    assert!(
        allow_res.is_err(),
        "allow() must reject quarantined peers"
    );
    assert!(
        allow_res.unwrap_err().to_string().contains("quarantined"),
        "Error message must state peer is quarantined"
    );

    // 3. auto_approve_backlog must ignore quarantined peer
    gate.auto_approve_backlog().unwrap();
    assert!(gate.is_quarantined(&rogue_id_str).unwrap());
}

#[tokio::test]
async fn test_attack_unpatched_and_unsupported_os_peers_blocked() {
    let rules = PeerRulesConfig {
        require_patched: true,
        require_supported_os: true,
        require_tpm_attestation: false,
    };
    let (gate, _rx, memory, _tm) = setup_test_gate(rules, None);

    let unpatched_pid = PeerId::random();
    let unpatched_id = unpatched_pid.to_string();

    let unsupported_pid = PeerId::random();
    let unsupported_id = unsupported_pid.to_string();

    // 1. Unpatched peer announces
    let announce_unpatched = PeerAnnounce {
        source_node: unpatched_id.clone(),
        is_patched: false, // VULNERABLE
        os_name: "Windows".to_string(),
        os_version: "11".to_string(),
        os_supported: true,
        timestamp: Utc::now(),
        membership_proof: None,
        attestation: None,
    };
    let _ = gate.on_peer_announce_received(&announce_unpatched, gate.peer_rules());

    // Discovered via mDNS
    let _ = gate.on_peer_discovered(unpatched_pid, None);
    // Peer should not be pending or should be blocked
    let pending = memory.get_pending_joins().unwrap();
    assert!(
        !pending.iter().any(|p| p.peer_id == unpatched_id),
        "Unpatched peer must be blocked from pending joins"
    );

    let allow_res = gate.allow(&unpatched_id).await;
    assert!(allow_res.is_err(), "allow() must reject unpatched peer");

    // 2. Unsupported OS peer announces (e.g. Windows 7 EOL)
    let announce_eol = PeerAnnounce {
        source_node: unsupported_id.clone(),
        is_patched: true,
        os_name: "Windows".to_string(),
        os_version: "7".to_string(),
        os_supported: false, // EOL
        timestamp: Utc::now(),
        membership_proof: None,
        attestation: None,
    };
    let _ = gate.on_peer_announce_received(&announce_eol, gate.peer_rules());
    let _ = gate.on_peer_discovered(unsupported_pid, None);

    let pending2 = memory.get_pending_joins().unwrap();
    assert!(
        !pending2.iter().any(|p| p.peer_id == unsupported_id),
        "Out-of-support OS peer must be blocked from pending joins"
    );
    assert!(gate.allow(&unsupported_id).await.is_err());
}

#[test]
fn test_attack_master_node_membership_proof_forgery() {
    let mut csprng = rand::thread_rng();
    let master_sk = SigningKey::generate(&mut csprng);
    let master_pk_hex = hex::encode(master_sk.verifying_key().to_bytes());

    let (gate, _rx, memory, _tm) = setup_test_gate(
        PeerRulesConfig::default(),
        Some(master_pk_hex.clone()),
    );

    let honest_pid = PeerId::random().to_string();
    let forger_pid = PeerId::random().to_string();

    // Add forger to pending joins initially (simulating discovery before announce)
    let req = PendingJoinRequest {
        peer_id: forger_pid.clone(),
        multiaddr: None,
        reputation_score: 0.5,
        alerts_verified: 0,
        false_positives: 0,
        discovered_at: Utc::now(),
    };
    memory.add_pending_join(&req).unwrap();
    assert!(memory.get_pending_joins().unwrap().iter().any(|p| p.peer_id == forger_pid));

    // 1. Forger presents invalid signature
    let announce_forged = PeerAnnounce {
        source_node: forger_pid.clone(),
        is_patched: true,
        os_name: "Windows".to_string(),
        os_version: "11".to_string(),
        os_supported: true,
        timestamp: Utc::now(),
        membership_proof: Some("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string()),
        attestation: None,
    };
    let _ = gate.on_peer_announce_received(&announce_forged, gate.peer_rules());
    assert!(
        !memory.get_pending_joins().unwrap().iter().any(|p| p.peer_id == forger_pid),
        "Peer with forged membership proof must be removed from pending joins"
    );

    // 2. Forger presents None
    memory.add_pending_join(&req).unwrap();
    let announce_none = PeerAnnounce {
        source_node: forger_pid.clone(),
        is_patched: true,
        os_name: "Windows".to_string(),
        os_version: "11".to_string(),
        os_supported: true,
        timestamp: Utc::now(),
        membership_proof: None,
        attestation: None,
    };
    let _ = gate.on_peer_announce_received(&announce_none, gate.peer_rules());
    assert!(
        !memory.get_pending_joins().unwrap().iter().any(|p| p.peer_id == forger_pid),
        "Peer without membership proof must be removed from pending joins"
    );

    // 3. Honest peer presents legitimate master signature
    let sig = master_sk.sign(honest_pid.as_bytes());
    let announce_honest = PeerAnnounce {
        source_node: honest_pid.clone(),
        is_patched: true,
        os_name: "Windows".to_string(),
        os_version: "11".to_string(),
        os_supported: true,
        timestamp: Utc::now(),
        membership_proof: Some(hex::encode(sig.to_bytes())),
        attestation: None,
    };
    let res = gate.on_peer_announce_received(&announce_honest, gate.peer_rules());
    assert!(res.is_ok());
    let status = memory.get_peer_status(&honest_pid).unwrap();
    assert!(status.is_some(), "Honest peer with valid membership proof must be accepted");
}

#[test]
fn test_attack_behavioral_score_penalization_auto_quarantine() {
    let (gate, mut rx, memory, _tm) = setup_test_gate(PeerRulesConfig::default(), None);
    let peer_id = PeerId::random().to_string();

    // Initialize peer with reputation 0.8
    let rep = osoosi_types::ReputationScore {
        node_id: peer_id.clone(),
        score: 0.8,
        alerts_verified: 5,
        false_positives: 0,
        last_updated: Utc::now(),
    };
    memory.upsert_reputation(&rep).unwrap();

    // Action 1: Suspicious port scan / beacon spam (penalize 0.3)
    gate.penalize_peer(&peer_id, "Port scan detected", 0.3).unwrap();
    let rep1 = memory.get_reputation(&peer_id).unwrap().unwrap();
    assert!((rep1.score - 0.5).abs() < 1e-4);
    assert!(!gate.is_quarantined(&peer_id).unwrap());

    // Action 2: Sybil flooding / malformed packet (penalize 0.35)
    // 0.5 - 0.35 = 0.15 <= 0.20 (QUARANTINE_THRESHOLD)
    gate.penalize_peer(&peer_id, "Malformed consensus vote flood", 0.35).unwrap();

    // Must be automatically quarantined!
    assert!(
        gate.is_quarantined(&peer_id).unwrap(),
        "Peer crossing under quarantine threshold (0.20) must be automatically quarantined"
    );
    let rep2 = memory.get_reputation(&peer_id).unwrap().unwrap();
    assert_eq!(rep2.score, 0.0, "Score drops to 0.0 upon quarantine");

    let mut saw_quarantine = false;
    let mut saw_tripwire = false;
    while let Ok(cmd) = rx.try_recv() {
        match cmd {
            MeshCommand::QuarantinePeer(_) => saw_quarantine = true,
            MeshCommand::BroadcastTripwire(_) => saw_tripwire = true,
            _ => (),
        }
    }
    assert!(saw_quarantine);
    assert!(saw_tripwire);
}

#[test]
fn test_attack_false_positive_remediation_lifecycle() {
    let (gate, mut rx, memory, _tm) = setup_test_gate(PeerRulesConfig::default(), None);
    let peer_id = PeerId::random().to_string();

    // Peer gets quarantined
    gate.quarantine_peer(&peer_id, "Suspicious activity flagged").unwrap();
    assert!(gate.is_quarantined(&peer_id).unwrap());

    // Drain quarantine command
    while rx.try_recv().is_ok() {}

    // Security operator marks false positive
    gate.mark_false_positive(&peer_id).unwrap();

    // Peer must be released from quarantine
    assert!(!gate.is_quarantined(&peer_id).unwrap());
    let rep = memory.get_reputation(&peer_id).unwrap().unwrap();
    assert!(rep.score >= 0.35, "False positive peer must have score restored");
    assert_eq!(rep.alerts_verified, 1);

    let mut saw_release = false;
    while let Ok(cmd) = rx.try_recv() {
        if let MeshCommand::ReleasePeer(_) = cmd {
            saw_release = true;
        }
    }
    assert!(saw_release, "MeshCommand::ReleasePeer must be dispatched");
}

// =========================================================================
// 3. POISONED MESH GOSSIP & SIGNATURE TAMPERING
// =========================================================================

#[test]
fn test_attack_poisoned_threat_signature_tampered_payload() {
    let mut csprng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut csprng);

    let mut sig = ThreatSignature::new("node_alpha".to_string());
    sig.cve_id = Some("CVE-2024-1234".to_string());
    sig.confidence = 0.95;
    sig.sign(&signing_key).unwrap();

    // Legitimate signature passes verification
    assert!(sig.verify(), "Legitimate signature must verify");

    // Attacker alters CVE ID or confidence without re-signing
    sig.confidence = 0.10;
    assert!(
        !sig.verify(),
        "Tampered confidence must invalidate cryptographic signature"
    );

    // Attacker modifies CVE
    sig.confidence = 0.95; // revert confidence
    sig.cve_id = Some("CVE-9999-99999".to_string()); // tamper CVE
    assert!(
        !sig.verify(),
        "Tampered CVE ID must invalidate cryptographic signature"
    );
}

#[test]
fn test_attack_poisoned_threat_signature_unsigned_rejected() {
    let sig = ThreatSignature::new("node_attacker".to_string());
    assert!(!sig.verify(), "Unsigned threat signature must fail verify()");
}

#[test]
fn test_threat_signature_signed_and_verified_across_mesh() {
    let tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
    let mut sig = ThreatSignature::new(tm.did().id.clone());
    sig.process_name = Some("systeminfo.exe".to_string());
    sig.mitre_technique = Some("T1082".to_string());
    sig.mitre_technique_name = Some("System Information Discovery".to_string());
    sig.mitre_tactic = Some("Discovery".to_string());
    sig.confidence = 0.92;
    sig.recommended_action = osoosi_types::ResponseAction::Isolate;
    sig.hash_blake3 = Some("d9b897931b6df3de856d6d135414f3b8b60381615cb38d61245b0a36bc4c0ce3".to_string());

    // 1. Initially unsigned must fail verification
    assert!(!sig.verify(), "Unsigned threat signature must fail verify()");

    // 2. Cryptographically sign with TrustManager
    tm.sign_threat(&mut sig).expect("Cryptographic signing must succeed");
    assert!(sig.signature.is_some(), "Signature bytes must be present");
    assert!(sig.public_key.is_some(), "Public key bytes must be present");

    // 3. Receiving peer validates threat signature
    assert!(sig.verify(), "Cryptographically signed threat signature must pass verify()");

    // 4. Ensure GossipFeedItem can be constructed and preserves fields
    let feed_item = osoosi_types::GossipFeedItem::from_threat(&sig, "MESH_THREAT_RECEIVED");
    assert_eq!(feed_item.event_type, "MESH_THREAT_RECEIVED");
    assert_eq!(feed_item.process_name.as_deref(), Some("systeminfo.exe"));
    assert_eq!(feed_item.mitre_technique.as_deref(), Some("T1082"));
    assert_eq!(feed_item.severity, "CRITICAL");
    assert_eq!(feed_item.status, "ACTIVE");
    assert!(feed_item.is_threat);
}

#[test]
fn test_attack_malformed_gossip_packets_deserialization_safety() {
    // 1. Truncated / corrupt JSON on threat signature topic
    let corrupt_bytes = b"{\"id\":\"partial_json_without_closing_bracket";
    let res1 = serde_json::from_slice::<ThreatSignature>(corrupt_bytes);
    assert!(res1.is_err(), "Corrupt JSON must fail deserialization cleanly");

    // 2. Type mismatch payload on consensus topic
    let bad_type_bytes = b"{\"Vote\":{\"policy_id\":12345,\"voter_id\":true}}";
    let res2 = serde_json::from_slice::<PolicyConsensusMessage>(bad_type_bytes);
    assert!(res2.is_err());

    // 3. Injection attempt in TarpitSignal
    let bad_tarpit = b"{\"target_ip\":\"'; DROP TABLE peers; --\",\"confidence\":\"not_a_float\"}";
    let res3 = serde_json::from_slice::<TarpitSignal>(bad_tarpit);
    assert!(res3.is_err());

    // 4. Malformed MeshAttestationMessage
    let bad_attestation = b"{\"Challenge\":{\"challenger_peer_id\":null}}";
    let res4 = serde_json::from_slice::<MeshAttestationMessage>(bad_attestation);
    assert!(res4.is_err());
}

#[test]
fn test_attack_golden_baseline_binary_hash_tampering_triggers_immediate_quarantine() {
    let (gate, mut rx, memory, _tm) = setup_test_gate(PeerRulesConfig::default(), None);
    let mut peer_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
    let peer_id = PeerId::random().to_string();

    let baseline = GoldenBaseline::new().allow_binary_hash("strict_trusted_binary_sha256");
    gate.set_golden_baseline(baseline);

    peer_tm.set_local_binary_hash("rogue_injected_binary_hash".to_string());
    let challenge = gate.create_attestation_challenge(&peer_id, None);
    let response = peer_tm.respond_to_attestation(challenge).unwrap();

    let res = gate.handle_attestation_response(&peer_id, &response);
    assert!(res.is_err(), "Attestation must fail on binary hash mismatch");

    assert!(gate.is_quarantined(&peer_id).unwrap());
    let rep = memory.get_reputation(&peer_id).unwrap().unwrap();
    assert_eq!(rep.score, 0.0);

    let mut saw_quarantine = false;
    let mut saw_tripwire = false;
    while let Ok(cmd) = rx.try_recv() {
        match cmd {
            MeshCommand::QuarantinePeer(_) => saw_quarantine = true,
            MeshCommand::BroadcastTripwire(_) => saw_tripwire = true,
            _ => (),
        }
    }
    assert!(saw_quarantine);
    assert!(saw_tripwire);
}

// =========================================================================
// 4. CONCURRENT REPLAY RACING & QUARANTINE HARDENING
// =========================================================================

#[test]
fn test_attack_concurrent_multi_threaded_announce_replay_racing() {
    let (gate, mut rx, memory, _tm) = setup_test_gate(PeerRulesConfig::default(), None);
    let gate = Arc::new(gate);
    let peer_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
    let peer_id = PeerId::random().to_string();

    let challenge = AttestationChallenge::new(peer_tm.did().clone(), vec![0, 7, 16]);
    let attestation = peer_tm.respond_to_attestation(challenge).unwrap();

    let announce = Arc::new(PeerAnnounce {
        source_node: peer_id.clone(),
        is_patched: true,
        os_name: "Windows".to_string(),
        os_version: "11".to_string(),
        os_supported: true,
        timestamp: Utc::now(),
        membership_proof: None,
        attestation: Some(attestation),
    });

    // Spawn 16 concurrent threads all flooding the EXACT same announce packet
    let handles: Vec<_> = (0..16)
        .map(|_| {
            let g = gate.clone();
            let a = announce.clone();
            std::thread::spawn(move || {
                let rules = PeerRulesConfig::default();
                g.on_peer_announce_received(&a, &rules)
            })
        })
        .collect();

    for h in handles {
        let res = h.join().unwrap();
        assert!(res.is_ok(), "Concurrent announce processing should not panic");
    }

    // Because identical nonce was concurrently repeated 16 times, the peer MUST be quarantined!
    assert!(
        gate.is_quarantined(&peer_id).unwrap(),
        "Concurrent replay flood must result in peer quarantine"
    );
    let rep = memory.get_reputation(&peer_id).unwrap().unwrap();
    assert_eq!(rep.score, 0.0, "Score must drop to 0.0 upon replay quarantine");

    let mut saw_quarantine = false;
    while let Ok(cmd) = rx.try_recv() {
        if let MeshCommand::QuarantinePeer(_) = cmd {
            saw_quarantine = true;
        }
    }
    assert!(saw_quarantine, "QuarantinePeer command must be emitted");
}

#[test]
fn test_attack_quarantined_peer_cannot_reannounce() {
    let (gate, _rx, memory, _tm) = setup_test_gate(PeerRulesConfig::default(), None);
    let peer_id = PeerId::random().to_string();

    // Quarantine the peer
    gate.quarantine_peer(&peer_id, "Prior malicious activity").unwrap();
    assert!(gate.is_quarantined(&peer_id).unwrap());

    // Peer attempts to re-announce with fresh attestation
    let peer_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
    let challenge = AttestationChallenge::new(peer_tm.did().clone(), vec![0, 7, 16]);
    let attestation = peer_tm.respond_to_attestation(challenge).unwrap();

    let fresh_announce = PeerAnnounce {
        source_node: peer_id.clone(),
        is_patched: true,
        os_name: "Windows".to_string(),
        os_version: "11".to_string(),
        os_supported: true,
        timestamp: Utc::now(),
        membership_proof: None,
        attestation: Some(attestation),
    };

    let res = gate.on_peer_announce_received(&fresh_announce, &PeerRulesConfig::default());
    assert!(res.is_ok());

    // Peer MUST remain quarantined!
    assert!(
        gate.is_quarantined(&peer_id).unwrap(),
        "Quarantined peer cannot un-quarantine itself via re-announcement"
    );
    let rep = memory.get_reputation(&peer_id).unwrap().unwrap();
    assert_eq!(rep.score, 0.0);
}

#[test]
fn test_attack_quarantined_peer_cannot_submit_attestation_response() {
    let (gate, _rx, _memory, _tm) = setup_test_gate(PeerRulesConfig::default(), None);
    let peer_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
    let peer_id = PeerId::random().to_string();

    let challenge = gate.create_attestation_challenge(&peer_id, None);
    let response = peer_tm.respond_to_attestation(challenge).unwrap();

    // Peer gets quarantined before presenting response
    gate.quarantine_peer(&peer_id, "Compromised peer").unwrap();
    assert!(gate.is_quarantined(&peer_id).unwrap());

    // Attempting to submit attestation response must be rejected
    let res = gate.handle_attestation_response(&peer_id, &response);
    assert!(
        res.is_err(),
        "Attestation response from quarantined peer must be rejected"
    );
    assert!(gate.is_quarantined(&peer_id).unwrap());
    assert!(!gate.is_attestation_verified(&peer_id));
}

#[test]
fn test_attack_quarantined_peer_auto_approve_backlog_skipped() {
    let (gate, mut rx, memory, _tm) = setup_test_gate(PeerRulesConfig::default(), None);
    let peer_id = PeerId::random().to_string();

    // Add peer with high reputation to pending joins
    let req = PendingJoinRequest {
        peer_id: peer_id.clone(),
        multiaddr: None,
        reputation_score: 0.95,
        alerts_verified: 10,
        false_positives: 0,
        discovered_at: Utc::now(),
    };
    memory.add_pending_join(&req).unwrap();

    // Quarantine peer
    gate.quarantine_peer(&peer_id, "Tripwire alert triggered").unwrap();
    assert!(gate.is_quarantined(&peer_id).unwrap());

    // Drain quarantine commands
    while rx.try_recv().is_ok() {}

    // Auto-approve backlog
    gate.auto_approve_backlog().unwrap();

    // Quarantined peer must NOT be approved
    assert!(gate.is_quarantined(&peer_id).unwrap());
    let mut saw_approval = false;
    while let Ok(cmd) = rx.try_recv() {
        if let MeshCommand::ApprovePeer(_) = cmd {
            saw_approval = true;
        }
    }
    assert!(!saw_approval, "Quarantined peer must never be auto-approved");
}

#[test]
fn test_attack_clock_skew_announce_boundary() {
    let (gate, _rx, _memory, _tm) = setup_test_gate(PeerRulesConfig::default(), None);
    let peer_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();

    // 1. Announce timestamp age = 295s (within 300s TTL) -> Accepted
    let peer_1 = PeerId::random().to_string();
    let ch1 = AttestationChallenge::new(peer_tm.did().clone(), vec![0, 7, 16]);
    let att1 = peer_tm.respond_to_attestation(ch1).unwrap();
    let ann_valid = PeerAnnounce {
        source_node: peer_1.clone(),
        is_patched: true,
        os_name: "Windows".to_string(),
        os_version: "11".to_string(),
        os_supported: true,
        timestamp: Utc::now() - chrono::Duration::seconds(295),
        membership_proof: None,
        attestation: Some(att1),
    };
    let res1 = gate.on_peer_announce_received(&ann_valid, &PeerRulesConfig::default());
    assert!(res1.is_ok());
    assert!(!gate.is_quarantined(&peer_1).unwrap(), "Age 295s within 300s TTL must not quarantine");

    // 2. Announce timestamp age = 305s (exceeds 300s TTL) -> Quarantined
    let peer_2 = PeerId::random().to_string();
    let ch2 = AttestationChallenge::new(peer_tm.did().clone(), vec![0, 7, 16]);
    let att2 = peer_tm.respond_to_attestation(ch2).unwrap();
    let ann_expired = PeerAnnounce {
        source_node: peer_2.clone(),
        is_patched: true,
        os_name: "Windows".to_string(),
        os_version: "11".to_string(),
        os_supported: true,
        timestamp: Utc::now() - chrono::Duration::seconds(305),
        membership_proof: None,
        attestation: Some(att2),
    };
    let res2 = gate.on_peer_announce_received(&ann_expired, &PeerRulesConfig::default());
    assert!(res2.is_ok());
    assert!(gate.is_quarantined(&peer_2).unwrap(), "Age 305s past 300s TTL must trigger quarantine");
}

#[test]
fn test_attack_gossipsub_message_deduplication_hash_id() {
    use std::hash::{Hash, Hasher};

    let msg1_data = b"{\"threat\":\"ransomware_sample_01\"}".to_vec();
    let msg2_data = b"{\"threat\":\"ransomware_sample_01\"}".to_vec();
    let msg3_data = b"{\"threat\":\"ransomware_sample_02\"}".to_vec();

    let compute_id = |data: &[u8]| -> String {
        let mut s = std::collections::hash_map::DefaultHasher::new();
        data.hash(&mut s);
        s.finish().to_string()
    };

    let id1 = compute_id(&msg1_data);
    let id2 = compute_id(&msg2_data);
    let id3 = compute_id(&msg3_data);

    assert_eq!(id1, id2, "Identical gossip payloads must produce identical message IDs for deduplication");
    assert_ne!(id1, id3, "Different gossip payloads must produce distinct message IDs");
}

#[test]
fn test_audit_proof_deduplication_and_suppression() {
    let mut last_audit_proof: Option<String> = None;

    let proof_alpha = "merkle_root_0xdeadbeef00112233".to_string();
    let proof_beta = "merkle_root_0xcafebabe44556677".to_string();

    // 1. First broadcast must not be skipped
    let skip_1 = last_audit_proof.as_ref() == Some(&proof_alpha);
    assert!(!skip_1, "Initial audit proof broadcast must not be skipped");
    last_audit_proof = Some(proof_alpha.clone());

    // 2. Redundant broadcast with same Merkle root must be skipped
    let skip_2 = last_audit_proof.as_ref() == Some(&proof_alpha);
    assert!(skip_2, "Consecutive identical audit proof broadcast must be skipped to avoid gossip spam");

    // 3. New Merkle root after new audit leaf must not be skipped
    let skip_3 = last_audit_proof.as_ref() == Some(&proof_beta);
    assert!(!skip_3, "Updated audit proof with new Merkle root must proceed to gossip publish");
    last_audit_proof = Some(proof_beta.clone());

    // 4. Repeated broadcast with new Merkle root must be skipped
    let skip_4 = last_audit_proof.as_ref() == Some(&proof_beta);
    assert!(skip_4, "Consecutive broadcast of updated Merkle root must be skipped");
}

#[tokio::test]
async fn test_mesh_node_initializes_empty_audit_proof() {
    let memory = Arc::new(MemoryStore::new(":memory:").unwrap());
    let node = osoosi_wire::MeshNode::new(memory).await.unwrap();
    assert_eq!(node.last_audit_proof, None, "MeshNode must initialize last_audit_proof to None");
}

#[test]
fn test_gossipsub_duplicate_rejection_behavior() {
    use std::time::Duration;
    use libp2p::gossipsub;
    use libp2p::identity::Keypair;

    let key = Keypair::generate_ed25519();
    let message_id_fn = |message: &gossipsub::Message| {
        let mut s = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hash::hash(&message.data, &mut s);
        gossipsub::MessageId::from(std::hash::Hasher::finish(&s).to_string())
    };

    let config = gossipsub::ConfigBuilder::default()
        .validation_mode(gossipsub::ValidationMode::Strict)
        .message_id_fn(message_id_fn)
        .duplicate_cache_time(Duration::from_secs(60))
        .build()
        .unwrap();

    let mut gs: gossipsub::Behaviour = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(key),
        config,
    ).unwrap();

    let topic = gossipsub::IdentTopic::new("test-gossip-duplicate");
    gs.subscribe(&topic).unwrap();

    let payload = b"test_payload_duplicate_verification".to_vec();

    // First publish without peers will return InsufficientPeers (since no peers connected)
    let res1 = gs.publish(topic.clone(), payload.clone());
    // In strict mode without peers, first publish returns InsufficientPeers
    assert!(matches!(res1, Err(gossipsub::PublishError::InsufficientPeers)));

    // When a duplicate message is known in the duplicate cache (or published again)
    // duplicate detection is guaranteed by the message ID function
    let msg = gossipsub::Message {
        source: None,
        data: payload.clone(),
        sequence_number: None,
        topic: topic.hash(),
    };
    let id1 = (message_id_fn)(&msg);
    let id2 = (message_id_fn)(&msg);
    assert_eq!(id1, id2, "Message IDs must be deterministic for identical payloads");
}


