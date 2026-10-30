//! Milestone M6: ThreatEngine Quorum Consensus, 100% Voter Participation,
//! and `VoterQuorumAlert` -> `ReaVoterEnvGateway` Integration Challenge.

use chrono::Utc;
use osoosi_core::rea_voter_env_gateway::{
    ProcessInstanceKey, ReaForensicVerdict, ReaVoterEnvGateway, VoterQuorumAlert,
};
use osoosi_memory::MemoryStore;
use osoosi_policy::engine::{PolicyEngine, ThreatVoter, VoteResult};
use osoosi_types::{HostEventSource, HostSecurityEvent, PolicyConfig, Priority, ResourceCategory};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

struct MockSilentController;

impl osoosi_types::TelemetryControllerInterface for MockSilentController {
    fn spawn_adaptive(
        &self,
        _cat: ResourceCategory,
        _prio: Priority,
        _task: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>,
    ) {
    }
    fn report_event(&self) {}
    fn is_burst_mode(&self) -> bool {
        false
    }
    fn is_silent_mode(&self) -> bool {
        true
    }
    fn is_socket_exhaustion(&self) -> bool {
        false
    }
    fn set_socket_exhaustion(&self, _v: bool) {}
    fn get_concurrency_limit(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = usize> + Send + '_>> {
        Box::pin(async { 4 })
    }
}

struct MockInstrumentedVoter {
    name: String,
    confidence: f32,
    weight: f32,
    heavy: bool,
    invocations: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl ThreatVoter for MockInstrumentedVoter {
    fn name(&self) -> String {
        self.name.clone()
    }
    fn is_heavy(&self) -> bool {
        self.heavy
    }
    async fn vote(&self, _event: &HostSecurityEvent) -> Option<VoteResult> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        if self.confidence > 0.0 {
            Some(VoteResult {
                confidence: self.confidence,
                reason: format!("{}: Invariant Breakout Analysis", self.name),
                weight: self.weight,
            })
        } else {
            None
        }
    }
}

fn create_security_event(pid: u32, start_ticks: u64, gate_flag: &str) -> HostSecurityEvent {
    let mut data = serde_json::json!({
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c exfiltrate_token",
        "ProcessId": pid,
        "ProcessStartTime": start_ticks,
    });
    if !gate_flag.is_empty() {
        data[gate_flag] = serde_json::json!(true);
    }
    HostSecurityEvent {
        source: HostEventSource::WindowsEventLog,
        event_id: 1,
        timestamp: Utc::now(),
        computer: "test-workstation".to_string(),
        data,
        causal_parent: None,
    }
}

#[tokio::test]
async fn test_high_confidence_quorum_alert_quarantines_in_reavoter_gateway() {
    let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
    let config = PolicyConfig::default();
    let engine = PolicyEngine::new(memory, config);

    let counter = Arc::new(AtomicUsize::new(0));
    let voter = Box::new(MockInstrumentedVoter {
        name: "ConsensusInfiltrationDetector".to_string(),
        confidence: 0.90, // 90% confidence -> 9000 bp (>= 6667 BFT quorum)
        weight: 3.0,
        heavy: false,
        invocations: counter.clone(),
    });
    engine.add_voter(voter).await;

    let gateway = Arc::new(ReaVoterEnvGateway::new(Duration::from_secs(30)));
    let gw_sink = gateway.clone();

    engine
        .set_voter_quorum_sink(Arc::new(move |alert| {
            gw_sink.ingest_voter_quorum(alert);
        }))
        .await;

    let target_pid = 7788u32;
    let target_ticks = 100020003000u64;
    let target_key = ProcessInstanceKey::new(target_pid, target_ticks);

    assert!(!gateway.is_quarantined(&target_key));

    let event = create_security_event(target_pid, target_ticks, "GatewayEvaluation");
    let verdict = engine.scan_event(&event).await;
    assert!(verdict.is_some());
    let sig = verdict.unwrap();
    assert!(sig.confidence >= 0.85);

    // Stage 1 Verification: Target must now be immediately locked in QuarantineHold in < 1 us
    assert!(
        gateway.is_quarantined(&target_key),
        "Process instance must be immediately quarantined upon high-confidence quorum alert"
    );
    assert_eq!(gateway.quarantined_count(), 1);

    // Stage 2 Verification: Ingesting benign REA verdict unfreezes the quarantined process
    gateway.ingest_rea_verdict(ReaForensicVerdict {
        target: target_key,
        binary_path: PathBuf::from("C:\\Windows\\System32\\cmd.exe"),
        script_or_module_path: None,
        extracted_c2_domains: Vec::new(),
        injected_module_hashes: Vec::new(),
        confirmed_malicious: false,
    });

    assert!(
        !gateway.is_quarantined(&target_key),
        "Benign REA forensic verdict must unfreeze quarantined target"
    );
    assert_eq!(gateway.quarantined_count(), 0);
}

#[tokio::test]
async fn test_sub_quorum_confidence_does_not_quarantine_in_reavoter_gateway() {
    let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
    let config = PolicyConfig::default();
    let engine = PolicyEngine::new(memory, config);

    let counter = Arc::new(AtomicUsize::new(0));
    // Low confidence voter (50% -> 5000 bp < 6667 BFT threshold)
    let voter = Box::new(MockInstrumentedVoter {
        name: "LowConfidenceAnomalyDetector".to_string(),
        confidence: 0.50,
        weight: 1.0,
        heavy: false,
        invocations: counter.clone(),
    });
    engine.add_voter(voter).await;

    let gateway = Arc::new(ReaVoterEnvGateway::new(Duration::from_secs(30)));
    let gw_sink = gateway.clone();
    engine
        .set_voter_quorum_sink(Arc::new(move |alert| {
            gw_sink.ingest_voter_quorum(alert);
        }))
        .await;

    let target_key = ProcessInstanceKey::new(4321, 555666777);
    let event = create_security_event(4321, 555666777, "GatewayEvaluation");
    let _ = engine.scan_event(&event).await;

    // Below 6667 bp, no quarantine should be imposed
    assert!(!gateway.is_quarantined(&target_key));
    assert_eq!(gateway.quarantined_count(), 0);
}

#[tokio::test]
async fn test_100pct_voter_participation_under_silent_mode_on_all_security_flags() {
    let security_flags = [
        "EnforceCedarGate",
        "GatewayEvaluation",
        "SecurityEvaluation",
        "RequireAllVoters",
        "EnforceSecurityGateway",
    ];

    for flag in security_flags {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let config = PolicyConfig::default();
        let mut engine = PolicyEngine::new(memory, config);
        engine.telemetry_controller = Some(Arc::new(MockSilentController));

        let counter = Arc::new(AtomicUsize::new(0));
        let heavy_voter = Box::new(MockInstrumentedVoter {
            name: format!("HeavyAnalyzer-{}", flag),
            confidence: 0.95,
            weight: 2.0,
            heavy: true,
            invocations: counter.clone(),
        });
        engine.add_voter(heavy_voter).await;

        let event = create_security_event(6100, 999111222, flag);
        let _ = engine.scan_event(&event).await;

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "Heavy voter must participate when {} is set under silent mode",
            flag
        );
    }
}

#[tokio::test]
async fn test_pid_0_never_emits_voter_quorum_alert() {
    let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
    let config = PolicyConfig::default();
    let engine = PolicyEngine::new(memory, config);

    let voter = Box::new(MockInstrumentedVoter {
        name: "HighConfidenceDetector".to_string(),
        confidence: 0.95,
        weight: 3.0,
        heavy: false,
        invocations: Arc::new(AtomicUsize::new(0)),
    });
    engine.add_voter(voter).await;

    let alerts_received = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink_sink = alerts_received.clone();
    engine
        .set_voter_quorum_sink(Arc::new(move |alert| {
            sink_sink.lock().unwrap().push(alert);
        }))
        .await;

    // Event with PID 0
    let event = create_security_event(0, 100020003000, "GatewayEvaluation");
    let sig = engine.scan_event(&event).await;
    assert!(sig.is_some());

    // Zero alerts must be emitted for PID 0
    let alerts = alerts_received.lock().unwrap();
    assert_eq!(alerts.len(), 0, "PID 0 must never emit VoterQuorumAlert");
}

#[tokio::test]
async fn test_sysmon_file_and_pipe_events_participate_100pct_under_silent_mode() {
    // Sysmon 11 (FileCreate) and 17 (PipeEvent)
    for (event_id, field_name, field_val) in [
        (11u32, "TargetFilename", "C:\\temp\\payload.dll"),
        (17u32, "PipeName", "\\Device\\NamedPipe\\cmd_pipe"),
    ] {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let config = PolicyConfig::default();
        let mut engine = PolicyEngine::new(memory, config);
        engine.telemetry_controller = Some(Arc::new(MockSilentController));

        let counter = Arc::new(AtomicUsize::new(0));
        let heavy_voter = Box::new(MockInstrumentedVoter {
            name: format!("HeavyAnalyzer-Event{}", event_id),
            confidence: 0.90,
            weight: 2.0,
            heavy: true,
            invocations: counter.clone(),
        });
        engine.add_voter(heavy_voter).await;

        let mut data = serde_json::json!({
            "ProcessId": 5432,
            "ProcessStartTime": 9988776655u64,
            "GatewayEvaluation": true,
        });
        data[field_name] = serde_json::json!(field_val);

        let event = HostSecurityEvent {
            source: HostEventSource::WindowsEventLog,
            event_id,
            timestamp: Utc::now(),
            computer: "test-workstation".to_string(),
            data,
            causal_parent: None,
        };

        let _ = engine.scan_event(&event).await;
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "Sysmon event {} must run heavy voter under silent mode when gateway flag is set",
            event_id
        );
    }
}

#[tokio::test]
async fn test_clear_voter_quorum_sink_detaches_listener() {
    let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
    let config = PolicyConfig::default();
    let engine = PolicyEngine::new(memory, config);

    let voter = Box::new(MockInstrumentedVoter {
        name: "HighConfidenceDetector".to_string(),
        confidence: 0.95,
        weight: 3.0,
        heavy: false,
        invocations: Arc::new(AtomicUsize::new(0)),
    });
    engine.add_voter(voter).await;

    let alerts_received = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink_sink = alerts_received.clone();
    engine
        .set_voter_quorum_sink(Arc::new(move |alert| {
            sink_sink.lock().unwrap().push(alert);
        }))
        .await;

    let event = create_security_event(8111, 100020003000, "GatewayEvaluation");
    let _ = engine.scan_event(&event).await;
    assert_eq!(alerts_received.lock().unwrap().len(), 1);

    // Clear sink
    engine.clear_voter_quorum_sink().await;

    let event2 = create_security_event(8222, 100020004000, "GatewayEvaluation");
    let _ = engine.scan_event(&event2).await;

    // Alerts count must remain 1 because sink is detached
    assert_eq!(
        alerts_received.lock().unwrap().len(),
        1,
        "Detached sink must not receive new alerts"
    );
}

#[test]
fn test_timestamp_desync_quarantine_matching_by_pid_and_ttl() {
    let gw = ReaVoterEnvGateway::new(Duration::from_secs(30));
    let registered_target = ProcessInstanceKey::new(9900, 111122223333);

    // Consensus voters quarantine PID 9900 with alert
    let alert = VoterQuorumAlert::new(registered_target, 8500, "consensus voter quorum");
    gw.ingest_voter_quorum(alert);

    // Caller attempts to check quarantine using a different start_time (e.g. from event timestamp fallback)
    let desynced_target = ProcessInstanceKey::new(9900, 444455556666);
    assert!(
        gw.is_quarantined(&desynced_target),
        "Gateway must recognize quarantine hold for matching PID with unexpired TTL even if ticks differ"
    );

    // Benign REA verdict unfreezes by PID
    gw.ingest_rea_verdict(ReaForensicVerdict {
        target: desynced_target,
        binary_path: PathBuf::from("C:\\Windows\\System32\\notepad.exe"),
        script_or_module_path: None,
        extracted_c2_domains: Vec::new(),
        injected_module_hashes: Vec::new(),
        confirmed_malicious: false,
    });

    assert!(
        !gw.is_quarantined(&desynced_target),
        "Unfreeze must clear hold by PID"
    );
}
