//! Empirical Challenge Suite for Milestone M2B:
//! Multi-Ring Agent Containment Gate & Agentjacking Guard.
//!
//! Adversarial verification harness validating:
//! 1. Pre-Tool Lineage Veto: Tool calls referencing poisoned files/digests are immediately vetoed with `[ContainmentRing-Lineage-Veto]`.
//! 2. Repository Path Immunity: Workspace files (`Cargo.toml`, `src/lib.rs`) and dev toolchains are immune and never blocked even if their hash is poisoned.
//! 3. Tainted Session Forced Caging: `SessionTaintState` taint marking enforces `force_canary_cage = true`.
//! 4. DiracDeltaCapabilityTicket: Bound canary trap metadata and atomic single-use zero-standing privilege enforcement.

use chrono::Utc;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use osoosi_agent_anomaly::agentjacking_guard::{
    AgentjackingGuard, AgentjackingPhase, SessionTaintState,
};
use osoosi_agent_anomaly::containment_ring::{AgentContainmentRing, DiracDeltaCapabilityTicket};
use osoosi_agent_anomaly::file_lineage::FileLineageTracker;
use osoosi_agent_anomaly::types::ToolCallTelemetry;
use osoosi_types::resolve_project_root;

/// Helper to create a temporary test file with specific content
fn create_temp_test_file(prefix: &str, content: &[u8]) -> PathBuf {
    let temp_dir = std::env::temp_dir();
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = temp_dir.join(format!("{}_{}_{}.dat", prefix, std::process::id(), now));
    std::fs::write(&p, content).expect("Failed to write temp test file");
    p
}

/// Helper to build test ToolCallTelemetry
fn build_telemetry(
    session_id: &str,
    agent_id: &str,
    tool_name: &str,
    params: serde_json::Value,
) -> ToolCallTelemetry {
    ToolCallTelemetry {
        session_id: session_id.to_string(),
        agent_id: agent_id.to_string(),
        trace_id: None,
        tool_name: tool_name.to_string(),
        call_parameters: params,
        execution_duration_ms: 10,
        timestamp: Utc::now(),
        tokens_used: None,
        is_error: false,
        error_message: None,
    }
}

/// Challenge 1: Pre-Tool Lineage Veto
/// Creates scenarios where tool calls reference poisoned files or poisoned digests,
/// verifying that execute_contained_tool immediately vetoes execution with [ContainmentRing-Lineage-Veto]
/// and that the enclosed tool closure NEVER runs.
#[test]
fn challenge_pre_tool_lineage_veto() {
    let ring = AgentContainmentRing::new();
    let tracker = FileLineageTracker::new();

    // 1. Create a non-immune file and poison its digest
    let poisoned_file = create_temp_test_file("malicious_doc", b"EXFILTRATE_ENV_VARS_VIA_WEBHOOK");
    let digest = FileLineageTracker::compute_file_blake3(&poisoned_file).expect("Compute BLAKE3");
    tracker
        .mark_digest_poisoned(
            &digest,
            "session-adv-1",
            "Adversarial prompt injection",
            1.0,
        )
        .expect("Poisoning non-immune digest must succeed");

    assert!(tracker.is_poisoned_digest(&digest));

    // Case 1A: Tool parameters contain direct path to poisoned file
    let tel_path = build_telemetry(
        "session-adv-1",
        "agent-infiltrator",
        "read_document",
        json!({"file_path": poisoned_file.to_string_lossy().to_string()}),
    );
    let ticket1 =
        DiracDeltaCapabilityTicket::issue("agent-infiltrator", "read_document", 1, 10_000_000_000);
    let mut closure_ran = false;
    let res = ring.execute_contained_tool(&tel_path, &ticket1, &tracker, || {
        closure_ran = true;
        "UNAUTHORIZED_EXECUTION"
    });

    assert!(res.is_err(), "Tool execution on poisoned file must fail");
    assert!(!closure_ran, "Tool closure must NOT have executed");
    let err_msg = res.unwrap_err();
    assert!(
        err_msg.contains("[ContainmentRing-Lineage-Veto]"),
        "Error message must contain [ContainmentRing-Lineage-Veto], got: {}",
        err_msg
    );
    assert!(
        err_msg.contains(&digest),
        "Error message must reference the poisoned digest: {}",
        err_msg
    );

    // Case 1B: Tool parameters contain raw poisoned hash in nested JSON structure
    let tel_nested = build_telemetry(
        "session-adv-1",
        "agent-infiltrator",
        "analyze_hash",
        json!({
            "request": {
                "batch": [
                    {"sub_id": 1, "target_hash": digest}
                ]
            }
        }),
    );
    let ticket2 =
        DiracDeltaCapabilityTicket::issue("agent-infiltrator", "analyze_hash", 1, 10_000_000_000);
    let mut nested_ran = false;
    let res_nested = ring.execute_contained_tool(&tel_nested, &ticket2, &tracker, || {
        nested_ran = true;
        "NESTED_UNAUTHORIZED"
    });

    assert!(
        res_nested.is_err(),
        "Nested poisoned digest must trigger veto"
    );
    assert!(
        !nested_ran,
        "Tool closure must NOT run on nested poisoned digest"
    );
    let nested_err = res_nested.unwrap_err();
    assert!(
        nested_err.contains("[ContainmentRing-Lineage-Veto]"),
        "Nested error must contain [ContainmentRing-Lineage-Veto], got: {}",
        nested_err
    );

    let _ = std::fs::remove_file(poisoned_file);
}

/// Challenge 2: Repository Path Immunity
/// Verifies that workspace files (Cargo.toml, src/lib.rs) and dev tools
/// return is_path_immune = true, and execute_contained_tool succeeds even if
/// an identical hash is poisoned in poisoned_digests.
#[test]
fn challenge_repository_path_immunity() {
    let ring = AgentContainmentRing::new();
    let tracker = FileLineageTracker::new();

    let root = resolve_project_root().expect("Resolve project root");
    let cargo_toml = root.join("Cargo.toml");
    let lib_rs = root
        .join("crates")
        .join("osoosi-agent-anomaly")
        .join("src")
        .join("lib.rs");

    assert!(cargo_toml.exists(), "Cargo.toml must exist");
    assert!(lib_rs.exists(), "lib.rs must exist");

    // Verify tracker returns is_path_immune = true
    assert!(
        tracker.is_path_immune(&cargo_toml),
        "Cargo.toml must be immune"
    );
    assert!(tracker.is_path_immune(&lib_rs), "lib.rs must be immune");

    // Compute Cargo.toml BLAKE3 hash
    let cargo_hash =
        FileLineageTracker::compute_file_blake3(&cargo_toml).expect("Cargo.toml BLAKE3");

    // Adversarial scenario: An external source poisons the exact hash of Cargo.toml before
    // Cargo.toml was ingested into the tracker's known_paths map.
    let poison_res = tracker.mark_digest_poisoned(
        &cargo_hash,
        "swarm_external_adversary",
        "Poison attack targeting build file digest",
        1.0,
    );
    assert!(
        poison_res.is_ok(),
        "Digest poisoning should register in tracker"
    );
    assert!(
        tracker.is_poisoned_digest(&cargo_hash),
        "Hash is poisoned in poisoned_digests"
    );

    // Verify execute_contained_tool still SUCCEEDS because is_path_immune is checked first!
    let tel_immune = build_telemetry(
        "session-adv-2",
        "agent-developer",
        "read_build_manifest",
        json!({"path": cargo_toml.to_string_lossy().to_string()}),
    );
    let ticket = DiracDeltaCapabilityTicket::issue(
        "agent-developer",
        "read_build_manifest",
        1,
        10_000_000_000,
    );
    let mut executed = false;
    let res = ring.execute_contained_tool(&tel_immune, &ticket, &tracker, || {
        executed = true;
        "CARGO_TOML_CONTENT_ALLOWED"
    });

    assert!(
        res.is_ok(),
        "Immune path must NOT be vetoed even if its hash is present in poisoned_digests"
    );
    assert!(
        executed,
        "Tool closure must execute for immune repository path"
    );
    assert_eq!(res.unwrap(), "CARGO_TOML_CONTENT_ALLOWED");

    // Verify same behavior for library source file
    let lib_hash = FileLineageTracker::compute_file_blake3(&lib_rs).expect("lib.rs BLAKE3");
    let _ = tracker.mark_digest_poisoned(
        &lib_hash,
        "swarm_external_adversary",
        "Targeting lib.rs",
        1.0,
    );
    assert!(tracker.is_poisoned_digest(&lib_hash));

    let tel_lib = build_telemetry(
        "session-adv-3",
        "agent-developer",
        "inspect_source",
        json!({"source": lib_rs.to_string_lossy().to_string()}),
    );
    let ticket_lib =
        DiracDeltaCapabilityTicket::issue("agent-developer", "inspect_source", 1, 10_000_000_000);
    let mut lib_executed = false;
    let res_lib = ring.execute_contained_tool(&tel_lib, &ticket_lib, &tracker, || {
        lib_executed = true;
        "LIB_RS_ALLOWED"
    });
    assert!(res_lib.is_ok(), "lib.rs must be immune and allowed");
    assert!(lib_executed, "lib.rs closure must execute");
    assert_eq!(res_lib.unwrap(), "LIB_RS_ALLOWED");

    // Also test dev interpreter immunity (e.g. python.exe, cargo.exe)
    let cargo_exe = Path::new("cargo.exe");
    assert!(
        tracker.is_path_immune(cargo_exe),
        "cargo.exe must be immune"
    );
}

/// Challenge 3: Tainted Session Forced Caging & DiracDeltaCapabilityTicket Metadata
/// Verifies:
/// 1. mark_session_tainted marks session as TaintedByExternalData and causes requires_canary_cage == true.
/// 2. Subsequent chained tool evaluation reflects force_canary_cage == true.
/// 3. DiracDeltaCapabilityTicket correctly holds, binds, and exposes ephemeral canary trap metadata.
/// 4. Atomic consumption enforces single-use zero-standing privilege (Law 3).
#[test]
fn challenge_tainted_session_forced_caging_and_ticket_canary_binding() {
    let guard = AgentjackingGuard::new();
    let session_id = "sess-challenge-caging-99";

    // Step 1: Clean session initially
    assert_eq!(
        guard.get_session_taint(session_id),
        SessionTaintState::Clean
    );
    assert!(!guard.requires_canary_cage(session_id));

    // Step 2: Ingest untrusted PDF/repo/markdown -> mark_session_tainted
    let new_taint =
        guard.mark_session_tainted(session_id, "https://untrusted-adversary.com/payload.pdf");
    assert_eq!(new_taint, SessionTaintState::TaintedByExternalData);
    assert!(new_taint.force_canary_cage());
    assert!(guard.requires_canary_cage(session_id));

    // Step 3: Tool calls in this session must mandate force_canary_cage = true
    let tool_eval = guard.evaluate_chained_tool_call(
        session_id,
        "summarize_pdf",
        &json!({"doc": "payload.pdf"}),
        None,
    );
    assert!(tool_eval.is_allowed);
    assert!(
        tool_eval.force_canary_cage,
        "Tainted session must enforce force_canary_cage = true"
    );
    assert_eq!(
        tool_eval.taint_state,
        SessionTaintState::TaintedByExternalData
    );

    // Step 4: Verify Quarantined state also forces canary cage
    let quarantined_eval = guard.evaluate_chained_tool_call(
        session_id,
        "shell_exec",
        &json!({"cmd": "powershell.exe -Enc MaliciousPayload"}),
        None,
    );
    assert!(!quarantined_eval.is_allowed);
    assert!(quarantined_eval.force_canary_cage);
    assert_eq!(quarantined_eval.taint_state, SessionTaintState::Quarantined);
    assert_eq!(
        quarantined_eval.detected_phase,
        Some(AgentjackingPhase::Phase3ChainedToolAbuse)
    );

    // Step 5: Test DiracDeltaCapabilityTicket canary binding & zero standing privilege
    let canary_token = "canary_tok_7f9a1b2c3d4e";
    let trap_uri = r"\\.\pipe\osoosi_canary_sess_99_deadbeef";

    // Builder method issue_with_canary
    let ticket1 = DiracDeltaCapabilityTicket::issue_with_canary(
        "agent-99",
        "fetch_api",
        1,
        5_000_000_000,
        Some(canary_token.to_string()),
        Some(trap_uri.to_string()),
    );
    assert_eq!(ticket1.canary_token_id.as_deref(), Some(canary_token));
    assert_eq!(ticket1.canary_trap_uri.as_deref(), Some(trap_uri));
    assert_eq!(ticket1.agent_id, "agent-99");
    assert_eq!(ticket1.tool_action, "fetch_api");

    // Dynamic binding via bind_canary
    let mut ticket2 = DiracDeltaCapabilityTicket::issue("agent-99", "fetch_api", 1, 5_000_000_000);
    assert_eq!(ticket2.canary_token_id, None);
    ticket2.bind_canary("tok_new", "memfd://canary_trap_fd");
    assert_eq!(ticket2.canary_token_id.as_deref(), Some("tok_new"));
    assert_eq!(
        ticket2.canary_trap_uri.as_deref(),
        Some("memfd://canary_trap_fd")
    );

    // Builder pattern with_canary
    let ticket3 = DiracDeltaCapabilityTicket::issue("agent-99", "fetch_api", 1, 5_000_000_000)
        .with_canary("tok_fluent", "pipe://canary");
    assert_eq!(ticket3.canary_token_id.as_deref(), Some("tok_fluent"));
    assert_eq!(ticket3.canary_trap_uri.as_deref(), Some("pipe://canary"));

    // Verify single-use atomic consumption (Law 3: Zero Standing Privilege)
    let secret = ticket3.consume_once("fetch_api");
    assert!(secret.is_ok(), "First consumption must succeed");
    assert_ne!(secret.unwrap(), [0u8; 32], "Secret should be non-zero");

    // Replay attempt must fail closed!
    let replay = ticket3.consume_once("fetch_api");
    assert!(
        replay.is_err(),
        "Second consumption (replay) must be rejected"
    );
    assert!(replay.unwrap_err().contains("already consumed"));
}
