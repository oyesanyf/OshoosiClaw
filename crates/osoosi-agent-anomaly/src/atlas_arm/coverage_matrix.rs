use super::atlas_matrix::{AtlasTactic, MitreAtlasMatrix};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Detailed defensive outcome distinguishing prevention from post-execution detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MitigationStatus {
    /// Prevented deterministically at the operating system, sandbox, or enclave boundary
    /// BEFORE any unauthorized execution could occur (e.g. Job Object, AppContainer, Schema).
    PreventedAtBoundary,
    /// Execution occurred but was detected post-launch by telemetry/anomaly supervisors,
    /// triggering circuit-breaker autotomy termination.
    DetectedPostExecution,
    /// Partially mitigated by application controls, but residual risk remains.
    PartiallyMitigated,
    /// Untested in current test suite.
    Untested,
    /// Threat vector does not apply to this agent architecture.
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasCoverageEntry {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: AtlasTactic,
    pub status: MitigationStatus,
    pub primary_enforcement_boundary: String,
    pub supporting_controls: Vec<String>,
    pub empirical_evidence_reference: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasCoverageSummary {
    pub total_assessed: usize,
    pub prevented_at_boundary_count: usize,
    pub detected_post_execution_count: usize,
    pub partially_mitigated_count: usize,
    pub untested_count: usize,
    pub not_applicable_count: usize,
    pub verified_prevention_rate: f64, // Percentage strictly prevented before launch
    pub total_coverage_percentage: f64,
}

/// ATLAS Coverage Matrix: Computes defense-in-depth alignment between
/// Agent Octopus security controls and MITRE ATLAS AI attack techniques.
pub struct AtlasCoverageMatrix {
    entries: HashMap<String, AtlasCoverageEntry>,
}

impl AtlasCoverageMatrix {
    pub fn build(matrix: &MitreAtlasMatrix) -> Self {
        let mut entries = HashMap::new();

        for tech in matrix.techniques() {
            let (status, boundary, controls, evidence) = match tech.technique_id.as_str() {
                "AML.T0000" => (
                    MitigationStatus::PreventedAtBoundary,
                    "Windows Job Object & AppContainer LPAC Moniker".to_string(),
                    vec![
                        "windows_sandbox::WindowsJobObject (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)".to_string(),
                        "windows_sandbox::WindowsJobObject (active_processes <= 1 clamp)".to_string(),
                        "windows_sandbox::WindowsAppContainerProfile (RFC S-1-15-2-... ACLs)".to_string(),
                        "openshell::WasmArmSandbox (Wasmtime hardware instruction fuel metering)".to_string(),
                    ],
                    "containment_tests::test_windows_job_object_and_appcontainer_kernel_isolation".to_string(),
                ),
                "AML.T0051" => (
                    MitigationStatus::PreventedAtBoundary,
                    "Deterministic Schema Lexer Enclave".to_string(),
                    vec![
                        "enclave::doc_extractor (AST JSON parser)".to_string(),
                        "deterministic::schema_guard (Lexical assertion)".to_string(),
                    ],
                    "breakout_defense_tests::test_indirect_prompt_injection_containment".to_string(),
                ),
                "AML.T0054" => (
                    MitigationStatus::PreventedAtBoundary,
                    "Deterministic Policy Engine".to_string(),
                    vec![
                        "deterministic::policy_guard (Spending ceiling)".to_string(),
                        "deterministic::fsm (FSM state enforcement)".to_string(),
                    ],
                    "breakout_defense_tests::test_deterministic_policy_spending_ceiling".to_string(),
                ),
                "AML.T0001" => (
                    MitigationStatus::PreventedAtBoundary,
                    "External Capability Authorization Engine".to_string(),
                    vec![
                        "security::capabilities::CapabilityToken (HMAC-SHA256 tokens)".to_string(),
                        "security::capabilities::ExternalAuthorizationEngine (Secret seed)".to_string(),
                    ],
                    "containment_tests::test_tool_privilege_escalation_blocked_by_capability_engine".to_string(),
                ),
                "AML.T0002" => (
                    MitigationStatus::PreventedAtBoundary,
                    "Strongly-Typed Output Enclave".to_string(),
                    vec![
                        "core::types::VerifiedInvoiceArtifact (Zero unparsed raw prompt passthrough)".to_string(),
                    ],
                    "breakout_defense_tests::test_benign_artifact_flow".to_string(),
                ),
                "AML.T0003" => (
                    MitigationStatus::PreventedAtBoundary,
                    "Cryptographic Identity Guard with Anti-Replay".to_string(),
                    vec![
                        "security::identity::AgentIdentity (HMAC secret verification)".to_string(),
                        "guard_arms::identity_guard (Monotonic sequence counter checks)".to_string(),
                    ],
                    "breakout_scripts::test_breakout_replay_attack_prevention".to_string(),
                ),
                "AML.T0016" => (
                    MitigationStatus::PreventedAtBoundary,
                    "Delegation Scope Guard".to_string(),
                    vec![
                        "security::delegation::DelegationScopeGuard (Intersection of permissions rule)".to_string(),
                    ],
                    "containment_tests::test_confused_deputy_privilege_laundering_blocked".to_string(),
                ),
                "AML.T0034" => (
                    MitigationStatus::PreventedAtBoundary,
                    "Guard Coordinator Quorum Consensus & Isolated Channels".to_string(),
                    vec![
                        "guard_arms::guard_coordinator (Guards watching guards quorum)".to_string(),
                        "neural_mesh::NeuralMesh (Explicit permitted route allowlists)".to_string(),
                    ],
                    "guard_arms_network_tests::test_guard_coordinator_peer_mutual_supervision_and_quorum_isolation".to_string(),
                ),
                "AML.T0031" => (
                    MitigationStatus::PreventedAtBoundary,
                    "Zero-Trust Google Egress Gate".to_string(),
                    vec![
                        "guard_arms::network_guard (Strict google.com host match via url::Url)".to_string(),
                        "enclave::http_gate (Port 443 only, no userinfo, no IP addresses)".to_string(),
                    ],
                    "breakout_scripts::test_breakout_adversarial_google_network_bypass_attempts".to_string(),
                ),
                "AML.T0024" => (
                    MitigationStatus::PreventedAtBoundary,
                    "Cloud Metadata & Private Subnet Filter".to_string(),
                    vec![
                        "guard_arms::network_guard (Direct IP & 169.254.169.254 blocking)".to_string(),
                    ],
                    "breakout_defense_tests::test_ssrf_metadata_blocking".to_string(),
                ),
                "AML.T0042" => (
                    MitigationStatus::DetectedPostExecution,
                    "Telemetry Watchdog & Shannon Entropy Anomaly Detector".to_string(),
                    vec![
                        "telemetry::detector::AnomalyDetector (Shannon entropy threshold)".to_string(),
                        "core::circuit_breaker::KillSwitch (Autotomy circuit breaking)".to_string(),
                        "windows_sandbox::WindowsJobObject (64MB memory clamp)".to_string(),
                    ],
                    "breakout_defense_tests::test_autotomy_circuit_breaking_and_regeneration".to_string(),
                ),
                "AML.T0043" => (
                    MitigationStatus::PreventedAtBoundary,
                    "Merkle Audit Hash Chain & Signed Transparency Checkpoints".to_string(),
                    vec![
                        "core::merkle::MerkleTree (Cryptographic provenance roots)".to_string(),
                        "ledger::transparency::TransparencyLog (Ed25519 checkpoint signatures)".to_string(),
                        "security::audit::SecurityAuditLog (Append-only disk-synced SHA-256 chain)".to_string(),
                    ],
                    "breakout_defense_tests::test_tampered_step_causes_merkle_rejection".to_string(),
                ),
                _ => (
                    MitigationStatus::Untested,
                    "None".to_string(),
                    vec![],
                    "None".to_string(),
                ),
            };

            entries.insert(
                tech.technique_id.clone(),
                AtlasCoverageEntry {
                    technique_id: tech.technique_id.clone(),
                    technique_name: tech.name.clone(),
                    tactic: tech.tactic.clone(),
                    status,
                    primary_enforcement_boundary: boundary,
                    supporting_controls: controls,
                    empirical_evidence_reference: evidence,
                },
            );
        }

        Self { entries }
    }

    pub fn get_coverage(&self, technique_id: &str) -> Option<&AtlasCoverageEntry> {
        self.entries.get(technique_id)
    }

    pub fn entries(&self) -> &HashMap<String, AtlasCoverageEntry> {
        &self.entries
    }

    pub fn summary(&self) -> AtlasCoverageSummary {
        let total = self.entries.len();
        let mut prevented = 0;
        let mut detected = 0;
        let mut partial = 0;
        let mut untested = 0;
        let mut na = 0;

        for entry in self.entries.values() {
            match entry.status {
                MitigationStatus::PreventedAtBoundary => prevented += 1,
                MitigationStatus::DetectedPostExecution => detected += 1,
                MitigationStatus::PartiallyMitigated => partial += 1,
                MitigationStatus::Untested => untested += 1,
                MitigationStatus::NotApplicable => na += 1,
            }
        }

        let verified_rate = if total == 0 {
            0.0
        } else {
            (prevented as f64 / total as f64) * 100.0
        };

        let total_coverage = if total == 0 {
            0.0
        } else {
            ((prevented as f64 + detected as f64 + (partial as f64 * 0.5)) / total as f64) * 100.0
        };

        AtlasCoverageSummary {
            total_assessed: total,
            prevented_at_boundary_count: prevented,
            detected_post_execution_count: detected,
            partially_mitigated_count: partial,
            untested_count: untested,
            not_applicable_count: na,
            verified_prevention_rate: verified_rate,
            total_coverage_percentage: total_coverage,
        }
    }
}
