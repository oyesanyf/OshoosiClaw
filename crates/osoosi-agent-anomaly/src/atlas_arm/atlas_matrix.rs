use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AtlasTactic {
    Reconnaissance,
    ResourceDevelopment,
    InitialAccess,
    MLModelAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    MLAttackStaging,
    Exfiltration,
    CommandAndControl,
    Impact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasTechnique {
    pub technique_id: String,
    pub name: String,
    pub tactic: AtlasTactic,
    pub description: String,
    pub relevant_mitigations: Vec<String>,
}

/// MITRE ATLAS Knowledge Base for AI System Adversarial Testing.
/// Covers the official 16 Tactics and key AI / Agent Swarm Techniques.
pub struct MitreAtlasMatrix {
    pub total_tactics_count: usize,
    pub total_techniques_count: usize,
    pub total_mitigations_count: usize,
    pub total_case_studies_count: usize,
    techniques: Vec<AtlasTechnique>,
}

impl MitreAtlasMatrix {
    pub fn new() -> Self {
        let mut techniques = Vec::new();

        // 1. Initial Access & Prompt Injection
        techniques.push(AtlasTechnique {
            technique_id: "AML.T0051".to_string(),
            name: "LLM Prompt Injection".to_string(),
            tactic: AtlasTactic::InitialAccess,
            description: "Direct or indirect prompt injection embedded in documents or user inputs".to_string(),
            relevant_mitigations: vec!["AML.M1001: Strict Schema Enclave".to_string(), "AML.M1002: Lexical AST Extraction".to_string()],
        });

        // 2. Jailbreak
        techniques.push(AtlasTechnique {
            technique_id: "AML.T0054".to_string(),
            name: "LLM Jailbreak".to_string(),
            tactic: AtlasTactic::Execution,
            description: "Adversarial prompts designed to bypass model alignment or safety filters".to_string(),
            relevant_mitigations: vec!["AML.M1003: Deterministic Policy Guard".to_string()],
        });

        // 3. Escape to Host
        techniques.push(AtlasTechnique {
            technique_id: "AML.T0000".to_string(),
            name: "Escape to Host Operating System".to_string(),
            tactic: AtlasTactic::Execution,
            description: "Attempting to break out of agent execution boundary into host Windows processes".to_string(),
            relevant_mitigations: vec!["AML.M1004: Windows Job Objects".to_string(), "AML.M1005: AppContainer LPAC".to_string(), "AML.M1006: Wasmtime Fuel Sandbox".to_string()],
        });

        // 4. Tool Poisoning
        techniques.push(AtlasTechnique {
            technique_id: "AML.T0001".to_string(),
            name: "Tool Poisoning / Malicious Capability Invocation".to_string(),
            tactic: AtlasTactic::Execution,
            description: "Manipulating agent function calling or parameters to invoke unauthorized tools".to_string(),
            relevant_mitigations: vec!["AML.M1007: HMAC Capability Tokens".to_string(), "AML.M1008: External Authorization Engine".to_string()],
        });

        // 5. Insecure Output Handling
        techniques.push(AtlasTechnique {
            technique_id: "AML.T0002".to_string(),
            name: "Insecure Output Handling".to_string(),
            tactic: AtlasTactic::Impact,
            description: "Passing unsanitized agent outputs to downstream privileged systems".to_string(),
            relevant_mitigations: vec!["AML.M1009: Strongly Typed Structured Artifacts".to_string()],
        });

        // 6. Agent Impersonation
        techniques.push(AtlasTechnique {
            technique_id: "AML.T0003".to_string(),
            name: "Agent Impersonation & Identity Spoofing".to_string(),
            tactic: AtlasTactic::DefenseEvasion,
            description: "Forging agent identity, sequence numbers, or headers to masquerade as another arm".to_string(),
            relevant_mitigations: vec!["AML.M1010: Cryptographic Identity Guard".to_string(), "AML.M1011: Monotonic Sequence Checks".to_string()],
        });

        // 7. Obtain Capabilities
        techniques.push(AtlasTechnique {
            technique_id: "AML.T0016".to_string(),
            name: "Obtain Capabilities / Privilege Laundering".to_string(),
            tactic: AtlasTactic::PrivilegeEscalation,
            description: "Subverting inter-agent delegation to gain unassigned permissions".to_string(),
            relevant_mitigations: vec!["AML.M1012: Delegation Scope Guard".to_string(), "AML.M1013: Capability Intersection Rule".to_string()],
        });

        // 8. Lateral Movement
        techniques.push(AtlasTechnique {
            technique_id: "AML.T0034".to_string(),
            name: "Lateral Movement in Agent Swarm".to_string(),
            tactic: AtlasTactic::LateralMovement,
            description: "Pivoting across agent communication channels to compromise peer agents".to_string(),
            relevant_mitigations: vec!["AML.M1014: Channel Isolation".to_string(), "AML.M1015: Quorum Consensus".to_string()],
        });

        // 9. Command and Control
        techniques.push(AtlasTechnique {
            technique_id: "AML.T0031".to_string(),
            name: "Command and Control / Egress Tunneling".to_string(),
            tactic: AtlasTactic::CommandAndControl,
            description: "Communicating with external attacker servers or C2 infrastructure".to_string(),
            relevant_mitigations: vec!["AML.M1016: Network Guard Google-Only Egress".to_string()],
        });

        // 10. Exfiltration via API
        techniques.push(AtlasTechnique {
            technique_id: "AML.T0024".to_string(),
            name: "Exfiltration via ML Inference / Web API".to_string(),
            tactic: AtlasTactic::Exfiltration,
            description: "Smuggling private corporate data out via HTTP requests or side channels".to_string(),
            relevant_mitigations: vec!["AML.M1017: Strict SSRF Blocking".to_string(), "AML.M1018: Url Parser Host Match".to_string()],
        });

        // 11. Resource Hijacking / DoS
        techniques.push(AtlasTechnique {
            technique_id: "AML.T0042".to_string(),
            name: "Resource Hijacking / Unbounded Computation".to_string(),
            tactic: AtlasTactic::Impact,
            description: "Exhausting host CPU, memory, or LLM token budgets to cause disruption".to_string(),
            relevant_mitigations: vec!["AML.M1019: Sentinel Guard Step Budgets".to_string(), "AML.M1020: 64MB Job Object Clamp".to_string()],
        });

        // 12. Craft Adversarial Data
        techniques.push(AtlasTechnique {
            technique_id: "AML.T0043".to_string(),
            name: "Craft Adversarial Data".to_string(),
            tactic: AtlasTactic::MLAttackStaging,
            description: "Manipulating dataset inputs or Merkle proofs to inject subtle errors".to_string(),
            relevant_mitigations: vec!["AML.M1021: Merkle Audit Hash Chain".to_string(), "AML.M1022: Integrity Guard Checkpoints".to_string()],
        });

        Self {
            total_tactics_count: 16,
            total_techniques_count: 208,
            total_mitigations_count: 40,
            total_case_studies_count: 73,
            techniques,
        }
    }

    pub fn techniques(&self) -> &[AtlasTechnique] {
        &self.techniques
    }

    pub fn get_technique(&self, id: &str) -> Option<&AtlasTechnique> {
        self.techniques.iter().find(|t| t.technique_id == id)
    }
}
