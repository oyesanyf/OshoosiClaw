pub mod context;
pub mod interceptor;
pub mod policy;
pub mod self_healing;
pub mod telemetry;

pub use context::{
    AgentSecuritySubject, AgentTrustTier, RaspAgentTrustTier, RaspDecision, RaspInterceptionEvent,
    RaspThreatCategory, TaintLevel,
};
pub use interceptor::{
    LateralA2AInterceptor, MemoryScratchpadInterceptor, PromptInvocationInterceptor,
    RaspInterceptor, SubstrateClampInterceptor, ToolActuatorInterceptor,
};
pub use policy::{AdaptiveMitigationTier, RaspCanaryManager, RaspPolicyConfig, RaspPolicyEngine};
pub use self_healing::RaspSelfHealingController;
pub use telemetry::{RaspTelemetryMetrics, RaspTelemetryRegistry};

pub use interceptor::CedarAuthorizationGateway;
pub use self_healing::{AdaptiveRlDefenseEngine, OtelSessionTelemetry};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub fn generate_trace_id() -> String {
    format!("{:032x}", rand::random::<u128>())
}

/// Real-Time Agentic Self-Protection (RT-ASP / RASP) unified engine.
///
/// Instruments runtime agent execution across:
/// 1. Invocations / Prompts & Directives (Prompt injection, jailbreaks, steganography, multilingual taint)
/// 2. Actuators / Tool-Calls (Parameter boundary, traversal, shell injection, Cedar PARC gate)
/// 3. Memory & Scratchpads (Canary tripwires, credential leakage redaction, cross-agent isolation)
/// 4. Agent-to-Agent Lateral Traffic (Collusion, un-attested disbursements, cyclic delegation)
/// 5. OS Substrate & Syscalls (Windows Job Object 64MB memory clamp, process creation veto)
/// 6. Autonomous Self-Healing & Closed-Loop Reinforcement Learning Integration
pub struct AgentRaspEngine {
    policy_engine: Arc<RaspPolicyEngine>,
    prompt_interceptor: PromptInvocationInterceptor,
    actuator_interceptor: ToolActuatorInterceptor,
    memory_interceptor: MemoryScratchpadInterceptor,
    lateral_interceptor: LateralA2AInterceptor,
    substrate_interceptor: SubstrateClampInterceptor,
    telemetry_registry: Arc<RaspTelemetryRegistry>,
    self_healing: Arc<RaspSelfHealingController>,
}

impl AgentRaspEngine {
    pub fn new(
        rl_defense: Arc<AdaptiveRlDefenseEngine>,
        otel_telemetry: Arc<OtelSessionTelemetry>,
    ) -> Self {
        let policy_engine = Arc::new(RaspPolicyEngine::default());
        let prompt_interceptor = PromptInvocationInterceptor::new(Arc::clone(&policy_engine));
        let actuator_interceptor = ToolActuatorInterceptor::new(Arc::clone(&policy_engine));
        let memory_interceptor = MemoryScratchpadInterceptor::new(Arc::clone(&policy_engine));
        let lateral_interceptor = LateralA2AInterceptor::new(Arc::clone(&policy_engine));
        let substrate_interceptor = SubstrateClampInterceptor::new(Arc::clone(&policy_engine));
        let telemetry_registry = Arc::new(RaspTelemetryRegistry::default());
        let self_healing = Arc::new(RaspSelfHealingController::new(rl_defense, otel_telemetry));

        Self {
            policy_engine,
            prompt_interceptor,
            actuator_interceptor,
            memory_interceptor,
            lateral_interceptor,
            substrate_interceptor,
            telemetry_registry,
            self_healing,
        }
    }
}

impl Default for AgentRaspEngine {
    fn default() -> Self {
        Self::new(
            Arc::new(AdaptiveRlDefenseEngine::default()),
            Arc::new(OtelSessionTelemetry::default()),
        )
    }
}

impl AgentRaspEngine {

    pub fn policy_engine(&self) -> Arc<RaspPolicyEngine> {
        Arc::clone(&self.policy_engine)
    }

    pub fn telemetry_registry(&self) -> Arc<RaspTelemetryRegistry> {
        Arc::clone(&self.telemetry_registry)
    }

    pub fn register_canary(&self, label: &str) -> String {
        self.policy_engine.canary_mgr().register_canary(label)
    }

    /// Intercepts incoming prompts and directives before LLM inference.
    pub fn inspect_invocation(
        &self,
        prompt: &str,
        language_code: Option<&str>,
        subject: &AgentSecuritySubject,
    ) -> (RaspDecision, Option<RaspThreatCategory>) {
        let start = Instant::now();
        let (decision, threat, _taint) =
            self.prompt_interceptor
                .inspect_prompt(prompt, language_code, subject);
        let latency_micros = start.elapsed().as_micros() as u64;

        let event = RaspInterceptionEvent {
            event_id: format!("rasp_inv_{:012x}", rand::random::<u64>()),
            timestamp_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            interceptor_name: "PromptInvocationInterceptor".to_string(),
            subject: subject.clone(),
            threat_category: threat,
            decision: decision.clone(),
            raw_input_summary: prompt.chars().take(128).collect(),
            sanitized_output_summary: None,
            latency_micros,
            trace_id: generate_trace_id(),
            remediated_by_rl: decision.is_blocked(),
            attributes: HashMap::new(),
        };

        self.telemetry_registry.record_event(event.clone());
        self.self_healing.handle_event(&event, &self.policy_engine);

        (decision, threat)
    }

    /// Intercepts tool calls before actuation.
    pub fn inspect_actuator(
        &self,
        tool_name: &str,
        params: &serde_json::Value,
        subject: &AgentSecuritySubject,
        cedar_gateway: Option<&CedarAuthorizationGateway>,
    ) -> (RaspDecision, Option<RaspThreatCategory>, serde_json::Value) {
        let start = Instant::now();
        let (decision, threat, modified_params) = self
            .actuator_interceptor
            .intercept_tool_call(tool_name, params, subject, cedar_gateway);
        let latency_micros = start.elapsed().as_micros() as u64;

        let event = RaspInterceptionEvent {
            event_id: format!("rasp_act_{:012x}", rand::random::<u64>()),
            timestamp_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            interceptor_name: "ToolActuatorInterceptor".to_string(),
            subject: subject.clone(),
            threat_category: threat,
            decision: decision.clone(),
            raw_input_summary: format!("{}({})", tool_name, params.to_string().chars().take(96).collect::<String>()),
            sanitized_output_summary: Some(modified_params.to_string().chars().take(96).collect()),
            latency_micros,
            trace_id: generate_trace_id(),
            remediated_by_rl: decision.is_blocked(),
            attributes: HashMap::new(),
        };

        self.telemetry_registry.record_event(event.clone());
        self.self_healing.handle_event(&event, &self.policy_engine);

        (decision, threat, modified_params)
    }

    /// Intercepts memory read operations and protects canaries / scratchpad partitions.
    pub fn inspect_memory_read(
        &self,
        key: &str,
        subject: &AgentSecuritySubject,
    ) -> (RaspDecision, Option<RaspThreatCategory>) {
        let start = Instant::now();
        let (decision, threat) = self.memory_interceptor.intercept_memory_read(key, subject);
        let latency_micros = start.elapsed().as_micros() as u64;

        let event = RaspInterceptionEvent {
            event_id: format!("rasp_mem_r_{:012x}", rand::random::<u64>()),
            timestamp_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            interceptor_name: "MemoryScratchpadInterceptor".to_string(),
            subject: subject.clone(),
            threat_category: threat,
            decision: decision.clone(),
            raw_input_summary: format!("READ {}", key),
            sanitized_output_summary: None,
            latency_micros,
            trace_id: generate_trace_id(),
            remediated_by_rl: decision.is_blocked(),
            attributes: HashMap::new(),
        };

        self.telemetry_registry.record_event(event.clone());
        self.self_healing.handle_event(&event, &self.policy_engine);

        (decision, threat)
    }

    /// Intercepts memory writes and scrubs credentials or trips on canaries.
    pub fn inspect_memory_write(
        &self,
        key: &str,
        content: &str,
        subject: &AgentSecuritySubject,
    ) -> (RaspDecision, Option<RaspThreatCategory>, String) {
        let start = Instant::now();
        let (decision, threat, sanitized) =
            self.memory_interceptor
                .intercept_memory_write(key, content, subject);
        let latency_micros = start.elapsed().as_micros() as u64;

        let event = RaspInterceptionEvent {
            event_id: format!("rasp_mem_w_{:012x}", rand::random::<u64>()),
            timestamp_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            interceptor_name: "MemoryScratchpadInterceptor".to_string(),
            subject: subject.clone(),
            threat_category: threat,
            decision: decision.clone(),
            raw_input_summary: format!("WRITE {} ({} chars)", key, content.len()),
            sanitized_output_summary: Some(sanitized.chars().take(64).collect()),
            latency_micros,
            trace_id: generate_trace_id(),
            remediated_by_rl: decision.is_blocked(),
            attributes: HashMap::new(),
        };

        self.telemetry_registry.record_event(event.clone());
        self.self_healing.handle_event(&event, &self.policy_engine);

        (decision, threat, sanitized)
    }

    /// Intercepts lateral agent-to-agent transactions.
    pub fn inspect_a2a_communication(
        &self,
        sender_subject: &AgentSecuritySubject,
        target_agent: &str,
        message: &serde_json::Value,
    ) -> (RaspDecision, Option<RaspThreatCategory>) {
        let start = Instant::now();
        let (decision, threat) =
            self.lateral_interceptor
                .intercept_a2a_message(sender_subject, target_agent, message);
        let latency_micros = start.elapsed().as_micros() as u64;

        let event = RaspInterceptionEvent {
            event_id: format!("rasp_a2a_{:012x}", rand::random::<u64>()),
            timestamp_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            interceptor_name: "LateralA2AInterceptor".to_string(),
            subject: sender_subject.clone(),
            threat_category: threat,
            decision: decision.clone(),
            raw_input_summary: format!("A2A {} -> {}", sender_subject.agent_id, target_agent),
            sanitized_output_summary: None,
            latency_micros,
            trace_id: generate_trace_id(),
            remediated_by_rl: decision.is_blocked(),
            attributes: HashMap::new(),
        };

        self.telemetry_registry.record_event(event.clone());
        self.self_healing.handle_event(&event, &self.policy_engine);

        (decision, threat)
    }

    /// Intercepts process creation attempts at the OS substrate boundary.
    pub fn inspect_substrate_spawn(
        &self,
        executable: &str,
        args: &[String],
        subject: &AgentSecuritySubject,
    ) -> (RaspDecision, Option<RaspThreatCategory>) {
        let start = Instant::now();
        let (decision, threat) =
            self.substrate_interceptor
                .intercept_process_spawn(executable, args, subject);
        let latency_micros = start.elapsed().as_micros() as u64;

        let event = RaspInterceptionEvent {
            event_id: format!("rasp_sub_spawn_{:012x}", rand::random::<u64>()),
            timestamp_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            interceptor_name: "SubstrateClampInterceptor".to_string(),
            subject: subject.clone(),
            threat_category: threat,
            decision: decision.clone(),
            raw_input_summary: format!("SPAWN {}", executable),
            sanitized_output_summary: None,
            latency_micros,
            trace_id: generate_trace_id(),
            remediated_by_rl: decision.is_blocked(),
            attributes: HashMap::new(),
        };

        self.telemetry_registry.record_event(event.clone());
        self.self_healing.handle_event(&event, &self.policy_engine);

        (decision, threat)
    }

    /// Intercepts memory requests against the 64MB clamp.
    pub fn inspect_substrate_memory(
        &self,
        requested_bytes: usize,
        current_usage_bytes: usize,
        subject: &AgentSecuritySubject,
    ) -> (RaspDecision, Option<RaspThreatCategory>) {
        let start = Instant::now();
        let (decision, threat) = self.substrate_interceptor.intercept_memory_allocation(
            requested_bytes,
            current_usage_bytes,
            subject,
        );
        let latency_micros = start.elapsed().as_micros() as u64;

        let event = RaspInterceptionEvent {
            event_id: format!("rasp_sub_mem_{:012x}", rand::random::<u64>()),
            timestamp_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            interceptor_name: "SubstrateClampInterceptor".to_string(),
            subject: subject.clone(),
            threat_category: threat,
            decision: decision.clone(),
            raw_input_summary: format!("ALLOC +{} bytes", requested_bytes),
            sanitized_output_summary: None,
            latency_micros,
            trace_id: generate_trace_id(),
            remediated_by_rl: decision.is_blocked(),
            attributes: HashMap::new(),
        };

        self.telemetry_registry.record_event(event.clone());
        self.self_healing.handle_event(&event, &self.policy_engine);

        (decision, threat)
    }

    /// Retrieves the most recent N interception events from telemetry registry.
    pub fn get_recent_events(&self, limit: usize) -> Vec<RaspInterceptionEvent> {
        self.telemetry_registry.get_recent_events(limit)
    }

    /// Returns aggregate status for the API and dashboard.
    pub fn status_summary(&self) -> serde_json::Value {
        let metrics = self.telemetry_registry.get_metrics();
        let config = self.policy_engine.config();
        serde_json::json!({
            "subsystem": "Real-Time Agentic Self-Protection (RT-ASP)",
            "status": "OPERATIONAL",
            "active_mitigation_tier": format!("{:?}", config.active_mitigation_tier),
            "max_memory_clamp_mb": config.max_memory_bytes_per_agent / (1024 * 1024),
            "unattested_disbursement_ceiling": config.max_ledger_disbursement_unattested,
            "compromised_canaries_count": self.policy_engine.canary_mgr().compromised_count(),
            "telemetry": metrics,
            "interceptors": [
                { "name": "PromptInvocationInterceptor", "status": "ACTIVE", "surface": "Invocation / Directive Ingest" },
                { "name": "ToolActuatorInterceptor", "status": "ACTIVE", "surface": "Actuator / Tool Execution" },
                { "name": "MemoryScratchpadInterceptor", "status": "ACTIVE", "surface": "Scratchpad & Context State" },
                { "name": "LateralA2AInterceptor", "status": "ACTIVE", "surface": "Inter-Agent Communication" },
                { "name": "SubstrateClampInterceptor", "status": "ACTIVE", "surface": "OS Substrate & Syscalls" }
            ]
        })
    }
}
