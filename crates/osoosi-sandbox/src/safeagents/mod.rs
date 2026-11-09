//! SafeAgents Native 3-Stage Inspection Pipeline Coordinator
//!
//! Provides zero-overhead, multi-stage inspection for agent tool calls before
//! execution in Tier 1 (Wasmtime) or Tier 2 (AppContainer/JobObject).

use osoosi_types::OctopusSecurityError;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub mod atif_scanner;
pub mod concurrency;
pub mod governance;
pub mod journal;
pub mod judge;
pub mod request_validator;
pub mod scrubber;

pub use atif_scanner::{
    needs_normalization, normalize_for_scan, AtifScannerConfig, AtifSeverity, AtifSignal,
    NativeAtifScanner, Stage2Verdict,
};
pub use concurrency::{ConcurrencyError, SafeAgentsConcurrencyController};
pub use governance::SafeAgentsGovernanceBridge;
pub use journal::{CallsJournal, CallsJournalRecord};
pub use judge::{IsolatedJudge, JudgeConfig, JudgeFallbackPolicy, JudgeVerdict};
pub use request_validator::{
    extract_hosts_from_text, RequestValidator, RequestValidatorConfig, Stage1Verdict,
};
pub use scrubber::{OshoosiScrubber, RedactionStats, ScrubberConfig};

/// Conversational context passed alongside a tool invocation request.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SafeAgentsContext {
    /// Permitted tool names declared in the current conversation schema.
    pub declared_tools: Vec<String>,
    /// Verbatim text of user prompt turns (used for external URL/IP sourcing).
    pub user_prompt_turns: Vec<String>,
    /// Prior assistant turns (strictly stripped during host validation).
    pub assistant_turns: Vec<String>,
    /// Explicitly allowlisted hosts or domain suffixes (e.g., "github.com").
    pub allowed_hosts: Vec<String>,
    /// Optional explicit raw JSON arguments string.
    pub raw_arguments_json: Option<String>,
    /// Action to take on blocked calls.
    pub block_action: SafeAgentsBlockAction,
}

/// Action to perform when a tool call is blocked by SafeAgents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SafeAgentsBlockAction {
    /// Return an Err(OctopusSecurityError::BreakoutDetected).
    #[default]
    FailClosedError,
    /// Return an Ok(TieredExecutionReceipt) with synthetic_text_notice populated.
    SyntheticReceipt,
}

/// Request submitted to the SafeAgents inspection pipeline.
#[derive(Debug, Clone)]
pub struct ToolInspectionRequest<'a> {
    pub agent_id: &'a str,
    pub tool_name: &'a str,
    pub arguments_json: &'a str,
    pub declared_tools: &'a [String],
    pub user_prompt_turns: &'a [String],
    pub assistant_turns: &'a [String],
    pub allowed_hosts: &'a [String],
}

/// Overall verdict emitted by the SafeAgents pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolInspectionVerdict {
    /// Tool call is safe and permitted to proceed to execution tiers.
    Allow,
    /// Tool call matched a security rule or policy violation and must be blocked.
    Blocked {
        reason: String,
        notice: String,
        signals: Vec<AtifSignal>,
    },
    /// Tool call matched medium-severity signals and was evaluated by Judge.
    Suspicious {
        signals: Vec<AtifSignal>,
        judge_verdict: Option<JudgeVerdict>,
    },
}

impl ToolInspectionVerdict {
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked { .. })
    }

    pub fn notice(&self) -> Option<&str> {
        match self {
            Self::Blocked { notice, .. } => Some(notice),
            _ => None,
        }
    }
}

/// Thread-safe coordinator running the 3-stage inspection pipeline.
#[derive(Clone)]
pub struct SafeAgentsPipeline {
    validator: Arc<RequestValidator>,
    atif_scanner: Arc<NativeAtifScanner>,
    judge: Option<Arc<IsolatedJudge>>,
    scrubber: Arc<OshoosiScrubber>,
    journal: Arc<CallsJournal>,
    concurrency: Arc<SafeAgentsConcurrencyController>,
}

impl SafeAgentsPipeline {
    pub fn new() -> Result<Self, OctopusSecurityError> {
        Ok(Self {
            validator: Arc::new(RequestValidator::default()),
            atif_scanner: Arc::new(NativeAtifScanner::new()),
            judge: IsolatedJudge::try_from_env().map(Arc::new),
            scrubber: Arc::new(OshoosiScrubber),
            journal: Arc::new(
                CallsJournal::default_path()
                    .map_err(|e| OctopusSecurityError::IsolationViolation(e.to_string()))?,
            ),
            concurrency: Arc::new(SafeAgentsConcurrencyController::default()),
        })
    }

    pub fn with_components(
        validator: Arc<RequestValidator>,
        atif_scanner: Arc<NativeAtifScanner>,
        judge: Option<Arc<IsolatedJudge>>,
        scrubber: Arc<OshoosiScrubber>,
        journal: Arc<CallsJournal>,
        concurrency: Arc<SafeAgentsConcurrencyController>,
    ) -> Self {
        Self {
            validator,
            atif_scanner,
            judge,
            scrubber,
            journal,
            concurrency,
        }
    }

    pub fn validator(&self) -> &Arc<RequestValidator> {
        &self.validator
    }

    pub fn atif_scanner(&self) -> &Arc<NativeAtifScanner> {
        &self.atif_scanner
    }

    pub fn judge(&self) -> Option<&Arc<IsolatedJudge>> {
        self.judge.as_ref()
    }

    pub fn scrubber(&self) -> &Arc<OshoosiScrubber> {
        &self.scrubber
    }

    pub fn journal(&self) -> &Arc<CallsJournal> {
        &self.journal
    }

    pub fn concurrency(&self) -> &Arc<SafeAgentsConcurrencyController> {
        &self.concurrency
    }

    /// Synchronous inspection entry point for TieredExecutionDispatcher.
    pub fn inspect_sync(
        &self,
        req: &ToolInspectionRequest,
    ) -> Result<ToolInspectionVerdict, OctopusSecurityError> {
        // Stage 1.1: Declared tools verification
        if !req.declared_tools.is_empty() && !req.declared_tools.iter().any(|t| t == req.tool_name)
        {
            let reason = "undeclared tool".to_string();
            let notice = format!(
                "[safeagents] blocked call to `{}`: {}",
                req.tool_name, reason
            );
            self.journal.log_blocked(
                req.agent_id,
                req.tool_name,
                req.arguments_json,
                &reason,
                &[],
            );
            return Ok(ToolInspectionVerdict::Blocked {
                reason,
                notice,
                signals: Vec::new(),
            });
        }

        // Stage 2: Native ATIF pattern scanning (<500µs)
        let signals = self.atif_scanner.scan_text(req.arguments_json);
        if let Some(high_sig) = signals.iter().find(|s| s.severity >= AtifSeverity::High) {
            let reason = format!("{}: {}", high_sig.id, high_sig.title);
            let notice = format!(
                "[safeagents] blocked call to `{}`: {}",
                req.tool_name, reason
            );
            self.journal.log_blocked(
                req.agent_id,
                req.tool_name,
                req.arguments_json,
                &reason,
                &signals,
            );
            return Ok(ToolInspectionVerdict::Blocked {
                reason,
                notice,
                signals,
            });
        }

        // Stage 1.2: Host sourcing verification (assistant turns strictly stripped)
        let extracted_hosts = extract_hosts_from_text(req.arguments_json);
        for host in extracted_hosts {
            if !self
                .validator
                .is_host_permitted(&host, req.user_prompt_turns, req.allowed_hosts)
            {
                let reason = format!("host `{}` appears nowhere in the conversation", host);
                let notice = format!(
                    "[safeagents] blocked call to `{}`: {}",
                    req.tool_name, reason
                );
                self.journal.log_blocked(
                    req.agent_id,
                    req.tool_name,
                    req.arguments_json,
                    &reason,
                    &[],
                );
                return Ok(ToolInspectionVerdict::Blocked {
                    reason,
                    notice,
                    signals: Vec::new(),
                });
            }
        }

        // Stage 3: Isolated Judge for Medium-severity signals
        let has_medium = signals.iter().any(|s| s.severity == AtifSeverity::Medium);
        if has_medium {
            if let Some(ref judge) = self.judge {
                let judge_res = judge.evaluate_sync(
                    req.user_prompt_turns,
                    req.tool_name,
                    req.arguments_json,
                    &signals,
                );
                match judge_res {
                    JudgeVerdict::Block {
                        ref reason,
                        ref notice,
                    } => {
                        self.journal.log_blocked(
                            req.agent_id,
                            req.tool_name,
                            req.arguments_json,
                            reason,
                            &signals,
                        );
                        return Ok(ToolInspectionVerdict::Blocked {
                            reason: reason.clone(),
                            notice: notice.clone(),
                            signals,
                        });
                    }
                    JudgeVerdict::Allow => {
                        self.journal.log_flagged(
                            req.agent_id,
                            req.tool_name,
                            req.arguments_json,
                            &signals,
                        );
                        return Ok(ToolInspectionVerdict::Suspicious {
                            signals,
                            judge_verdict: Some(JudgeVerdict::Allow),
                        });
                    }
                }
            }
        }

        self.journal
            .log_allowed(req.agent_id, req.tool_name, req.arguments_json);
        Ok(ToolInspectionVerdict::Allow)
    }

    /// Asynchronous inspection entry point.
    pub async fn inspect_async(
        &self,
        req: &ToolInspectionRequest<'_>,
    ) -> Result<ToolInspectionVerdict, OctopusSecurityError> {
        // Stage 1.1: Declared tools verification
        if !req.declared_tools.is_empty() && !req.declared_tools.iter().any(|t| t == req.tool_name)
        {
            let reason = "undeclared tool".to_string();
            let notice = format!(
                "[safeagents] blocked call to `{}`: {}",
                req.tool_name, reason
            );
            self.journal.log_blocked(
                req.agent_id,
                req.tool_name,
                req.arguments_json,
                &reason,
                &[],
            );
            return Ok(ToolInspectionVerdict::Blocked {
                reason,
                notice,
                signals: Vec::new(),
            });
        }

        // Stage 2: Native ATIF pattern scanning (<500µs)
        let _permit = self.concurrency.acquire_atif_scan().await;
        let signals = self.atif_scanner.scan_text(req.arguments_json);
        drop(_permit);

        if let Some(high_sig) = signals.iter().find(|s| s.severity >= AtifSeverity::High) {
            let reason = format!("{}: {}", high_sig.id, high_sig.title);
            let notice = format!(
                "[safeagents] blocked call to `{}`: {}",
                req.tool_name, reason
            );
            self.journal.log_blocked(
                req.agent_id,
                req.tool_name,
                req.arguments_json,
                &reason,
                &signals,
            );
            return Ok(ToolInspectionVerdict::Blocked {
                reason,
                notice,
                signals,
            });
        }

        // Stage 1.2: Host sourcing verification (assistant turns strictly stripped)
        let extracted_hosts = extract_hosts_from_text(req.arguments_json);
        for host in extracted_hosts {
            if !self
                .validator
                .is_host_permitted(&host, req.user_prompt_turns, req.allowed_hosts)
            {
                let reason = format!("host `{}` appears nowhere in the conversation", host);
                let notice = format!(
                    "[safeagents] blocked call to `{}`: {}",
                    req.tool_name, reason
                );
                self.journal.log_blocked(
                    req.agent_id,
                    req.tool_name,
                    req.arguments_json,
                    &reason,
                    &[],
                );
                return Ok(ToolInspectionVerdict::Blocked {
                    reason,
                    notice,
                    signals: Vec::new(),
                });
            }
        }

        // Stage 3: Isolated Judge for Medium-severity signals
        let has_medium = signals.iter().any(|s| s.severity == AtifSeverity::Medium);
        if has_medium {
            if let Some(ref judge) = self.judge {
                let task = req.user_prompt_turns.join("\n");
                let judge_res = judge
                    .evaluate(&task, req.tool_name, req.arguments_json, &signals)
                    .await;
                match judge_res {
                    JudgeVerdict::Block {
                        ref reason,
                        ref notice,
                    } => {
                        self.journal.log_blocked(
                            req.agent_id,
                            req.tool_name,
                            req.arguments_json,
                            reason,
                            &signals,
                        );
                        return Ok(ToolInspectionVerdict::Blocked {
                            reason: reason.clone(),
                            notice: notice.clone(),
                            signals,
                        });
                    }
                    JudgeVerdict::Allow => {
                        self.journal.log_flagged(
                            req.agent_id,
                            req.tool_name,
                            req.arguments_json,
                            &signals,
                        );
                        return Ok(ToolInspectionVerdict::Suspicious {
                            signals,
                            judge_verdict: Some(JudgeVerdict::Allow),
                        });
                    }
                }
            }
        }

        self.journal
            .log_allowed(req.agent_id, req.tool_name, req.arguments_json);
        Ok(ToolInspectionVerdict::Allow)
    }
}
