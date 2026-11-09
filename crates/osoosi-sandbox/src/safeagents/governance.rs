//! SafeAgents Governance Bridge (`KillSwitch` & CAGE CBF Trip Hooks)
//!
//! Enforces immediate termination and fail-closed isolation whenever
//! high-severity ATIF signals or Judge blocks are detected.

use crate::kill_switch::ProcessTable;
use crate::safeagents::atif_scanner::{AtifSeverity, AtifSignal};
use crate::safeagents::journal::{CallsJournal, CallsJournalRecord};
use osoosi_policy::cage::cbf::ControlBarrierFunction;
use osoosi_types::OctopusSecurityError;
use std::sync::Arc;

/// Governance bridge connecting inspection verdicts to KillSwitch and CAGE CBF.
#[derive(Clone)]
pub struct SafeAgentsGovernanceBridge {
    process_table: Arc<ProcessTable>,
    cbf_evaluator: Arc<ControlBarrierFunction>,
    journal: Arc<CallsJournal>,
}

impl SafeAgentsGovernanceBridge {
    pub fn new(process_table: Arc<ProcessTable>, journal: Arc<CallsJournal>) -> Self {
        Self {
            process_table,
            cbf_evaluator: Arc::new(ControlBarrierFunction::default()),
            journal,
        }
    }

    pub fn process_table(&self) -> &Arc<ProcessTable> {
        &self.process_table
    }

    pub fn cbf_evaluator(&self) -> &Arc<ControlBarrierFunction> {
        &self.cbf_evaluator
    }

    pub fn journal(&self) -> &Arc<CallsJournal> {
        &self.journal
    }

    /// Evaluates inspection findings and trips governance controls if high severity.
    pub async fn handle_high_severity_violation(
        &self,
        agent_id: &str,
        tool_name: &str,
        raw_arguments: &str,
        signals: &[AtifSignal],
        task: &str,
    ) -> Result<(), OctopusSecurityError> {
        let high_severity_signal = signals.iter().find(|s| s.severity >= AtifSeverity::High);

        if let Some(signal) = high_severity_signal {
            tracing::error!(
                "GOVERNANCE TRIP: High-severity ATIF pattern detected ({}: {}) on agent '{}'",
                signal.id,
                signal.title,
                agent_id
            );

            // 1. Terminate the active agent process via KillSwitch (epoch increment)
            let killed = self.process_table.kill(agent_id).await;
            tracing::warn!("KillSwitch actuation on '{}': success={}", agent_id, killed);

            // 2. Record CAGE CBF violation in audit log & telemetry
            let record = CallsJournalRecord::new(
                "blocked",
                tool_name,
                raw_arguments,
                Some(&signal.id),
                signals.to_vec(),
                None,
                "native_atif_scanner",
                task,
            );
            self.journal.emit(record).await;

            return Err(OctopusSecurityError::BreakoutDetected(format!(
                "KillSwitch & CAGE CBF tripped: high-severity ATIF pattern '{}'",
                signal.id
            )));
        }

        Ok(())
    }

    /// Synchronous governance trip helper for synchronous execution paths.
    pub fn handle_high_severity_violation_sync(
        &self,
        agent_id: &str,
        tool_name: &str,
        raw_arguments: &str,
        signals: &[AtifSignal],
        task: &str,
    ) -> Result<(), OctopusSecurityError> {
        let high_severity_signal = signals.iter().find(|s| s.severity >= AtifSeverity::High);

        if let Some(signal) = high_severity_signal {
            tracing::error!(
                "GOVERNANCE TRIP (SYNC): High-severity ATIF pattern detected ({}: {}) on agent '{}'",
                signal.id,
                signal.title,
                agent_id
            );

            // Synchronously emit blocked record
            let record = CallsJournalRecord::new(
                "blocked",
                tool_name,
                raw_arguments,
                Some(&signal.id),
                signals.to_vec(),
                None,
                "native_atif_scanner",
                task,
            );
            self.journal.emit_sync(record);

            return Err(OctopusSecurityError::BreakoutDetected(format!(
                "KillSwitch & CAGE CBF tripped: high-severity ATIF pattern '{}'",
                signal.id
            )));
        }

        Ok(())
    }

    /// Handles judge block event, logging verdict to journal.
    pub async fn handle_judge_block(
        &self,
        agent_id: &str,
        tool_name: &str,
        raw_arguments: &str,
        reason: &str,
        signals: &[AtifSignal],
        task: &str,
    ) {
        tracing::warn!(
            "GOVERNANCE JUDGE BLOCK: Judge blocked call '{}' on agent '{}': {}",
            tool_name,
            agent_id,
            reason
        );

        let record = CallsJournalRecord::new(
            "blocked",
            tool_name,
            raw_arguments,
            Some("judge_block"),
            signals.to_vec(),
            Some(reason),
            "ollama_judge",
            task,
        );
        self.journal.emit(record).await;
    }
}
