use chrono::{DateTime, Utc};
use dashmap::DashMap;
use osoosi_types::{ActionState, HostSecurityEvent, ResponseAction, ThreatSignature};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use tracing::{debug, info};

/// A single event in a process's timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelinedEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub details: String,
    pub confidence: f32,
}

/// Context for a specific process, aggregating findings from multiple engines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessContext {
    pub pid: u32,
    pub image: String,
    pub timeline: VecDeque<TimelinedEvent>,
    pub static_findings: Vec<String>,
    pub total_score: f32,
    pub last_updated: DateTime<Utc>,
    pub is_signed: bool,
    pub last_alerted: Option<DateTime<Utc>>,
}

impl ProcessContext {
    pub fn new(pid: u32, image: String) -> Self {
        Self {
            pid,
            image,
            timeline: VecDeque::with_capacity(50),
            static_findings: Vec::new(),
            total_score: 0.0,
            last_updated: Utc::now(),
            is_signed: false,
            last_alerted: None,
        }
    }

    pub fn add_event(&mut self, event_type: &str, details: &str, score: f32) {
        let now = Utc::now();
        let elapsed_secs = (now - self.last_updated).num_seconds().max(0) as f32;
        if elapsed_secs > 30.0 {
            let decay = 0.1 * (elapsed_secs / 30.0);
            self.total_score = (self.total_score - decay).max(0.0);
        }

        if self.timeline.len() >= 50 {
            self.timeline.pop_front();
        }
        self.timeline.push_back(TimelinedEvent {
            timestamp: now,
            event_type: event_type.to_string(),
            details: details.to_string(),
            confidence: score,
        });
        self.total_score = (self.total_score + score).min(1.0);
        self.last_updated = now;
    }
}

/// Intelligent Event Correlator for OpenỌ̀ṣọ́ọ̀sì.
///
/// Correlates static analysis (CAPA, YARA) with dynamic behavior (Sysmon)
/// to detect complex attack chains like C2 beacons and persistence.
pub struct EventCorrelator {
    /// PID -> Context
    processes: DashMap<u32, ProcessContext>,
    /// Sliding window for cross-process correlation (e.g. process injection)
    _global_timeline: VecDeque<TimelinedEvent>,
}

impl EventCorrelator {
    pub fn new() -> Self {
        Self {
            processes: DashMap::new(),
            _global_timeline: VecDeque::with_capacity(100),
        }
    }

    /// Process a new host event and correlate it with existing findings.
    pub async fn correlate_sysmon(&self, event: &HostSecurityEvent) -> Option<ThreatSignature> {
        let pid = event.data.get("ProcessId").and_then(|v| v.as_u64())? as u32;
        // Ignore PID 0 (Idle) and PID 4 (System) from generic network/IO correlation
        if pid == 0 || pid == 4 {
            return None;
        }

        let image = event
            .data
            .get("Image")
            .and_then(|i| i.as_str())
            .unwrap_or("unknown");

        let mut ctx = self
            .processes
            .entry(pid)
            .or_insert_with(|| ProcessContext::new(pid, image.to_string()));

        if ctx.image == "unknown" && image != "unknown" {
            ctx.image = image.to_string();
        }

        let event_id = event.event_id;
        let mut alert_score: f32 = 0.0;
        let mut reason = String::new();

        match event_id {
            1 => {
                // Process Creation
                let parent_image = event
                    .data
                    .get("ParentImage")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let command_line = event
                    .data
                    .get("CommandLine")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                // Suspicious: PowerShell with encoded commands or discovery tools
                if command_line.contains("-enc")
                    || command_line.contains("whoami")
                    || command_line.contains("net user")
                {
                    alert_score = 0.3;
                    reason = format!("Suspicious command line execution: {}", command_line);
                }
                ctx.add_event(
                    "ProcessCreate",
                    &format!("Parent: {} | Cmd: {}", parent_image, command_line),
                    alert_score,
                );
            }
            3 => {
                // Network Connection
                let dest_ip = event
                    .data
                    .get("DestinationIp")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let dest_port = event
                    .data
                    .get("DestinationPort")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                // Check if process has C2 capabilities from CAPA/Static analysis
                let has_c2_cap = ctx.static_findings.iter().any(|f| {
                    f.contains("communication") || f.contains("c2") || f.contains("network")
                });

                if has_c2_cap {
                    alert_score = 0.5; // High boost if static capabilities match dynamic behavior
                    reason = format!(
                        "Process with forensic C2 markers initiated network connection to {}:{}",
                        dest_ip, dest_port
                    );
                } else if !ctx.is_signed {
                    alert_score = 0.15;
                    reason = format!(
                        "Unsigned process initiated network connection to {}:{}",
                        dest_ip, dest_port
                    );
                }

                ctx.add_event(
                    "Network",
                    &format!("To {}:{}", dest_ip, dest_port),
                    alert_score,
                );
            }
            11 => {
                // File Create
                let target_path = event
                    .data
                    .get("TargetFilename")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if target_path.contains("\\Windows\\System32")
                    || target_path.contains("AppData\\Roaming")
                {
                    alert_score = 0.2;
                    reason = format!(
                        "Process created file in sensitive directory: {}",
                        target_path
                    );
                }
                ctx.add_event("FileCreate", target_path, alert_score);
            }
            13 => {
                // Registry Value Set
                let target_key = event
                    .data
                    .get("TargetObject")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if target_key.contains("\\CurrentVersion\\Run")
                    || target_key.contains("\\Services\\")
                {
                    alert_score = 0.3;
                    reason = format!("Process modified persistence registry key: {}", target_key);
                }
                ctx.add_event("Registry", target_key, alert_score);
            }
            22 => {
                // DNS Query
                let query = event
                    .data
                    .get("QueryName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                // Detect potential DGA or exfiltration
                if query.len() > 30 && query.matches(char::is_numeric).count() > 5 {
                    alert_score = 0.35;
                    reason = format!("Suspicious DNS query (possible DGA/Tunneling): {}", query);
                }
                ctx.add_event("DNS", query, alert_score);
            }
            7 => {
                // Image Load
                let image_loaded = event
                    .data
                    .get("ImageLoaded")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if image_loaded.contains("Temp\\") || image_loaded.contains("AppData\\") {
                    alert_score = 0.1;
                    reason = format!(
                        "Suspicious Image Load from user directory: {}",
                        image_loaded
                    );
                }
                ctx.add_event("ImageLoad", image_loaded, alert_score);
            }
            8 => {
                // CreateRemoteThread
                let target_image = event
                    .data
                    .get("TargetImage")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                alert_score = 0.6; // High suspicion for cross-process thread creation
                reason = format!("Process created a remote thread in: {}", target_image);
                ctx.add_event("Injection", &format!("To {}", target_image), alert_score);
            }
            10 => {
                // Process Access
                let target_image = event
                    .data
                    .get("TargetImage")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if target_image.contains("lsass.exe") {
                    alert_score = 0.7;
                    reason =
                        format!("Process accessed LSASS memory (potential credential dumping)");
                }
                ctx.add_event(
                    "ProcessAccess",
                    &format!("To {}", target_image),
                    alert_score,
                );
            }
            25 => {
                // Process Tampering
                alert_score = 0.8;
                reason = format!("Process tampering detected (hollowing/herpaderping)");
                ctx.add_event("Tampering", "Detected", alert_score);
            }
            _ => {}
        }

        if alert_score > 0.25 && ctx.total_score >= 0.70 {
            let now = Utc::now();
            if let Some(last) = ctx.last_alerted {
                if now - last < chrono::Duration::seconds(60) {
                    return None;
                }
            }

            let mut sig = ThreatSignature::new("localhost".to_string());
            sig.confidence = ctx.total_score.min(0.99);
            sig.process_name = Some(ctx.image.clone());
            sig.add_reason(format!("Intelligent Correlation: {}", reason));
            sig.add_reason(format!("Combined Suspicion Score: {:.2}", ctx.total_score));
            let mut action = if ctx.total_score > 0.85 {
                ResponseAction::Isolate
            } else {
                ResponseAction::Alert
            };

            // If image is unknown, cap action to Alert (never Isolate unknown image)
            if ctx.image == "unknown" && action == ResponseAction::Isolate {
                action = ResponseAction::Alert;
            }

            sig.recommended_action = action;

            // If very high confidence, mark for human approval if disruptive
            if sig.recommended_action == ResponseAction::Isolate {
                sig.require_approval = true;
                sig.action_state = ActionState::Pending;
            }

            ctx.last_alerted = Some(now);

            return Some(sig);
        }

        None
    }

    /// Add a static analysis finding (from CAPA, YARA, etc.) to a process context.
    pub fn add_static_finding(&self, pid: u32, image: &str, finding: &str, confidence: f32) {
        let mut ctx = self
            .processes
            .entry(pid)
            .or_insert_with(|| ProcessContext::new(pid, image.to_string()));
        ctx.static_findings.push(finding.to_string());
        ctx.total_score = (ctx.total_score + confidence * 0.5).min(1.0);
        ctx.last_updated = Utc::now();
        info!(
            "Correlator: Added static finding for PID {}: {} (New Score: {:.2})",
            pid, finding, ctx.total_score
        );
    }

    /// Set process signature status.
    pub fn set_signed_status(&self, pid: u32, is_signed: bool) {
        if let Some(mut ctx) = self.processes.get_mut(&pid) {
            ctx.is_signed = is_signed;
        }
    }

    /// Get summary for LLM reasoning.
    pub fn get_process_summary(&self, pid: u32) -> Option<String> {
        let ctx = self.processes.get(&pid)?;
        let timeline_str = ctx
            .timeline
            .iter()
            .map(|e| {
                format!(
                    "[{}] {}: {}",
                    e.timestamp.format("%H:%M:%S"),
                    e.event_type,
                    e.details
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        Some(format!(
            "Process: {} (PID: {})\nSigned: {}\nStatic Findings: {:?}\nSuspicion Score: {:.2}\nTimeline:\n{}",
            ctx.image, ctx.pid, ctx.is_signed, ctx.static_findings, ctx.total_score, timeline_str
        ))
    }

    /// Perform a deep investigation of a process using an LLM.
    pub async fn investigate_with_llm(
        &self,
        pid: u32,
        llm: &osoosi_behavioral::SmolLMAnalyzer,
    ) -> anyhow::Result<Option<ThreatSignature>> {
        let summary = match self.get_process_summary(pid) {
            Some(s) => s,
            None => return Ok(None),
        };

        info!("Correlator: Starting LLM investigation for PID {}...", pid);

        let prompt = format!(
            "Analyze the following process behavior and static findings. Is this malicious? Respond with a JSON object containing 'is_malicious' (bool), 'confidence' (float 0-1), and 'reasoning' (string).\n\n{}",
            summary
        );

        let response = llm.generate_text(&prompt, 100).await?;
        debug!("LLM Investigation Response: {}", response);

        // Simple heuristic parsing (in production this would be more robust)
        if response.contains("\"is_malicious\": true") {
            let mut sig = ThreatSignature::new("localhost".to_string());
            sig.process_name = self.processes.get(&pid).map(|p| p.image.clone());
            sig.confidence = 0.85; // Base high confidence from LLM
            sig.add_reason("LLM Investigation: Behavioral pattern confirmed as malicious.");
            sig.add_reason(format!("LLM Reasoning: {}", response));
            sig.recommended_action = ResponseAction::Alert;
            return Ok(Some(sig));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sysmon_event(event_id: u32, pid: u64, image: &str, extra_data: Vec<(&str, &str)>) -> HostSecurityEvent {
        let mut map = serde_json::Map::new();
        map.insert("ProcessId".to_string(), serde_json::json!(pid));
        map.insert("Image".to_string(), serde_json::json!(image));
        for (k, v) in extra_data {
            map.insert(k.to_string(), serde_json::json!(v));
        }

        HostSecurityEvent {
            source: osoosi_types::HostEventSource::WindowsEventLog,
            event_id,
            timestamp: Utc::now(),
            computer: "TEST-HOST".to_string(),
            data: serde_json::Value::Object(map),
            causal_parent: None,
        }
    }

    #[tokio::test]
    async fn test_ignore_kernel_pids() {
        let correlator = EventCorrelator::new();

        // PID 0 (Idle)
        let ev0 = make_sysmon_event(3, 0, "unknown", vec![("DestinationIp", "8.8.8.8"), ("DestinationPort", "53")]);
        assert!(correlator.correlate_sysmon(&ev0).await.is_none());
        assert!(!correlator.processes.contains_key(&0));

        // PID 4 (System)
        let ev4 = make_sysmon_event(3, 4, "System", vec![("DestinationIp", "1.1.1.1"), ("DestinationPort", "445")]);
        assert!(correlator.correlate_sysmon(&ev4).await.is_none());
        assert!(!correlator.processes.contains_key(&4));
    }

    #[tokio::test]
    async fn test_benign_event_does_not_trigger_even_with_high_total_score() {
        let correlator = EventCorrelator::new();
        let pid = 1234;

        // Seed high score statically
        correlator.add_static_finding(pid, "malicious.exe", "c2_network_beacon", 1.0);
        correlator.add_static_finding(pid, "malicious.exe", "persistence_registry", 1.0);
        // total_score is now 1.0

        // Send a benign event (event_id 999 with alert_score 0.0)
        let benign = make_sysmon_event(999, pid as u64, "malicious.exe", vec![]);
        let alert = correlator.correlate_sysmon(&benign).await;
        assert!(alert.is_none(), "Benign event with alert_score 0.0 must not trigger an alert");
    }

    #[tokio::test]
    async fn test_debounce_and_cooldown_per_pid() {
        let correlator = EventCorrelator::new();
        let pid = 5678;

        // Seed context so total_score >= 0.70
        correlator.add_static_finding(pid, "cmd.exe", "c2_activity", 1.0);
        correlator.add_static_finding(pid, "cmd.exe", "credential_dump", 1.0);

        // High alert_score event: Process Access to lsass.exe (alert_score 0.7)
        let ev1 = make_sysmon_event(10, pid as u64, "cmd.exe", vec![("TargetImage", "C:\\Windows\\System32\\lsass.exe")]);
        let sig1 = correlator.correlate_sysmon(&ev1).await;
        assert!(sig1.is_some(), "First suspicious event should trigger threat signature");

        // Immediately send another suspicious event (Process Creation with -enc)
        let ev2 = make_sysmon_event(1, pid as u64, "cmd.exe", vec![("CommandLine", "powershell -enc AAAA")]);
        let sig2 = correlator.correlate_sysmon(&ev2).await;
        assert!(sig2.is_none(), "Second event within 60s debounce window should be suppressed");
    }

    #[tokio::test]
    async fn test_unknown_image_action_capped_to_alert() {
        let correlator = EventCorrelator::new();
        let pid = 8888;

        // Seed high score
        correlator.add_static_finding(pid, "unknown", "c2", 1.0);
        correlator.add_static_finding(pid, "unknown", "tamper", 1.0);

        // Process Access lsass.exe (alert_score 0.7) -> total_score > 0.85
        let ev = make_sysmon_event(10, pid as u64, "unknown", vec![("TargetImage", "lsass.exe")]);
        let sig = correlator.correlate_sysmon(&ev).await.expect("Should trigger");
        assert_eq!(sig.recommended_action, ResponseAction::Alert, "Unknown image must never be isolated");
    }

    #[test]
    fn test_score_decay_after_inactivity() {
        let mut ctx = ProcessContext::new(9999, "test.exe".to_string());
        ctx.total_score = 0.8;
        // Set last_updated to 60 seconds ago
        ctx.last_updated = Utc::now() - chrono::Duration::seconds(60);

        // Add event with 0 score
        ctx.add_event("FileCreate", "benign.txt", 0.0);

        // 60 secs elapsed: decay = 0.1 * (60 / 30) = 0.2. New total_score should be 0.6.
        assert!((ctx.total_score - 0.6).abs() < 0.01);
    }
}

