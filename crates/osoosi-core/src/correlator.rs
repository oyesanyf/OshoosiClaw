use chrono::{DateTime, Utc};
use dashmap::DashMap;
use osoosi_types::{ActionState, ResponseAction, SysmonEvent, ThreatSignature};
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
        }
    }

    pub fn add_event(&mut self, event_type: &str, details: &str, score: f32) {
        if self.timeline.len() >= 50 {
            self.timeline.pop_front();
        }
        self.timeline.push_back(TimelinedEvent {
            timestamp: Utc::now(),
            event_type: event_type.to_string(),
            details: details.to_string(),
            confidence: score,
        });
        self.total_score = (self.total_score + score).min(1.0);
        self.last_updated = Utc::now();
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

    /// Process a new Sysmon event and correlate it with existing findings.
    pub async fn correlate_sysmon(&self, event: &SysmonEvent) -> Option<ThreatSignature> {
        let pid = event.process_id()?;
        let image = event
            .data
            .get("Image")
            .and_then(|i| i.as_str())
            .unwrap_or("unknown");

        let mut ctx = self
            .processes
            .entry(pid)
            .or_insert_with(|| ProcessContext::new(pid, image.to_string()));

        let event_id = event.event_id;
        let event_type = (event_id as u16).to_string();
        let mut alert_score: f32 = 0.0;
        let mut reason = String::new();

        match event_type.as_str() {
            "1" => {
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
            "3" => {
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
            "11" => {
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
            "13" => {
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
            "22" => {
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
            "7" => {
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
            "8" => {
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
            "10" => {
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
            "25" => {
                // Process Tampering
                alert_score = 0.8;
                reason = format!("Process tampering detected (hollowing/herpaderping)");
                ctx.add_event("Tampering", "Detected", alert_score);
            }
            _ => {}
        }

        if alert_score > 0.3 || ctx.total_score > 0.7 {
            let mut sig = ThreatSignature::new("localhost".to_string());
            sig.confidence = ctx.total_score.min(0.99);
            sig.process_name = Some(ctx.image.clone());
            sig.add_reason(format!("Intelligent Correlation: {}", reason));
            sig.add_reason(format!("Combined Suspicion Score: {:.2}", ctx.total_score));
            sig.recommended_action = if ctx.total_score > 0.85 {
                ResponseAction::Isolate
            } else {
                ResponseAction::Alert
            };

            // If very high confidence, mark for human approval if disruptive
            if sig.recommended_action == ResponseAction::Isolate {
                sig.require_approval = true;
                sig.action_state = ActionState::Pending;
            }

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

        let response = llm.generate_text(&prompt, 100)?;
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
