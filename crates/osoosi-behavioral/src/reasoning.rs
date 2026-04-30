//! Reasoning Telemetry Engine (The "Reflex" Layer)
//! Integrates LLM Fast-Thought reasoning directly into the native telemetry ingestion stream.

use anyhow::Result;
use osoosi_types::SysmonEvent;
use tokio::sync::mpsc;
use std::sync::Arc;
use tracing::{info, warn, error};
use crate::llm_engine::SmolLMAnalyzer;

pub struct ReasoningTelemetryEngine {
    native_rx: mpsc::Receiver<SysmonEvent>,
    out_tx: mpsc::Sender<SysmonEvent>,
    ai_cortex: Arc<SmolLMAnalyzer>,
}

impl ReasoningTelemetryEngine {
    pub fn new(
        native_rx: mpsc::Receiver<SysmonEvent>,
        out_tx: mpsc::Sender<SysmonEvent>,
        ai_cortex: Arc<SmolLMAnalyzer>,
    ) -> Self {
        Self {
            native_rx,
            out_tx,
            ai_cortex,
        }
    }

    /// Starts the reasoning loop. 
    /// This "thinks" about events as they are ingested from ETW.
    pub async fn run(mut self) -> Result<()> {
        info!("🧠 [REASONING-INGESTION] Active AI Reasoning Layer enabled on telemetry stream.");

        while let Some(mut event) = self.native_rx.recv().await {
            // 1. Identify "Thought-Worthy" Events
            // We don't think about every event (too slow), only those flagged by the native engine
            // or high-risk types (ProcessCreate, remote threads).
            let is_suspicious = event.data.get("RuleName").is_some() || 
                               event.event_id == 1 || // ProcessCreate
                               event.event_id == 8;   // CreateRemoteThread

            if is_suspicious {
                // 2. Perform "Fast-Thought" Reasoning
                // We use the local SmolLM model for millisecond-latency intent analysis.
                let event_json = serde_json::to_string(&event)?;
                let cortex = self.ai_cortex.clone();
                
                // We run this in a background task to not stall the ingestion pipeline
                let out_tx = self.out_tx.clone();
                tokio::spawn(async move {
                    match cortex.analyze_intent_fast(&event_json).await {
                        Ok(insight) => {
                            if insight.risk_score > 0.6 {
                                warn!("🤔 [AI-INSIGHT] High-risk intent detected for {}: {}", 
                                    event.data.get("Image").and_then(|v| v.as_str()).unwrap_or("unknown"),
                                    insight.reasoning
                                );
                                
                                // Enrich the event with AI insights
                                event.data.insert("AI_Insight".to_string(), serde_json::json!(insight.reasoning));
                                event.data.insert("AI_RiskScore".to_string(), serde_json::json!(insight.risk_score));
                                event.data.insert("RuleName".to_string(), serde_json::json!(format!("ai_detection=true,risk={}", insight.risk_score)));
                            }
                            let _ = out_tx.try_send(event);
                        }
                        Err(e) => {
                            error!("AI Reasoning failed: {}", e);
                            let _ = out_tx.try_send(event);
                        }
                    }
                });
            } else {
                // Normal event, pass through
                let _ = self.out_tx.try_send(event).await;
            }
        }

        Ok(())
    }
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct AIIntentInsight {
    pub risk_score: f32,
    pub reasoning: String,
    pub intent_category: String,
}
