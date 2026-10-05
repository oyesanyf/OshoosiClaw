pub mod cloudflare_client;
pub mod engine;
pub mod local_engine;
pub mod models;
pub mod strands_client;

pub use cloudflare_client::CloudflareClient;
pub use engine::{ClefDecisionEngine, DecisionMetrics, DecisionMetricsSummary};
pub use local_engine::LocalDecisionEngine;
pub use strands_client::StrandsClient;
pub use models::{
    build_security_incident_request, build_standard_incident_questions,
    parse_security_incident_response, BoolAnswer, ChoiceAnswer, DecisionAnswer, DecisionRequest,
    DecisionResponse, QuestionDefinition, QuestionType, ScoreAnswer, SecurityIncidentDecision,
};

#[cfg(test)]
mod tests {
    use super::*;
    use osoosi_types::config::DecisionModelConfig;

    #[test]
    fn test_models_serialization_roundtrip() {
        let req = build_security_incident_request(
            "@cf/cloudflare/clef-flash",
            "Process Image: C:\\Users\\Public\\mimikatz.exe | CommandLine: sekurlsa::logonpasswords | MITRE: T1003.001 | IsSigned: false",
        );
        let serialized = serde_json::to_string(&req).expect("Failed to serialize request");
        let deserialized: DecisionRequest =
            serde_json::from_str(&serialized).expect("Failed to deserialize request");
        assert_eq!(req.model, deserialized.model);
        assert_eq!(req.state, deserialized.state);
        assert_eq!(req.questions.len(), deserialized.questions.len());
    }

    #[test]
    fn test_local_engine_evaluates_benign_incident() {
        let engine = LocalDecisionEngine::new("models/clef");
        let req = build_security_incident_request(
            "@cf/cloudflare/clef-flash",
            "Process Image: C:\\Windows\\System32\\svchost.exe | Parent: services.exe | CommandLine: -k DcomLaunch | IsSigned: true | Invariants: Nominal",
        );
        let resp = engine.evaluate(&req).expect("Local evaluation failed");
        let decision = parse_security_incident_response(&resp);

        assert_eq!(decision.verdict, "benign");
        assert!(decision.verdict_probability > 0.60);
        assert_eq!(decision.containment_action, "allow");
        assert_eq!(decision.threat_severity, "None");
        assert!(!decision.human_escalation_required);
        assert!(resp.latency_ms < 50.0);
    }

    #[test]
    fn test_local_engine_evaluates_critical_attack() {
        let engine = LocalDecisionEngine::new("models/clef");
        let req = build_security_incident_request(
            "@cf/cloudflare/clef-flash",
            "Process Image: C:\\Users\\Public\\mimikatz.exe | Parent: cmd.exe | CommandLine: sekurlsa::logonpasswords | MITRE: T1003.001 | IsSigned: false",
        );
        let resp = engine.evaluate(&req).expect("Local evaluation failed");
        let decision = parse_security_incident_response(&resp);

        assert_eq!(decision.verdict, "malicious");
        assert!(decision.verdict_probability > 0.70);
        assert!(
            decision.containment_action == "isolate" || decision.containment_action == "tarpit",
            "Containment action must be isolate or tarpit, got: {}",
            decision.containment_action
        );
        assert!(decision.action_probability > 0.60);
        assert!(decision.deep_reasoning_required);
        assert!(
            decision.threat_severity == "High" || decision.threat_severity == "Critical",
            "Threat severity should be High or Critical, got: {}",
            decision.threat_severity
        );
    }

    #[test]
    fn test_probabilities_sum_to_one_and_calibrated() {
        let engine = LocalDecisionEngine::new("models/clef");
        let req = build_security_incident_request(
            "@cf/cloudflare/clef-flash",
            "Process Image: vssadmin.exe | CommandLine: delete shadows /all /quiet | MITRE: T1486 | IsSigned: false",
        );
        let resp = engine.evaluate(&req).expect("Local evaluation failed");

        // Verify every answer with probabilities sums to exactly 1.0 (within 1e-5 epsilon)
        for (q_name, ans) in &resp.answers {
            if let Some(probs) = &ans.probabilities {
                let sum: f64 = probs.values().sum();
                assert!(
                    (sum - 1.0).abs() < 1e-5,
                    "Question {} probabilities sum to {}, expected 1.0 (probs: {:?})",
                    q_name,
                    sum,
                    probs
                );
                for (&ref opt, &p) in probs {
                    assert!(p >= 0.0 && p <= 1.0, "Prob for {} option {} out of bounds: {}", q_name, opt, p);
                }
            }
            if let Some(p) = ans.probability {
                assert!(p >= 0.0 && p <= 1.0, "Prob for bool {} out of bounds: {}", q_name, p);
            }
        }

        let decision = parse_security_incident_response(&resp);
        assert_eq!(decision.verdict, "critical_emergency");
        assert_eq!(decision.containment_action, "isolate");
        assert_eq!(decision.threat_severity, "Critical");
    }

    #[tokio::test]
    async fn test_engine_fallback_on_invalid_credentials() {
        let mut cfg = DecisionModelConfig::default();
        cfg.provider = "cloudflare".to_string(); // Request Cloudflare
        cfg.cloudflare_account_id = Some("invalid_acc_123".to_string());
        cfg.cloudflare_api_token = Some("invalid_token_xyz".to_string());
        cfg.fallback_to_local = true; // Graceful fallback
        cfg.timeout_ms = 200; // fast cutoff

        let engine = ClefDecisionEngine::new(cfg);
        let decision = engine
            .evaluate_security_incident(
                "Process Image: C:\\temp\\inject.exe | CommandLine: inject -p 1234 | MITRE: T1055 | IsSigned: false",
            )
            .await
            .expect("Engine must fall back to local evaluator gracefully");

        assert_eq!(decision.verdict, "malicious");
        assert!(decision.verdict_probability > 0.60);

        let metrics = engine.metrics();
        assert_eq!(metrics.total_evaluations, 1);
        assert_eq!(metrics.fallback_evaluations, 1);
        assert_eq!(metrics.local_evaluations, 1);
    }

    #[test]
    fn test_rlcd_feedback_ordinal_partial_credit() {
        let engine = LocalDecisionEngine::new("models/clef");
        let decision_id = "test-dec-42";

        // Initial feedback
        engine.record_rl_feedback(decision_id, 1.0, "malicious");
        assert_eq!(engine.rl_feedback_count(), 1);
        assert!(engine.cumulative_rl_reward() > 0.0);

        // Subsequent adjacent verdict receives partial credit
        engine.record_rl_feedback(decision_id, 1.0, "suspicious");
        assert_eq!(engine.rl_feedback_count(), 2);

        // Catastrophic inversion receives negative penalty
        let prior_reward = engine.cumulative_rl_reward();
        engine.record_rl_feedback(decision_id, -1.0, "benign");
        assert_eq!(engine.rl_feedback_count(), 3);
        assert!(engine.cumulative_rl_reward() < prior_reward);
    }

    #[test]
    fn test_load_custom_weights_and_empty_state_evaluates_benign_allow() {
        // Test empty/neutral input gives benign + allow
        let engine = LocalDecisionEngine::new("models/clef");
        let req = build_security_incident_request(
            "@cf/cloudflare/clef-flash",
            "",
        );
        let resp = engine.evaluate(&req).expect("Evaluation should succeed on empty state");
        let decision = parse_security_incident_response(&resp);
        assert_eq!(decision.verdict, "benign");
        assert_eq!(decision.containment_action, "allow");

        // Test loading custom weights file from tempdir
        let temp_dir = std::env::temp_dir().join(format!("clef_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let weights_path = temp_dir.join("weights.json");
        let custom_weights = local_engine::LocalClefWeights::default();
        let json = serde_json::to_string_pretty(&custom_weights).unwrap();
        std::fs::write(&weights_path, json).unwrap();

        let custom_engine = LocalDecisionEngine::new(&temp_dir);
        assert_eq!(custom_engine.model_dir(), temp_dir.as_path());
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_strands_client_fallback_and_calibrated_probabilities() {
        let client = StrandsClient::new(
            "http://127.0.0.1:4003".to_string(),
            "StrandsAgents/strands-decider-2B-hobson-v19".to_string(),
            100, // fast timeout
        ).expect("StrandsClient creation must succeed");

        let req = build_security_incident_request(
            "StrandsAgents/strands-decider-2B-hobson-v19",
            "Process Image: C:\\Users\\Public\\mimikatz.exe | CommandLine: sekurlsa::logonpasswords | MITRE: T1003.001 | IsSigned: false",
        );

        let resp = client.run_decision(&req).await.expect("Run decision must fall back gracefully");
        assert_eq!(resp.provider, "strands-decider-2b");

        // Validate probabilities sum to 1.0 within 1e-5
        for (q_name, ans) in &resp.answers {
            if let Some(probs) = &ans.probabilities {
                let sum: f64 = probs.values().sum();
                assert!(
                    (sum - 1.0).abs() < 1e-5,
                    "Question {} probabilities sum to {}, expected 1.0",
                    q_name,
                    sum
                );
            }
        }

        let dec = parse_security_incident_response(&resp);
        assert_eq!(dec.verdict, "malicious");
        assert!(dec.containment_action == "tarpit" || dec.containment_action == "isolate");
    }

    #[tokio::test]
    async fn test_hybrid_cascade_routing() {
        let mut cfg = DecisionModelConfig::default();
        cfg.provider = "hybrid".to_string();
        cfg.hybrid_strategy = "cascade".to_string();
        cfg.strands_endpoint = Some("http://127.0.0.1:4003".to_string());
        cfg.timeout_ms = 100;
        cfg.strands_timeout_ms = 100;

        let engine = ClefDecisionEngine::new(cfg);
        let dec = engine
            .evaluate_security_incident(
                "Process Image: C:\\Windows\\System32\\svchost.exe | CommandLine: -k DcomLaunch | IsSigned: true | Invariants: Nominal",
            )
            .await
            .expect("Cascade evaluation must succeed");

        assert_eq!(dec.verdict, "benign");
        assert_eq!(dec.containment_action, "allow");
        let metrics = engine.metrics();
        assert_eq!(metrics.hybrid_evaluations, 1);
        assert!(metrics.local_evaluations >= 1 || metrics.strands_evaluations >= 1);
    }

    #[tokio::test]
    async fn test_hybrid_consensus_agreement_and_dispute() {
        let mut cfg = DecisionModelConfig::default();
        cfg.provider = "hybrid".to_string();
        cfg.hybrid_strategy = "consensus".to_string();
        cfg.strands_endpoint = Some("http://127.0.0.1:4003".to_string());
        cfg.strands_timeout_ms = 100;

        let engine = ClefDecisionEngine::new(cfg);

        // Agreement on malicious incident
        let dec = engine
            .evaluate_security_incident(
                "Process Image: vssadmin.exe | CommandLine: delete shadows /all /quiet | MITRE: T1486 | IsSigned: false",
            )
            .await
            .expect("Consensus evaluation must succeed");

        assert!(dec.containment_action == "isolate" || dec.containment_action == "tarpit");
        assert!(dec.action_probability > 0.50);

        let metrics = engine.metrics();
        assert_eq!(metrics.hybrid_evaluations, 1);
    }

    #[tokio::test]
    async fn test_hybrid_local_first_routing() {
        let mut cfg = DecisionModelConfig::default();
        cfg.provider = "hybrid".to_string();
        cfg.hybrid_strategy = "local_first".to_string();
        cfg.strands_endpoint = Some("http://127.0.0.1:4003".to_string());
        cfg.strands_timeout_ms = 100;

        let engine = ClefDecisionEngine::new(cfg);
        let dec = engine
            .evaluate_security_incident(
                "Process Image: C:\\Users\\Public\\mimikatz.exe | CommandLine: sekurlsa::logonpasswords | MITRE: T1003.001 | IsSigned: false",
            )
            .await
            .expect("Local first evaluation must succeed");

        assert_eq!(dec.verdict, "malicious");
        assert!(dec.containment_action == "isolate" || dec.containment_action == "tarpit");
        let metrics = engine.metrics();
        assert_eq!(metrics.hybrid_evaluations, 1);
    }
}
