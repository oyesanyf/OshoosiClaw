//! Semantic Intent Verification.
//!
//! Uses high-dimensional command embeddings to distinguish between admin and malicious intent.

use dashmap::DashMap;

pub struct SemanticEngine {
    /// Baseline of "authorized" command embeddings (simplified to keyword vectors for now)
    #[allow(dead_code)]
    authorized_intent: DashMap<String, Vec<f32>>,
}

impl Default for SemanticEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticEngine {
    pub fn new() -> Self {
        let auth = DashMap::new();
        // Seed with common admin intents
        auth.insert("admin_service_check".to_string(), vec![0.1, 0.9, 0.05]);
        auth.insert("file_listing".to_string(), vec![0.8, 0.2, 0.1]);
        
        Self { authorized_intent: auth }
    }

    /// Calculate "Semantic Distance" of a command.
    /// In a production environment, this would use a transformer model (e.g. BERT).
    /// Here we use a heuristic mapping as a placeholder for the algorithm.
    pub fn verify_intent(&self, command_line: &str) -> f32 {
        let cmd = command_line.to_lowercase();
        
        // heuristic: base64 encoded chunks in powershell often imply malicious intent (obfuscation)
        if (cmd.contains("powershell") || cmd.contains("pwsh")) && (cmd.contains("-enc") || cmd.contains("base64")) {
            return 0.95; // High anomaly / Semantic Drift
        }

        // heuristic: credential dumping tools
        if cmd.contains("sekurlsa") || cmd.contains("logonpasswords") || cmd.contains("pypykatz") {
            return 0.99;
        }

        // Default: low drift
        0.05
    }
}
