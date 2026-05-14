use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticalFilterConfig {
    pub compression_ratio: f32,
    pub preserve_keywords: Vec<String>,
}

impl Default for StatisticalFilterConfig {
    fn default() -> Self {
        Self {
            compression_ratio: 0.5,
            preserve_keywords: vec![
                "Process".to_string(),
                "Malicious".to_string(),
                "Threat".to_string(),
                "Suspicious".to_string(),
                "Action".to_string(),
                "PID".to_string(),
                "Hash".to_string(),
                "IP".to_string(),
            ],
        }
    }
}

pub struct StatisticalFilter {
    config: StatisticalFilterConfig,
}

impl StatisticalFilter {
    pub fn new(config: StatisticalFilterConfig) -> Self {
        Self { config }
    }

    pub fn filter(&self, tokens: Vec<String>) -> Vec<String> {
        if self.config.compression_ratio >= 1.0 {
            return tokens;
        }

        let mut filtered = Vec::new();
        let target_len = (tokens.len() as f32 * self.config.compression_ratio) as usize;
        
        // Simple heuristic: Keep keywords, then keep every Nth token until target_len
        let mut important_indices = std::collections::HashSet::new();
        
        for (i, token) in tokens.iter().enumerate() {
            let lower = token.to_lowercase();
            if self.config.preserve_keywords.iter().any(|k| lower.contains(&k.to_lowercase())) {
                important_indices.insert(i);
            }
        }

        let mut current_idx = 0;
        while important_indices.len() < target_len && current_idx < tokens.len() {
            important_indices.insert(current_idx);
            current_idx += (1.0 / self.config.compression_ratio).max(1.0) as usize;
        }

        for i in 0..tokens.len() {
            if important_indices.contains(&i) {
                filtered.push(tokens[i].clone());
            }
        }

        filtered
    }
}
