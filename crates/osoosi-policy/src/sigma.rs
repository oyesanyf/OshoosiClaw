//! Lightweight Sigma-like rule evaluator for Sysmon events.
//! Supports basic selection logic and conditions.

use osoosi_types::SysmonEvent;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaRule {
    pub title: String,
    pub description: Option<String>,
    pub level: String,
    pub detection: SelectionCriteria,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionCriteria {
    pub selection: HashMap<String, SigmaValue>,
    pub condition: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SigmaValue {
    Single(String),
    List(Vec<String>),
}

pub struct SigmaEngine {
    rules: Vec<SigmaRule>,
}

impl Default for SigmaEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SigmaEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn load_rules_from_dir(&mut self, dir: &std::path::Path) {
        if !dir.exists() {
            return;
        }
        let mut count = 0;
        for entry in walkdir::WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                let p = entry.path();
                if p.extension()
                    .map(|e| e == "yml" || e == "yaml")
                    .unwrap_or(false)
                {
                    if let Ok(content) = std::fs::read_to_string(p) {
                        if let Ok(rule) = serde_yaml::from_str::<SigmaRule>(&content) {
                            self.rules.push(rule);
                            count += 1;
                        }
                    }
                }
            }
        }
        info!("Loaded {} Sigma rules from {}", count, dir.display());
    }

    pub fn check(&self, event: &SysmonEvent) -> Vec<&SigmaRule> {
        let mut matches = Vec::new();
        for rule in &self.rules {
            if self.evaluate_rule(rule, event) {
                matches.push(rule);
            }
        }
        matches
    }

    fn evaluate_rule(&self, rule: &SigmaRule, event: &SysmonEvent) -> bool {
        // Simplified: only handles 'selection' and basic conditions
        if rule.detection.condition != "selection" {
            return false;
        }

        for (key, expected) in &rule.detection.selection {
            let (field_name, modifier) = if let Some(idx) = key.find('|') {
                (&key[..idx], Some(&key[idx + 1..]))
            } else {
                (key.as_str(), None)
            };

            let actual_val = if field_name == "EventID" {
                Some(event.event_id as u32 as u64).map(|v| v.to_string())
            } else {
                event
                    .data
                    .get(field_name)
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            };

            let Some(val) = actual_val else {
                return false;
            };

            if !self.match_value(&val, expected, modifier) {
                return false;
            }
        }

        true
    }

    fn match_value(&self, actual: &str, expected: &SigmaValue, modifier: Option<&str>) -> bool {
        match expected {
            SigmaValue::Single(s) => self.match_single(actual, s, modifier),
            SigmaValue::List(l) => l.iter().any(|s| self.match_single(actual, s, modifier)),
        }
    }

    fn match_single(&self, actual: &str, expected: &str, modifier: Option<&str>) -> bool {
        let actual_l = actual.to_lowercase();
        let expected_l = expected.to_lowercase();

        match modifier {
            Some("contains") => actual_l.contains(&expected_l),
            Some("endswith") => actual_l.ends_with(&expected_l),
            Some("startswith") => actual_l.starts_with(&expected_l),
            _ => actual_l == expected_l,
        }
    }
}
