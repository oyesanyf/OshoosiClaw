//! Advanced Sigma Detection Engine (Adapted from Rustinel).
//!
//! Provides full support for Sigma modifiers, complex boolean logic,
//! and platform-specific logsource filtering.

use anyhow::Result;

use evalexpr::*;
use ipnetwork::IpNetwork;
use osoosi_types::HostSecurityEvent;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaRule {
    pub title: String,
    pub description: Option<String>,
    pub level: Option<String>,
    pub status: Option<String>,
    pub logsource: LogSource,
    pub detection: Detection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSource {
    pub product: Option<String>,
    pub category: Option<String>,
    pub service: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    #[serde(flatten)]
    pub selections: HashMap<String, Selection>,
    pub condition: String,
    pub falsepositives: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Selection {
    List(Vec<String>),
    Map(HashMap<String, serde_yaml::Value>),
    Keywords(Vec<String>),
}

#[derive(Debug, Clone)]
pub enum FieldPattern {
    Exact(String, bool),
    Contains(String, bool),
    StartsWith(String, bool),
    EndsWith(String, bool),
    Regex(Regex),
    Cidr(IpNetwork),
    Numeric(f64, NumericOp),
    Null,
    NotNull,
}

#[derive(Debug, Clone, Copy)]
pub enum NumericOp {
    Lt, Gt, Le, Ge,
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub rule: SigmaRule,
    pub selections: HashMap<String, SelectionCompiled>,
    pub condition_tree: Option<Node>,
}

#[derive(Debug, Clone)]
pub struct SelectionCompiled {
    pub field_criteria: Vec<FieldCriterion>,
    pub keywords: Vec<FieldPattern>,
}

#[derive(Debug, Clone)]
pub struct FieldCriterion {
    pub field: String,
    pub patterns: Vec<FieldPattern>,
    pub is_all: bool,
}

pub struct SigmaEngine {
    /// Rules indexed by their logsource (service or product).
    indexed_rules: HashMap<String, Vec<CompiledRule>>,
    /// Rules that apply globally or couldn't be indexed.
    global_rules: Vec<CompiledRule>,
    pub total_detections: std::sync::atomic::AtomicU64,
}

impl Default for SigmaEngine {
    fn default() -> Self { Self::new() }
}

impl SigmaEngine {
    pub fn new() -> Self {
        Self {
            indexed_rules: HashMap::new(),
            global_rules: Vec::new(),
            total_detections: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn check_rule_count(&self) -> usize {
        self.global_rules.len() + self.indexed_rules.values().map(|v| v.len()).sum::<usize>()
    }

    pub fn load_rules_from_dir(&mut self, dir: &Path) {
        if !dir.exists() { return; }
        let mut count = 0;
        for entry in walkdir::WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                let p = entry.path();
                if p.extension().map_or(false, |ext| ext == "yml" || ext == "yaml") {
                    if let Ok(content) = std::fs::read_to_string(p) {
                        if let Ok(rule) = serde_yaml::from_str::<SigmaRule>(&content) {
                            if let Ok(compiled) = self.compile_rule(rule) {
                                let service = compiled.rule.logsource.service.as_deref();
                                let product = compiled.rule.logsource.product.as_deref();
                                
                                if let Some(s) = service {
                                    self.indexed_rules.entry(s.to_lowercase()).or_default().push(compiled);
                                } else if let Some(p) = product {
                                    self.indexed_rules.entry(p.to_lowercase()).or_default().push(compiled);
                                } else {
                                    self.global_rules.push(compiled);
                                }
                                count += 1;
                            }
                        }
                    }
                }
            }
        }
        info!("Loaded {} Advanced Sigma rules from {}", count, dir.display());
    }

    fn compile_rule(&self, rule: SigmaRule) -> Result<CompiledRule> {
        let mut selections = HashMap::new();
        let mut selection_keys = Vec::new();

        for (id, sel) in &rule.detection.selections {
            if id == "condition" || id == "falsepositives" { continue; }
            selection_keys.push(id.clone());
            let mut field_criteria = Vec::new();
            let mut keywords = Vec::new();

            match sel {
                Selection::Keywords(k) => {
                    for kw in k {
                        keywords.push(self.parse_string_pattern(kw, &[], false));
                    }
                }
                Selection::List(l) => {
                    for val in l {
                        keywords.push(self.parse_string_pattern(val, &[], false));
                    }
                }
                Selection::Map(m) => {
                    for (key, val) in m {
                        let (field, modifiers) = self.parse_field_key(key);
                        let patterns = self.parse_field_value(val, &modifiers)?;
                        field_criteria.push(FieldCriterion {
                            field: field.to_string(),
                            patterns,
                            is_all: modifiers.contains(&"all"),
                        });
                    }
                }
            }
            selections.insert(id.clone(), SelectionCompiled { field_criteria, keywords });
        }

        let transpiled = self.transpile_sigma_condition(&rule.detection.condition, &selection_keys);
        let condition_tree = build_operator_tree(&transpiled).ok();

        Ok(CompiledRule { rule, selections, condition_tree })
    }

    fn transpile_sigma_condition(&self, condition: &str, keys: &[String]) -> String {
        let mut res = condition.to_string();
        
        // Handle aggregations
        if res.contains("1 of them") {
            res = res.replace("1 of them", &format!("({})", keys.join(" || ")));
        }
        if res.contains("all of them") {
            res = res.replace("all of them", &format!("({})", keys.join(" && ")));
        }
        
        // Pattern aggregations: "1 of selection*"
        let re = Regex::new(r"(1|all) of ([a-zA-Z_][a-zA-Z0-9_]*)\*").unwrap();
        let cloned_res = res.clone();
        for cap in re.captures_iter(&cloned_res) {
            let quant = &cap[1];
            let pat = &cap[2];
            let matched: Vec<String> = keys.iter().filter(|k| k.starts_with(pat)).cloned().collect();
            if !matched.is_empty() {
                let expr = if quant == "1" { matched.join(" || ") } else { matched.join(" && ") };
                res = res.replace(&cap[0], &format!("({})", expr));
            }
        }

        // Logical operators
        res = Regex::new(r"\bAND\b").unwrap().replace_all(&res, "&&").to_string();
        res = Regex::new(r"\band\b").unwrap().replace_all(&res, "&&").to_string();
        res = Regex::new(r"\bOR\b").unwrap().replace_all(&res, "||").to_string();
        res = Regex::new(r"\bor\b").unwrap().replace_all(&res, "||").to_string();
        res = Regex::new(r"\bNOT\b").unwrap().replace_all(&res, "!").to_string();
        res = Regex::new(r"\bnot\b").unwrap().replace_all(&res, "!").to_string();
        
        res
    }

    fn parse_field_key<'a>(&self, key: &'a str) -> (&'a str, Vec<&'a str>) {
        let parts: Vec<&str> = key.split('|').collect();
        if parts.len() == 1 { (parts[0], vec![]) } else { (parts[0], parts[1..].to_vec()) }
    }

    fn parse_field_value(&self, value: &serde_yaml::Value, modifiers: &[&str]) -> Result<Vec<FieldPattern>> {
        let mut patterns = Vec::new();
        let is_cased = modifiers.contains(&"cased");
        
        match value {
            serde_yaml::Value::String(s) => {
                patterns.push(self.parse_string_pattern(s, modifiers, is_cased));
            }
            serde_yaml::Value::Sequence(seq) => {
                for item in seq {
                    if let Some(s) = item.as_str() {
                        patterns.push(self.parse_string_pattern(s, modifiers, is_cased));
                    }
                }
            }
            _ => {
                if let Some(s) = value.as_str() {
                    patterns.push(self.parse_string_pattern(s, modifiers, is_cased));
                }
            }
        }
        Ok(patterns)
    }

    fn parse_string_pattern(&self, s: &str, modifiers: &[&str], is_cased: bool) -> FieldPattern {
        if s.contains('*') || s.contains('?') {
            let re_str = self.convert_wildcard_to_regex(s, is_cased);
            if let Ok(re) = Regex::new(&re_str) {
                return FieldPattern::Regex(re);
            }
        }
        
        if modifiers.contains(&"contains") {
            FieldPattern::Contains(s.to_string(), is_cased)
        } else if modifiers.contains(&"startswith") {
            FieldPattern::StartsWith(s.to_string(), is_cased)
        } else if modifiers.contains(&"endswith") {
            FieldPattern::EndsWith(s.to_string(), is_cased)
        } else {
            FieldPattern::Exact(s.to_string(), is_cased)
        }
    }

    fn convert_wildcard_to_regex(&self, pattern: &str, is_cased: bool) -> String {
        let mut regex = if is_cased { "^".to_string() } else { "(?i)^".to_string() };
        for c in pattern.chars() {
            match c {
                '*' => regex.push_str(".*"),
                '?' => regex.push('.'),
                _ => regex.push_str(&regex::escape(&c.to_string())),
            }
        }
        regex.push('$');
        regex
    }

    pub fn check(&self, event: &HostSecurityEvent) -> Vec<&SigmaRule> {
        let mut matches = Vec::new();
        
        // 1. Identify the logsource of this event
        let mut event_sources = Vec::new();
        
        // Map HostEventSource to Sigma logsource strings
        match event.source {
            osoosi_types::HostEventSource::WindowsEventLog => {
                event_sources.push("windows".to_string());
                if let Some(provider) = event.data.get("ProviderName").and_then(|v| v.as_str()) {
                    let prov_lower = provider.to_lowercase();
                    if prov_lower.contains("sysmon") {
                        event_sources.push("sysmon".to_string());
                    } else if prov_lower.contains("security") {
                        event_sources.push("security".to_string());
                    } else if prov_lower.contains("system") {
                        event_sources.push("system".to_string());
                    }
                }
            }
            osoosi_types::HostEventSource::LinuxAudit => {
                event_sources.push("linux".to_string());
                event_sources.push("auditd".to_string());
            }
            osoosi_types::HostEventSource::LinuxAuthLog => {
                event_sources.push("linux".to_string());
                event_sources.push("auth".to_string());
            }
            osoosi_types::HostEventSource::Ebpf => {
                event_sources.push("linux".to_string());
                event_sources.push("ebpf".to_string());
            }
            _ => {}
        }

        // 2. Evaluate Global Rules
        for rule in &self.global_rules {
            if self.evaluate_rule(rule, event) {
                matches.push(&rule.rule);
            }
        }

        // 3. Evaluate Indexed Rules (The "Jet" optimization)
        for src in event_sources {
            if let Some(rules) = self.indexed_rules.get(&src) {
                for rule in rules {
                    if self.evaluate_rule(rule, event) {
                        matches.push(&rule.rule);
                    }
                }
            }
        }

        if !matches.is_empty() {
            self.total_detections.fetch_add(matches.len() as u64, std::sync::atomic::Ordering::Relaxed);
        }
        matches
    }

    fn evaluate_rule(&self, rule: &CompiledRule, event: &HostSecurityEvent) -> bool {
        let mut results = HashMap::new();
        for (id, sel) in &rule.selections {
            results.insert(id.clone(), self.check_selection(sel, event));
        }

        if let Some(tree) = &rule.condition_tree {
            let mut context = HashMapContext::new();
            for (id, &val) in &results {
                let _ = context.set_value(id.clone(), Value::from(val));
            }
            tree.eval_boolean_with_context(&context).unwrap_or(false)
        } else {
            false
        }
    }

    fn check_selection(&self, sel: &SelectionCompiled, event: &HostSecurityEvent) -> bool {
        for kw in &sel.keywords {
            if self.matches_any_field(event, kw) { return true; }
        }
        if sel.field_criteria.is_empty() && sel.keywords.is_empty() { return false; }
        if sel.field_criteria.is_empty() { return false; }

        for criterion in &sel.field_criteria {
            let field_val = event.data.get(&criterion.field).and_then(|v| v.as_str());
            let matched = match field_val {
                Some(v) => {
                    if criterion.is_all {
                        criterion.patterns.iter().all(|p| self.match_pattern(v, p))
                    } else {
                        criterion.patterns.iter().any(|p| self.match_pattern(v, p))
                    }
                }
                None => criterion.patterns.iter().any(|p| matches!(p, FieldPattern::Null)),
            };
            if !matched { return false; }
        }
        true
    }

    fn matches_any_field(&self, event: &HostSecurityEvent, pattern: &FieldPattern) -> bool {
        if let Some(obj) = event.data.as_object() {
            for val in obj.values() {
                if let Some(s) = val.as_str() {
                    if self.match_pattern(s, pattern) { return true; }
                }
            }
        }
        false
    }

    fn match_pattern(&self, actual: &str, pattern: &FieldPattern) -> bool {
        match pattern {
            FieldPattern::Exact(s, cased) => if *cased { actual == s } else { actual.eq_ignore_ascii_case(s) },
            FieldPattern::Contains(s, cased) => if *cased { actual.contains(s) } else { actual.to_lowercase().contains(&s.to_lowercase()) },
            FieldPattern::StartsWith(s, cased) => if *cased { actual.starts_with(s) } else { actual.to_lowercase().starts_with(&s.to_lowercase()) },
            FieldPattern::EndsWith(s, cased) => if *cased { actual.ends_with(s) } else { actual.to_lowercase().ends_with(&s.to_lowercase()) },
            FieldPattern::Regex(re) => re.is_match(actual),
            FieldPattern::Cidr(net) => actual.parse::<std::net::IpAddr>().map_or(false, |ip| net.contains(ip)),
            FieldPattern::Numeric(val, op) => actual.parse::<f64>().map_or(false, |a| match op {
                NumericOp::Lt => a < *val,
                NumericOp::Gt => a > *val,
                NumericOp::Le => a <= *val,
                NumericOp::Ge => a >= *val,
            }),
            FieldPattern::Null => false,
            FieldPattern::NotNull => true,
        }
    }
}
