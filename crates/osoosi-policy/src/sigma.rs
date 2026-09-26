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
    #[serde(default)]
    pub tags: Vec<String>,
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
    pub timeframe: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Selection {
    List(Vec<String>),
    ListOfMaps(Vec<HashMap<String, serde_yaml::Value>>),
    Map(HashMap<String, serde_yaml::Value>),
    Keywords(Vec<String>),
    Other(serde_yaml::Value),
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
    pub map_alternatives: Vec<Vec<FieldCriterion>>,
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
            if id == "condition" || id == "falsepositives" || id == "timeframe" { continue; }
            selection_keys.push(id.clone());
            let mut map_alternatives = Vec::new();
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
                    let mut group = Vec::new();
                    for (key, val) in m {
                        let (field, modifiers) = self.parse_field_key(key);
                        let patterns = self.parse_field_value(val, &modifiers)?;
                        group.push(FieldCriterion {
                            field: field.to_string(),
                            patterns,
                            is_all: modifiers.contains(&"all"),
                        });
                    }
                    map_alternatives.push(group);
                }
                Selection::ListOfMaps(list) => {
                    for m in list {
                        let mut group = Vec::new();
                        for (key, val) in m {
                            let (field, modifiers) = self.parse_field_key(key);
                            let patterns = self.parse_field_value(val, &modifiers)?;
                            group.push(FieldCriterion {
                                field: field.to_string(),
                                patterns,
                                is_all: modifiers.contains(&"all"),
                            });
                        }
                        map_alternatives.push(group);
                    }
                }
                Selection::Other(_) => {}
            }
            selections.insert(id.clone(), SelectionCompiled { map_alternatives, keywords });
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
            serde_yaml::Value::Number(n) => {
                patterns.push(self.parse_string_pattern(&n.to_string(), modifiers, is_cased));
            }
            serde_yaml::Value::Bool(b) => {
                patterns.push(self.parse_string_pattern(&b.to_string(), modifiers, is_cased));
            }
            serde_yaml::Value::Sequence(seq) => {
                for item in seq {
                    if let Some(s) = item.as_str() {
                        patterns.push(self.parse_string_pattern(s, modifiers, is_cased));
                    } else if let Some(n) = item.as_i64() {
                        patterns.push(self.parse_string_pattern(&n.to_string(), modifiers, is_cased));
                    } else if let Some(n) = item.as_u64() {
                        patterns.push(self.parse_string_pattern(&n.to_string(), modifiers, is_cased));
                    } else if let Some(b) = item.as_bool() {
                        patterns.push(self.parse_string_pattern(&b.to_string(), modifiers, is_cased));
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
        if sel.map_alternatives.is_empty() && sel.keywords.is_empty() { return false; }
        if sel.map_alternatives.is_empty() { return false; }

        for group in &sel.map_alternatives {
            let mut group_matched = true;
            for criterion in group {
                let field_val = get_event_field_value(event, &criterion.field);
                let matched = match field_val {
                    Some(ref v) => {
                        if criterion.is_all {
                            criterion.patterns.iter().all(|p| self.match_pattern(v, p))
                        } else {
                            criterion.patterns.iter().any(|p| self.match_pattern(v, p))
                        }
                    }
                    None => criterion.patterns.iter().any(|p| matches!(p, FieldPattern::Null)),
                };
                if !matched {
                    group_matched = false;
                    break;
                }
            }
            if group_matched {
                return true;
            }
        }
        false
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

pub fn get_event_field_value(event: &HostSecurityEvent, field: &str) -> Option<String> {
    let field_lower = field.to_ascii_lowercase();

    // 1. Special case: EventID / event_id
    if field_lower == "eventid" || field_lower == "event_id" {
        return Some(event.event_id.to_string());
    }

    // 2. Special case: Channel
    if field_lower == "channel" {
        if let Some(ch) = event.data.get("Channel").and_then(|v| v.as_str()) {
            return Some(ch.to_string());
        }
        let provider = event.data.get("ProviderName").and_then(|v| v.as_str()).unwrap_or("");
        if provider.to_lowercase().contains("sysmon")
            || event.source == osoosi_types::HostEventSource::WindowsEventLog
        {
            return Some("Microsoft-Windows-Sysmon/Operational".to_string());
        }
    }

    // 3. Direct lookup in event.data
    if let Some(val) = event.data.get(field) {
        if let Some(s) = value_to_string(val) {
            return Some(s);
        }
    }

    // 4. Case-insensitive lookup in event.data
    if let Some(obj) = event.data.as_object() {
        for (k, v) in obj {
            if k.eq_ignore_ascii_case(field) {
                if let Some(s) = value_to_string(v) {
                    return Some(s);
                }
            }
        }
    }

    // 5. Special fallback mappings for standard process creation fields
    if field_lower == "originalfilename" || field_lower == "original_file_name" {
        if let Some(img) = event.data.get("Image").and_then(|v| v.as_str()) {
            if let Some(fname) = std::path::Path::new(img).file_name().and_then(|n| n.to_str()) {
                return Some(fname.to_string());
            }
        }
    }

    None
}

fn value_to_string(val: &serde_json::Value) -> Option<String> {
    match val {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use osoosi_types::HostEventSource;

    #[test]
    fn test_sysmon_systeminfo_sigma_rule_evaluation() {
        let yaml_rule = r#"
title: Suspicious Execution of Systeminfo
id: 072cd776-d1c7-58e2-3eac-b49412c39e82
status: test
description: Detects usage of the "systeminfo" command to retrieve information
tags:
    - attack.discovery
    - attack.t1082
    - sysmon
logsource:
    category: process_creation
    product: windows
detection:
    process_creation:
        EventID: 1
        Channel: Microsoft-Windows-Sysmon/Operational
    selection:
        - Image|endswith: \systeminfo.exe
        - OriginalFileName: sysinfo.exe
    condition: process_creation and selection
level: low
ruletype: Sigma
"#;

        let rule: SigmaRule = serde_yaml::from_str(yaml_rule).expect("Must deserialize SigmaRule");
        assert_eq!(rule.tags, vec!["attack.discovery", "attack.t1082", "sysmon"]);

        let mut engine = SigmaEngine::new();
        let compiled = engine.compile_rule(rule).expect("Must compile rule");
        engine.global_rules.push(compiled);

        let event = HostSecurityEvent {
            event_id: 1,
            timestamp: Utc::now(),
            source: HostEventSource::WindowsEventLog,
            computer: "DESKTOP-TEST".to_string(),
            data: serde_json::json!({
                "Image": "C:\\Windows\\System32\\systeminfo.exe",
                "CommandLine": "systeminfo",
                "ProviderName": "Microsoft-Windows-Sysmon",
            }),
            causal_parent: None,
        };

        let matches = engine.check(&event);
        assert_eq!(matches.len(), 1, "Sysmon systeminfo execution rule must match");
        assert_eq!(matches[0].title, "Suspicious Execution of Systeminfo");
        assert!(matches[0].tags.contains(&"attack.t1082".to_string()));
    }

    #[test]
    fn test_sysmon_whoami_priv_sigma_rule_evaluation() {
        let yaml_rule = r#"
title: Security Privileges Enumeration Via Whoami.EXE
id: 50445625-a1e8-d511-8687-4343f2ce9a3e
status: test
description: Detects a whoami.exe executed with the /priv command line flag
tags:
    - attack.privilege-escalation
    - attack.discovery
    - attack.t1033
    - sysmon
logsource:
    category: process_creation
    product: windows
detection:
    process_creation:
        EventID: 1
        Channel: Microsoft-Windows-Sysmon/Operational
    selection_img:
        - Image|endswith: \whoami.exe
        - OriginalFileName: whoami.exe
    selection_cli:
        CommandLine|contains:
            - ' /priv'
            - ' -priv'
    condition: process_creation and (all of selection_*)
level: high
ruletype: Sigma
"#;

        let rule: SigmaRule = serde_yaml::from_str(yaml_rule).expect("Must deserialize SigmaRule");
        assert_eq!(rule.tags, vec!["attack.privilege-escalation", "attack.discovery", "attack.t1033", "sysmon"]);

        let mut engine = SigmaEngine::new();
        let compiled = engine.compile_rule(rule).expect("Must compile rule");
        engine.global_rules.push(compiled);

        let event = HostSecurityEvent {
            event_id: 1,
            timestamp: Utc::now(),
            source: HostEventSource::WindowsEventLog,
            computer: "DESKTOP-TEST".to_string(),
            data: serde_json::json!({
                "Image": "C:\\Windows\\System32\\whoami.exe",
                "CommandLine": "whoami /priv",
                "ProviderName": "Microsoft-Windows-Sysmon",
            }),
            causal_parent: None,
        };

        let matches = engine.check(&event);
        assert_eq!(matches.len(), 1, "Sysmon whoami /priv rule must match");
        assert_eq!(matches[0].title, "Security Privileges Enumeration Via Whoami.EXE");
        assert!(matches[0].tags.contains(&"attack.t1033".to_string()));
    }
}
