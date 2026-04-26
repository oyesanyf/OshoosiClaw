//! Auto-generated YARA rules from threat detections.
//! When a high-confidence threat is detected, generate a YARA rule and write to yara dir.

use osoosi_types::ThreatSignature;
use std::path::PathBuf;
use tracing::info;

pub fn yara_gen_enabled() -> bool {
    std::env::var("OSOOSI_YARA_GEN_ENABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true)
}

fn yara_dir() -> PathBuf {
    std::env::var("OSOOSI_YARA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("yara"))
}

/// Generate YARA rule from threat and write to yara/osoosi_generated/.
/// Returns the rule content for mesh sharing.
pub fn generate_yara_from_threat(sig: &ThreatSignature) -> Option<String> {
    if !yara_gen_enabled() {
        return None;
    }
    let rule_name = format!(
        "OsoosiGen_{}",
        sig.id
            .replace('-', "_")
            .chars()
            .take(20)
            .collect::<String>()
    );
    let mut has_strings = false;
    let mut strings_section = String::new();
    let mut cond_parts = Vec::new();

    if let Some(ref proc) = sig.process_name {
        let safe = proc.replace('\\', "\\\\").replace('\"', "\\\"");
        strings_section.push_str(&format!("        $proc = \"{}\" ascii wide\n", safe));
        cond_parts.push("$proc".to_string());
        has_strings = true;
    }
    if let Some(ref hash) = sig.hash_blake3 {
        let hex: String = hash.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if hex.len() >= 32 {
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .filter_map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
                .collect();
            let spaced: String = bytes
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" ");
            strings_section.push_str(&format!("        $h = {{ {} }}\n", spaced));
            cond_parts.push("$h".to_string());
            has_strings = true;
        }
    }
    if !has_strings {
        return None;
    }

    let cond_str = if cond_parts.len() == 1 {
        cond_parts[0].clone()
    } else {
        "any of them".to_string()
    };

    let meta = format!(
        "        confidence = {} source_node = \"{}\"",
        sig.confidence,
        sig.source_node.replace('\"', "'")
    );
    let rule = format!(
        r#"rule {}
{{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
{}
    strings:
{}
    condition:
        {}
}}"#,
        rule_name, meta, strings_section, cond_str
    );

    let gen_dir = yara_dir().join("osoosi_generated");
    if let Err(e) = std::fs::create_dir_all(&gen_dir) {
        tracing::warn!("YARA gen: could not create {}: {}", gen_dir.display(), e);
        return Some(rule);
    }
    let path = gen_dir.join(format!("{}.yar", rule_name));
    if let Err(e) = std::fs::write(&path, &rule) {
        tracing::warn!("YARA gen: could not write {}: {}", path.display(), e);
    } else {
        info!("Generated YARA rule: {}", path.display());
    }
    Some(rule)
}
