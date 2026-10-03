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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_yara_no_strings() {
        let sig = ThreatSignature::new("test_node".to_string());
        assert!(generate_yara_from_threat(&sig).is_none());
    }

    #[test]
    fn test_generate_yara_compilation_and_matching() {
        let temp_dir = std::env::temp_dir().join(format!("osoosi_test_yara_{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        std::env::set_var("OSOOSI_YARA_DIR", temp_dir.to_string_lossy().to_string());

        let mut sig = ThreatSignature::new("mesh_node_01".to_string());
        sig.id = "11223344-5566-7788-99aa-bbccddeeff00".to_string();
        sig.process_name = Some("mimikatz.exe".to_string());
        sig.hash_blake3 = Some("deadbeefcafebabe0123456789abcdefdeadbeefcafebabe0123456789abcdef".to_string());
        sig.confidence = 0.95;

        let rule_opt = generate_yara_from_threat(&sig);
        assert!(rule_opt.is_some(), "Expected generated rule");
        let rule_str = rule_opt.unwrap();

        // 1. Verify the generated rule compiles with yara_x
        let mut compiler = yara_x::Compiler::new();
        compiler.add_source(rule_str.as_str()).expect("Generated YARA rule must compile cleanly");
        let rules = compiler.build();
        let mut scanner = yara_x::Scanner::new(&rules);

        // 2. Verify matching on process name
        let payload_proc = b"dummy process image with mimikatz.exe present";
        let results = scanner.scan(payload_proc).unwrap();
        let matches: Vec<&str> = results.matching_rules().map(|r| r.identifier()).collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], "OsoosiGen_11223344_5566_7788_9");

        // 3. Verify clean file cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
