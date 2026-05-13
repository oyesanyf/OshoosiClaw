use yara_x;
use std::path::Path;
use tracing::{info, warn};

fn fix_yara_escapes(s: &str) -> String {
    // Standard valid escapes in YARA + common regex escapes
    let valid = "nrt\\\"\'xuUdwsDWSbB0123456789$^*+?()[]{}|.^/ ";
    let mut result = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() {
            let next = chars[i+1];
            if next == '\\' {
                // Literal backslash: valid, push both and skip
                result.push('\\');
                result.push('\\');
                i += 2;
                continue;
            } else if valid.contains(next) {
                // Other valid escape: push both and skip
                result.push('\\');
                result.push(next);
                i += 2;
                continue;
            } else {
                // Invalid escape: escape the backslash itself
                result.push('\\');
                result.push('\\');
                result.push(next);
                i += 2;
                continue;
            }
        }
        result.push(chars[i]);
        i += 1;
    }
    result
}

fn sanitize_yara_content(content: &str) -> String {
    let mut result = content.to_string();

    // 1. Fix invalid escapes in strings and regexes
    let string_regex = regex::Regex::new(r#"(?s)".*?""#).unwrap();
    result = string_regex.replace_all(&result, |caps: &regex::Captures| {
        fix_yara_escapes(&caps[0])
    }).to_string();

    let regex_decl_regex = regex::Regex::new(r"(?s)/.*?/").unwrap();
    result = regex_decl_regex.replace_all(&result, |caps: &regex::Captures| {
        fix_yara_escapes(&caps[0])
    }).to_string();

    // 2. Fix unescaped forward slashes in regex: /.../.../ -> /...\/.../
    let regex_fixer = regex::Regex::new(r"/[^ \n].*?/[ ]*(wide|ascii|nocase|fullword|\n|;)").unwrap();
    result = regex_fixer.replace_all(&result, |caps: &regex::Captures| {
        let r = &caps[0];
        if r.len() < 3 { return r.to_string(); }
        
        if let Some(end_idx) = r[1..].find('/') {
            let internal = &r[1..end_idx + 1];
            let mut fixed_internal = String::with_capacity(internal.len());
            let mut escaped = false;
            for c in internal.chars() {
                if c == '\\' {
                    escaped = !escaped;
                } else if c == '/' && !escaped {
                    fixed_internal.push('\\');
                } else {
                    escaped = false;
                }
                fixed_internal.push(c);
            }
            format!("/{}/{}", fixed_internal, &r[end_idx + 2..])
        } else {
            r.to_string()
        }
    }).to_string();

    // 3. Fix empty alternatives
    result = result.replace("|/", "/");
    result = result.replace("/|", "/");
    result = result.replace("||", "|");

    // 4. Fix regexes followed immediately by keywords (prevents 'c' being seen as modifier)
    // Use regex to find slashes followed by keywords, ensuring we catch things like /condition: or //condition:
    let re_boundary = regex::Regex::new(r"(/+)(condition:|strings:|meta:|rule\b)").unwrap();
    result = re_boundary.replace_all(&result, " $1 $2").to_string();

    // Specific common cases that might have escaped the regex
    result = result.replace("/condition:", "/ condition:");
    result = result.replace("//condition:", " // condition:");

    result
}

/// Load YARA rules from the rules directory for use by the native Yara-X engine.
pub fn load_rules() -> yara_x::Rules {
    let mut compiler = yara_x::Compiler::new();
    let yara_dir = std::env::var("OSOOSI_YARA_DIR").unwrap_or_else(|_| "yara".to_string());
    let path = Path::new(&yara_dir);
    
    if !path.exists() {
        warn!("YARA rules directory {:?} not found. Starting with empty ruleset.", path);
        return compiler.build();
    }

    // Add the base directory to the include search path to resolve relative includes
    compiler.add_include_dir(path);

    let mut count = 0;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if entry_path.extension().map(|e| e == "yar" || e == "yara").unwrap_or(false) {
                if let Ok(content) = std::fs::read_to_string(&entry_path) {
                    let sanitized = sanitize_yara_content(&content);
                    let source = yara_x::SourceCode::from(sanitized.as_str())
                        .with_origin(entry_path.to_string_lossy().as_ref());
                    if let Err(e) = compiler.add_source(source) {
                        warn!("Failed to compile YARA rule {:?}: {}", entry_path, e);
                    } else {
                        count += 1;
                    }
                }
            }
        }
    }
    
    // Also load generated rules
    let gen_dir = path.join("osoosi_generated");
    if gen_dir.exists() {
        compiler.add_include_dir(&gen_dir);
        if let Ok(entries) = std::fs::read_dir(&gen_dir) {
            for entry in entries.flatten() {
                 let entry_path = entry.path();
                 if let Ok(content) = std::fs::read_to_string(&entry_path) {
                    let sanitized = sanitize_yara_content(&content);
                    let source = yara_x::SourceCode::from(sanitized.as_str())
                        .with_origin(entry_path.to_string_lossy().as_ref());
                    let _ = compiler.add_source(source);
                    count += 1;
                }
            }
        }
    }

    // Add High-Priority Built-in C2 Rules
    let c2_rules = r#"
        rule C2_Beacon_Generic {
            strings:
                $mz = { 4D 5A }
                $cobalt_strike = "beacon.dll"
                $sliver = "sliver"
            condition:
                $mz and ($cobalt_strike or $sliver)
        }
    "#;
    if let Err(e) = compiler.add_source(c2_rules) {
        warn!("Failed to compile built-in C2 YARA rules: {}", e);
    } else {
        count += 1;
    }

    info!("Loaded {} YARA rule(s) into native Yara-X engine.", count);
    compiler.build()
}
