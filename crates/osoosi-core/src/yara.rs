use yara_x;
use std::path::Path;
use tracing::{info, warn};

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
                    let source = yara_x::SourceCode::from(content.as_str())
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
                    let source = yara_x::SourceCode::from(content.as_str())
                        .with_origin(entry_path.to_string_lossy().as_ref());
                    let _ = compiler.add_source(source);
                    count += 1;
                }
            }
        }
    }

    info!("Loaded {} YARA rule(s) into native Yara-X engine.", count);
    compiler.build()
}
