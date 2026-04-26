use osoosi_types::ThreatSignature;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};
use yara_x::{Compiler, Rules, Scanner};

pub struct YaraAnalyzer {
    rules: Option<Rules>,
}

impl YaraAnalyzer {
    pub fn new() -> Self {
        let rules_dir = std::env::var("OSOOSI_YARA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("yara"));
        
        let mut compiler = Compiler::new();
        let mut loaded = 0;

        // Load all .yar files in the yara directory
        if rules_dir.exists() {
            for entry in walkdir::WalkDir::new(&rules_dir)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.path()
                        .extension()
                        .map_or(false, |ext| ext == "yar" || ext == "yara")
                })
            {
                if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    if let Err(e) = compiler.add_source(content.as_str()) {
                        warn!("YARA: Failed to add rule from {:?}: {}", entry.path(), e);
                    } else {
                        loaded += 1;
                    }
                }
            }
        }

        let rules = if loaded > 0 {
            Some(compiler.build())
        } else {
            debug!("YARA: No rules loaded.");
            None
        };

        Self { rules }
    }

    /// Scan a file with all loaded YARA rules.
    pub fn scan_file(&self, path: &Path) -> anyhow::Result<Vec<String>> {
        if !path.exists() {
            return Ok(Vec::new());
        }

        let rules = match &self.rules {
            Some(r) => r,
            None => return Ok(Vec::new()),
        };

        let mut scanner = Scanner::new(rules);

        let file_data = std::fs::read(path)?;
        let scan_results = scanner.scan(&file_data)?;

        let mut matches = Vec::new();
        for m in scan_results.matching_rules() {
            matches.push(m.identifier().to_string());
        }

        if !matches.is_empty() {
            info!("YARA: Matches found for {:?}: {:?}", path, matches);
        }

        Ok(matches)
    }

    /// Analyze a file and return a ThreatSignature if any rules match.
    pub fn analyze(&self, path: &Path) -> anyhow::Result<Option<ThreatSignature>> {
        let matches = self.scan_file(path)?;
        if matches.is_empty() {
            return Ok(None);
        }

        let mut sig = ThreatSignature::new("localhost".to_string());
        sig.process_name = path.file_name().and_then(|n| n.to_str()).map(String::from);
        sig.confidence = 0.5 + (0.1 * matches.len() as f32).min(0.48);
        for m in matches {
            sig.add_reason(format!("YARA Match: {}", m));
        }

        Ok(Some(sig))
    }
}
