use yara_x;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use tracing::{info, warn, debug};

fn string_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r#"(?s)".*?""#).unwrap())
}

fn regex_decl_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"(?s)/.*?/").unwrap())
}

fn regex_fixer() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"/[^ \n].*?/[ ]*(wide|ascii|nocase|fullword|\n|;)").unwrap())
}

fn boundary_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"(/+)(condition:|strings:|meta:|rule\b)").unwrap())
}

fn rule_ident_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"\brule\s+([a-zA-Z0-9_]+)\s*(?:\{|:)").unwrap())
}

fn fix_yara_escapes(s: &str) -> String {
    let valid = "nrt\\\"\'xuUdwsDWSbB0123456789$^*+?()[]{}|.^/ ";
    let mut result = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() {
            let next = chars[i+1];
            if next == '\\' {
                result.push('\\');
                result.push('\\');
                i += 2;
                continue;
            } else if valid.contains(next) {
                result.push('\\');
                result.push(next);
                i += 2;
                continue;
            } else {
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

pub fn sanitize_yara_content(content: &str) -> String {
    // Fast path: avoid expensive regex passes if content doesn't contain problematic characters
    if !content.contains('\\') && !content.contains("/condition:") && !content.contains("||") && !content.contains("|/") && !content.contains("/|") {
        return content.to_string();
    }

    let mut result = content.to_string();

    // 1. Fix invalid escapes in strings and regexes
    if result.contains('\\') {
        result = string_regex().replace_all(&result, |caps: &regex::Captures| {
            fix_yara_escapes(&caps[0])
        }).to_string();

        result = regex_decl_regex().replace_all(&result, |caps: &regex::Captures| {
            fix_yara_escapes(&caps[0])
        }).to_string();
    }

    // 2. Fix unescaped forward slashes in regex: /.../.../ -> /...\/.../
    result = regex_fixer().replace_all(&result, |caps: &regex::Captures| {
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
    result = boundary_regex().replace_all(&result, " $1 $2").to_string();

    // Specific common cases that might have escaped the regex
    result = result.replace("/condition:", "/ condition:");
    result = result.replace("//condition:", " // condition:");

    result
}

/// Sanitizer check for generated YARA rules:
/// If a rule from `osoosi_generated` only checks a generic process name with no hash or other conditions,
/// skip compiling it and log a debug message.
pub fn is_unsafe_generic_generated_rule(path_or_ident: &str, content: &str) -> bool {
    let lower_path = path_or_ident.to_ascii_lowercase();
    let is_generated = lower_path.contains("osoosi_generated")
        || lower_path.contains("generated")
        || path_or_ident.starts_with("OsoosiGen_");

    if !is_generated {
        return false;
    }

    let lower_content = content.to_ascii_lowercase();
    let has_hash = lower_content.contains("$h = {") || lower_content.contains("$h=");

    // If it has no hash:
    if !has_hash {
        let generic_proc_names = [
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            "python.exe",
            "python3.exe",
            "pythonw.exe",
            "conhost.exe",
            "explorer.exe",
            "svchost.exe",
            "rundll32.exe",
            "antigravity.exe",
            "filecoauth.exe",
            "git.exe",
            "cargo.exe",
            "rustc.exe",
            "code.exe",
            "bash.exe",
            "wsl.exe",
            "unknown",
            "googledrivefs.exe",
            "language_server_windows_x64.exe",
            "osoosi.exe",
            "osoosi-cli.exe",
        ];

        let has_proc = lower_content.contains("$proc");
        let has_generic_name = generic_proc_names.iter().any(|name| lower_content.contains(name));
        if has_proc || has_generic_name {
            return true;
        }
    }

    // If condition has 'any of them' and has $proc, it would match on process name alone without hash
    if lower_content.contains("any of them") && lower_content.contains("$proc") {
        return true;
    }

    false
}


#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct YaraRuleMetadata {
    pub identifier: String,
    pub file_path: String,
    pub is_generated: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct YaraEngineStatus {
    pub total_rules: usize,
    pub custom_rules: usize,
    pub generated_rules: usize,
    pub feed_rules: usize,
    pub last_reloaded_at: chrono::DateTime<chrono::Utc>,
    pub last_feed_update_at: Option<chrono::DateTime<chrono::Utc>>,
    pub directories_searched: Vec<String>,
    pub total_scans: u64,
    pub total_matches: u64,
    pub is_updating: bool,
}

#[derive(Clone)]
pub struct YaraManager {
    rules: Arc<parking_lot::RwLock<Arc<yara_x::Rules>>>,
    status: Arc<parking_lot::RwLock<YaraEngineStatus>>,
    rule_sources: Arc<parking_lot::RwLock<Vec<YaraRuleMetadata>>>,
    dynamic_sources: Arc<parking_lot::RwLock<std::collections::HashMap<String, String>>>,
    base_file_sources: Arc<parking_lot::RwLock<Vec<(PathBuf, String, String)>>>,
    canonical_dirs: Arc<parking_lot::RwLock<Vec<PathBuf>>>,
    dirs_searched: Arc<parking_lot::RwLock<Vec<String>>>,
}

impl Default for YaraManager {
    fn default() -> Self {
        Self::new()
    }
}

impl YaraManager {
    /// Initialize a new YaraManager by recursively discovering all rules and compiling the active engine.
    pub fn new() -> Self {
        let (dirs_searched, canonical_dirs, file_sources) = collect_file_sources();
        let dynamic_sources = std::collections::HashMap::new();
        let (rules, status, metadata) = compile_sources_to_rules(
            &canonical_dirs,
            dirs_searched.clone(),
            &file_sources,
            &dynamic_sources,
        );

        Self {
            rules: Arc::new(parking_lot::RwLock::new(Arc::new(rules))),
            status: Arc::new(parking_lot::RwLock::new(status)),
            rule_sources: Arc::new(parking_lot::RwLock::new(metadata)),
            dynamic_sources: Arc::new(parking_lot::RwLock::new(dynamic_sources)),
            base_file_sources: Arc::new(parking_lot::RwLock::new(file_sources)),
            canonical_dirs: Arc::new(parking_lot::RwLock::new(canonical_dirs)),
            dirs_searched: Arc::new(parking_lot::RwLock::new(dirs_searched)),
        }
    }

    /// Check if offline mode is explicitly requested via environment variable.
    pub fn is_offline() -> bool {
        std::env::var("OSOOSI_OFFLINE_MODE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    /// Read the latest active hot-swapped rules pointer.
    /// Clones the `Arc<yara_x::Rules>` handle in nanosecond time, allowing active scanners
    /// to scan lock-free without ever reading stale rules or blocking compiler updates.
    pub fn active_rules(&self) -> Arc<yara_x::Rules> {
        self.rules.read().clone()
    }

    /// Internal compilation and atomic hot-swap of the active rules pointer.
    fn recompile_and_hotswap(&self) -> anyhow::Result<usize> {
        let canonical_dirs = self.canonical_dirs.read().clone();
        let dirs_searched = self.dirs_searched.read().clone();
        let file_sources = self.base_file_sources.read().clone();
        let dynamic_sources = self.dynamic_sources.read().clone();

        let (new_rules, new_status, new_metadata) = compile_sources_to_rules(
            &canonical_dirs,
            dirs_searched,
            &file_sources,
            &dynamic_sources,
        );
        let total = new_status.total_rules;

        // Atomically hot-swap active rules pointer
        {
            let mut rules_guard = self.rules.write();
            *rules_guard = Arc::new(new_rules);
        }

        // Update status while preserving scan counts and last_feed_update_at
        {
            let mut status_guard = self.status.write();
            let prev_scans = status_guard.total_scans;
            let prev_matches = status_guard.total_matches;
            let prev_feed_update = status_guard.last_feed_update_at;
            *status_guard = new_status;
            status_guard.total_scans = prev_scans;
            status_guard.total_matches = prev_matches;
            if status_guard.last_feed_update_at.is_none() {
                status_guard.last_feed_update_at = prev_feed_update;
            }
        }

        // Update rule sources
        {
            let mut sources_guard = self.rule_sources.write();
            *sources_guard = new_metadata;
        }

        info!("[YARA] Dynamically hot-swapped rules pointer. Total active: {}.", total);
        Ok(total)
    }

    /// Reload rules from disk (re-scans directories for new/updated feed files) and atomically hot-swaps.
    pub fn reload_rules(&self) -> anyhow::Result<usize> {
        let (dirs_searched, canonical_dirs, file_sources) = collect_file_sources();
        {
            let mut bfs = self.base_file_sources.write();
            *bfs = file_sources;
        }
        {
            let mut cd = self.canonical_dirs.write();
            *cd = canonical_dirs;
        }
        {
            let mut ds = self.dirs_searched.write();
            *ds = dirs_searched;
        }

        self.recompile_and_hotswap()
    }

    /// Asynchronously reload rules in a blocking worker thread.
    pub async fn reload_rules_async(&self) -> anyhow::Result<usize> {
        let ym = self.clone();
        tokio::task::spawn_blocking(move || ym.reload_rules()).await?
    }

    /// Validate, write (best-effort), and atomically hot-load a single YARA rule without restarting the EDR agent.
    pub fn hot_load_rule(&self, rule_content: &str, identifier: &str) -> anyhow::Result<bool> {
        if is_unsafe_generic_generated_rule(identifier, rule_content) {
            debug!("[YARA] Skipping generic process rule without hash: {}", identifier);
            anyhow::bail!("Rule {} rejected: generic process name without cryptographic hash", identifier);
        }
        let sanitized = sanitize_yara_content(rule_content);

        // 1. Validate rule syntax with an isolated test compiler
        let mut test_compiler = yara_x::Compiler::new();
        test_compiler
            .add_source(sanitized.as_str())
            .map_err(|e| anyhow::anyhow!("Validation failed for rule {}: {}", identifier, e))?;
        let _ = test_compiler.build();

        // 2. Best-effort write to generated rule directories for offline persistence
        let clean_id = identifier.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
        let filename = format!("{}.yar", clean_id);

        let target_dirs = [
            PathBuf::from("rules/osoosi_generated"),
            PathBuf::from("yara/osoosi_generated"),
            PathBuf::from("../../rules/osoosi_generated"),
            PathBuf::from("../../yara/osoosi_generated"),
        ];

        for dir in &target_dirs {
            if std::fs::create_dir_all(dir).is_ok() {
                let file_path = dir.join(&filename);
                let _ = std::fs::write(&file_path, &sanitized);
            }
        }

        // 3. Register in dynamic in-memory rules
        {
            let mut dyn_guard = self.dynamic_sources.write();
            dyn_guard.insert(identifier.to_string(), sanitized);
        }

        // 4. Immediately compile and atomically hot-swap active rules pointer
        self.recompile_and_hotswap()?;
        Ok(true)
    }

    /// Operator alias for hot_load_rule.
    pub fn add_rule(&self, rule_content: &str, identifier: &str) -> anyhow::Result<bool> {
        self.hot_load_rule(rule_content, identifier)
    }

    /// Hot-load in-memory rule directly without touching disk.
    pub fn hot_load_memory_rule(&self, rule_content: &str, identifier: &str) -> anyhow::Result<bool> {
        if is_unsafe_generic_generated_rule(identifier, rule_content) {
            debug!("[YARA] Skipping generic process rule without hash: {}", identifier);
            anyhow::bail!("Rule {} rejected: generic process name without cryptographic hash", identifier);
        }
        let sanitized = sanitize_yara_content(rule_content);
        let mut test_compiler = yara_x::Compiler::new();
        test_compiler
            .add_source(sanitized.as_str())
            .map_err(|e| anyhow::anyhow!("Validation failed for rule {}: {}", identifier, e))?;
        let _ = test_compiler.build();

        {
            let mut dyn_guard = self.dynamic_sources.write();
            dyn_guard.insert(identifier.to_string(), sanitized);
        }

        self.recompile_and_hotswap()?;
        Ok(true)
    }

    /// Dynamically remove a rule by identifier and atomically hot-swap the rules pointer.
    pub fn remove_rule(&self, identifier: &str) -> anyhow::Result<bool> {
        let removed = {
            let mut dyn_guard = self.dynamic_sources.write();
            dyn_guard.remove(identifier).is_some()
        };
        if removed {
            self.recompile_and_hotswap()?;
        }
        Ok(removed)
    }

    /// Clear all in-memory dynamic rules and atomically hot-swap back to base rules.
    pub fn clear_dynamic_rules(&self) -> anyhow::Result<usize> {
        let count = {
            let mut dyn_guard = self.dynamic_sources.write();
            let len = dyn_guard.len();
            dyn_guard.clear();
            len
        };
        if count > 0 {
            self.recompile_and_hotswap()?;
        }
        Ok(count)
    }

    /// Directly hot-swap active Rules pointer with pre-compiled rules.
    pub fn hot_swap_rules(&self, new_rules: yara_x::Rules) {
        let mut rules_guard = self.rules.write();
        *rules_guard = Arc::new(new_rules);
    }

    /// Scan byte buffer with the active YARA engine and return matching rule identifiers.
    pub fn scan_bytes(&self, bytes: &[u8]) -> Vec<String> {
        let rules = self.active_rules();
        let mut scanner = yara_x::Scanner::new(&rules);
        let matches = match scanner.scan(bytes) {
            Ok(results) => results
                .matching_rules()
                .map(|r| r.identifier().to_string())
                .collect(),
            Err(e) => {
                warn!("YARA scan_bytes error: {}", e);
                Vec::new()
            }
        };

        {
            let mut st = self.status.write();
            st.total_scans += 1;
            st.total_matches += matches.len() as u64;
        }

        matches
    }

    /// Scan file at specified path with the active YARA engine.
    pub fn scan_file(&self, path: &Path) -> anyhow::Result<Vec<String>> {
        let bytes = std::fs::read(path)?;
        Ok(self.scan_bytes(&bytes))
    }

    /// Get current YARA engine status.
    pub fn get_status(&self) -> YaraEngineStatus {
        self.status.read().clone()
    }

    /// Get all loaded rule metadata.
    pub fn get_sources(&self) -> Vec<YaraRuleMetadata> {
        self.rule_sources.read().clone()
    }

    /// Get copy of active dynamic rules map.
    pub fn get_dynamic_rules(&self) -> std::collections::HashMap<String, String> {
        self.dynamic_sources.read().clone()
    }

    /// Update community threat feeds from online sources and reload the engine.
    /// Gracefully falls back if offline.
    pub async fn update_feeds_and_reload(&self) -> anyhow::Result<usize> {
        {
            let mut st = self.status.write();
            st.is_updating = true;
        }

        let offline = Self::is_offline();
        let mut downloaded_any = false;

        if !offline {
            let feed_urls = [
                ("yara_forge_core.yar", "https://raw.githubusercontent.com/YARAHQ/yara-forge/main/dist/yara-rules-core.yar"),
                ("florian_c2_hunting.yar", "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_c2_hunting.yar"),
                ("abusech_rules.yar", "https://raw.githubusercontent.com/YARAHQ/yara-forge/main/rules/abusech_rules.yar"),
            ];

            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(8))
                .user_agent("OshoosiClaw/1.0 (EDR Dynamic Threat Feed Synchronizer)")
                .build()
                .unwrap_or_else(|_| reqwest::Client::new());

            let target_dirs = [
                PathBuf::from("yara/feeds"),
                PathBuf::from("rules/feeds"),
                PathBuf::from("../../yara/feeds"),
                PathBuf::from("../../rules/feeds"),
            ];

            for (filename, url) in &feed_urls {
                match client.get(*url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        if let Ok(text) = resp.text().await {
                            if !text.trim().is_empty() {
                                let sanitized = sanitize_yara_content(&text);
                                for dir in &target_dirs {
                                    if std::fs::create_dir_all(dir).is_ok() {
                                        let file_path = dir.join(filename);
                                        let _ = std::fs::write(&file_path, &sanitized);
                                    }
                                }
                                downloaded_any = true;
                                info!("[YARA] Downloaded and cached threat feed: {}", filename);
                            }
                        }
                    }
                    Ok(resp) => {
                        debug!("[YARA] Feed download HTTP {} for {}", resp.status(), url);
                    }
                    Err(e) => {
                        debug!("[YARA] Feed download error for {}: {} (offline fallback active)", url, e);
                    }
                }
            }
        } else {
            info!("[YARA] Offline mode configured: skipping external feed network requests.");
        }

        if !downloaded_any && !offline {
            info!("[YARA] Feed update skipped or offline; falling back to existing local rule sets.");
        }

        let count = self.reload_rules()?;

        {
            let mut st = self.status.write();
            if downloaded_any {
                st.last_feed_update_at = Some(chrono::Utc::now());
            }
            st.is_updating = false;
        }

        Ok(count)
    }
}

/// Discover all candidate YARA rule directories and collect all file paths and their contents.
pub fn collect_file_sources() -> (Vec<String>, Vec<PathBuf>, Vec<(PathBuf, String, String)>) {
    let mut dirs_searched: Vec<String> = Vec::new();
    let mut canonical_dirs: Vec<PathBuf> = Vec::new();

    let env_dir = std::env::var("OSOOSI_YARA_DIR").ok().map(PathBuf::from);

    let base_roots = if Path::new("rules").exists() || Path::new("yara").exists() {
        vec![PathBuf::from("rules"), PathBuf::from("yara")]
    } else if Path::new("../../rules").exists() || Path::new("../../yara").exists() {
        vec![PathBuf::from("../../rules"), PathBuf::from("../../yara")]
    } else if Path::new("../rules").exists() || Path::new("../yara").exists() {
        vec![PathBuf::from("../rules"), PathBuf::from("../yara")]
    } else if Path::new("deploy/yara").exists() {
        vec![PathBuf::from("deploy/yara")]
    } else if Path::new("../../deploy/yara").exists() {
        vec![PathBuf::from("../../deploy/yara")]
    } else {
        vec![PathBuf::from("yara")]
    };

    let mut candidate_list = Vec::new();
    if let Some(d) = env_dir {
        candidate_list.push(d);
    }
    candidate_list.extend(base_roots);

    for candidate in candidate_list {
        if candidate.exists() && candidate.is_dir() {
            let canonical = candidate.canonicalize().unwrap_or_else(|_| candidate.clone());
            if !canonical_dirs.contains(&canonical) {
                dirs_searched.push(candidate.to_string_lossy().to_string());
                canonical_dirs.push(canonical);
            }
        }
    }

    let mut visited_canonical_files = std::collections::HashSet::new();
    let mut curated_files: Vec<PathBuf> = Vec::new();
    let mut gen_files: Vec<(PathBuf, std::time::SystemTime)> = Vec::new();

    for dir in &canonical_dirs {
        for entry in walkdir::WalkDir::new(dir).follow_links(true).into_iter().flatten() {
            let path = entry.path();
            if path.is_file() {
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext == "yar" || ext == "yara" {
                    if let Ok(file_meta) = path.metadata() {
                        if file_meta.len() > 1_048_576 {
                            continue;
                        }
                        let canon_file = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
                        if !visited_canonical_files.insert(canon_file) {
                            continue;
                        }

                        let p_str = path.to_string_lossy();
                        if p_str.contains("osoosi_generated") {
                            let mtime = file_meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                            gen_files.push((path.to_path_buf(), mtime));
                        } else {
                            curated_files.push(path.to_path_buf());
                        }
                    }
                }
            }
        }
    }

    // Anti-staleness retention: sort generated threat rules newest first and load active window
    let max_gen_rules = std::env::var("OSOOSI_MAX_GENERATED_RULES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(500);

    gen_files.sort_by(|a, b| b.1.cmp(&a.1));
    gen_files.truncate(max_gen_rules);

    let mut target_paths: Vec<PathBuf> = curated_files;
    target_paths.extend(gen_files.into_iter().map(|(p, _)| p));

    let mut collected_files: Vec<(PathBuf, String, String)> = Vec::new();
    for path in target_paths {
        if let Ok(content) = std::fs::read_to_string(&path) {
            let path_str = path.to_string_lossy().to_string();
            if is_unsafe_generic_generated_rule(&path_str, &content) {
                debug!("[YARA] Skipping generic process rule without hash from disk: {}", path_str);
                continue;
            }
            let sanitized = sanitize_yara_content(&content);
            collected_files.push((path, path_str, sanitized));
        }
    }

    (dirs_searched, canonical_dirs, collected_files)
}

/// Compile all discovered disk sources, builtins, and active dynamic in-memory rules into a single yara_x::Rules engine.
pub fn compile_sources_to_rules(
    canonical_dirs: &[PathBuf],
    dirs_searched: Vec<String>,
    collected_files: &[(PathBuf, String, String)],
    dynamic_rules: &std::collections::HashMap<String, String>,
) -> (yara_x::Rules, YaraEngineStatus, Vec<YaraRuleMetadata>) {
    let mut compiler = yara_x::Compiler::new();

    for dir in canonical_dirs {
        compiler.add_include_dir(dir);
        let gen_dir = dir.join("osoosi_generated");
        if gen_dir.exists() {
            compiler.add_include_dir(&gen_dir);
        }
        let feeds_dir = dir.join("feeds");
        if feeds_dir.exists() {
            compiler.add_include_dir(&feeds_dir);
        }
    }

    let mut metadata = Vec::new();

    // High-performance batched compiler addition:
    // Compiling thousands of tiny files individually has heavy per-source overhead in yara-x.
    // Batching rules into 50-rule chunks compiles orders of magnitude faster.
    let batch_size = 50;
    for chunk in collected_files.chunks(batch_size) {
        let mut batched_src = String::with_capacity(chunk.len() * 300);
        let mut chunk_metadata = Vec::new();

        for (path, path_str, sanitized) in chunk {
            if is_unsafe_generic_generated_rule(path_str, sanitized) {
                debug!("[YARA] Skipping generic process rule without hash: {}", path_str);
                continue;
            }
            batched_src.push_str(sanitized);
            batched_src.push('\n');

            let mut found_rules = 0;
            for cap in rule_ident_regex().captures_iter(sanitized) {
                let ident = cap[1].to_string();
                let is_gen = path_str.contains("osoosi_generated")
                    || path_str.contains("generated")
                    || ident.starts_with("OsoosiGen_");
                chunk_metadata.push(YaraRuleMetadata {
                    identifier: ident,
                    file_path: path_str.clone(),
                    is_generated: is_gen,
                });
                found_rules += 1;
            }
            if found_rules == 0 {
                let stem = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("rule");
                chunk_metadata.push(YaraRuleMetadata {
                    identifier: stem.to_string(),
                    file_path: path_str.clone(),
                    is_generated: path_str.contains("osoosi_generated"),
                });
            }
        }

        let source = yara_x::SourceCode::from(batched_src.as_str());
        match compiler.add_source(source) {
            Ok(_) => {
                metadata.extend(chunk_metadata);
            }
            Err(_) => {
                // Fallback: compile items in this batch one-by-one to preserve valid rules
                for (path, path_str, sanitized) in chunk {
                    if is_unsafe_generic_generated_rule(path_str, sanitized) {
                        debug!("[YARA] Skipping generic process rule without hash: {}", path_str);
                        continue;
                    }
                    let single_source = yara_x::SourceCode::from(sanitized.as_str())
                        .with_origin(path_str.as_str());
                    match compiler.add_source(single_source) {
                        Ok(_) => {
                            for cap in rule_ident_regex().captures_iter(sanitized) {
                                let ident = cap[1].to_string();
                                let is_gen = path_str.contains("osoosi_generated")
                                    || path_str.contains("generated")
                                    || ident.starts_with("OsoosiGen_");
                                metadata.push(YaraRuleMetadata {
                                    identifier: ident,
                                    file_path: path_str.clone(),
                                    is_generated: is_gen,
                                });
                            }
                        }
                        Err(e) => {
                            debug!("Skipping YARA file {:?} due to compilation note: {}", path, e);
                        }
                    }
                }
            }
        }
    }

    // Add High-Priority Built-in C2 and Zero-Day Rules
    let c2_rules = r#"
        rule C2_Beacon_Generic {
            strings:
                $mz = { 4D 5A }
                $cobalt_strike = "beacon.dll"
                $sliver_rpc = "sliverpb.SliverRPC"
                $sliver_proto = "sliver.pb.go"
                $sliver_pkg = "github.com/bishopfox/sliver"
            condition:
                $mz and ($cobalt_strike or $sliver_rpc or $sliver_proto or $sliver_pkg)
        }

        rule ZeroDay_Suspicious_Memory_Beacon {
            strings:
                $reflect_load = "ReflectiveLoader" ascii wide
                $mem_exec = "VirtualAllocEx" ascii wide
                $queue_user_apc = "QueueUserAPC" ascii wide
            condition:
                2 of them
        }
    "#;
    let builtin_source = yara_x::SourceCode::from(c2_rules).with_origin("builtin_rules.yar");
    if let Err(e) = compiler.add_source(builtin_source) {
        warn!("Failed to compile built-in C2 YARA rules: {}", e);
    } else {
        metadata.push(YaraRuleMetadata {
            identifier: "C2_Beacon_Generic".to_string(),
            file_path: "builtin".to_string(),
            is_generated: false,
        });
        metadata.push(YaraRuleMetadata {
            identifier: "ZeroDay_Suspicious_Memory_Beacon".to_string(),
            file_path: "builtin".to_string(),
            is_generated: false,
        });
    }

    // Add In-Memory Dynamic Rules (Hot-loaded via mesh, auto-gen threats, feeds, or operator)
    let mut compiled_idents: std::collections::HashSet<String> = metadata
        .iter()
        .map(|m| m.identifier.clone())
        .collect();

    for (ident, rule_src) in dynamic_rules {
        if is_unsafe_generic_generated_rule(ident, rule_src) {
            debug!("[YARA] Skipping generic process rule without hash from dynamic memory: {}", ident);
            continue;
        }
        let sanitized = sanitize_yara_content(rule_src);
        let mut parsed_idents = Vec::new();
        for cap in rule_ident_regex().captures_iter(&sanitized) {
            parsed_idents.push(cap[1].to_string());
        }
        if parsed_idents.is_empty() {
            parsed_idents.push(ident.clone());
        }

        // Avoid duplicate collision if the rule was already read from file during batched loading
        if parsed_idents.iter().any(|id| compiled_idents.contains(id)) {
            debug!("Dynamic rule '{}' already present in compiled set, skipping duplicate", ident);
            continue;
        }

        let source = yara_x::SourceCode::from(sanitized.as_str()).with_origin(ident.as_str());
        match compiler.add_source(source) {
            Ok(_) => {
                for id in parsed_idents {
                    compiled_idents.insert(id.clone());
                    metadata.push(YaraRuleMetadata {
                        identifier: id,
                        file_path: "dynamic_memory".to_string(),
                        is_generated: true,
                    });
                }
            }
            Err(e) => {
                warn!("Failed to compile dynamic in-memory rule '{}': {}", ident, e);
            }
        }
    }

    let total_rules = metadata.len();
    let mut custom_rules = 0;
    let mut generated_rules = 0;
    let mut feed_rules = 0;

    for meta in &metadata {
        if meta.is_generated {
            generated_rules += 1;
        } else if meta.file_path.contains("feeds")
            || meta.file_path.contains("detection-rules")
            || meta.file_path.contains("yara-rules")
            || meta.file_path.contains("packages")
        {
            feed_rules += 1;
        } else {
            custom_rules += 1;
        }
    }

    let status = YaraEngineStatus {
        total_rules,
        custom_rules,
        generated_rules,
        feed_rules,
        last_reloaded_at: chrono::Utc::now(),
        last_feed_update_at: None,
        directories_searched: dirs_searched,
        total_scans: 0,
        total_matches: 0,
        is_updating: false,
    };

    let rules = compiler.build();
    info!("Loaded {} YARA rule(s) into native Yara-X engine.", total_rules);
    (rules, status, metadata)
}

/// Recursively discover and load all YARA rules across configured directories.
pub fn load_rules_recursive() -> (yara_x::Rules, YaraEngineStatus, Vec<YaraRuleMetadata>) {
    let (dirs_searched, canonical_dirs, collected_files) = collect_file_sources();
    let empty_dynamic = std::collections::HashMap::new();
    compile_sources_to_rules(&canonical_dirs, dirs_searched, &collected_files, &empty_dynamic)
}

/// Backward-compatible load_rules wrapper.
pub fn load_rules() -> yara_x::Rules {
    load_rules_recursive().0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c2_beacon_generic_refinement() {
        let rules = load_rules();
        let mut scanner = yara_x::Scanner::new(&rules);

        // Binary with MZ header and general word "sliver" (should NOT trigger C2_Beacon_Generic)
        let innocent_llama = b"MZ some binary data containing the word sliver in english";
        let results = scanner.scan(innocent_llama).unwrap();
        let matches: Vec<&str> = results.matching_rules().map(|r| r.identifier()).collect();
        assert!(!matches.contains(&"C2_Beacon_Generic"));

        // Binary with MZ header and sliverpb.SliverRPC (SHOULD trigger C2_Beacon_Generic)
        let malicious_sliver_rpc = b"MZ binary payload containing sliverpb.SliverRPC bytes";
        let results = scanner.scan(malicious_sliver_rpc).unwrap();
        let matches: Vec<&str> = results.matching_rules().map(|r| r.identifier()).collect();
        assert!(matches.contains(&"C2_Beacon_Generic"));

        // Binary with MZ header and sliver.pb.go (SHOULD trigger C2_Beacon_Generic)
        let malicious_sliver_proto = b"MZ binary payload containing sliver.pb.go bytes";
        let results = scanner.scan(malicious_sliver_proto).unwrap();
        let matches: Vec<&str> = results.matching_rules().map(|r| r.identifier()).collect();
        assert!(matches.contains(&"C2_Beacon_Generic"));

        // Binary with MZ header and github.com/bishopfox/sliver (SHOULD trigger C2_Beacon_Generic)
        let malicious_sliver_pkg = b"MZ binary payload containing github.com/bishopfox/sliver bytes";
        let results = scanner.scan(malicious_sliver_pkg).unwrap();
        let matches: Vec<&str> = results.matching_rules().map(|r| r.identifier()).collect();
        assert!(matches.contains(&"C2_Beacon_Generic"));

        // Binary with MZ header and beacon.dll (SHOULD trigger C2_Beacon_Generic)
        let malicious_cobalt = b"MZ binary payload containing beacon.dll bytes";
        let results = scanner.scan(malicious_cobalt).unwrap();
        let matches: Vec<&str> = results.matching_rules().map(|r| r.identifier()).collect();
        assert!(matches.contains(&"C2_Beacon_Generic"));
    }

    #[test]
    fn test_yara_manager_scan_and_status() {
        let manager = YaraManager::new();
        let status = manager.get_status();
        assert!(status.total_rules >= 2, "Built-in rules must be loaded");
        assert!(!status.directories_searched.is_empty() || status.total_rules > 0);

        let matches = manager.scan_bytes(b"MZ binary payload containing beacon.dll bytes");
        assert!(matches.contains(&"C2_Beacon_Generic".to_string()));

        let clean_matches = manager.scan_bytes(b"Clean harmless file buffer");
        assert!(clean_matches.is_empty());

        let status_after = manager.get_status();
        assert_eq!(status_after.total_scans, 2);
        assert!(status_after.total_matches >= 1);
    }

    #[test]
    fn test_yara_manager_hot_load() {
        let manager = YaraManager::new();
        let unique_suffix = uuid::Uuid::new_v4().to_string().replace('-', "_");
        let rule_name = format!("Test_HotLoad_{}", unique_suffix);
        let sig = format!("SUPER_SECRET_{}", unique_suffix);
        let test_rule = format!(r#"
            rule {} {{
                strings:
                    $sig = "{}"
                condition:
                    $sig
            }}
        "#, rule_name, sig);

        let res = manager.hot_load_rule(&test_rule, &rule_name);
        assert!(res.is_ok(), "Hot-loading valid rule must succeed");

        let probe = format!("Payload containing {} bytes", sig).into_bytes();
        let matches = manager.scan_bytes(&probe);
        assert!(matches.contains(&rule_name));

        let _ = std::fs::remove_file(format!("rules/osoosi_generated/{}.yar", rule_name));
        let _ = std::fs::remove_file(format!("yara/osoosi_generated/{}.yar", rule_name));
    }

    #[test]
    fn test_dynamic_rule_hotswap_realtime() {
        let manager = YaraManager::new();
        let unique_suffix = uuid::Uuid::new_v4().to_string().replace('-', "_");
        let rule_name = format!("Threat_ZeroDay_{}", unique_suffix);
        let sig_string = format!("PAYLOAD_SIG_{}", unique_suffix);
        let probe_target = format!("Some prefix data {} some suffix", sig_string).into_bytes();

        // Step 1: Before rule addition, scanning must NOT match
        let pre_matches = manager.scan_bytes(&probe_target);
        assert!(
            !pre_matches.contains(&rule_name),
            "Must not match non-existent rule initially"
        );

        // Step 2: Dynamically add rule on the fly
        let new_rule = format!(r#"
            rule {} {{
                strings:
                    $payload = "{}"
                condition:
                    $payload
            }}
        "#, rule_name, sig_string);

        let loaded = manager.hot_load_rule(&new_rule, &rule_name).expect("hot load must succeed");
        assert!(loaded);

        // Step 3: Immediately scan the exact same payload without restart: MUST match!
        let post_matches = manager.scan_bytes(&probe_target);
        assert!(
            post_matches.contains(&rule_name),
            "Newly hot-swapped rule must match immediately in real-time"
        );

        // Clean buffer must still not match
        let clean_matches = manager.scan_bytes(b"Completely harmless file data");
        assert!(clean_matches.is_empty());

        let _ = std::fs::remove_file(format!("rules/osoosi_generated/{}.yar", rule_name));
        let _ = std::fs::remove_file(format!("yara/osoosi_generated/{}.yar", rule_name));
    }

    #[test]
    fn test_dynamic_rule_syntax_error_immunity() {
        let manager = YaraManager::new();
        let initial_rules_count = manager.active_rules().iter().count();

        // Attempt to hot-load an invalid/broken rule (missing identifier and broken syntax)
        let broken_rule = r#"
            rule {
                strings:
                    $bad = "syntax_error"
                condition:
            }
        "#;

        let res = manager.hot_load_rule(broken_rule, "broken_rule_test");
        assert!(res.is_err(), "Invalid rule syntax must be rejected cleanly");

        // Engine must remain valid and intact
        let current_rules_count = manager.active_rules().iter().count();
        assert_eq!(initial_rules_count, current_rules_count);

        // Existing rules still work
        let matches = manager.scan_bytes(b"MZ binary payload containing beacon.dll bytes");
        assert!(matches.contains(&"C2_Beacon_Generic".to_string()));
    }

    #[test]
    fn test_dynamic_rule_removal_and_clear() {
        let manager = YaraManager::new();
        let probe_payload = b"TARGET_TO_BE_REMOVED_778899";

        let temp_rule = r#"
            rule Ephemeral_Dynamic_Threat {
                strings:
                    $sig = "TARGET_TO_BE_REMOVED_778899"
                condition:
                    $sig
            }
        "#;

        // Hot load memory rule
        manager.hot_load_memory_rule(temp_rule, "Ephemeral_Dynamic_Threat").expect("hot load ok");
        assert!(manager.scan_bytes(probe_payload).contains(&"Ephemeral_Dynamic_Threat".to_string()));

        // Remove rule dynamically
        let removed = manager.remove_rule("Ephemeral_Dynamic_Threat").expect("remove ok");
        assert!(removed);

        // Immediately after removal, payload should no longer match
        assert!(!manager.scan_bytes(probe_payload).contains(&"Ephemeral_Dynamic_Threat".to_string()));
    }

    #[test]
    fn test_dynamic_rule_concurrent_access() {
        let manager = Arc::new(YaraManager::new());
        let unique_suffix = uuid::Uuid::new_v4().to_string().replace('-', "_");
        let rule_name = format!("Concurrent_Test_{}", unique_suffix);
        let sig_string = format!("CONCURRENT_PROBE_{}", unique_suffix);
        let probe = format!("Some prefix {} suffix", sig_string).into_bytes();

        let rule_src = format!(r#"
            rule {} {{
                strings:
                    $str = "{}"
                condition:
                    $str
            }}
        "#, rule_name, sig_string);

        // Spawn multiple reader threads scanning simultaneously
        let mut handles = Vec::new();
        for _ in 0..8 {
            let m = manager.clone();
            let p = probe.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    let _ = m.scan_bytes(&p);
                    std::thread::yield_now();
                }
            }));
        }

        // Hot-swap in the middle of active reading
        manager.hot_load_rule(&rule_src, &rule_name).expect("concurrent hot load ok");

        for h in handles {
            h.join().expect("thread joined successfully");
        }

        // Final verification that scanner sees the rule
        assert!(manager.scan_bytes(&probe).contains(&rule_name));

        let _ = std::fs::remove_file(format!("rules/osoosi_generated/{}.yar", rule_name));
        let _ = std::fs::remove_file(format!("yara/osoosi_generated/{}.yar", rule_name));
    }

    #[test]
    fn test_unsafe_generic_generated_rule_rejected() {
        let unsafe_rule = r#"
            rule OsoosiGen_TestGeneric {
                strings:
                    $proc = "powershell.exe" ascii wide
                condition:
                    $proc
            }
        "#;
        assert!(is_unsafe_generic_generated_rule("yara/osoosi_generated/OsoosiGen_TestGeneric.yar", unsafe_rule));
        assert!(is_unsafe_generic_generated_rule("OsoosiGen_TestGeneric", unsafe_rule));

        let manager = YaraManager::new();
        let res = manager.hot_load_rule(unsafe_rule, "OsoosiGen_TestGeneric");
        assert!(res.is_err(), "Generic process rule without hash must be rejected by hot_load_rule");

        let safe_rule = r#"
            rule OsoosiGen_SafeRule {
                strings:
                    $proc = "malware.exe" ascii wide
                    $h = { DE AD BE EF }
                condition:
                    $proc and $h
            }
        "#;
        assert!(!is_unsafe_generic_generated_rule("yara/osoosi_generated/OsoosiGen_SafeRule.yar", safe_rule));
    }
}

