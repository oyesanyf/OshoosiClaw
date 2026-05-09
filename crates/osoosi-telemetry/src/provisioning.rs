//! Agent Provisioning and Installation.
//!
//! Manages the automated installation of telemetry dependencies across OS platforms.
//! Windows: Native ETW (Zero-Process)
//! Linux: Native eBPF / auditd
//! macOS: Endpoint Security Framework

use osoosi_types::{extract_zip, SecuredExecutor};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use tracing::{info, warn};

/// Opt-in: download MalConv / SmolLM2 from `oyesanyf/OshoosiClaw-Weights` during provisioning. Default **off** — that bundle often 404s unless you publish it.
fn use_bundled_hf_weights() -> bool {
    std::env::var("OSOOSI_USE_BUNDLED_HF_WEIGHTS").map_or(false, |v| {
        v != "0" && !v.eq_ignore_ascii_case("false") && !v.eq_ignore_ascii_case("no")
    })
}

pub struct AgentProvisioner {
    executor: Arc<dyn SecuredExecutor>,
}

impl AgentProvisioner {
    pub fn new(executor: Arc<dyn SecuredExecutor>) -> Self {
        Self { executor }
    }

    /// Provision the agent's telemetry dependencies based on the host OS.
    pub async fn provision_telemetry(&self) -> anyhow::Result<()> {
        self.provision_firewall().await?;
        self.provision_malconv_weights().await?;
        self.provision_behavioral_model().await?;
        Ok(())
    }


    /// Provision Firewall rules for the Oshoosi Mesh.
    pub async fn provision_firewall(&self) -> anyhow::Result<()> {
        info!("Provisioning firewall rules for mesh networking...");

        #[cfg(target_os = "windows")]
        {
            let tcp_ports = [
                ("OshoosiMesh-Main", "4001"),
                ("OshoosiMesh-Control", "9000"),
                ("OshoosiMesh-Alt", "9876"),
                ("OshoosiDashboard", "3030"),
            ];
            let udp_ports = [
                ("OshoosiMesh-Discovery", "4001"),
                ("OshoosiMesh-mDNS", "5353"),
            ];

            for (name, port) in tcp_ports {
                self.ensure_windows_rule(name, port, "TCP").await?;
            }
            for (name, port) in udp_ports {
                self.ensure_windows_rule(name, port, "UDP").await?;
            }
        }

        #[cfg(target_os = "linux")]
        {
            let tcp_ports = ["4001", "9000", "9876", "3030"];
            let udp_ports = ["4001", "5353"];

            // Try ufw first
            if self.command_exists("ufw").await {
                for port in tcp_ports {
                    let mut cmd = Command::new("sudo");
                    cmd.args(["ufw", "allow", &format!("{}/tcp", port)]);
                    let _ = self.executor.execute(cmd).await;
                }
                for port in udp_ports {
                    let mut cmd = Command::new("sudo");
                    cmd.args(["ufw", "allow", &format!("{}/udp", port)]);
                    let _ = self.executor.execute(cmd).await;
                }
            } else if self.command_exists("firewall-cmd").await {
                for port in tcp_ports {
                    let mut cmd = Command::new("sudo");
                    cmd.args(["firewall-cmd", "--permanent", "--add-port", &format!("{}/tcp", port)]);
                    let _ = self.executor.execute(cmd).await;
                }
                for port in udp_ports {
                    let mut cmd = Command::new("sudo");
                    cmd.args(["firewall-cmd", "--permanent", "--add-port", &format!("{}/udp", port)]);
                    let _ = self.executor.execute(cmd).await;
                }
                let mut cmd = Command::new("sudo");
                cmd.args(["firewall-cmd", "--reload"]);
                let _ = self.executor.execute(cmd).await;
            } else if self.command_exists("iptables").await {
                for port in tcp_ports {
                    let mut cmd = Command::new("sudo");
                    cmd.args(["iptables", "-I", "INPUT", "-p", "tcp", "--dport", port, "-j", "ACCEPT"]);
                    let _ = self.executor.execute(cmd).await;
                }
                for port in udp_ports {
                    let mut cmd = Command::new("sudo");
                    cmd.args(["iptables", "-I", "INPUT", "-p", "udp", "--dport", port, "-j", "ACCEPT"]);
                    let _ = self.executor.execute(cmd).await;
                }
            }
        }

        info!("Firewall provisioning note: Oshoosi requires incoming TCP ports 4001, 9000, 9876, and 3030.");

        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn ensure_windows_rule(&self, name: &str, port: &str, protocol: &str) -> anyhow::Result<()> {
        let mut check = Command::new("netsh");
        check.args([
            "advfirewall",
            "firewall",
            "show",
            "rule",
            &format!("name={}", name),
        ]);

        if !self.executor.execute(check).await?.status.success() {
            info!("Adding firewall rule: {} (Port {}/{})...", name, port, protocol);
            let mut add = Command::new("netsh");
            add.args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={}", name),
                "dir=in",
                "action=allow",
                &format!("protocol={}", protocol),
                &format!("localport={}", port),
                "enable=yes",
                "profile=any",
            ]);
            self.executor.execute(add).await?;
        }
        Ok(())
    }


    /// Helper to execute a command with a specified number of retries.
    async fn exec_with_retry(
        &self,
        program: &str,
        args: &[&str],
        name: &str,
        retries: usize,
    ) -> anyhow::Result<()> {
        let mut last_error = None;
        for i in 1..=retries {
            if i > 1 {
                info!("Attempt {}/{} to {}...", i, retries, name);
                tokio::time::sleep(std::time::Duration::from_secs(3 * (i - 1) as u64)).await;
            }
            let mut cmd = Command::new(program);
            cmd.args(args);
            match self.executor.execute(cmd).await {
                Ok(output) if output.status.success() => return Ok(()),
                Ok(output) => {
                    last_error = Some(anyhow::anyhow!(
                        "Command '{}' failed with status: {}",
                        name,
                        output.status
                    ))
                }
                Err(e) => {
                    last_error = Some(anyhow::anyhow!("Execution error for '{}': {}", name, e))
                }
            }
        }
        Err(last_error
            .unwrap_or_else(|| anyhow::anyhow!("Failed {} after {} retries", name, retries)))
    }

    #[cfg(target_os = "windows")]
    async fn command_exists_win(&self, cmd: &str) -> bool {
        let mut check_cmd = Command::new("where");
        check_cmd.arg(cmd);
        self.executor
            .execute(check_cmd)
            .await
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Check if a command exists in the system PATH.
    async fn command_exists(&self, cmd: &str) -> bool {
        #[cfg(target_os = "windows")]
        {
            self.command_exists_win(cmd).await
        }
        #[cfg(not(target_os = "windows"))]
        {
            let mut check_cmd = Command::new("which");
            check_cmd.arg(cmd);
            self.executor
                .execute(check_cmd)
                .await
                .map(|o| o.status.success())
                .unwrap_or(false)
        }
    }




    #[cfg(target_os = "windows")]
    async fn _provision_windows(&self) -> anyhow::Result<()> {
        info!("Provisioning Windows telemetry (Native Zero-Process ETW)...");
        // Native engine is self-contained, no external binary needed
        Ok(())
    }



    /// Linux: Install Auditd
    /// Linux: Native eBPF / auditd
    #[cfg(target_os = "linux")]
    async fn provision_linux(&self) -> anyhow::Result<()> {
        info!("Provisioning Linux telemetry (Native eBPF)...");
        Ok(())
    }



    /// macOS: Check for Endpoint Security
    #[cfg(target_os = "macos")]
    async fn provision_macos(&self) -> anyhow::Result<()> {
        info!("Provisioning macOS telemetry (Endpoint Security Framework)...");
        info!("macOS uses native ESF. Ensure the binary is granted Full Disk Access.");
        // No explicit install needed for ESF, it's a kernel feature
        Ok(())
    }






    #[cfg(target_os = "windows")]
    pub async fn apply_blocking_rules(&self, rules: &[osoosi_types::BlockingRule]) -> anyhow::Result<()> {
        info!("Provisioner: Applying {} persistent blocking rules to Windows Registry...", rules.len());
        
        for rule in rules {
            if rule.kind == osoosi_types::BlockingKind::Executable {
                let path = std::path::Path::new(&rule.path);
                if let Some(exe_name) = path.file_name().and_then(|n| n.to_str()) {
                    info!("Enforcing Hard-Block for {}: IFEO Debugger -> blocked.exe", exe_name);
                    
                    let mut cmd = Command::new("reg");
                    cmd.args([
                        "add",
                        &format!(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{}", exe_name),
                        "/v", "Debugger",
                        "/t", "REG_SZ",
                        "/d", "systray.exe", // Using systray.exe as a safe "noop" debugger
                        "/f"
                    ]);
                    
                    if let Err(e) = self.executor.execute(cmd).await {
                        warn!("Failed to apply IFEO block for {}: {}", exe_name, e);
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn provision_yara_rules(&self) -> anyhow::Result<()> {
        self.provision_yara_rules_with_sandbox(false).await
    }

    /// Provision YARA rules. If `sandboxed` is true, the caller has already
    /// verified that OpenShell handled the download — skip re-downloading.
    pub async fn provision_yara_rules_with_sandbox(&self, sandboxed: bool) -> anyhow::Result<()> {
        let yara_base_dir = std::path::Path::new("yara");
        if !yara_base_dir.exists() {
            std::fs::create_dir_all(&yara_base_dir)?;
        }

        if sandboxed {
            info!("YARA rules were provisioned via OpenShell sandbox. Skipping direct download.");
            let _ = self.sanitize_yara_rules(yara_base_dir);
            return Ok(());
        }

        let sources = [
            ("yara_forge", "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-extended.zip"),
            ("signature_base", "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip"),
            ("community", "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip"),
            ("reversinglabs", "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/refs/heads/master.zip"),
            ("elastic", "https://github.com/elastic/protections-artifacts/archive/refs/heads/main.zip"),
            ("mandiant", "https://github.com/mandiant/red_team_tool_countermeasures/archive/refs/heads/master.zip"),
            ("inquest", "https://github.com/InQuest/yara-rules/archive/refs/heads/master.zip"),
            ("bartblaze", "https://github.com/bartblaze/Yara-rules/archive/refs/heads/master.zip"),
            ("tenable", "https://github.com/tenable/yara-rules/archive/refs/heads/master.zip"),
            ("mikesxrs", "https://github.com/mikesxrs/Open-Source-YARA-rules/archive/refs/heads/master.zip"),
            ("100daysofyara", "https://github.com/100DaysofYARA/2026/archive/refs/heads/main.zip"),
            ("chronicle", "https://github.com/chronicle/GCTI/archive/refs/heads/main.zip"),
        ];

        for (name, url) in sources {
            let target_sub_dir = yara_base_dir.join(name);
            if !target_sub_dir.exists() {
                std::fs::create_dir_all(&target_sub_dir)?;
            }

            // Only download if the subfolder is empty
            if let Ok(entries) = std::fs::read_dir(&target_sub_dir) {
                if entries.filter_map(|e| e.ok()).count() > 1 {
                    info!(
                        "YARA rules for '{}' already present at {}.",
                        name,
                        target_sub_dir.display()
                    );
                    continue;
                }
            }

            info!(
                "YARA rules for '{}' missing. Downloading from {}...",
                name, url
            );
            let zip_path = target_sub_dir.join(format!("{}_temp.zip", name));

            // Use resumable downloader
            self.download_with_resume(url, &zip_path).await?;

            info!("Extracting YARA '{}' rules...", name);
            let tmp_extract = target_sub_dir.join(format!("{}_tmp_extract", name));

            #[cfg(target_os = "windows")]
            {
                let _ = std::fs::remove_dir_all(&tmp_extract);
                extract_zip(&zip_path, &tmp_extract)?;
                
                // RESILIENCE: If extracted into a single subfolder, move content up
                if let Ok(entries) = std::fs::read_dir(&tmp_extract) {
                    let subdirs: Vec<_> = entries.filter_map(|e| e.ok()).collect();
                    if subdirs.len() == 1 && subdirs[0].path().is_dir() {
                        let sub_path = subdirs[0].path();
                        if let Ok(sub_entries) = std::fs::read_dir(&sub_path) {
                            for entry in sub_entries.filter_map(|e| e.ok()) {
                                let dest = target_sub_dir.join(entry.file_name());
                                let _ = std::fs::rename(entry.path(), dest);
                            }
                        }
                    } else {
                        // Move everything from tmp_extract to target_sub_dir
                        if let Ok(entries) = std::fs::read_dir(&tmp_extract) {
                            for entry in entries.filter_map(|e| e.ok()) {
                                let dest = target_sub_dir.join(entry.file_name());
                                let _ = std::fs::rename(entry.path(), dest);
                            }
                        }
                    }
                }
                let _ = std::fs::remove_dir_all(&tmp_extract);
            }
            #[cfg(not(target_os = "windows"))]
            {
                let sh_cmd = format!(
                    "unzip -o {} -d {} && cp -r {}/*/* {}/ && rm -rf {}",
                    zip_path.to_string_lossy(),
                    tmp_extract.to_string_lossy(),
                    tmp_extract.to_string_lossy(),
                    target_sub_dir.to_string_lossy(),
                    tmp_extract.to_string_lossy()
                );
                let mut cmd = Command::new("sh");
                cmd.args(["-c", &sh_cmd]);
                let _ = self.executor.execute(cmd).await;
            }
            let _ = std::fs::remove_file(&zip_path);

            // Sanitize rules after extraction to remove incompatibilities
            let _ = self.sanitize_yara_rules(&target_sub_dir);
        }

        info!("Finalizing YARA rules (sanitizing for compatibility)...");
        let _ = self.sanitize_yara_rules(yara_base_dir);

        Ok(())
    }

    /// Download a file with support for resuming partial downloads (HTTP Range).
    pub async fn download_with_resume(
        &self,
        url: &str,
        dest: &std::path::Path,
    ) -> anyhow::Result<()> {
        self.executor.download(url, dest, true).await
    }

    /// Add a Windows Defender exclusion for a specific path.
    pub async fn add_defender_exclusion(&self, path: &std::path::Path) -> anyhow::Result<()> {
        #[cfg(target_os = "windows")]
        {
            // Resolve to absolute path for exclusion
            let full_path = std::env::current_dir()?.join(path);
            let path_str = full_path.to_string_lossy();

            info!("Adding Windows Defender exclusion for: {}...", path_str);
            osoosi_types::add_defender_exclusion(path_str.as_ref())?;
            info!("Windows Defender exclusion added successfully.");
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = path;
            Ok(())
        }
    }

    /// Sanitize YARA rules to prevent compilation errors (androguard imports, type mismatches, missing includes).
    pub fn sanitize_yara_rules(&self, dir: &std::path::Path) -> anyhow::Result<()> {
        let mut seen_rules = std::collections::HashSet::new();
        self.sanitize_yara_rules_internal(dir, &mut seen_rules)
    }

    fn sanitize_yara_rules_internal(
        &self,
        dir: &std::path::Path,
        seen_rules: &mut std::collections::HashSet<String>,
    ) -> anyhow::Result<()> {
        use std::path::Path;
        if !dir.exists() {
            return Ok(());
        }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                let _ = self.sanitize_yara_rules_internal(&path, seen_rules);
            } else if path
                .extension()
                .map_or(false, |e| e == "yar" || e == "yara")
            {
                // Use lossy reading to handle potential encoding issues in malware rules
                if let Ok(bytes) = std::fs::read(&path) {
                    let raw_content = String::from_utf8_lossy(&bytes);
                    // Pre-pass: fix unclosed block comments where */ was written as *\/
                    let content = raw_content.replace("*\\/", "*/");
                    let content_lower = content.to_lowercase();

                    let has_andro = content_lower.contains("import \"androguard\"")
                        || content_lower.contains("import 'androguard'");
                    let has_crash = content.contains("pe.exports(\"Crash\")")
                        && content.contains("& pe.characteristics");
                    let has_include =
                        content.contains("include \"") || content.contains("include '");
                    let has_empty_regex = (content.contains("|/") || content.contains("| /"))
                        && content.contains('=');
                    let has_backslash = content.contains('\\');
                    let has_unclosed_repetition = content.contains("?{")
                        || content.contains("? {")
                        || content.contains("?  {");
                    let has_unk_identifier = (content.contains("filename")
                        || content.contains("filetype"))
                        && (content.contains("==") || content.contains("!="));
                    let has_duplicate_maze = path.to_string_lossy().contains("RANSOM_Maze.yar")
                        && content.matches("rule Maze").count() > 1;
                    let has_broken_comment = raw_content.contains("*\\/");

                    if has_andro
                        || has_crash
                        || has_include
                        || has_empty_regex
                        || has_backslash
                        || has_unclosed_repetition
                        || has_duplicate_maze
                        || has_unk_identifier
                        || has_broken_comment
                    {
                        let mut lines = Vec::new();
                        let mut changed = false;
                        if has_broken_comment {
                            changed = true;
                        }
                        let mut maze_count = 0;
                        let parent = path.parent().unwrap_or(Path::new("."));

                        for line in content.lines() {
                            let mut new_line = line.to_string();
                            let trimmed = line.trim();

                            if trimmed.starts_with("//") {
                                lines.push(new_line);
                                continue;
                            }

                            let lower = trimmed.to_lowercase();

                            // 1. Disable androguard imports
                            if (trimmed.starts_with("import") || trimmed.starts_with("//import"))
                                && trimmed.contains("androguard")
                            {
                                new_line = format!("// {}", line);
                                changed = true;
                            }
                            // 2. Fix APT_CrashOverride.yar type mismatch (boolean & int)
                            else if (line.contains("pe.exports(\"Crash\")")
                                || line.contains("pe.exports(\"crash\")"))
                                && line.contains("& pe.characteristics")
                            {
                                new_line = line
                                    .replace(
                                        "pe.exports(\"Crash\")",
                                        "pe.exports(\"Crash\") != false",
                                    )
                                    .replace(
                                        "pe.exports(\"crash\")",
                                        "pe.exports(\"crash\") != false",
                                    )
                                    .replace("& pe.characteristics", "and pe.characteristics != 0");
                                changed = true;
                            }
                            // 3. Fix missing includes
                            else if trimmed.starts_with("include") && !trimmed.starts_with("//") {
                                let q = if trimmed.contains('\"') { '\"' } else { '\'' };
                                let parts: Vec<&str> = trimmed.split(q).collect();
                                if parts.len() >= 2 {
                                    let inc_path_str = parts[1];
                                    let inc_path = parent.join(inc_path_str);
                                    if !inc_path.exists() {
                                        let alt_path = parent
                                            .parent()
                                            .unwrap_or(Path::new("."))
                                            .join(inc_path_str);
                                        if !alt_path.exists() {
                                            new_line = format!("// {}", line);
                                            changed = true;
                                        }
                                    }
                                }
                            }
                            // 4. Fix empty regex matches
                            else if (trimmed.contains("|/") || trimmed.contains("| /"))
                                && trimmed.contains('=')
                                && trimmed.contains('/')
                            {
                                if let Some(idx) = new_line.find("|/") {
                                    new_line.replace_range(idx..idx + 1, "");
                                    changed = true;
                                } else if let Some(idx) = new_line.find("| /") {
                                    new_line.replace_range(idx..idx + 1, "");
                                    changed = true;
                                }
                            }
                            // 5. Fix unclosed counted repetition
                            else if trimmed.contains('/')
                                && trimmed.contains('=')
                                && (trimmed.contains("?{") || trimmed.contains("? {"))
                            {
                                if new_line.contains("?{") {
                                    new_line = new_line.replace("?{", "?\\{");
                                    changed = true;
                                } else if new_line.contains("? {") {
                                    new_line = new_line.replace("? {", "? \\{");
                                    changed = true;
                                }
                            }
                            // 6. Comment out unknown identifiers (filename, filetype, filepath, extension)
                            else if (lower.contains("filename")
                                || lower.contains("filetype")
                                || lower.contains("filepath")
                                || lower.contains("extension"))
                                && (lower.contains("==")
                                    || lower.contains("!=")
                                    || lower.contains("matches")
                                    || lower.contains("contains"))
                            {
                                new_line = format!("// {}", line);
                                changed = true;
                            }
                            // 7. Handle duplicate Maze rule
                            else if trimmed.starts_with("rule Maze") {
                                maze_count += 1;
                                if maze_count > 1 {
                                    new_line = line.replace("rule Maze", "rule Maze_Duplicate");
                                    changed = true;
                                }
                            }

                            // 8. Fix broken hex string delimiters and invalid escape sequences
                            if trimmed.contains('\\') && !new_line.trim().starts_with("//") {
                                // Fix hex string delimiters: \{ ... \} → { ... }
                                if new_line.contains("= \\{") || new_line.contains("=\\{") {
                                    new_line =
                                        new_line.replace("= \\{", "= {").replace("=\\{", "={");
                                    changed = true;
                                }
                                if new_line.contains("\\}")
                                    && (new_line.contains("= {") || new_line.contains("={"))
                                {
                                    new_line = new_line.replace("\\}", "}");
                                    changed = true;
                                }
                                let chars: Vec<char> = new_line.chars().collect();
                                let mut i = 0;
                                let mut fixed = String::new();
                                let mut esc_changed = false;
                                while i < chars.len() {
                                    if chars[i] == '\\' && i + 1 < chars.len() {
                                        let next = chars[i + 1];
                                        let valid = matches!(
                                            next,
                                            'n' | 'r'
                                                | 't'
                                                | '\\'
                                                | '\"'
                                                | '\''
                                                | 'x'
                                                | 'u'
                                                | 'U'
                                                | 'd'
                                                | 'w'
                                                | 's'
                                                | 'D'
                                                | 'W'
                                                | 'S'
                                                | 'b'
                                                | 'B'
                                                | '0'
                                                ..='9'
                                                    | '$'
                                                    | '^'
                                                    | '*'
                                                    | '+'
                                                    | '?'
                                                    | '('
                                                    | ')'
                                                    | '['
                                                    | ']'
                                                    | '{'
                                                    | '}'
                                                    | '|'
                                                    | '.'
                                                    | '/'
                                                    | ' '
                                        );
                                        if !valid {
                                            fixed.push('\\');
                                            fixed.push('\\');
                                            fixed.push(next);
                                            i += 2;
                                            esc_changed = true;
                                            continue;
                                        }
                                        fixed.push(chars[i]);
                                        fixed.push(next);
                                        i += 2;
                                        continue;
                                    }
                                    fixed.push(chars[i]);
                                    i += 1;
                                }
                                if esc_changed {
                                    new_line = fixed;
                                    changed = true;
                                }
                            }

                            // 9. Global Deduplication
                            if trimmed.contains("rule ") && !new_line.trim().starts_with("//") {
                                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                                for (idx, part) in parts.iter().enumerate() {
                                    if *part == "rule" && idx + 1 < parts.len() {
                                        let rule_name = parts[idx + 1]
                                            .trim_end_matches('{')
                                            .split(':')
                                            .next()
                                            .unwrap_or("")
                                            .trim();
                                        if seen_rules.contains(rule_name) {
                                            let new_rule_name = format!("{}_Duplicate", rule_name);
                                            new_line =
                                                new_line.replacen(rule_name, &new_rule_name, 1);
                                            changed = true;
                                        } else {
                                            seen_rules.insert(rule_name.to_string());
                                        }
                                        break;
                                    }
                                }
                            }

                            lines.push(new_line);
                        }

                        if changed {
                            info!("Sanitized YARA rule (Hardened): {}", path.display());
                            let _ = std::fs::write(&path, lines.join("\n"));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Provision MalConv weights for direct byte-level classification.
    /// Default: **no** download — the historical Hugging Face bundle URL often 404s. Set
    /// `OSOOSI_USE_BUNDLED_HF_WEIGHTS=1` to attempt `oyesanyf/OshoosiClaw-Weights`, or place `malconv.safetensors` under `models/malware/`.
    pub async fn provision_malconv_weights(&self) -> anyhow::Result<()> {
        let models_dir = osoosi_types::resolve_models_dir();
        let malconv_dir = Path::new(&models_dir).join("malware");
        let weight_path = malconv_dir.join("malconv.safetensors");

        if weight_path.exists() {
            if let Ok(m) = std::fs::metadata(&weight_path) {
                if m.len() > 1024 {
                    info!("MalConv weights already available.");
                    return Ok(());
                } else {
                    warn!("Existing MalConv weights file is too small ({} bytes). Re-downloading...", m.len());
                }
            }
        }
        if !use_bundled_hf_weights() {
            info!("MalConv weights not present; skipping Hugging Face download (set OSOOSI_USE_BUNDLED_HF_WEIGHTS=1 to try the Oshoosi bundle, or add malconv.safetensors under models/malware).");
            return Ok(());
        }

        info!("MalConv weights missing. Downloading from Oshoosi Hugging Face bundle (OSOOSI_USE_BUNDLED_HF_WEIGHTS)...");
        std::fs::create_dir_all(&malconv_dir)?;

        // Try to use HF_TOKEN if available, otherwise just use the public URL
        let mut urls = vec![
            "https://huggingface.co/oyesanyf/OshoosiClaw-Weights/resolve/main/malconv.safetensors?download=true".to_string(),
            "https://huggingface.co/oyesanyf/OshoosiClaw/resolve/main/models/malware/malconv.safetensors?download=true".to_string(),
        ];
        
        if let Ok(u) = std::env::var("OSOOSI_MALCONV_WEIGHTS_URL") {
            if !u.trim().is_empty() {
                urls.insert(0, u.trim().to_string());
            }
        }

        let mut success = false;
        for url in urls {
            match self.download_with_resume(&url, &weight_path).await {
                Ok(_) => {
                    success = true;
                    info!("Successfully provisioned MalConv weights from {}", url);
                    break;
                }
                Err(e) => {
                    warn!("Failed to download MalConv weights from {}: {}", url, e);
                }
            }
        }

        if !success {
            return Err(anyhow::anyhow!("All MalConv weight mirrors failed. ML detection will be degraded."));
        }

        if let Ok(m) = std::fs::metadata(&weight_path) {
            if m.len() < 1024 {
                warn!("Downloaded MalConv weights are suspiciously small ({} bytes). Check HF_TOKEN or repository existence.", m.len());
                let _ = std::fs::remove_file(&weight_path);
            } else {
                info!("MalConv weights provisioned successfully ({} bytes).", m.len());
            }
        }
        
        Ok(())
    }

    /// SmolLM2 ONNX + tokenizer. Same opt-in as [`provision_malconv_weights`]: no HF hit unless
    /// `OSOOSI_USE_BUNDLED_HF_WEIGHTS=1` (or files already on disk / use `ensure_ai_models` public Hub paths).
    pub async fn provision_behavioral_model(&self) -> anyhow::Result<()> {
        let models_dir = osoosi_types::resolve_models_dir();
        let smollm_dir = Path::new(&models_dir).join("smollm");
        let model_path = smollm_dir.join("smollm2-135m-it.onnx");
        let tokenizer_path = smollm_dir.join("tokenizer.json");

        if model_path.exists() && tokenizer_path.exists() {
            info!("Behavioral model weights (SmolLM2) already available.");
            return Ok(());
        }
        if !use_bundled_hf_weights() {
            info!("SmolLM2 bundle not present; skipping oyesanyf Hugging Face download (set OSOOSI_USE_BUNDLED_HF_WEIGHTS=1, or run bootstrap / place files in models/smollm).");
            return Ok(());
        }

        info!("Behavioral model weights missing. Provisioning from Oshoosi Hugging Face bundle (OSOOSI_USE_BUNDLED_HF_WEIGHTS)...");
        std::fs::create_dir_all(&smollm_dir)?;

        let model_url = "https://huggingface.co/oyesanyf/OshoosiClaw-Weights/resolve/main/smollm2-135m-it.onnx?download=true";
        let tokenizer_url = "https://huggingface.co/oyesanyf/OshoosiClaw-Weights/resolve/main/tokenizer.json?download=true";

        if !model_path.exists() {
            self.download_with_resume(model_url, &model_path).await?;
        }
        if !tokenizer_path.exists() {
            self.download_with_resume(tokenizer_url, &tokenizer_path)
                .await?;
        }

        info!("Behavioral model weights provisioned successfully.");
        Ok(())
    }

}

