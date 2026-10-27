use osoosi_telemetry::AgentProvisioner;
use osoosi_types::BlockingRule;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Returns `true` if the binary is a core OS component, administrative tool/LOLBin,
/// developer SDK tool, or trusted signed binary that should never be permanently blocked.
pub fn is_protected_or_benign_system_path(path: &str) -> bool {
    let trimmed = path.trim().trim_matches('"');
    if trimmed.is_empty() {
        return false;
    }

    // Never protect binaries in user-writable, temp, or untrusted locations
    if crate::rea::is_untrusted_writable_or_temp_path(trimmed) {
        return false;
    }

    let normalized = osoosi_types::normalize_nt_device_path(trimmed);

    // Core OS kernel and session managers (PIDs 0, 4, smss, csrss, lsass) must not be permanently blocked via IFEO
    if osoosi_types::is_protected_os_shell_or_desktop_binary(&normalized)
        || osoosi_runtime::tarpit::is_protected_system_or_security_process(999_999, &normalized)
    {
        return true;
    }

    if normalized.to_ascii_lowercase().ends_with(".exe")
        && !AgentProvisioner::is_safe_for_ifeo_block(&normalized)
    {
        return true;
    }

    // Non-executable extensions should not be IFEO blocked
    let p_fwd = normalized.replace('\\', "/").to_lowercase();
    let non_executable_exts = [
        ".dll", ".winmd", ".so", ".dylib", ".pyd", ".xs.dll", ".cpl", ".msc", ".sys", ".drv",
    ];
    if non_executable_exts.iter().any(|ext| p_fwd.ends_with(ext)) {
        return true;
    }

    // Core Unix and macOS system directories
    if p_fwd.starts_with("/bin/")
        || p_fwd.starts_with("/sbin/")
        || p_fwd.starts_with("/usr/bin/")
        || p_fwd.starts_with("/usr/sbin/")
        || p_fwd.starts_with("/usr/libexec/")
        || p_fwd.starts_with("/system/library/")
    {
        return true;
    }

    // Verified cryptographic signature or Windows Security Catalog check
    let p = std::path::Path::new(&normalized);
    if p.is_file() && crate::win_trust::is_trusted_signed_binary(p) {
        return true;
    }

    false
}

pub fn is_non_killable_persistent_os_or_user_daemon(proc_name_or_path: &str) -> bool {
    let raw = proc_name_or_path.trim().trim_matches('"');
    if raw.is_empty() {
        return false;
    }
    let lower = raw.to_ascii_lowercase();
    let filename = lower.rsplit(['\\', '/']).next().unwrap_or(lower.as_str());
    let stem = filename.strip_suffix(".exe").unwrap_or(filename);

    if stem.starts_with("python") {
        return true;
    }

    const NON_KILLABLE: &[&str] = &[
        "system",
        "registry",
        "memcompression",
        "smss",
        "csrss",
        "wininit",
        "services",
        "lsass",
        "lsm",
        "winlogon",
        "userinit",
        "logonui",
        "svchost",
        "fontdrvhost",
        "dwm",
        "sihost",
        "taskhostw",
        "dllhost",
        "conhost",
        "openconsole",
        "windowsterminal",
        "wt",
        "explorer",
        "shellhost",
        "shellexperiencehost",
        "startmenuexperiencehost",
        "applicationframehost",
        "systemsettings",
        "textinputhost",
        "ctfmon",
        "searchhost",
        "searchapp",
        "searchui",
        "searchindexer",
        "searchprotocolhost",
        "searchfilterhost",
        "runtimebroker",
        "backgroundtaskhost",
        "spoolsv",
        "audiodg",
        "wmiprvse",
        "wmiapsrv",
        "vssvc",
        "tiworker",
        "trustedinstaller",
        "taskmgr",
        "consent",
        "werfault",
        "osoosi",
        "oshoosi",
        "osoosi_service",
        "osoosi-cli",
        "osoosi-auditor",
        "sysmon",
        "sysmon64",
        "velociraptor",
        "osqueryi",
        "osqueryd",
        "msmpeng",
        "mpdefendercoreservice",
        "securityhealthservice",
        "securityhealthsystray",
        "securityhealthhost",
        "nissrv",
        "senseir",
        "sensendr",
        "mpcmdrun",
        "smartscreen",
        "chrome",
        "chrome_proxy",
        "msedge",
        "msedgewebview2",
        "firefox",
        "brave",
        "code",
        "code-insiders",
        "antigravity",
        "devenv",
        "cargo",
        "rustc",
        "rustup",
        "git",
        "docker",
        "dockerd",
        "wsl",
        "wslhost",
        "wslservice",
        "sshd",
        "systemd",
        "init",
        "dbus-daemon",
        "ollama",
        "ollama_llama_server",
        "node",
        "py",
    ];

    NON_KILLABLE.contains(&stem)
}

pub fn can_terminate_transient_lolbin_or_payload_pid(
    pid: u32,
    image: &str,
    cmd_line: &str,
) -> bool {
    if pid <= 4 || pid == std::process::id() {
        return false;
    }
    if is_non_killable_persistent_os_or_user_daemon(image) {
        return false;
    }

    let lower_cmd = cmd_line.to_ascii_lowercase();
    const PROTECTED_DEV_SCRIPTS: &[&str] = &[
        "build_and_submit.ps1",
        "solo_pr_ship.ps1",
        "restart-service",
        "get-process",
        "get-nettcpconnection",
        "get-ciminstance",
        "signtool",
        "cargo ",
        "git ",
    ];
    if PROTECTED_DEV_SCRIPTS.iter().any(|s| lower_cmd.contains(s)) {
        return false;
    }

    let raw = image.trim().trim_matches('"');
    let lower_image = raw.to_ascii_lowercase();
    let filename = lower_image
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(lower_image.as_str());
    let stem = filename.strip_suffix(".exe").unwrap_or(filename);

    if matches!(stem, "powershell" | "pwsh" | "cmd" | "bash" | "sh") {
        const SHELL_ATTACK_INDICATORS: &[&str] = &[
            "invoke-atomictest",
            "-enc",
            "-encodedcommand",
            "frombase64string",
            "downloadstring",
            "downloadfile",
            "invoke-expression",
            "iex(",
            "iex ",
            "mimikatz",
            "sekurlsa",
            "lsadump",
            "comsvcs",
            "minidump",
            "vssadmin",
            "shadowcopy",
            "bcdedit",
            "wbadmin",
            "ntdsutil",
            "reg save",
            "reg.exe save",
            "sc sdset",
            "sc.exe sdset",
            "calc.exe",
            "win32calc",
            "certutil",
            "bitsadmin",
            "mshta",
            "regsvr32",
            "rundll32",
            "procdump",
            "net user",
            "net1 user",
            "localgroup administrators",
            "-w hidden",
            "-windowstyle hidden",
            "wmic ",
        ];
        let has_attack = SHELL_ATTACK_INDICATORS
            .iter()
            .any(|ind| lower_cmd.contains(ind));
        let is_cleanup = lower_cmd.contains("-cleanup -force") && !lower_cmd.contains("try {");
        return has_attack && !is_cleanup;
    }

    if crate::system_check::is_administrative_lolbin(image) {
        return true;
    }

    !is_protected_or_benign_system_path(image)
}

pub struct BlockingManager {
    rules: RwLock<Vec<BlockingRule>>,
    #[cfg(target_os = "windows")]
    provisioner: Arc<AgentProvisioner>,
    #[cfg(not(target_os = "windows"))]
    _provisioner: Arc<AgentProvisioner>,
}

impl BlockingManager {
    pub fn new(provisioner: Arc<AgentProvisioner>) -> Self {
        let rules = Self::load_rules_sync().unwrap_or_default();
        Self {
            rules: RwLock::new(rules),
            #[cfg(target_os = "windows")]
            provisioner,
            #[cfg(not(target_os = "windows"))]
            _provisioner: provisioner,
        }
    }

    fn load_rules_sync() -> anyhow::Result<Vec<BlockingRule>> {
        let purged_ifeo = osoosi_types::purge_ifeo_systray_debugger_hooks_native();
        if purged_ifeo > 0 {
            info!(
                "BlockingManager: Purged {} legacy IFEO Debugger=systray.exe registry hooks during startup.",
                purged_ifeo
            );
        }
        let path = osoosi_types::resolve_base_dir().join("blocking_rules.json");
        if path.exists() {
            let data = std::fs::read_to_string(&path)?;
            let rules: Vec<BlockingRule> = serde_json::from_str(&data)?;
            let original_count = rules.len();
            let sanitized_rules: Vec<BlockingRule> = rules
                .into_iter()
                .filter(|r| !is_protected_or_benign_system_path(&r.path))
                .collect();
            let purged_count = original_count.saturating_sub(sanitized_rules.len());
            if purged_count > 0 {
                info!(
                    "BlockingManager: Purged {} false-positive/protected rules during startup sanitization.",
                    purged_count
                );
                let _ = Self::save_rules_internal(&sanitized_rules);
            }
            info!(
                "BlockingManager: Loaded {} persistent rules from {:?}.",
                sanitized_rules.len(),
                path
            );
            Ok(sanitized_rules)
        } else {
            Ok(Vec::new())
        }
    }

    fn save_rules_internal(rules: &[BlockingRule]) -> anyhow::Result<()> {
        let data = serde_json::to_string_pretty(rules)?;
        let path = osoosi_types::resolve_base_dir().join("blocking_rules.json");
        std::fs::write(path, data)?;
        Ok(())
    }

    pub async fn save_rules(&self) -> anyhow::Result<()> {
        let rules = self.rules.read().await;
        Self::save_rules_internal(&rules)
    }

    pub async fn update_sysmon(&self, _rules: &[BlockingRule]) -> anyhow::Result<()> {
        #[cfg(target_os = "windows")]
        self.provisioner.apply_blocking_rules(_rules).await?;
        Ok(())
    }

    pub async fn add_rule(&self, rule: BlockingRule) -> anyhow::Result<()> {
        if is_protected_or_benign_system_path(&rule.path) {
            warn!(
                "BlockingManager: Refusing to add protected OS/LOLBin/trusted vendor binary to persistent FileBlockExecutable: {}",
                rule.path
            );
            return Ok(());
        }

        info!("BlockingManager: Adding rule for path: {}", rule.path);
        let mut rules = self.rules.write().await;
        if !rules
            .iter()
            .any(|r| r.path == rule.path && r.kind == rule.kind)
        {
            rules.push(rule);
            let _ = Self::save_rules_internal(&rules);
            let rules_snapshot = rules.clone();
            drop(rules);
            self.update_sysmon(&rules_snapshot).await?;
        }
        Ok(())
    }

    pub async fn remove_rule(&self, path: &str) -> anyhow::Result<()> {
        info!("BlockingManager: Removing rule for path: {}", path);
        let mut rules = self.rules.write().await;
        let original_len = rules.len();
        rules.retain(|r| r.path != path && !r.path.eq_ignore_ascii_case(path));
        if rules.len() < original_len {
            let _ = Self::save_rules_internal(&rules);
            let rules_snapshot = rules.clone();
            drop(rules);
            #[cfg(target_os = "windows")]
            let _ = self.provisioner.remove_blocking_rule_registry(path).await;
            self.update_sysmon(&rules_snapshot).await?;
        } else {
            drop(rules);
            #[cfg(target_os = "windows")]
            let _ = self.provisioner.remove_blocking_rule_registry(path).await;
        }
        Ok(())
    }

    pub async fn purge_benign_rules(&self) -> anyhow::Result<Vec<String>> {
        let mut rules = self.rules.write().await;
        let mut purged = Vec::new();
        let mut retained = Vec::new();

        for rule in rules.drain(..) {
            if is_protected_or_benign_system_path(&rule.path) {
                purged.push(rule.path);
            } else {
                retained.push(rule);
            }
        }

        *rules = retained;
        let _ = Self::save_rules_internal(&rules);
        let rules_snapshot = rules.clone();
        drop(rules);

        #[cfg(target_os = "windows")]
        {
            for p in &purged {
                let _ = self.provisioner.remove_blocking_rule_registry(p).await;
            }
            let _ = self.provisioner.purge_all_ifeo_debugger_hooks().await;
        }

        if !purged.is_empty() {
            info!(
                "BlockingManager: Purged {} false-positive/protected rules from blocklist: {:?}",
                purged.len(),
                purged
            );
            self.update_sysmon(&rules_snapshot).await?;
        }

        Ok(purged)
    }

    pub async fn get_rules(&self) -> Vec<BlockingRule> {
        self.rules.read().await.clone()
    }

    /// Autonomous termination of a process by its PID.
    pub async fn block_by_pid(&self, pid: u32) -> anyhow::Result<()> {
        if pid <= 4 || pid == std::process::id() {
            return Ok(());
        }
        let proc_name = osoosi_runtime::tarpit::get_process_name(pid);
        if osoosi_runtime::tarpit::is_protected_system_or_security_process(pid, &proc_name)
            || osoosi_types::is_protected_os_shell_or_desktop_binary(&proc_name)
        {
            info!(
                "BlockingManager: Refusing autonomous termination of protected process PID {} ({})",
                pid, proc_name
            );
            return Ok(());
        }
        info!(
            "BlockingManager: Autonomous termination triggered for PID {} ({})",
            pid, proc_name
        );

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            use windows::Win32::Foundation::CloseHandle;
            use windows::Win32::System::Threading::{
                OpenProcess, TerminateProcess, PROCESS_TERMINATE,
            };

            unsafe {
                if let Ok(handle) = OpenProcess(PROCESS_TERMINATE, false, pid) {
                    let _ = TerminateProcess(handle, 5);
                    let _ = CloseHandle(handle);
                }
            }

            let _ = std::process::Command::new(osoosi_types::resolve_system_binary("taskkill.exe"))
                .args(["/F", "/T", "/PID", &pid.to_string()])
                .creation_flags(0x08000000)
                .status();
        }

        #[cfg(unix)]
        {
            let _ = std::process::Command::new("kill")
                .args(["-9", &pid.to_string()])
                .status();
        }

        Ok(())
    }

    #[allow(unused_variables)]
    pub async fn kill_transient_lolbin_or_payload_pid(
        &self,
        pid: u32,
        parent_pid: Option<u32>,
        image: &str,
        cmd_line: &str,
        reason: &str,
        strict_lockdown: bool,
    ) -> anyhow::Result<bool> {
        let _ = (&parent_pid, reason, strict_lockdown);
        if !can_terminate_transient_lolbin_or_payload_pid(pid, image, cmd_line) {
            return Ok(false);
        }
        let live_name = osoosi_runtime::tarpit::get_process_name(pid);
        if live_name != "unknown" && is_non_killable_persistent_os_or_user_daemon(&live_name) {
            return Ok(false);
        }

        info!(
            "BlockingManager: Active IPS terminating transient PID {} ({}) (System32 disk untouched)",
            pid, image
        );

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            use windows::Win32::Foundation::CloseHandle;
            use windows::Win32::System::Threading::{
                OpenProcess, TerminateProcess, PROCESS_TERMINATE,
            };

            unsafe {
                if let Ok(handle) = OpenProcess(PROCESS_TERMINATE, false, pid) {
                    let _ = TerminateProcess(handle, 5);
                    let _ = CloseHandle(handle);
                }
            }

            let _ = std::process::Command::new(osoosi_types::resolve_system_binary("taskkill.exe"))
                .args(["/F", "/T", "/PID", &pid.to_string()])
                .creation_flags(0x08000000)
                .status();

            if strict_lockdown {
                if let Some(ppid) = parent_pid {
                    if ppid > 4 && ppid != std::process::id() {
                        let ppid_name = osoosi_runtime::tarpit::get_process_name(ppid);
                        let ppid_lc = ppid_name.to_ascii_lowercase();
                        if (ppid_lc == "powershell.exe"
                            || ppid_lc == "pwsh.exe"
                            || ppid_lc == "cmd.exe")
                            && !is_non_killable_persistent_os_or_user_daemon(&ppid_name)
                        {
                            let cmd_lc = cmd_line.to_ascii_lowercase();
                            let r_lc = reason.to_ascii_lowercase();
                            let is_attack = cmd_lc.contains("invoke-atomictest")
                                || cmd_lc.contains("-enc")
                                || cmd_lc.contains("mimikatz")
                                || cmd_lc.contains("calc.exe")
                                || cmd_lc.contains("win32calc")
                                || cmd_lc.contains("sc.exe")
                                || cmd_lc.contains("sc sdset")
                                || cmd_lc.contains("reg save")
                                || r_lc.contains("sigma")
                                || r_lc.contains("atomic")
                                || r_lc.contains("attack.t1");
                            if is_attack {
                                unsafe {
                                    if let Ok(h) = OpenProcess(PROCESS_TERMINATE, false, ppid) {
                                        let _ = TerminateProcess(h, 5);
                                        let _ = CloseHandle(h);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        #[cfg(unix)]
        {
            let _ = std::process::Command::new("kill")
                .args(["-9", &pid.to_string()])
                .status();
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osoosi_types::{async_trait, BlockingKind, BlockingRule, SecuredExecutor};
    use std::path::Path;
    use std::process::{Command, Output};

    struct MockTestExecutor;

    #[async_trait]
    impl SecuredExecutor for MockTestExecutor {
        async fn execute(&self, _cmd: Command) -> anyhow::Result<Output> {
            #[cfg(unix)]
            use std::os::unix::process::ExitStatusExt;
            #[cfg(windows)]
            use std::os::windows::process::ExitStatusExt;

            Ok(Output {
                status: ExitStatusExt::from_raw(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }

        async fn download(&self, _url: &str, _dest: &Path, _resume: bool) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_blocking_manager_add_and_remove_rule() {
        let executor = Arc::new(MockTestExecutor);
        let provisioner = Arc::new(AgentProvisioner::new(executor));
        let manager = BlockingManager::new(provisioner);

        let test_rule = BlockingRule {
            path: r"C:\test\sample_malware.exe".to_string(),
            kind: BlockingKind::Executable,
        };

        // Ensure add_rule completes without async deadlock
        let res = manager.add_rule(test_rule.clone()).await;
        assert!(res.is_ok(), "add_rule failed: {:?}", res.err());

        // Verify rule is stored
        let rules = manager.get_rules().await;
        assert!(rules.iter().any(|r| r.path == test_rule.path));

        // Test removing rule
        let rem_res = manager.remove_rule(&test_rule.path).await;
        assert!(rem_res.is_ok(), "remove_rule failed: {:?}", rem_res.err());

        // Verify rule is removed
        let rules_after = manager.get_rules().await;
        assert!(!rules_after.iter().any(|r| r.path == test_rule.path));
    }

    #[tokio::test]
    async fn test_protected_and_benign_paths_refused_and_purged() {
        let executor = Arc::new(MockTestExecutor);
        let provisioner = Arc::new(AgentProvisioner::new(executor));
        let manager = BlockingManager::new(provisioner);

        // Verify protected detection across Windows, Linux, and macOS
        assert!(is_protected_or_benign_system_path(
            r"C:\Windows\System32\cmd.exe"
        ));
        assert!(is_protected_or_benign_system_path(
            r"\Device\HarddiskVolume4\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe"
        ));
        assert!(is_protected_or_benign_system_path(
            r"\Device\HarddiskVolume4\Windows\System32\sihost.exe"
        ));
        if std::path::Path::new(r"C:\Program Files\PostgreSQL\16\bin\postgres.exe").is_file() {
            assert!(is_protected_or_benign_system_path(
                r"C:\Program Files\PostgreSQL\16\bin\postgres.exe"
            ));
        }
        assert!(is_protected_or_benign_system_path(
            r"C:\Python314\python.exe"
        ));
        assert!(is_protected_or_benign_system_path(
            r"C:\Program Files\WSL\wsl.exe"
        ));
        assert!(is_protected_or_benign_system_path("/usr/bin/bash"));
        assert!(is_protected_or_benign_system_path("/usr/bin/gnome-shell"));
        assert!(is_protected_or_benign_system_path(
            "/usr/libexec/tracker-miner-fs-3"
        ));
        assert!(is_protected_or_benign_system_path(
            "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"
        ));
        assert!(is_protected_or_benign_system_path(
            "/System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter"
        ));
        assert!(is_protected_or_benign_system_path(
            "/System/Library/CoreServices/Spotlight.app/Contents/MacOS/Spotlight"
        ));
        assert!(is_protected_or_benign_system_path(
            r"C:\app\component.winmd"
        ));
        assert!(!is_protected_or_benign_system_path(
            r"C:\malware\bad_trojan.exe"
        ));
        assert!(!is_protected_or_benign_system_path(
            "/tmp/evil_miner_payload"
        ));

        // Refuse to add protected rule
        let protected_rule = BlockingRule {
            path: r"C:\Windows\System32\powershell.exe".to_string(),
            kind: BlockingKind::Executable,
        };
        let res = manager.add_rule(protected_rule.clone()).await;
        assert!(res.is_ok());
        let rules = manager.get_rules().await;
        assert!(!rules.iter().any(|r| r.path == protected_rule.path));

        // Test purge_benign_rules
        // Force insert a benign rule directly for testing purge
        {
            let mut w = manager.rules.write().await;
            w.push(BlockingRule {
                path: r"C:\Windows\System32\powershell.exe".to_string(),
                kind: BlockingKind::Executable,
            });
            w.push(BlockingRule {
                path: r"C:\temp\actual_malware.exe".to_string(),
                kind: BlockingKind::Executable,
            });
        }
        let purged = manager.purge_benign_rules().await.unwrap();
        assert_eq!(purged.len(), 1);
        assert!(purged[0].contains("powershell.exe"));
        let remaining = manager.get_rules().await;
        assert!(remaining
            .iter()
            .any(|r| r.path.contains("actual_malware.exe")));
        assert!(!remaining.iter().any(|r| r.path.contains("powershell.exe")));
    }

    #[tokio::test]
    async fn test_atomic_calc_payload_spawn_detected_and_transient_pid_eligible() {
        // 1. can_terminate_transient_lolbin_or_payload_pid on calc.exe spawned by PowerShell / cmd
        assert!(can_terminate_transient_lolbin_or_payload_pid(
            4321,
            r"C:\Windows\System32\calc.exe",
            "calc.exe"
        ));
        assert!(can_terminate_transient_lolbin_or_payload_pid(
            4322,
            r"C:\Windows\System32\calc.exe",
            "powershell.exe -ExecutionPolicy Bypass -Command calc.exe"
        ));

        // 2. System32\calc.exe is protected on disk so it is never IFEO blocked or quarantined
        assert!(is_protected_or_benign_system_path(
            r"C:\Windows\System32\calc.exe"
        ));

        // 3. Critical OS, daemon, browser, and IDE processes MUST NEVER be terminated
        let critical_processes = [
            r"C:\Windows\System32\lsass.exe",
            r"C:\Windows\System32\csrss.exe",
            r"C:\Windows\System32\svchost.exe",
            r"C:\Windows\explorer.exe",
            r"C:\Program Files\OshoosiClaw\osoosi.exe",
            r"C:\Python314\python3.14t.exe",
            r"C:\Users\oyesanyf\AppData\Local\Programs\Microsoft VS Code\Code.exe",
        ];
        for proc in critical_processes {
            assert!(
                !can_terminate_transient_lolbin_or_payload_pid(9999, proc, proc),
                "Process {} must be protected from transient kill",
                proc
            );
        }
    }
}
