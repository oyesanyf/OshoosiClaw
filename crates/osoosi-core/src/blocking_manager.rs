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

    if crate::system_check::is_administrative_lolbin(trimmed) {
        return true;
    }

    let p_norm = trimmed.replace('/', "\\").to_lowercase();
    let p_fwd = trimmed.replace('\\', "/").to_lowercase();

    let win_protected = [
        r"c:\windows\",
        r"\windows\system32\",
        r"\windows\syswow64\",
        r"\windows\winsxs\",
        r"\program files\windowsapps\",
        r"\program files\wsl\",
        r"\program files (x86)\windows kits\",
        r"\program files\windows kits\",
        r"\program files (x86)\reference assemblies\",
        r"\microsoft visual studio\",
        r"\program files\postgresql\",
        r"\program files (x86)\synology\",
        r"c:\python",
        r"c:\strawberry\",
        r"\wix_tools\",
        r"\edb_mtk.exe",
        r"\edb_pgagent",
        r"\edb_pem_agent",
    ];

    if win_protected.iter().any(|pattern| p_norm.contains(pattern)) {
        return true;
    }

    let linux_protected = [
        "/bin/",
        "/sbin/",
        "/usr/bin/",
        "/usr/sbin/",
        "/usr/lib/",
        "/usr/libexec/",
        "/lib/",
        "/lib64/",
        "/etc/",
    ];

    if linux_protected
        .iter()
        .any(|pattern| p_fwd.starts_with(pattern) || p_fwd.contains(pattern))
    {
        return true;
    }

    let non_executable_exts = [".winmd", ".so", ".pyd", ".xs.dll"];
    if non_executable_exts.iter().any(|ext| p_fwd.ends_with(ext)) {
        return true;
    }

    let p = std::path::Path::new(trimmed);
    if p.exists() && crate::win_trust::is_trusted_signed_binary(p) {
        return true;
    }

    false
}

pub struct BlockingManager {
    rules: RwLock<Vec<BlockingRule>>,
    provisioner: Arc<AgentProvisioner>,
}

impl BlockingManager {
    pub fn new(provisioner: Arc<AgentProvisioner>) -> Self {
        let rules = Self::load_rules_sync().unwrap_or_default();
        Self {
            rules: RwLock::new(rules),
            provisioner,
        }
    }

    fn load_rules_sync() -> anyhow::Result<Vec<BlockingRule>> {
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

    pub async fn update_sysmon(&self, rules: &[BlockingRule]) -> anyhow::Result<()> {
        #[cfg(target_os = "windows")]
        self.provisioner.apply_blocking_rules(rules).await?;
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
            self.update_sysmon(&rules).await?;
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

        if !purged.is_empty() {
            info!(
                "BlockingManager: Purged {} false-positive/protected rules from blocklist: {:?}",
                purged.len(),
                purged
            );
            let _ = Self::save_rules_internal(&rules);
            let rules_snapshot = rules.clone();
            drop(rules);
            #[cfg(target_os = "windows")]
            for p in &purged {
                let _ = self.provisioner.remove_blocking_rule_registry(p).await;
            }
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
        info!(
            "BlockingManager: Autonomous termination triggered for PID {}",
            pid
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
                    let _ = TerminateProcess(handle, 1);
                    let _ = CloseHandle(handle);
                }
            }

            let _ = std::process::Command::new(osoosi_types::resolve_system_binary("taskkill.exe"))
                .args(["/F", "/T", "/PID", &pid.to_string()])
                .creation_flags(0x08000000)
                .status();
        }

        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("kill")
                .args(["-9", &pid.to_string()])
                .status();
        }

        Ok(())
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

        // Verify protected detection
        assert!(is_protected_or_benign_system_path(
            r"C:\Windows\System32\cmd.exe"
        ));
        assert!(is_protected_or_benign_system_path(
            r"C:\Program Files\PostgreSQL\16\bin\postgres.exe"
        ));
        assert!(is_protected_or_benign_system_path(
            r"C:\Python314\python.exe"
        ));
        assert!(is_protected_or_benign_system_path(
            r"C:\Program Files\WSL\wsl.exe"
        ));
        assert!(is_protected_or_benign_system_path("/usr/bin/bash"));
        assert!(is_protected_or_benign_system_path(
            r"C:\app\component.winmd"
        ));
        assert!(!is_protected_or_benign_system_path(
            r"C:\malware\bad_trojan.exe"
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
                path: r"C:\Program Files (x86)\Synology\bin\cloud.exe".to_string(),
                kind: BlockingKind::Executable,
            });
            w.push(BlockingRule {
                path: r"C:\temp\actual_malware.exe".to_string(),
                kind: BlockingKind::Executable,
            });
        }
        let purged = manager.purge_benign_rules().await.unwrap();
        assert_eq!(purged.len(), 1);
        assert!(purged[0].contains("Synology"));
        let remaining = manager.get_rules().await;
        assert!(remaining
            .iter()
            .any(|r| r.path.contains("actual_malware.exe")));
        assert!(!remaining.iter().any(|r| r.path.contains("Synology")));
    }
}
