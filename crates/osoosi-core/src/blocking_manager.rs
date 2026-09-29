use osoosi_telemetry::AgentProvisioner;
use osoosi_types::BlockingRule;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

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
            info!("BlockingManager: Loaded {} persistent rules from {:?}.", rules.len(), path);
            Ok(rules)
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

    pub async fn add_rule(&self, rule: BlockingRule) -> anyhow::Result<()> {
        info!("BlockingManager: Adding rule for path: {}", rule.path);
        let mut rules = self.rules.write().await;
        if !rules
            .iter()
            .any(|r| r.path == rule.path && r.kind == rule.kind)
        {
            rules.push(rule);
            let _ = Self::save_rules_internal(&rules);
            #[cfg(target_os = "windows")]
            self.provisioner.apply_blocking_rules(&rules).await?;
        }
        Ok(())
    }

    pub async fn remove_rule(&self, path: &str) -> anyhow::Result<()> {
        info!("BlockingManager: Removing rule for path: {}", path);
        let mut rules = self.rules.write().await;
        let original_len = rules.len();
        rules.retain(|r| r.path != path);
        if rules.len() < original_len {
            let _ = Self::save_rules_internal(&rules);
            #[cfg(target_os = "windows")]
            self.provisioner.apply_blocking_rules(&rules).await?;
        }
        Ok(())
    }

    pub async fn get_rules(&self) -> Vec<BlockingRule> {
        self.rules.read().await.clone()
    }

    /// Autonomous termination of a process by its PID.
    pub async fn block_by_pid(&self, pid: u32) -> anyhow::Result<()> {
        info!("BlockingManager: Autonomous termination triggered for PID {}", pid);
        
        #[cfg(target_os = "windows")]
        {
            let _ = std::process::Command::new("taskkill")
                .args(["/F", "/PID", &pid.to_string()])
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
            #[cfg(windows)]
            use std::os::windows::process::ExitStatusExt;
            #[cfg(unix)]
            use std::os::unix::process::ExitStatusExt;

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
}
