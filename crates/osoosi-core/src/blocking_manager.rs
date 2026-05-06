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
        let mut manager = Self {
            rules: RwLock::new(Vec::new()),
            provisioner,
        };
        let _ = manager.load_rules();
        manager
    }

    fn load_rules(&mut self) -> anyhow::Result<()> {
        let path = osoosi_types::resolve_base_dir().join("blocking_rules.json");
        if path.exists() {
            let data = std::fs::read_to_string(&path)?;
            let rules: Vec<BlockingRule> = serde_json::from_str(&data)?;
            let mut guard = self.rules.blocking_write();
            *guard = rules;
            info!("BlockingManager: Loaded {} persistent rules from {:?}.", guard.len(), path);
        }
        Ok(())
    }

    async fn save_rules(&self) -> anyhow::Result<()> {
        let rules = self.rules.read().await;
        let data = serde_json::to_string_pretty(&*rules)?;
        let path = osoosi_types::resolve_base_dir().join("blocking_rules.json");
        std::fs::write(path, data)?;
        Ok(())
    }

    pub async fn add_rule(&self, rule: BlockingRule) -> anyhow::Result<()> {
        info!("BlockingManager: Adding rule for path: {}", rule.path);
        let mut rules = self.rules.write().await;
        if !rules
            .iter()
            .any(|r| r.path == rule.path && r.kind == rule.kind)
        {
            rules.push(rule);
            let _ = self.save_rules().await;
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
