use std::sync::Arc;
use tokio::sync::RwLock;
use osoosi_types::BlockingRule;
use osoosi_telemetry::AgentProvisioner;
use tracing::info;

pub struct BlockingManager {
    rules: RwLock<Vec<BlockingRule>>,
    provisioner: Arc<AgentProvisioner>,
}

impl BlockingManager {
    pub fn new(provisioner: Arc<AgentProvisioner>) -> Self {
        Self {
            rules: RwLock::new(Vec::new()),
            provisioner,
        }
    }

    pub async fn add_rule(&self, rule: BlockingRule) -> anyhow::Result<()> {
        info!("BlockingManager: Adding rule for path: {}", rule.path);
        let mut rules = self.rules.write().await;
        if !rules.iter().any(|r| r.path == rule.path && r.kind == rule.kind) {
            rules.push(rule);
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
}
