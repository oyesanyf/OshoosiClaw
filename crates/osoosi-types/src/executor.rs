use async_trait::async_trait;
use std::path::Path;
use std::process::{Command, Output};

#[async_trait]
pub trait SecuredExecutor: Send + Sync {
    /// Execute a command. If sandboxing is enabled, this runs inside a controlled environment.
    async fn execute(&self, cmd: Command) -> anyhow::Result<Output>;

    /// Download a file. If sandboxing is enabled, this is proxied through a secure gateway.
    /// If 'resume' is true, attempts to resume from the current file size.
    async fn download(&self, url: &str, dest: &Path, resume: bool) -> anyhow::Result<()>;
}
