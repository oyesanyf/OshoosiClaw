use std::path::Path;
use std::process::Output;
use async_trait::async_trait;
use tracing::info;
use tokio::process::Command;
use osoosi_types::SecuredExecutor;

/// Default implementation: executes directly on the host system.
pub struct DirectExecutor {
    client: reqwest::Client,
}

impl DirectExecutor {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(600))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }
}

#[async_trait]
impl SecuredExecutor for DirectExecutor {
    async fn execute(&self, cmd: std::process::Command) -> anyhow::Result<Output> {
        let mut tokio_cmd = Command::from(cmd);
        let output = tokio_cmd.output().await?;
        Ok(output)
    }

    async fn download(&self, url: &str, dest: &Path, resume: bool) -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt;
        use futures::StreamExt;

        let mut request = self.client.get(url);
        
        if resume && dest.exists() {
            let size = std::fs::metadata(dest)?.len();
            if size > 0 {
                request = request.header("Range", format!("bytes={}-", size));
            }
        }

        // Support HF_TOKEN for Hugging Face downloads
        if url.contains("huggingface.co") {
            if let Ok(token) = std::env::var("HF_TOKEN") {
                request = request.header("Authorization", format!("Bearer {}", token));
            } else if let Ok(token) = std::env::var("HUGGING_FACE_HUB_TOKEN") {
                request = request.header("Authorization", format!("Bearer {}", token));
            }
        }

        let resp = request.send().await?;
        let status = resp.status();
        
        if status == reqwest::StatusCode::RANGE_NOT_SATISFIABLE {
            return Ok(()); // Already finished
        }

        if !status.is_success() && status != reqwest::StatusCode::PARTIAL_CONTENT {
            return Err(anyhow::anyhow!("Download failed with status: {}", status));
        }

        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(resume)
            .write(true)
            .open(dest).await?;

        // If it's a 200 OK but we requested a resume, the server might not support it.
        // We should truncate if we have existing data.
        if status == reqwest::StatusCode::OK && resume {
            let _ = file.set_len(0).await;
        }

        let mut stream = resp.bytes_stream();
        while let Some(item) = stream.next().await {
            let chunk = item?;
            file.write_all(&chunk).await?;
        }
        file.flush().await?;
        Ok(())
    }
}

/// OpenShell implementation: executes commands and downloads inside a sandboxed container.
pub struct OpenShellExecutor {
    sandbox_name: String,
    policy_path: Option<String>,
}

impl OpenShellExecutor {
    pub fn new(sandbox_name: &str, policy_path: Option<&str>) -> Self {
        Self {
            sandbox_name: sandbox_name.to_string(),
            policy_path: policy_path.map(|s| s.to_string()),
        }
    }

    /// [NEW] Detect if NVIDIA OpenShell is available on this system.
    pub async fn is_available() -> bool {
        // Check for 'openshell' binary and 'docker' status
        let openshell_check = Command::new("openshell")
            .arg("--version")
            .output().await;
        
        if let Ok(output) = openshell_check {
            if output.status.success() {
                // Also check if docker is running
                let docker_check = Command::new("docker")
                    .arg("info")
                    .output().await;
                return docker_check.map(|o| o.status.success()).unwrap_or(false);
            }
        }
        false
    }

    async fn ensure_sandbox(&self) -> anyhow::Result<()> {
        // Check if sandbox exists
        let check = Command::new("openshell")
            .args(["sandbox", "list"])
            .output().await?;
        
        let stdout = String::from_utf8_lossy(&check.stdout);
        if stdout.contains(&self.sandbox_name) {
            return Ok(());
        }

        info!("Creating OpenShell sandbox: {}...", self.sandbox_name);
        let mut create_cmd = Command::new("openshell");
        create_cmd.args(["sandbox", "create", &self.sandbox_name]);
        
        if let Some(ref policy) = self.policy_path {
            create_cmd.args(["--policy", policy]);
        }

        let status = create_cmd.status().await?;
        if !status.success() {
            return Err(anyhow::anyhow!("Failed to create OpenShell sandbox: {}", self.sandbox_name));
        }

        Ok(())
    }
}

#[async_trait]
impl SecuredExecutor for OpenShellExecutor {
    async fn execute(&self, cmd: std::process::Command) -> anyhow::Result<Output> {
        self.ensure_sandbox().await?;
        
        // Wrap command in 'openshell sandbox connect'
        let mut wrapped = Command::new("openshell");
        wrapped.args(["sandbox", "connect", &self.sandbox_name, "--"]);
        wrapped.arg(cmd.get_program());
        for arg in cmd.get_args() {
            wrapped.arg(arg);
        }

        let output = wrapped.output().await?;
        Ok(output)
    }

    async fn download(&self, url: &str, dest: &Path, resume: bool) -> anyhow::Result<()> {
        self.ensure_sandbox().await?;

        info!("Sandboxed Download (OpenShell): {} -> {:?}", url, dest);
        
        // Use curl inside the sandbox to perform the download, leveraging OpenShell's L7 policy engine
        let dest_str = dest.to_string_lossy();
        let mut wrapped = Command::new("openshell");
        wrapped.args(["sandbox", "connect", &self.sandbox_name, "--", "curl", "-L"]);
        
        if resume {
            wrapped.arg("-C").arg("-");
        }
        
        if url.contains("huggingface.co") {
            if let Ok(token) = std::env::var("HF_TOKEN") {
                wrapped.arg("-H").arg(format!("Authorization: Bearer {}", token));
            } else if let Ok(token) = std::env::var("HUGGING_FACE_HUB_TOKEN") {
                wrapped.arg("-H").arg(format!("Authorization: Bearer {}", token));
            }
        }
        
        wrapped.arg("-o").arg(dest_str.as_ref()).arg(url);

        let status = wrapped.status().await?;
        if !status.success() {
            return Err(anyhow::anyhow!("Sandboxed download failed via OpenShell for: {}", url));
        }

        Ok(())
    }
}

/// [NEW] Universal factory to get the best possible executor for the current host.
pub async fn get_best_executor() -> std::sync::Arc<dyn SecuredExecutor> {
    if OpenShellExecutor::is_available().await {
        info!("NVIDIA OpenShell detected. Using containerized sandbox.");
        std::sync::Arc::new(OpenShellExecutor::new("osoosi-runtime", None))
    } else {
        // Fallback to Native OS Sandbox (Landlock/JobObjects)
        // For now, this returns DirectExecutor which will eventually 
        // trigger the Landlock/AppContainer logic.
        info!("NVIDIA OpenShell/Docker not available. Falling back to Native OS Sandboxing.");
        std::sync::Arc::new(DirectExecutor::new())
    }
}
