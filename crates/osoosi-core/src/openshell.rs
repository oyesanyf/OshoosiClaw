//! NVIDIA OpenShell Integration for OpenỌ̀ṣọ́ọ̀sì
//!
//! Provides sandboxed execution environments using NVIDIA OpenShell
//! for defense-in-depth protection. The agent can run inside an OpenShell
//! sandbox with policy-enforced filesystem, network, and process isolation.
//!
//! OpenShell is integrated as an external CLI tool (`openshell`), not as a
//! Rust crate dependency, because it uses a different Rust edition (2024)
//! and has heavy gRPC/K8s dependencies.

use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{info, warn, error};

/// Default sandbox policy path relative to the osoosi installation directory.
const DEFAULT_POLICY_PATH: &str = "config/openshell-policy.yaml";

/// Result of an OpenShell operation.
#[derive(Debug, Clone)]
pub struct OpenShellResult {
    pub success: bool,
    pub message: String,
    pub sandbox_name: Option<String>,
}

/// Status of the OpenShell installation and gateway.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OpenShellStatus {
    pub installed: bool,
    pub version: Option<String>,
    pub gateway_running: bool,
    pub sandboxes: Vec<SandboxInfo>,
}

/// Information about a running OpenShell sandbox.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SandboxInfo {
    pub name: String,
    pub status: String,
}

/// Manager for OpenShell sandbox lifecycle.
pub struct OpenShellManager {
    /// Path to the openshell CLI binary.
    cli_path: PathBuf,
    /// Path to the osoosi sandbox policy YAML.
    policy_path: PathBuf,
}

impl OpenShellManager {
    /// Create a new OpenShellManager.
    ///
    /// Searches for the `openshell` binary in:
    /// 1. `OPENSHELL_CLI_PATH` environment variable
    /// 2. System PATH
    /// 3. Common install locations (~/.local/bin, /usr/local/bin)
    pub fn new() -> Self {
        let cli_path = Self::find_openshell_cli();
        let policy_path = Self::find_policy_path();
        Self { cli_path, policy_path }
    }

    /// Check if OpenShell CLI is available on this system.
    pub fn is_available(&self) -> bool {
        self.cli_path.exists() || Self::which_openshell().is_some()
    }

    /// Get the full status of OpenShell (installation, gateway, sandboxes).
    pub fn status(&self) -> OpenShellStatus {
        let installed = self.is_available();
        let version = if installed { self.get_version() } else { None };
        let gateway_running = if installed { self.check_gateway() } else { false };
        let sandboxes = if installed && gateway_running {
            self.list_sandboxes().unwrap_or_default()
        } else {
            vec![]
        };

        OpenShellStatus {
            installed,
            version,
            gateway_running,
            sandboxes,
        }
    }

    /// Get the OpenShell CLI version.
    fn get_version(&self) -> Option<String> {
        let output = Command::new(&self.cli_path)
            .arg("--version")
            .output()
            .ok()?;
        if output.status.success() {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            Some(version)
        } else {
            None
        }
    }

    /// Check if the OpenShell gateway is running.
    fn check_gateway(&self) -> bool {
        let output = Command::new(&self.cli_path)
            .args(["gateway", "status"])
            .output();
        match output {
            Ok(o) => o.status.success(),
            Err(_) => false,
        }
    }

    /// List all active sandboxes.
    fn list_sandboxes(&self) -> anyhow::Result<Vec<SandboxInfo>> {
        let output = Command::new(&self.cli_path)
            .args(["sandbox", "list"])
            .output()?;

        if !output.status.success() {
            return Ok(vec![]);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut sandboxes = vec![];

        // Parse the sandbox list output (skip header line)
        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                sandboxes.push(SandboxInfo {
                    name: parts[0].to_string(),
                    status: parts[1].to_string(),
                });
            }
        }

        Ok(sandboxes)
    }

    /// Deploy the OpenShell gateway (required before creating sandboxes).
    pub fn deploy_gateway(&self) -> OpenShellResult {
        info!("Deploying OpenShell gateway...");

        let output = Command::new(&self.cli_path)
            .args(["gateway", "deploy"])
            .output();

        match output {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                let stderr = String::from_utf8_lossy(&o.stderr);
                if o.status.success() {
                    info!("OpenShell gateway deployed successfully");
                    OpenShellResult {
                        success: true,
                        message: stdout.to_string(),
                        sandbox_name: None,
                    }
                } else {
                    error!("OpenShell gateway deploy failed: {}", stderr);
                    OpenShellResult {
                        success: false,
                        message: stderr.to_string(),
                        sandbox_name: None,
                    }
                }
            }
            Err(e) => OpenShellResult {
                success: false,
                message: format!("Failed to run openshell: {}", e),
                sandbox_name: None,
            },
        }
    }

    /// Create a new sandbox for the osoosi agent with the configured policy.
    ///
    /// The sandbox name defaults to "osoosi" but can be customized.
    pub fn create_sandbox(&self, name: Option<&str>) -> OpenShellResult {
        let sandbox_name = name.unwrap_or("osoosi");
        info!("Creating OpenShell sandbox '{}' with policy: {:?}", sandbox_name, self.policy_path);

        let mut cmd = Command::new(&self.cli_path);
        cmd.args(["sandbox", "create"]);

        // Apply the sandbox policy if available
        if self.policy_path.exists() {
            cmd.args(["--policy", &self.policy_path.to_string_lossy()]);
        } else {
            warn!("OpenShell policy not found at {:?}. Using default restrictive policy.", self.policy_path);
        }

        // Set the sandbox name
        cmd.args(["--name", sandbox_name]);

        // Run the osoosi agent inside the sandbox
        cmd.args(["--", "osoosi", "start"]);

        let output = cmd.output();

        match output {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                let stderr = String::from_utf8_lossy(&o.stderr);
                if o.status.success() {
                    info!("OpenShell sandbox '{}' created successfully", sandbox_name);
                    OpenShellResult {
                        success: true,
                        message: stdout.to_string(),
                        sandbox_name: Some(sandbox_name.to_string()),
                    }
                } else {
                    error!("OpenShell sandbox creation failed: {}", stderr);
                    OpenShellResult {
                        success: false,
                        message: stderr.to_string(),
                        sandbox_name: None,
                    }
                }
            }
            Err(e) => OpenShellResult {
                success: false,
                message: format!("Failed to run openshell: {}", e),
                sandbox_name: None,
            },
        }
    }

    /// Connect to an existing sandbox (interactive terminal).
    pub fn connect_sandbox(&self, name: Option<&str>) -> OpenShellResult {
        let sandbox_name = name.unwrap_or("osoosi");
        info!("Connecting to OpenShell sandbox '{}'...", sandbox_name);

        let status = Command::new(&self.cli_path)
            .args(["sandbox", "connect", sandbox_name])
            .status();

        match status {
            Ok(s) => OpenShellResult {
                success: s.success(),
                message: if s.success() {
                    "Disconnected from sandbox".to_string()
                } else {
                    format!("Connection exited with code {:?}", s.code())
                },
                sandbox_name: Some(sandbox_name.to_string()),
            },
            Err(e) => OpenShellResult {
                success: false,
                message: format!("Failed to connect: {}", e),
                sandbox_name: None,
            },
        }
    }

    /// Apply or update the security policy on a running sandbox.
    pub fn apply_policy(&self, sandbox_name: Option<&str>, policy_path: Option<&Path>) -> OpenShellResult {
        let name = sandbox_name.unwrap_or("osoosi");
        let policy = policy_path.unwrap_or(&self.policy_path);

        if !policy.exists() {
            return OpenShellResult {
                success: false,
                message: format!("Policy file not found: {:?}", policy),
                sandbox_name: Some(name.to_string()),
            };
        }

        info!("Applying OpenShell policy to sandbox '{}': {:?}", name, policy);

        let output = Command::new(&self.cli_path)
            .args(["policy", "set", name, "--policy", &policy.to_string_lossy(), "--wait"])
            .output();

        match output {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                let stderr = String::from_utf8_lossy(&o.stderr);
                OpenShellResult {
                    success: o.status.success(),
                    message: if o.status.success() { stdout.to_string() } else { stderr.to_string() },
                    sandbox_name: Some(name.to_string()),
                }
            }
            Err(e) => OpenShellResult {
                success: false,
                message: format!("Failed to apply policy: {}", e),
                sandbox_name: None,
            },
        }
    }

    /// Destroy a sandbox.
    pub fn destroy_sandbox(&self, name: Option<&str>) -> OpenShellResult {
        let sandbox_name = name.unwrap_or("osoosi");
        info!("Destroying OpenShell sandbox '{}'...", sandbox_name);

        let output = Command::new(&self.cli_path)
            .args(["sandbox", "destroy", sandbox_name])
            .output();

        match output {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                let stderr = String::from_utf8_lossy(&o.stderr);
                OpenShellResult {
                    success: o.status.success(),
                    message: if o.status.success() { stdout.to_string() } else { stderr.to_string() },
                    sandbox_name: Some(sandbox_name.to_string()),
                }
            }
            Err(e) => OpenShellResult {
                success: false,
                message: format!("Failed to destroy sandbox: {}", e),
                sandbox_name: None,
            },
        }
    }

    /// Stream logs from a sandbox.
    pub fn stream_logs(&self, name: Option<&str>) -> OpenShellResult {
        let sandbox_name = name.unwrap_or("osoosi");

        let status = Command::new(&self.cli_path)
            .args(["logs", sandbox_name, "--tail"])
            .status();

        match status {
            Ok(s) => OpenShellResult {
                success: s.success(),
                message: "Log streaming ended".to_string(),
                sandbox_name: Some(sandbox_name.to_string()),
            },
            Err(e) => OpenShellResult {
                success: false,
                message: format!("Failed to stream logs: {}", e),
                sandbox_name: None,
            },
        }
    }

    /// Install OpenShell CLI on this system (Linux/macOS).
    pub fn install() -> OpenShellResult {
        info!("Installing NVIDIA OpenShell CLI...");

        #[cfg(unix)]
        {
            let output = Command::new("sh")
                .args(["-c", "curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh"])
                .output();

            match output {
                Ok(o) => {
                    let stdout = String::from_utf8_lossy(&o.stdout);
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    OpenShellResult {
                        success: o.status.success(),
                        message: if o.status.success() { stdout.to_string() } else { stderr.to_string() },
                        sandbox_name: None,
                    }
                }
                Err(e) => OpenShellResult {
                    success: false,
                    message: format!("Installation failed: {}", e),
                    sandbox_name: None,
                },
            }
        }

        #[cfg(windows)]
        {
            // On Windows, use pip/uv or download the binary directly
            let output = Command::new("pip")
                .args(["install", "-U", "openshell"])
                .output();

            match output {
                Ok(o) => {
                    let stdout = String::from_utf8_lossy(&o.stdout);
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    if o.status.success() {
                        OpenShellResult {
                            success: true,
                            message: stdout.to_string(),
                            sandbox_name: None,
                        }
                    } else {
                        // Fallback: try uv
                        if let Ok(uv_out) = Command::new("uv")
                            .args(["tool", "install", "-U", "openshell"])
                            .output()
                        {
                            OpenShellResult {
                                success: uv_out.status.success(),
                                message: String::from_utf8_lossy(&uv_out.stdout).to_string(),
                                sandbox_name: None,
                            }
                        } else {
                            OpenShellResult {
                                success: false,
                                message: format!("pip install failed: {}. Try: uv tool install openshell", stderr),
                                sandbox_name: None,
                            }
                        }
                    }
                }
                Err(e) => OpenShellResult {
                    success: false,
                    message: format!("Installation failed (pip not found): {}. Install with: uv tool install openshell", e),
                    sandbox_name: None,
                },
            }
        }
    }

    // --- Internal helpers ---

    fn find_openshell_cli() -> PathBuf {
        // 1. Environment variable
        if let Ok(p) = std::env::var("OPENSHELL_CLI_PATH") {
            let path = PathBuf::from(p);
            if path.exists() {
                return path;
            }
        }

        // 2. System PATH
        if let Some(p) = Self::which_openshell() {
            return p;
        }

        // 3. Common install locations
        #[cfg(unix)]
        {
            if let Ok(home) = std::env::var("HOME") {
                let local_bin = PathBuf::from(&home).join(".local/bin/openshell");
                if local_bin.exists() { return local_bin; }
            }
            let usr_local = PathBuf::from("/usr/local/bin/openshell");
            if usr_local.exists() { return usr_local; }
        }

        #[cfg(windows)]
        {
            if let Ok(userprofile) = std::env::var("USERPROFILE") {
                let local_bin = PathBuf::from(&userprofile).join(".local\\bin\\openshell.exe");
                if local_bin.exists() { return local_bin; }
            }
        }

        // Fallback: hope it's on PATH
        PathBuf::from("openshell")
    }

    fn which_openshell() -> Option<PathBuf> {
        #[cfg(windows)]
        let output = Command::new("where").arg("openshell").output().ok()?;
        #[cfg(unix)]
        let output = Command::new("which").arg("openshell").output().ok()?;

        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()?
                .trim()
                .to_string();
            Some(PathBuf::from(path))
        } else {
            None
        }
    }

    fn find_policy_path() -> PathBuf {
        // 1. Environment variable
        if let Ok(p) = std::env::var("OPENSHELL_SANDBOX_POLICY") {
            let path = PathBuf::from(p);
            if path.exists() { return path; }
        }

        // 2. Next to executable
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                let policy = parent.join(DEFAULT_POLICY_PATH);
                if policy.exists() { return policy; }
            }
        }

        // 3. Current directory
        let cwd_policy = PathBuf::from(DEFAULT_POLICY_PATH);
        if cwd_policy.exists() { return cwd_policy; }

        // Fallback
        PathBuf::from(DEFAULT_POLICY_PATH)
    }
}
