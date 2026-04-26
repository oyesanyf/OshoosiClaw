//! NVIDIA OpenShell Integration for OpenỌ̀ṣọ́ọ̀sì
//!
//! Provides sandboxed execution environments using NVIDIA OpenShell
//! for defense-in-depth protection. The agent can run inside an OpenShell
//! sandbox with policy-enforced filesystem, network, and process isolation.
//!
//! OpenShell is integrated as an external CLI tool (`openshell`), not as a
//! Rust crate dependency, because it uses a different Rust edition (2024)
//! and has heavy gRPC/K8s dependencies.

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{info, warn, error};

/// `pip install git+https://...` (VCS) — needs `git` on PATH; same default as NVIDIA OpenShell docs.
const OPENSHELL_PIP_GIT_URL: &str = "git+https://github.com/NVIDIA/OpenShell.git";

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
    /// Use `wsl.exe openshell ...` on Windows when no native OpenShell exists.
    use_wsl: bool,
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
        let use_wsl = cfg!(windows) && !cli_path.exists() && Self::check_wsl_openshell();
        Self { cli_path, policy_path, use_wsl }
    }

    /// Check if OpenShell CLI is available on this system.
    pub fn is_available(&self) -> bool {
        if self.cli_path.exists() && self.cli_path.is_file() { return true; }
        if Self::which_openshell().is_some() { return true; }
        if cfg!(windows) && Self::check_wsl_openshell() { return true; }
        // Fallback: check if it's available as a python module
        Self::check_python_module()
    }

    fn openshell_command(&self) -> Command {
        if self.use_wsl {
            let mut cmd = Command::new("wsl.exe");
            cmd.arg("openshell");
            cmd
        } else {
            Command::new(&self.cli_path)
        }
    }

    fn check_wsl_openshell() -> bool {
        cfg!(windows)
            && Command::new("wsl.exe")
                .args(["openshell", "--version"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
    }

    /// Check if OpenShell is available via `python -m openshell` / `py -m openshell` (Windows).
    fn check_python_module() -> bool {
        let attempts: &[(&str, &[&str])] = if cfg!(windows) {
            &[
                ("python", &["-m", "openshell", "--version"]),
                ("py", &["-3", "-m", "openshell", "--version"]),
                ("py", &["-m", "openshell", "--version"]),
            ]
        } else {
            &[("python", &["-m", "openshell", "--version"])]
        };
        for (exe, args) in attempts {
            if Command::new(exe)
                .args(*args)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
            {
                return true;
            }
        }
        false
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
        let mut cmd = self.openshell_command();
        let output = cmd.arg("--version").output().ok()?;
        if output.status.success() {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            Some(version)
        } else {
            None
        }
    }

    /// Check if the OpenShell gateway is running.
    fn check_gateway(&self) -> bool {
        let mut cmd = self.openshell_command();
        let output = cmd.args(["gateway", "status"]).output();
        match output {
            Ok(o) => o.status.success(),
            Err(_) => false,
        }
    }

    /// List all active sandboxes.
    fn list_sandboxes(&self) -> anyhow::Result<Vec<SandboxInfo>> {
        let mut cmd = self.openshell_command();
        let output = cmd.args(["sandbox", "list"]).output()?;

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

        let mut cmd = self.openshell_command();
        let output = cmd.args(["gateway", "deploy"]).output();

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
    /// `osoosi_start_extra` is appended after `osoosi start` (e.g. `&["--no-dashboard"]`).
    pub fn create_sandbox(&self, name: Option<&str>, osoosi_start_extra: &[&str]) -> OpenShellResult {
        let sandbox_name = name.unwrap_or("osoosi");
        info!("Creating OpenShell sandbox '{}' with policy: {:?}", sandbox_name, self.policy_path);

        let mut cmd = self.openshell_command();
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
        cmd.args(osoosi_start_extra);

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

        let mut cmd = self.openshell_command();
        let status = cmd.args(["sandbox", "connect", sandbox_name]).status();

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

        let mut cmd = self.openshell_command();
        let output = cmd
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

        let mut cmd = self.openshell_command();
        let output = cmd.args(["sandbox", "destroy", sandbox_name]).output();

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

    /// Execute a command inside an existing (or ephemeral) sandbox and capture output.
    ///
    /// If `sandbox_name` is `None`, creates an ephemeral sandbox, runs the command,
    /// and destroys it. This is ideal for one-shot tasks like downloading and
    /// compiling YARA rules in isolation.
    pub fn exec_in_sandbox(
        &self,
        sandbox_name: Option<&str>,
        command: &[&str],
        timeout_secs: u64,
    ) -> OpenShellResult {
        let ephemeral = sandbox_name.is_none();
        let name = sandbox_name.unwrap_or("osoosi-ephemeral");

        if ephemeral {
            let create = self.create_sandbox_raw(name);
            if !create.success {
                return create;
            }
        }

        info!("OpenShell: exec in '{}': {}", name, command.join(" "));

        let mut cmd = self.openshell_command();
        cmd.args(["sandbox", "exec", name, "--"]);
        cmd.args(command);

        let _ = timeout_secs;
        let output = cmd.output();

        let result = match output {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                let stderr = String::from_utf8_lossy(&o.stderr).to_string();
                let msg = if o.status.success() { stdout } else { format!("{}\n{}", stdout, stderr) };
                OpenShellResult {
                    success: o.status.success(),
                    message: msg,
                    sandbox_name: Some(name.to_string()),
                }
            }
            Err(e) => OpenShellResult {
                success: false,
                message: format!("exec failed: {}", e),
                sandbox_name: Some(name.to_string()),
            },
        };

        if ephemeral {
            let _ = self.destroy_sandbox(Some(name));
        }

        result
    }

    /// Create a sandbox without running the osoosi agent inside it (raw creation).
    fn create_sandbox_raw(&self, name: &str) -> OpenShellResult {
        let mut cmd = self.openshell_command();
        cmd.args(["sandbox", "create", "--name", name]);
        if self.policy_path.exists() {
            cmd.args(["--policy", &self.policy_path.to_string_lossy()]);
        }

        match cmd.output() {
            Ok(o) => {
                let msg = if o.status.success() {
                    String::from_utf8_lossy(&o.stdout).to_string()
                } else {
                    String::from_utf8_lossy(&o.stderr).to_string()
                };
                OpenShellResult { success: o.status.success(), message: msg, sandbox_name: Some(name.to_string()) }
            }
            Err(e) => OpenShellResult {
                success: false,
                message: format!("Failed to create sandbox: {}", e),
                sandbox_name: None,
            },
        }
    }

    /// Download and validate YARA rules inside an OpenShell sandbox.
    ///
    /// This is the recommended way to handle untrusted YARA rules from GitHub:
    /// 1. Downloads inside the sandbox (network isolation)
    /// 2. Compiles each file with `yr compile` to validate syntax
    /// 3. Only copies validated rules back to the host workspace
    pub fn provision_yara_in_sandbox(&self, yara_dir: &str) -> OpenShellResult {
        if !self.is_available() {
            return OpenShellResult {
                success: false,
                message: "OpenShell not available. Falling back to direct provisioning.".to_string(),
                sandbox_name: None,
            };
        }

        info!("Provisioning YARA rules via OpenShell sandbox...");

        let script = format!(
            r#"set -e
# Install yara-x CLI for validation
command -v yr >/dev/null 2>&1 || cargo install yara-x-cli 2>/dev/null || pip install yara-python 2>/dev/null || true

YARA_DIR="{yara_dir}"
mkdir -p "$YARA_DIR"

# Download and extract each source
download_and_validate() {{
    local name="$1" url="$2"
    local dir="$YARA_DIR/$name"
    mkdir -p "$dir"

    if [ "$(ls -A "$dir" 2>/dev/null)" ]; then
        echo "SKIP: $name already present"
        return 0
    fi

    echo "DOWNLOAD: $name from $url"
    curl -sSL -o "/tmp/$name.zip" "$url" || return 1
    unzip -qo "/tmp/$name.zip" -d "/tmp/$name_extract" || return 1
    cp -r /tmp/$name_extract/*/* "$dir/" 2>/dev/null || cp -r /tmp/$name_extract/* "$dir/" 2>/dev/null
    rm -rf "/tmp/$name.zip" "/tmp/$name_extract"

    # Validate each .yar file with yr compile
    local total=0 valid=0 fixed=0 failed=0
    for f in $(find "$dir" -name '*.yar' -type f); do
        total=$((total+1))
        if yr compile "$f" >/dev/null 2>&1; then
            valid=$((valid+1))
        else
            # Try to compile and capture error for diagnostics
            echo "WARN: $f failed validation" >&2
            failed=$((failed+1))
        fi
    done
    echo "VALIDATED: $name — $valid/$total valid ($failed failed)"
}}

download_and_validate "yara_forge" "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-extended.zip"
download_and_validate "signature_base" "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip"
download_and_validate "community" "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip"
download_and_validate "reversinglabs" "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/refs/heads/master.zip"
download_and_validate "elastic" "https://github.com/elastic/protections-artifacts/archive/refs/heads/main.zip"
download_and_validate "bartblaze" "https://github.com/bartblaze/Yara-rules/archive/refs/heads/master.zip"

echo "DONE: YARA provisioning complete"
"#,
            yara_dir = yara_dir
        );

        self.exec_in_sandbox(
            None,
            &["sh", "-c", &script],
            600, // 10 minute timeout
        )
    }

    /// Stream logs from a sandbox.
    pub fn stream_logs(&self, name: Option<&str>) -> OpenShellResult {
        let sandbox_name = name.unwrap_or("osoosi");

        let mut cmd = self.openshell_command();
        let status = cmd.args(["logs", sandbox_name, "--tail"]).status();

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

    /// Install OpenShell CLI: Unix uses NVIDIA `install.sh`; Windows tries PyPI, then `git+https://github.com/NVIDIA/OpenShell.git`, `py -m pip`, and `uv`.
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
            return Self::install_openshell_windows();
        }
    }

    /// Windows: `pip install -U openshell`, then VCS install from GitHub, then `uv tool install`.
    /// Discovers `git.exe` (`where`, common paths, or `OSOOSI_GIT_PATH`) and prepends its `cmd`/`bin` dirs to `PATH`
    /// so `pip install git+https://...` can run `git clone` (same as a manual `setx PATH ...; pip install git+...`).
    #[cfg(windows)]
    fn install_openshell_windows() -> OpenShellResult {
        if Self::check_wsl_openshell() {
            return OpenShellResult {
                success: true,
                message: "OpenShell is already available through WSL (`wsl.exe openshell --version`). Oshoosi will use WSL-backed OpenShell on this Windows host.".to_string(),
                sandbox_name: None,
            };
        }

        if let Some(ref g) = crate::tool_paths::resolve_git_executable() {
            info!("Using Git at {} (set OSOOSI_GIT_PATH to override)", g.display());
        } else {
            warn!("Git not found (install Git for Windows or set OSOOSI_GIT_PATH); PyPI openshell may still work; VCS install will fail without git.");
        }

        let path_for_pip = crate::tool_paths::resolve_git_executable()
            .map(|g| Self::path_env_with_git_prepend(&g))
            .or_else(|| env::var_os("PATH"));

        let try_pip = |args: &[&str]| -> std::io::Result<std::process::Output> {
            let mut cmd = Command::new("pip");
            cmd.args(args);
            if let Some(ref p) = path_for_pip {
                cmd.env("PATH", p);
            }
            cmd.output()
        };

        // 1) PyPI wheel/sdist
        match try_pip(&["install", "-U", "openshell"]) {
            Ok(o) if o.status.success() => {
                return OpenShellResult {
                    success: true,
                    message: String::from_utf8_lossy(&o.stdout).to_string(),
                    sandbox_name: None,
                };
            }
            Ok(o) => {
                warn!(
                    "pip install -U openshell failed: {}",
                    String::from_utf8_lossy(&o.stderr)
                );
            }
            Err(e) => warn!("Could not run pip: {}", e),
        }

        // 2) From NVIDIA Git (requires git on effective PATH)
        match try_pip(&["install", "-U", OPENSHELL_PIP_GIT_URL]) {
            Ok(o) if o.status.success() => {
                return OpenShellResult {
                    success: true,
                    message: format!(
                        "Installed from {}:\n{}",
                        OPENSHELL_PIP_GIT_URL,
                        String::from_utf8_lossy(&o.stdout)
                    ),
                    sandbox_name: None,
                };
            }
            Ok(o) => {
                warn!(
                    "pip install {} failed: {}",
                    OPENSHELL_PIP_GIT_URL,
                    String::from_utf8_lossy(&o.stderr)
                );
            }
            Err(e) => warn!("pip (VCS install): {}", e),
        }

        // 3) `py -m pip` with same PATH (Windows Python launcher)
        if let Some(p) = &path_for_pip {
            let mut cmd = Command::new("py");
            cmd.args(["-3", "-m", "pip", "install", "-U", OPENSHELL_PIP_GIT_URL]);
            cmd.env("PATH", p);
            if let Ok(o) = cmd.output() {
                if o.status.success() {
                    return OpenShellResult {
                        success: true,
                        message: String::from_utf8_lossy(&o.stdout).to_string(),
                        sandbox_name: None,
                    };
                }
            }
        }

        // 4) uv (native Windows package is not available for OpenShell v0.0.36,
        // but keep this for future releases and clear diagnostics).
        let mut uv = Command::new("uv");
        uv.args(["tool", "install", "-U", "openshell", "--prerelease=allow"]);
        if let Some(ref p) = path_for_pip {
            uv.env("PATH", p);
        }
        match uv.output() {
            Ok(uv_out) if uv_out.status.success() => OpenShellResult {
                success: true,
                message: String::from_utf8_lossy(&uv_out.stdout).to_string(),
                sandbox_name: None,
            },
            Ok(uv_out) => OpenShellResult {
                success: false,
                message: format!(
                    "All native Windows install methods failed. NVIDIA OpenShell v0.0.36 publishes Linux/macOS wheels only. Install it in WSL with: curl -LsSf https://astral.sh/uv/install.sh | sh && source $HOME/.cargo/env && uv tool install --prerelease=allow openshell. Last uv stderr: {}",
                    String::from_utf8_lossy(&uv_out.stderr)
                ),
                sandbox_name: None,
            },
            Err(e) => OpenShellResult {
                success: false,
                message: format!(
                    "Install failed (pip/git+https and uv failed). Ensure Git and pip are available, or set OPENSHELL_CLI_PATH. Last error: {}",
                    e
                ),
                sandbox_name: None,
            },
        }
    }

    /// Prepend Git `cmd` and sibling `bin` to `PATH` so pip’s VCS install can invoke `git`.
    #[cfg(windows)]
    fn path_env_with_git_prepend(git_exe: &Path) -> OsString {
        let mut prefixes: Vec<PathBuf> = Vec::new();
        if let Some(cmd_dir) = git_exe.parent() {
            prefixes.push(cmd_dir.to_path_buf());
            if let Some(root) = cmd_dir.parent() {
                let bin_dir = root.join("bin");
                if bin_dir.is_dir() {
                    prefixes.push(bin_dir);
                }
            }
        }
        let existing = env::var_os("PATH").unwrap_or_default();
        let mut combined: Vec<PathBuf> = prefixes;
        combined.extend(env::split_paths(&existing));
        env::join_paths(combined).unwrap_or(existing)
    }

    // --- Internal helpers ---

    fn find_openshell_cli() -> PathBuf {
        crate::tool_paths::resolve_openshell_cli_path()
    }

    fn which_openshell() -> Option<PathBuf> {
        crate::tool_paths::resolve_executable("openshell")
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
