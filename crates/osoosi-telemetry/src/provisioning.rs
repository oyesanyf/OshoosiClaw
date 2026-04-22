//! Agent Provisioning and Installation.
//!
//! Manages the automated installation of telemetry dependencies across OS platforms.
//! Windows: Sysmon
//! Linux: Sysmon for Linux
//! macOS: Endpoint Security Framework

use std::path::Path;
use std::process::Command;
use tracing::{info, warn, error};
use std::sync::Arc;
use osoosi_types::SecuredExecutor;

pub struct AgentProvisioner {
    executor: Arc<dyn SecuredExecutor>,
}

impl AgentProvisioner {
    pub fn new(executor: Arc<dyn SecuredExecutor>) -> Self {
        Self { executor }
    }

    /// Provision the agent's telemetry dependencies based on the host OS.
    pub async fn provision_telemetry(&self) -> anyhow::Result<()> {
        #[cfg(target_os = "windows")]
        {
            self.provision_windows().await?;
            self.provision_firewall().await?;
            self.provision_capa().await
        }
        #[cfg(target_os = "linux")]
        {
            self.provision_firewall().await?;
            self.provision_linux().await?;
            self.provision_capa().await
        }
        #[cfg(target_os = "macos")]
        {
            self.provision_firewall().await?;
            self.provision_macos().await?;
            self.provision_capa().await
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Err(anyhow::anyhow!("Unsupported operating system for automated provisioning."))
        }
    }

    /// Provision ClamAV validator (best-effort install per OS).
    pub async fn provision_clamav(&self) -> anyhow::Result<()> {
        #[cfg(target_os = "windows")]
        {
            self.provision_windows_clamav().await
        }
        #[cfg(target_os = "linux")]
        {
            self.provision_linux_clamav().await
        }
        #[cfg(target_os = "macos")]
        {
            self.provision_macos_clamav().await
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Err(anyhow::anyhow!(
                "Unsupported operating system for automated ClamAV provisioning."
            ))
        }
    }

    /// Provision OpenSSL (needed for X.509 / CSR generation).
    pub async fn provision_openssl(&self) -> anyhow::Result<()> {
        #[cfg(target_os = "windows")]
        {
            self.provision_windows_openssl().await
        }
        #[cfg(target_os = "linux")]
        {
            self.provision_linux_openssl().await
        }
        #[cfg(target_os = "macos")]
        {
            self.provision_macos_openssl().await
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Err(anyhow::anyhow!(
                "Unsupported operating system for automated OpenSSL provisioning."
            ))
        }
    }

    /// Provision Firewall rules for the Oshoosi Mesh.
    pub async fn provision_firewall(&self) -> anyhow::Result<()> {
        info!("Provisioning firewall rules for mesh networking...");
        
        #[cfg(target_os = "windows")]
        {
            // Mesh Port: 9000 (libp2p), Dashboard Port: 3000
            let ports = [("OshoosiMesh", "9000"), ("OshoosiDashboard", "3000")];
            for (name, port) in ports {
                let check_cmd = format!("netsh advfirewall firewall show rule name='{}'", name);
                let mut check = Command::new("powershell");
                check.args(["-NoProfile", "-Command", &check_cmd]);
                
                if !self.executor.execute(check).await?.status.success() {
                    info!("Adding firewall rule: {} (Port {})...", name, port);
                    let add_cmd = format!(
                        "netsh advfirewall firewall add rule name='{}' dir=in action=allow protocol=TCP localport={}",
                        name, port
                    );
                    let mut add = Command::new("powershell");
                    add.args(["-NoProfile", "-Command", &add_cmd]);
                    self.executor.execute(add).await?;
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            // Try ufw first
            if self.command_exists("ufw").await {
                let mut cmd = Command::new("sudo");
                cmd.args(["ufw", "allow", "9000/tcp"]);
                let _ = self.executor.execute(cmd).await;
                let mut cmd = Command::new("sudo");
                cmd.args(["ufw", "allow", "3000/tcp"]);
                let _ = self.executor.execute(cmd).await;
            } else if self.command_exists("firewall-cmd").await {
                let mut cmd = Command::new("sudo");
                cmd.args(["firewall-cmd", "--permanent", "--add-port=9000/tcp"]);
                let _ = self.executor.execute(cmd).await;
                let mut cmd = Command::new("sudo");
                cmd.args(["firewall-cmd", "--permanent", "--add-port=3000/tcp"]);
                let _ = self.executor.execute(cmd).await;
                let mut cmd = Command::new("sudo");
                cmd.args(["firewall-cmd", "--reload"]);
                let _ = self.executor.execute(cmd).await;
            }
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn provision_windows_openssl(&self) -> anyhow::Result<()> {
        if self.command_exists_win("openssl").await {
            info!("OpenSSL already available on Windows.");
            return Ok(());
        }

        info!("OpenSSL not found. Attempting non-interactive install via winget...");
        
        // IDs to try in order
        let ids = ["ShiningLight.OpenSSL", "ShiningLight.OpenSSL.PostgreSQL", "OpenSSL.OpenSSL"];
        
        for id in ids {
            info!("Attempting winget install: {}...", id);
            let mut cmd = Command::new("winget");
            cmd.args(["install", "--id", id, "--silent", "--accept-package-agreements", "--accept-source-agreements"]);
            
            // We use executor.execute here
            match self.executor.execute(cmd).await {
                Ok(output) => {
                    if output.status.success() {
                        if self.command_exists_win("openssl").await {
                            info!("OpenSSL installer (ID: {}) finished successfully.", id);
                            return Ok(());
                        }
                    }
                }
                Err(_) => {}
            }
        }
        
        // 2. Fallback to direct download from slproweb.com
        info!("OpenSSL winget entries failed. Using direct download from slproweb.com...");
        
        let urls = [
            ("Win64 Full EXE", "https://slproweb.com/download/Win64OpenSSL-4_0_0.exe"),
            ("Win64 Full MSI", "https://slproweb.com/download/Win64OpenSSL-4_0_0.msi"),
            ("Win32 Light MSI", "https://slproweb.com/download/Win32OpenSSL_Light-4_0_0.msi"),
            ("Win32 Light EXE", "https://slproweb.com/download/Win32OpenSSL_Light-4_0_0.exe"),
        ];

        for (name, url) in urls {
            info!("Attempting direct download of {}: {}...", name, url);
            let is_msi = url.ends_with(".msi");
            let installer_path = std::env::temp_dir().join(if is_msi { "openssl.msi" } else { "openssl.exe" });
            
            if self.download_with_resume(url, &installer_path).await.is_ok() {
                info!("OpenSSL {} downloaded. Running silent setup...", name);
                let res = if is_msi {
                    self.exec_with_retry("msiexec", &["/i", &installer_path.to_string_lossy(), "/qn", "/norestart"], &format!("OpenSSL {} Installation", name), 2).await
                } else {
                    self.exec_with_retry(&installer_path.to_string_lossy(), &["/verysilent", "/sp-", "/suppressmsgboxes", "/norestart"], &format!("OpenSSL {} Installation", name), 2).await
                };

                if res.is_ok() {
                    let _ = std::fs::remove_file(&installer_path);
                    if self.command_exists_win("openssl").await {
                        info!("OpenSSL {} installed successfully.", name);
                        // Validation step
                        let mut verify_cmd = Command::new("openssl");
                        verify_cmd.arg("version");
                        if let Ok(output) = self.executor.execute(verify_cmd).await {
                            if output.status.success() {
                                info!("Validated OpenSSL: {}", String::from_utf8_lossy(&output.stdout).trim());
                                return Ok(());
                            }
                        }
                    }
                }
                let _ = std::fs::remove_file(&installer_path);
            } else {
                warn!("Failed to download {} from {}.", name, url);
            }
        }

        Err(anyhow::anyhow!(
            "Failed to install OpenSSL via winget or direct download variants. Please install manually from https://slproweb.com/products/Win32OpenSSL.html"
        ))
    }

    /// Helper to execute a command with a specified number of retries.
    async fn exec_with_retry(&self, program: &str, args: &[&str], name: &str, retries: usize) -> anyhow::Result<()> {
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
                Ok(output) => last_error = Some(anyhow::anyhow!("Command '{}' failed with status: {}", name, output.status)),
                Err(e) => last_error = Some(anyhow::anyhow!("Execution error for '{}': {}", name, e)),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Failed {} after {} retries", name, retries)))
    }

    #[cfg(target_os = "windows")]
    async fn command_exists_win(&self, cmd: &str) -> bool {
        let mut check_cmd = Command::new("where");
        check_cmd.arg(cmd);
        self.executor.execute(check_cmd).await
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
            self.executor.execute(check_cmd).await
                .map(|o| o.status.success())
                .unwrap_or(false)
        }
    }

    #[cfg(target_os = "linux")]
    async fn provision_linux_openssl(&self) -> anyhow::Result<()> {
        if self.command_exists("openssl").await {
            info!("OpenSSL already available on Linux.");
            return Ok(());
        }

        warn!("OpenSSL not found. Attempting Linux package installation...");
        let candidates: &[(&str, &[&str])] = &[
            ("sudo", &["apt-get", "update"]),
            ("sudo", &["apt-get", "install", "-y", "openssl", "libssl-dev"]),
            ("sudo", &["dnf", "install", "-y", "openssl", "openssl-devel"]),
            ("sudo", &["yum", "install", "-y", "openssl", "openssl-devel"]),
            ("sudo", &["zypper", "--non-interactive", "install", "openssl", "libopenssl-devel"]),
        ];

        for (bin, args) in candidates {
            let mut cmd = Command::new(bin);
            cmd.args(*args);
            match self.executor.execute(cmd).await {
                Ok(output) => {
                    if output.status.success() && self.command_exists("openssl").await {
                        info!("Installed OpenSSL using: {} {}", bin, args.join(" "));
                        return Ok(());
                    }
                }
                _ => continue,
            }
        }

        Err(anyhow::anyhow!(
            "Failed to install OpenSSL on Linux. Please install 'openssl' manually using your package manager."
        ))
    }

    #[cfg(target_os = "macos")]
    async fn provision_macos_openssl(&self) -> anyhow::Result<()> {
        if self.command_exists("openssl").await || self.command_exists("/usr/local/opt/openssl/bin/openssl").await {
            info!("OpenSSL already available on macOS.");
            return Ok(());
        }

        let has_brew = self.command_exists("brew").await;
        if has_brew {
            let mut cmd = Command::new("brew");
            cmd.args(["install", "openssl"]);
            let output = self.executor.execute(cmd).await?;
            if output.status.success() {
                info!("OpenSSL installed via Homebrew.");
                return Ok(());
            }
        }

        Err(anyhow::anyhow!(
            "Failed to install OpenSSL on macOS. Install via Homebrew (`brew install openssl`) or manually."
        ))
    }

    /// Windows: Install Sysmon
    #[cfg(target_os = "windows")]
    async fn provision_windows(&self) -> anyhow::Result<()> {
        info!("Provisioning Windows telemetry (Sysmon)...");
        
        let config_dir = Path::new("config");
        if !config_dir.exists() {
            let _ = std::fs::create_dir_all(config_dir);
        }
        
        // Requirement: Sysmon must use latest SwiftOnSecurity config downloaded at start
        let user_cfg_url = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml";
        let cfg_fallback = config_dir.join("sysmonconfig-export.xml");
        
        info!("Downloading latest Sysmon configuration from SwiftOnSecurity GitHub...");
        if let Err(e) = self.download_with_resume(user_cfg_url, &cfg_fallback).await {
            warn!("Failed to download latest Sysmon config: {}. Will use existing or default if available.", e);
        }

        let cfg_primary = config_dir.join("config.xml");
        let config = if cfg_primary.is_file() {
            Some(cfg_primary.as_path())
        } else if cfg_fallback.is_file() {
            Some(cfg_fallback.as_path())
        } else {
            None
        };
        self.ensure_windows_sysmon(config).await
    }

    #[cfg(target_os = "windows")]
    async fn ensure_windows_sysmon(&self, config_path: Option<&Path>) -> anyhow::Result<()> {
        let binary = self.ensure_sysmon_binary().await?;
        self.fix_wrong_arch_sysmon(&binary).await;
        let is_installed = self.sysmon_service_active().await;

        if is_installed {
            info!("Sysmon is already active.");
            if let Some(cfg) = config_path {
                info!("Updating Sysmon config from {}...", cfg.display());
                self.run_sysmon_with_repair(&binary, &["-accepteula", "-c"], Some(cfg)).await?;
                info!("Sysmon config updated successfully.");
            }
            return Ok(());
        }

        info!("Installing Sysmon...");
        if let Some(cfg) = config_path {
            info!("Using Sysmon config {}", cfg.display());

            // Preferred documented form: sysmon64 -accepteula -i <configfile>
            if self
                .run_sysmon_with_repair(&binary, &["-accepteula", "-i"], Some(cfg))
                .await
                .is_ok()
            {
                info!("Sysmon installed successfully with config.");
                return Ok(());
            }

            // Fallback: install default then apply config
            if self
                .run_sysmon_with_repair(&binary, &["-accepteula", "-i"], None)
                .await
                .is_ok()
                && self
                    .run_sysmon_with_repair(&binary, &["-accepteula", "-c"], Some(cfg))
                    .await
                    .is_ok()
                {
                    info!("Sysmon installed and config applied successfully.");
                    return Ok(());
                }
        } else if self
            .run_sysmon_with_repair(&binary, &["-accepteula", "-i"], None)
            .await
            .is_ok()
        {
            info!("Sysmon installed successfully.");
            return Ok(());
        }

        Err(anyhow::anyhow!("Sysmon installation failed."))
    }

    #[cfg(target_os = "windows")]
    async fn run_sysmon_with_repair(
        &self,
        binary: &Path,
        args: &[&str],
        cfg: Option<&Path>,
    ) -> anyhow::Result<()> {
        self.run_sysmon_with_repair_once(binary, args, cfg, true).await
    }

    #[cfg(target_os = "windows")]
    async fn run_sysmon_with_repair_once(
        &self,
        binary: &Path,
        args: &[&str],
        cfg: Option<&Path>,
        allow_repair: bool,
    ) -> anyhow::Result<()> {
        let mut current_allow_repair = allow_repair;
        let mut current_args = args;
        
        loop {
            let mut cmd = Command::new(binary);
            cmd.args(current_args);
            if let Some(c) = cfg {
                cmd.arg(c);
            }
            let output = self.executor.execute(cmd).await?;
            if output.status.success() {
                return Ok(());
            }

            let mut combined = String::new();
            combined.push_str(&String::from_utf8_lossy(&output.stdout));
            combined.push('\n');
            combined.push_str(&String::from_utf8_lossy(&output.stderr));
            let combined_lc = combined.to_ascii_lowercase();

            if current_allow_repair && combined_lc.contains("already registered") {
                warn!("Sysmon reports an already-registered driver. Reinstalling (uninstall force -> install/update)...");
                let mut uninstall_cmd = Command::new(binary);
                uninstall_cmd.args(["-accepteula", "-u", "force"]);
                let status = self.executor.execute(uninstall_cmd).await?.status;
                if !status.success() {
                    return Err(anyhow::anyhow!(
                        "Sysmon uninstall (force) failed while recovering from registered driver state."
                    ));
                }
                current_allow_repair = false;
                continue;
            }

            return Err(anyhow::anyhow!("Sysmon command failed: {}", combined.trim()));
        }
    }

    #[cfg(target_os = "windows")]
    fn is_64bit_os() -> bool {
        std::env::var("PROCESSOR_ARCHITECTURE")
            .map(|a| a.eq_ignore_ascii_case("AMD64") || a.eq_ignore_ascii_case("ARM64"))
            .unwrap_or(cfg!(target_pointer_width = "64"))
    }

    #[cfg(target_os = "windows")]
    async fn sysmon_service_active(&self) -> bool {
        let svc = if Self::is_64bit_os() { "Sysmon64" } else { "Sysmon" };
        let mut cmd = Command::new("sc");
        cmd.args(["query", svc]);
        let output = self.executor.execute(cmd).await;
        match output {
            Ok(o) if o.status.success() => {
                let text = String::from_utf8_lossy(&o.stdout);
                text.contains("RUNNING")
            }
            _ => false,
        }
    }

    /// Detect a stuck 32-bit Sysmon on 64-bit OS and remove it.
    #[cfg(target_os = "windows")]
    async fn fix_wrong_arch_sysmon(&self, binary_64: &Path) {
        if !Self::is_64bit_os() {
            return;
        }
        let mut check_cmd = Command::new("sc");
        check_cmd.args(["query", "Sysmon"]);
        let query = self.executor.execute(check_cmd).await;
        let has_32bit_svc = query.map(|o| o.status.success()).unwrap_or(false);
        if !has_32bit_svc {
            return;
        }
        warn!(
            "Found 32-bit Sysmon service on 64-bit OS (causes Error 1067). \
             Uninstalling to replace with Sysmon64..."
        );
        let mut uninstall_cmd = Command::new(binary_64);
        uninstall_cmd.args(["-accepteula", "-u", "force"]);
        let _ = self.executor.execute(uninstall_cmd).await;
    }

    #[cfg(target_os = "windows")]
    async fn ensure_sysmon_binary(&self) -> anyhow::Result<std::path::PathBuf> {
        let is_64 = Self::is_64bit_os();
        let (required, alt) = if is_64 {
            ("Sysmon64.exe", "Sysmon.exe")
        } else {
            ("Sysmon.exe", "Sysmon64.exe")
        };

        let required_path = osoosi_types::resolve_sysmon_path();
        if required_path.exists() {
            return Ok(required_path);
        }

        if !is_64 {
            let alt_path = Path::new(alt);
            if alt_path.exists() {
                return Ok(alt_path.to_path_buf());
            }
        }

        warn!(
            "{} not found in current directory. Downloading from Microsoft Sysinternals...",
            required
        );

        let zip_path = Path::new("Sysmon.zip");
        self.download_with_resume("https://download.sysinternals.com/files/Sysmon.zip", zip_path).await?;

        info!("Extracting Sysmon...");
        let cmd_str = format!("Expand-Archive -Path '{}' -DestinationPath '.' -Force; Remove-Item '{}'", zip_path.display(), zip_path.display());
        self.exec_with_retry("powershell", &["-NoProfile", "-NonInteractive", "-Command", &cmd_str], "Sysmon Extraction", 2).await?;
        info!("Sysmon downloaded and extracted successfully.");

        if required_path.exists() {
            info!("Using {} (64-bit: {})", required, is_64);
            Ok(required_path.to_path_buf())
        } else {
            Err(anyhow::anyhow!(
                "Sysmon downloaded, but {} was not found after extraction. \
                 On 64-bit Windows, Sysmon64.exe is required.",
                required
            ))
        }
    }

    #[cfg(target_os = "windows")]
    async fn provision_windows_clamav(&self) -> anyhow::Result<()> {
        if self.windows_clam_available() {
            info!("ClamAV already available on Windows.");
            return Ok(());
        }

        let version = std::env::var("OSOOSI_CLAMAV_VERSION").unwrap_or_else(|_| "1.5.2".to_string());
        let arch_flavor = if cfg!(target_arch = "aarch64") {
            "win.arm64"
        } else if cfg!(target_arch = "x86") {
            "win.win32"
        } else {
            "win.x64"
        };
        let default_url = format!(
            "https://www.clamav.net/downloads/production/clamav-{}.{}.msi",
            version, arch_flavor
        );
        let download_url = std::env::var("OSOOSI_CLAMAV_URL_WINDOWS").unwrap_or(default_url);
        let installer_path = std::env::temp_dir().join("osoosi-clamav.msi");
        let installer_path_str = installer_path.to_string_lossy().to_string();

        info!("ClamAV not found. Downloading installer from official ClamAV downloads...");
        self.download_with_resume(&download_url, &installer_path).await?;

        info!("Installing ClamAV silently...");
        self.exec_with_retry("msiexec", &["/i", &installer_path_str, "/qn", "/norestart"], "ClamAV Installation", 2).await?;

        let _ = std::fs::remove_file(&installer_path);

        if self.windows_clam_available() {
            info!("ClamAV installed successfully on Windows.");
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "ClamAV install finished, but clamscan was not detected. Ensure ClamAV bin folder is on PATH."
            ))
        }
    }

    #[cfg(target_os = "windows")]
    fn windows_clam_available(&self) -> bool {
        if Command::new("where")
            .arg("clamscan")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return true;
        }

        let mut candidates = Vec::new();
        if let Ok(pf) = std::env::var("ProgramFiles") {
            candidates.push(Path::new(&pf).join("ClamAV").join("clamscan.exe"));
        }
        if let Ok(pf86) = std::env::var("ProgramFiles(x86)") {
            candidates.push(Path::new(&pf86).join("ClamAV").join("clamscan.exe"));
        }
        candidates.iter().any(|p| p.is_file())
    }

    /// Linux: Install Auditd
    #[cfg(target_os = "linux")]
    async fn provision_linux(&self) -> anyhow::Result<()> {
        info!("Provisioning Linux telemetry (Sysmon for Linux)...");
        let default_cfg = Path::new("config").join("sysmonconfig-export.xml");
        let config = default_cfg.as_path().is_file().then_some(default_cfg.as_path());

        if !self.linux_sysmon_installed().await {
            self.install_linux_sysmon_package().await?;
        }

        // Ensure daemon is started on boot and running now.
        let mut enable_cmd = Command::new("sudo");
        enable_cmd.args(["systemctl", "enable", "--now", "sysmon"]);
        let _ = self.executor.execute(enable_cmd).await;

        if let Some(cfg) = config {
            info!("Applying Sysmon for Linux config from {}...", cfg.display());
            self.apply_linux_sysmon_config(cfg).await?;
        }

        info!("Sysmon for Linux provisioning complete.");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn linux_sysmon_installed(&self) -> bool {
        let mut check_cmd = Command::new("sh");
        check_cmd.args(["-c", "command -v sysmon >/dev/null 2>&1"]);
        let has_sysmon_cmd = self.executor.execute(check_cmd).await
            .map(|s| s.status.success())
            .unwrap_or(false);
        let has_opt_sysmon = Path::new("/opt/sysmon/sysmon").exists();
        has_sysmon_cmd || has_opt_sysmon
    }

    #[cfg(target_os = "linux")]
    async fn install_linux_sysmon_package(&self) -> anyhow::Result<()> {
        warn!("Sysmon for Linux not found. Attempting package installation...");
        if let Err(e) = self.setup_linux_microsoft_repo().await {
            warn!("Microsoft Linux repo bootstrap failed (continuing anyway): {}", e);
        }

        // Try known package managers and common package names.
        let candidates: &[(&str, &[&str])] = &[
            ("sudo", &["apt-get", "update"]),
            ("sudo", &["apt-get", "install", "-y", "sysmonforlinux"]),
            ("sudo", &["apt-get", "install", "-y", "sysmon"]),
            ("sudo", &["dnf", "install", "-y", "sysmonforlinux"]),
            ("sudo", &["dnf", "install", "-y", "sysmon"]),
            ("sudo", &["yum", "install", "-y", "sysmonforlinux"]),
            ("sudo", &["yum", "install", "-y", "sysmon"]),
            ("sudo", &["zypper", "--non-interactive", "install", "sysmonforlinux"]),
            ("sudo", &["zypper", "--non-interactive", "install", "sysmon"]),
        ];

        for (bin, args) in candidates {
            let mut cmd = Command::new(bin);
            cmd.args(*args);
            if let Ok(output) = self.executor.execute(cmd).await {
                if output.status.success() && self.linux_sysmon_installed().await {
                    info!("Installed Sysmon for Linux using: {} {}", bin, args.join(" "));
                    return Ok(());
                }
            }
        }

        Err(anyhow::anyhow!(
            "Failed to install Sysmon for Linux. Ensure Microsoft Linux repositories are configured, \
             then install package 'sysmonforlinux' (or 'sysmon') and rerun provisioning."
        ))
    }

    #[cfg(target_os = "linux")]
    async fn setup_linux_microsoft_repo(&self) -> anyhow::Result<()> {
        // Debian/Ubuntu family: use Microsoft bootstrap .deb package.
        if self.command_exists("apt-get").await {
            let apt_repo = Path::new("/etc/apt/sources.list.d/microsoft-prod.list");
            if !apt_repo.exists() {
                info!("Bootstrapping Microsoft apt repository...");
                let mut bootstrap_cmd = Command::new("sh");
                bootstrap_cmd.args([
                    "-c",
                    "set -e; . /etc/os-release; \
                     curl -fsSL \"https://packages.microsoft.com/config/${ID}/${VERSION_ID}/packages-microsoft-prod.deb\" \
                     -o /tmp/packages-microsoft-prod.deb; \
                     sudo dpkg -i /tmp/packages-microsoft-prod.deb; \
                     rm -f /tmp/packages-microsoft-prod.deb",
                ]);
                let status = self.executor.execute(bootstrap_cmd).await?.status;
                if !status.success() {
                    return Err(anyhow::anyhow!("Failed to bootstrap Microsoft apt repository."));
                }
            }
            let mut update_cmd = Command::new("sudo");
            update_cmd.args(["apt-get", "update"]);
            let _ = self.executor.execute(update_cmd).await;
            return Ok(());
        }

        // RHEL/Fedora family: create Microsoft yum/dnf repo file.
        if self.command_exists("dnf").await || self.command_exists("yum").await {
            let yum_repo = Path::new("/etc/yum.repos.d/microsoft-prod.repo");
            if !yum_repo.exists() {
                info!("Bootstrapping Microsoft yum/dnf repository...");
                let mut bootstrap_cmd = Command::new("sh");
                bootstrap_cmd.args([
                    "-c",
                    "set -e; sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc; \
                     printf '[packages-microsoft-com-prod]\nname=packages-microsoft-com-prod\nbaseurl=https://packages.microsoft.com/rhel/$releasever/prod/\nenabled=1\ngpgcheck=1\ngpgkey=https://packages.microsoft.com/keys/microsoft.asc\n' \
                     | sudo tee /etc/yum.repos.d/microsoft-prod.repo >/dev/null",
                ]);
                let status = self.executor.execute(bootstrap_cmd).await?.status;
                if !status.success() {
                    return Err(anyhow::anyhow!("Failed to bootstrap Microsoft yum/dnf repository."));
                }
            }
            if self.command_exists("dnf").await {
                let mut makecache_cmd = Command::new("sudo");
                makecache_cmd.args(["dnf", "makecache"]);
                let _ = self.executor.execute(makecache_cmd).await;
            } else {
                let mut makecache_cmd = Command::new("sudo");
                makecache_cmd.args(["yum", "makecache"]);
                let _ = self.executor.execute(makecache_cmd).await;
            }
            return Ok(());
        }

        Err(anyhow::anyhow!(
            "Unsupported Linux package manager for automatic Microsoft repo bootstrap."
        ))
    }

    #[cfg(target_os = "linux")]
    async fn command_exists(&self, cmd: &str) -> bool {
        let mut check_cmd = Command::new("sh");
        check_cmd.args(["-c", &format!("command -v {} >/dev/null 2>&1", cmd)]);
        self.executor.execute(check_cmd).await
            .map(|s| s.status.success())
            .unwrap_or(false)
    }

    #[cfg(target_os = "linux")]
    async fn apply_linux_sysmon_config(&self, cfg: &Path) -> anyhow::Result<()> {
        let mut primary_cmd = Command::new("sudo");
        primary_cmd.args(["sysmon", "-c"]).arg(cfg);
        if let Ok(output) = self.executor.execute(primary_cmd).await {
            if output.status.success() {
                return Ok(());
            }
        }

        let mut fallback_cmd = Command::new("sudo");
        fallback_cmd.args(["/opt/sysmon/sysmon", "-c"]).arg(cfg);
        let status = self.executor.execute(fallback_cmd).await?.status;
        if status.success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Failed to apply Sysmon for Linux config."))
        }
    }

    #[cfg(target_os = "linux")]
    async fn provision_linux_clamav(&self) -> anyhow::Result<()> {
        if self.command_exists("clamscan").await {
            info!("ClamAV already available on Linux.");
            return Ok(());
        }

        warn!("ClamAV not found. Attempting Linux package installation...");
        let candidates: &[(&str, &[&str])] = &[
            ("sudo", &["apt-get", "update"]),
            ("sudo", &["apt-get", "install", "-y", "clamav", "clamav-daemon"]),
            ("sudo", &["dnf", "install", "-y", "clamav", "clamav-update"]),
            ("sudo", &["yum", "install", "-y", "clamav", "clamav-update"]),
            ("sudo", &["zypper", "--non-interactive", "install", "clamav"]),
        ];

        for (bin, args) in candidates {
            let mut cmd = Command::new(bin);
            cmd.args(*args);
            if let Ok(output) = self.executor.execute(cmd).await {
                if output.status.success() && self.command_exists("clamscan").await {
                    let mut freshclam_cmd = Command::new("sudo");
                    freshclam_cmd.args(["systemctl", "enable", "--now", "clamav-freshclam"]);
                    let _ = self.executor.execute(freshclam_cmd).await;
                    info!("Installed ClamAV using: {} {}", bin, args.join(" "));
                    return Ok(());
                }
            }
        }

        Err(anyhow::anyhow!(
            "Failed to install ClamAV on Linux. Install from distro packages or official binaries: https://www.clamav.net/downloads"
        ))
    }

    /// macOS: Check for Endpoint Security
    #[cfg(target_os = "macos")]
    async fn provision_macos(&self) -> anyhow::Result<()> {
        info!("Provisioning macOS telemetry (Endpoint Security Framework)...");
        info!("macOS uses native ESF. Ensure the binary is granted Full Disk Access.");
        // No explicit install needed for ESF, it's a kernel feature
        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn provision_macos_clamav(&self) -> anyhow::Result<()> {
        let has_clam = self.command_exists("clamscan").await;
        if has_clam {
            info!("ClamAV already available on macOS.");
            return Ok(());
        }

        let has_brew = self.command_exists("brew").await;
        if has_brew {
            let mut cmd = Command::new("brew");
            cmd.args(["install", "clamav"]);
            let status = self.executor.execute(cmd).await?.status;
            if status.success() {
                info!("ClamAV installed via Homebrew.");
                return Ok(());
            }
        }

        Err(anyhow::anyhow!(
            "Failed to install ClamAV on macOS. Install from Homebrew (`brew install clamav`) or official package: https://www.clamav.net/downloads"
        ))
    }

    /// Legacy support for explicit Sysmon installation (Windows only)
    pub async fn install<P: AsRef<Path>>(&self, binary_path: P, config_path: Option<P>) -> anyhow::Result<()> {
        #[cfg(target_os = "windows")]
        {
            let binary = binary_path.as_ref();
            if !binary.exists() {
                return Err(anyhow::anyhow!("Specified binary {:?} does not exist.", binary));
            }
            let already_installed = self.sysmon_service_active().await;
            let cfg_ref = config_path.as_ref().map(|c| c.as_ref());
            if already_installed {
                self.run_sysmon_with_repair(binary, &["-accepteula", "-c"], cfg_ref).await
            } else {
                self.run_sysmon_with_repair(binary, &["-accepteula", "-i"], cfg_ref).await
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (binary_path, config_path);
            Err(anyhow::anyhow!("Explicit Sysmon installation is only supported on Windows. Use automated provision on this platform."));
        }
    }


    /// Provision FLOSS (FLARE Obfuscated String Solver) for deobfuscating malware strings.
    pub async fn provision_floss(&self) -> anyhow::Result<()> {
        let version = "3.1.1";
        
        #[cfg(target_os = "windows")]
        {
            let floss_exe = osoosi_types::resolve_floss_path();
            if self.command_exists_win("floss").await || floss_exe.exists() {
                info!("FLOSS already available on Windows.");
                return Ok(());
            }

            let url = format!("https://github.com/mandiant/flare-floss/releases/download/v{}/floss-v{}-windows.zip", version, version);
            let target_dir = floss_exe.parent().unwrap_or(&osoosi_types::resolve_tools_dir().join("floss")).to_path_buf();
            let target_dir_str = target_dir.to_string_lossy();

             info!("FLOSS not found. Downloading v{} for Windows...", version);
             let zip_path = target_dir.join("floss.zip");
             
             tokio::fs::create_dir_all(&target_dir).await?;
             self.download_with_resume(&url, &zip_path).await?;

            info!("Extracting FLOSS...");
            let ps_cmd = format!(
                 "New-Item -ItemType Directory -Force -Path '{}' | Out-Null; \
                  Expand-Archive -Path '{}' -DestinationPath '{}' -Force; \
                  Remove-Item '{}'",
                 target_dir_str, zip_path.to_string_lossy(), target_dir_str, zip_path.to_string_lossy()
            );

            self.exec_with_retry("powershell", &["-NoProfile", "-NonInteractive", "-Command", &ps_cmd], "FLOSS Extraction", 2).await?;
            Ok(())
        }

        #[cfg(target_os = "linux")]
        {
            if self.command_exists("floss") {
                info!("FLOSS already available on Linux.");
                return Ok(());
            }

            let url = format!("https://github.com/mandiant/flare-floss/releases/download/v{}/floss-v{}-linux.zip", version, version);
            info!("FLOSS not found. Downloading v{} for Linux...", version);
            
            let status = Command::new("sh").args(["-c", &format!(
                "curl -L -o /tmp/floss.zip {} && sudo unzip -o /tmp/floss.zip -d /usr/local/bin && sudo chmod +x /usr/local/bin/floss && rm /tmp/floss.zip",
                url
            )]).status()?;

            if status.success() {
                info!("FLOSS v{} installed to /usr/local/bin.", version);
                Ok(())
            } else {
                Err(anyhow::anyhow!("Failed to install FLOSS on Linux."))
            }
        }

        #[cfg(target_os = "macos")]
        {
            if self.command_exists("floss") {
                info!("FLOSS already available on macOS.");
                return Ok(());
            }

            let url = format!("https://github.com/mandiant/flare-floss/releases/download/v{}/floss-v{}-macos.zip", version, version);
            info!("FLOSS not found. Downloading v{} for macOS...", version);
            
            let status = Command::new("sh").args(["-c", &format!(
                 "curl -L -o /tmp/floss.zip {} && unzip -o /tmp/floss.zip -d /usr/local/bin && chmod +x /usr/local/bin/floss && rm /tmp/floss.zip",
                 url
            )]).status()?;

            if status.success() {
                info!("FLOSS v{} installed to /usr/local/bin.", version);
                Ok(())
            } else {
                Err(anyhow::anyhow!("Failed to install FLOSS on macOS."))
            }
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Err(anyhow::anyhow!("FLOSS provisioning not supported on this platform."))
        }
    }

    /// Provision HollowsHunter (memory forensics scanner) for detecting in-memory implants.
    /// Detects: process hollowing, DLL injection, reflective PE loading, shellcode, API hooks.
    pub async fn provision_hollows_hunter(&self) -> anyhow::Result<()> {
        let version = "0.4.1.1";

        #[cfg(target_os = "windows")]
        {
            let exe_path = osoosi_types::resolve_hollows_hunter_path();
            let target_dir = exe_path.parent().unwrap_or(&osoosi_types::resolve_tools_dir().join("hollows_hunter")).to_path_buf();
            let target_dir_str = target_dir.to_string_lossy();
            
            if exe_path.exists() {
                info!("HollowsHunter already available at {}.", exe_path.display());
                return Ok(());
            }

            let url = format!(
                "https://github.com/hasherezade/hollows_hunter/releases/download/v{}/hollows_hunter64.zip",
                version
            );

             info!("HollowsHunter not found. Downloading v{} for Windows (64-bit)...", version);
             let zip_path = target_dir.join("hh.zip");
             
             tokio::fs::create_dir_all(&target_dir).await?;
             self.download_with_resume(&url, &zip_path).await?;

            info!("Extracting HollowsHunter...");
            let cmd_str = format!("Expand-Archive -Path '{}' -DestinationPath '{}' -Force", zip_path.display(), target_dir.display());
            self.exec_with_retry("powershell", &["-NoProfile", "-NonInteractive", "-Command", &cmd_str], "HollowsHunter Extraction", 2).await?;
            Ok(())
        }

        #[cfg(target_os = "linux")]
        {
            if self.command_exists("hollows_hunter") {
                info!("HollowsHunter already available on Linux.");
                return Ok(());
            }

            // HollowsHunter is Windows-only; on Linux we use pe-sieve via Wine or skip
            info!("HollowsHunter is Windows-native. On Linux, memory forensics uses /proc/<pid>/maps scanning.");
            Ok(())
        }

        #[cfg(target_os = "macos")]
        {
            info!("HollowsHunter is Windows-native. On macOS, memory forensics uses vmmap-based scanning.");
            Ok(())
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Err(anyhow::anyhow!("HollowsHunter provisioning not supported on this platform."))
        }
    }

    /// Provision ngrep (network grep) for deep packet inspection on Windows.
    pub async fn provision_ngrep(&self) -> anyhow::Result<()> {
        #[cfg(target_os = "windows")]
        {
            let exe_path = osoosi_types::resolve_ngrep_path();
            let target_dir = exe_path.parent().unwrap_or(&osoosi_types::resolve_tools_dir().join("ngrep")).to_path_buf();
            let target_dir_str = target_dir.to_string_lossy();

            if exe_path.exists() {
                info!("ngrep already available at {}.", exe_path.display());
                return Ok(());
            }

            let version = "1.49.0";
            let url = format!(
                "https://github.com/jpr5/ngrep/releases/download/v{}/ngrep-windows-x86_64.zip",
                version
            );

             info!("ngrep not found. Downloading v{} for Windows...", version);
             let zip_path = target_dir.join("ngrep.zip");
             
             tokio::fs::create_dir_all(&target_dir).await?;
             self.download_with_resume(&url, &zip_path).await?;

            info!("Extracting ngrep...");
            let cmd_str = format!("Expand-Archive -Path '{}' -DestinationPath '{}' -Force", zip_path.display(), target_dir.display());
            self.exec_with_retry("powershell", &["-NoProfile", "-NonInteractive", "-Command", &cmd_str], "ngrep Extraction", 2).await?;
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok(()) // Non-windows uses sniffglue
        }
    }

    /// Provision Npcap (packet capture driver) required for ngrep on Windows.
    pub async fn provision_npcap(&self) -> anyhow::Result<()> {
        #[cfg(target_os = "windows")]
        {
            // Check if npcap is likely installed by looking for the driver or dll
            let system32 = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
            let wpcap_dll = std::path::Path::new(&system32).join("System32").join("wpcap.dll");
            
            if wpcap_dll.exists() {
                info!("Npcap (or WinPcap) detected via wpcap.dll. Skipping install.");
                return Ok(());
            }

            let url = "https://npcap.com/dist/npcap-1.78.exe";
            let installer_path = std::env::temp_dir().join("npcap-installer.exe");

            info!("Npcap not detected. Downloading official installer...");
            self.download_with_resume(url, &installer_path).await?;

            info!("Installing Npcap silently (requires Elevation)...");
            // /S = Silent, /admin_only=1, /dot11_support=0, /loopback_support=1
            self.exec_with_retry(installer_path.to_str().unwrap(), &["/S", "/admin_only=1", "/dot11_support=0", "/loopback_support=1"], "Npcap Installation", 2).await?;
            let _ = std::fs::remove_file(&installer_path);
            
            info!("Npcap installed successfully.");
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok(())
        }
    }

    /// Provision sniffglue (sandboxed network sniffer) for deep packet inspection on Unix.
    pub async fn provision_sniffglue(&self) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            if self.command_exists("sniffglue").await {
                info!("sniffglue already available on Linux.");
                return Ok(());
            }

            warn!("sniffglue not found. Attempting Linux package installation...");
            let candidates: &[(&str, &[&str])] = &[
                ("sudo", &["apt-get", "update"]),
                ("sudo", &["apt-get", "install", "-y", "sniffglue"]),
                ("sudo", &["dnf", "install", "-y", "sniffglue"]),
                ("sudo", &["yum", "install", "-y", "sniffglue"]),
            ];

            for (bin, args) in candidates {
                let mut cmd = Command::new(bin);
                cmd.args(*args);
                if let Ok(output) = self.executor.execute(cmd).await {
                    if output.status.success() && self.command_exists("sniffglue").await {
                        info!("Installed sniffglue using: {} {}", bin, args.join(" "));
                        return Ok(());
                    }
                }
            }
            
            // Fallback to cargo install
            if self.command_exists("cargo").await {
                info!("Package managers failed. Attempting cargo install sniffglue...");
                let mut cmd = Command::new("cargo");
                cmd.args(["install", "sniffglue"]);
                let status = self.executor.execute(cmd).await?.status;
                if status.success() {
                    return Ok(());
                }
            }

            Err(anyhow::anyhow!("Failed to install sniffglue on Linux."))
        }
        #[cfg(target_os = "macos")]
        {
            if self.command_exists("sniffglue").await {
                info!("sniffglue already available on macOS.");
                return Ok(());
            }

            if self.command_exists("brew").await {
                info!("Installing sniffglue via Homebrew...");
                let mut cmd = Command::new("brew");
                cmd.args(["install", "sniffglue"]);
                let status = self.executor.execute(cmd).await?.status;
                if status.success() {
                    return Ok(());
                }
            }

            Err(anyhow::anyhow!("Failed to install sniffglue on macOS."))
        }
        #[cfg(target_os = "windows")]
        {
            Ok(()) // Windows uses ngrep
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
             Err(anyhow::anyhow!("sniffglue provisioning not supported on this platform."))
        }
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
                let _ = std::fs::create_dir_all(&target_sub_dir);
            }

            // Only download if the subfolder is empty
            if let Ok(entries) = std::fs::read_dir(&target_sub_dir) {
                if entries.filter_map(|e| e.ok()).count() > 1 {
                    info!("YARA rules for '{}' already present at {}.", name, target_sub_dir.display());
                    continue;
                }
            }

            info!("YARA rules for '{}' missing. Downloading from {}...", name, url);
            let zip_path = target_sub_dir.join(format!("{}_temp.zip", name));
            
            // Use resumable downloader
            self.download_with_resume(url, &zip_path).await?;

            info!("Extracting YARA '{}' rules...", name);
            let tmp_extract = target_sub_dir.join(format!("{}_tmp_extract", name));

            #[cfg(target_os = "windows")]
            {
                let ps_cmd = format!(
                    "$ProgressPreference='SilentlyContinue'; \
                     if (Test-Path '{}') {{ Remove-Item -Recurse -Force '{}' -ErrorAction SilentlyContinue }} \
                     Expand-Archive -Path '{}' -DestinationPath '{}' -Force; \
                     $subdirs = Get-ChildItem -Path '{}' -Directory; \
                     if ($subdirs.Count -eq 1) {{ \
                        Copy-Item -Path \"$($subdirs[0].FullName)\\*\" -Destination '{}' -Recurse -Force; \
                     }} else {{ \
                        Copy-Item -Path \"{}/*\" -Destination '{}' -Recurse -Force; \
                     }} \
                     Remove-Item -Recurse -Force '{}'",
                     tmp_extract.to_string_lossy(), tmp_extract.to_string_lossy(), zip_path.to_string_lossy(), tmp_extract.to_string_lossy(), tmp_extract.to_string_lossy(), target_sub_dir.to_string_lossy(), tmp_extract.to_string_lossy(), target_sub_dir.to_string_lossy(), tmp_extract.to_string_lossy()
                );
                
                self.exec_with_retry("powershell", &["-NoProfile", "-NonInteractive", "-Command", &ps_cmd], &format!("Extract YARA {}", name), 2).await?;
            }
            #[cfg(not(target_os = "windows"))]
            {
                 let sh_cmd = format!(
                    "unzip -o {} -d {} && cp -r {}/*/* {}/ && rm -rf {}",
                    zip_path.to_string_lossy(), tmp_extract.to_string_lossy(), tmp_extract.to_string_lossy(), target_sub_dir.to_string_lossy(), tmp_extract.to_string_lossy()
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
    pub async fn download_with_resume(&self, url: &str, dest: &std::path::Path) -> anyhow::Result<()> {
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
            let ps_cmd = format!("Add-MpPreference -ExclusionPath '{}' -ErrorAction SilentlyContinue", path_str);
            
            let mut cmd = Command::new("powershell");
            cmd.args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd]);
            let status = self.executor.execute(cmd).await?.status;
            
            if status.success() {
                info!("Windows Defender exclusion added successfully.");
                Ok(())
            } else {
                warn!("Failed to add Defender exclusion. This typically requires Administrator privileges.");
                Err(anyhow::anyhow!("Defender exclusion failed (check privileges)."))
            }
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

    fn sanitize_yara_rules_internal(&self, dir: &std::path::Path, seen_rules: &mut std::collections::HashSet<String>) -> anyhow::Result<()> {
        use std::path::Path;
        if !dir.exists() { return Ok(()); }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                let _ = self.sanitize_yara_rules_internal(&path, seen_rules);
            } else if path.extension().map_or(false, |e| e == "yar" || e == "yara") {
                // Use lossy reading to handle potential encoding issues in malware rules
                if let Ok(bytes) = std::fs::read(&path) {
                    let raw_content = String::from_utf8_lossy(&bytes);
                    // Pre-pass: fix unclosed block comments where */ was written as *\/
                    let content = raw_content.replace("*\\/", "*/");
                    let content_lower = content.to_lowercase();

                    let has_andro = content_lower.contains("import \"androguard\"") || content_lower.contains("import 'androguard'");
                    let has_crash = content.contains("pe.exports(\"Crash\")") && content.contains("& pe.characteristics");
                    let has_include = content.contains("include \"") || content.contains("include '");
                    let has_empty_regex = (content.contains("|/") || content.contains("| /")) && content.contains('=');
                    let has_backslash = content.contains('\\');
                    let has_unclosed_repetition = content.contains("?{") || content.contains("? {") || content.contains("?  {");
                    let has_unk_identifier = (content.contains("filename") || content.contains("filetype")) && (content.contains("==") || content.contains("!="));
                    let has_duplicate_maze = path.to_string_lossy().contains("RANSOM_Maze.yar") && content.matches("rule Maze").count() > 1;
                    let has_broken_comment = raw_content.contains("*\\/");

                    if has_andro || has_crash || has_include || has_empty_regex || has_backslash || has_unclosed_repetition || has_duplicate_maze || has_unk_identifier || has_broken_comment {
                        let mut lines = Vec::new();
                        let mut changed = false;
                        if has_broken_comment { changed = true; }
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
                            if (trimmed.starts_with("import") || trimmed.starts_with("//import")) && trimmed.contains("androguard") {
                                new_line = format!("// {}", line);
                                changed = true;
                            }
                            // 2. Fix APT_CrashOverride.yar type mismatch (boolean & int)
                            else if (line.contains("pe.exports(\"Crash\")") || line.contains("pe.exports(\"crash\")")) && line.contains("& pe.characteristics") {
                                new_line = line.replace("pe.exports(\"Crash\")", "pe.exports(\"Crash\") != false")
                                              .replace("pe.exports(\"crash\")", "pe.exports(\"crash\") != false")
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
                                        let alt_path = parent.parent().unwrap_or(Path::new(".")).join(inc_path_str);
                                        if !alt_path.exists() {
                                            new_line = format!("// {}", line);
                                            changed = true;
                                        }
                                    }
                                }
                            }
                            // 4. Fix empty regex matches
                            else if (trimmed.contains("|/") || trimmed.contains("| /")) && trimmed.contains('=') && trimmed.contains('/') {
                                if let Some(idx) = new_line.find("|/") {
                                    new_line.replace_range(idx..idx+1, "");
                                    changed = true;
                                } else if let Some(idx) = new_line.find("| /") {
                                    new_line.replace_range(idx..idx+1, "");
                                    changed = true;
                                }
                            }
                            // 5. Fix unclosed counted repetition
                            else if trimmed.contains('/') && trimmed.contains('=') && (trimmed.contains("?{") || trimmed.contains("? {")) {
                                if new_line.contains("?{") {
                                    new_line = new_line.replace("?{", "?\\{");
                                    changed = true;
                                } else if new_line.contains("? {") {
                                    new_line = new_line.replace("? {", "? \\{");
                                    changed = true;
                                }
                            }
                            // 6. Comment out unknown identifiers (filename, filetype, filepath, extension)
                            else if (lower.contains("filename") || lower.contains("filetype") || lower.contains("filepath") || lower.contains("extension"))
                                     && (lower.contains("==") || lower.contains("!=") || lower.contains("matches") || lower.contains("contains")) {
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
                                    new_line = new_line.replace("= \\{", "= {").replace("=\\{", "={");
                                    changed = true;
                                }
                                if new_line.contains("\\}") && (new_line.contains("= {") || new_line.contains("={")) {
                                    new_line = new_line.replace("\\}", "}");
                                    changed = true;
                                }
                                let chars: Vec<char> = new_line.chars().collect();
                                let mut i = 0;
                                let mut fixed = String::new();
                                let mut esc_changed = false;
                                while i < chars.len() {
                                    if chars[i] == '\\' && i + 1 < chars.len() {
                                        let next = chars[i+1];
                                        let valid = matches!(next,
                                            'n' | 'r' | 't' | '\\' | '\"' | '\'' | 'x' | 'u' | 'U'
                                            | 'd' | 'w' | 's' | 'D' | 'W' | 'S' | 'b' | 'B'
                                            | '0'..='9' | '$' | '^' | '*' | '+' | '?' | '(' | ')'
                                            | '[' | ']' | '{' | '}' | '|' | '.' | '/' | ' '
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
                                        let rule_name = parts[idx+1].trim_end_matches('{').split(':').next().unwrap_or("").trim();
                                        if seen_rules.contains(rule_name) {
                                            let new_rule_name = format!("{}_Duplicate", rule_name);
                                            new_line = new_line.replacen(rule_name, &new_rule_name, 1);
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
    /// Provision CAPA rules, signatures, and standalone binary from Mandiant's GitHub.
    pub async fn provision_capa(&self) -> anyhow::Result<()> {
        let capa_dir = osoosi_types::resolve_capa_dir();
        let rules_dir = osoosi_types::resolve_capa_rules_dir();
        let sigs_dir = osoosi_types::resolve_capa_sigs_dir();

        #[cfg(target_os = "windows")]
        let capa_bin = capa_dir.join("capa.exe");
        #[cfg(not(target_os = "windows"))]
        let capa_bin = capa_dir.join("capa");

        if rules_dir.exists() && sigs_dir.exists() && (capa_bin.exists() || self.command_exists("capa").await) {
            info!("CAPA dependencies already provisioned.");
            return Ok(());
        }

        if !capa_dir.exists() {
            std::fs::create_dir_all(&capa_dir)?;
        }

        let version = "9.4.0";

        // 1. Download Binary if missing
        if !capa_bin.exists() && !self.command_exists("capa").await {
            info!("Downloading CAPA binary (v{})...", version);
            
            #[cfg(target_os = "windows")]
            let url = format!("https://github.com/mandiant/capa/releases/download/v{}/capa-v{}-windows.zip", version, version);
            
            #[cfg(target_os = "linux")]
            let url = {
                let arch = if std::env::consts::ARCH == "aarch64" { "-arm64" } else { "" };
                format!("https://github.com/mandiant/capa/releases/download/v{}/capa-v{}-linux{}.zip", version, version, arch)
            };
            
            #[cfg(target_os = "macos")]
            let url = {
                let arch = if std::env::consts::ARCH == "aarch64" { "-arm64" } else { "" };
                format!("https://github.com/mandiant/capa/releases/download/v{}/capa-v{}-macos{}.zip", version, version, arch)
            };
            
            let zip_path = capa_dir.join("capa_bin.zip");
            
            // Add AV exclusion on Windows before downloading
            #[cfg(target_os = "windows")]
            {
                let exclusion_path = capa_dir.to_string_lossy();
                let ps_cmd = format!("Add-MpPreference -ExclusionPath '{}' -ErrorAction SilentlyContinue", exclusion_path);
                let _ = self.exec_with_retry("powershell", &["-NoProfile", "-Command", &ps_cmd], "AV Exclusion", 1).await;
            }

            self.download_with_resume(&url, &zip_path).await?;
            
            info!("Extracting CAPA binary...");
            #[cfg(target_os = "windows")]
            {
                let cmd_str = format!("Expand-Archive -Path '{}' -DestinationPath '{}' -Force", zip_path.display(), capa_dir.display());
                self.exec_with_retry("powershell", &["-NoProfile", "-NonInteractive", "-Command", &cmd_str], "CAPA Binary Extraction", 2).await?;
                
                // RESILIENCE: Check if extracted into a subfolder and move it out
                let subfolder = capa_dir.join(format!("capa-v{}-windows", version));
                if subfolder.exists() {
                    let sub_bin = subfolder.join("capa.exe");
                    if sub_bin.exists() {
                        let _ = std::fs::rename(sub_bin, &capa_bin);
                    }
                    let _ = std::fs::remove_dir_all(subfolder);
                }
            }
            #[cfg(not(target_os = "windows"))]
            {
                let cmd_str = format!("unzip -o '{}' -d '{}'", zip_path.display(), capa_dir.display());
                let mut cmd = std::process::Command::new("sh");
                cmd.args(["-c", &cmd_str]);
                let _ = self.executor.execute(cmd).await;
                
                // RESILIENCE: Handle subfolder extraction on Linux/Mac
                let os_name = if cfg!(target_os = "macos") { "macos" } else { "linux" };
                let arch_suffix = if std::env::consts::ARCH == "aarch64" { "-arm64" } else { "" };
                let subfolder = capa_dir.join(format!("capa-v{}-{}{}", version, os_name, arch_suffix));
                
                if subfolder.exists() {
                    let sub_bin = subfolder.join("capa");
                    if sub_bin.exists() {
                        let _ = std::fs::rename(sub_bin, &capa_bin);
                    }
                    let _ = std::fs::remove_dir_all(subfolder);
                }
                
                let _ = std::process::Command::new("chmod").args(["+x", &capa_bin.to_string_lossy()]).status();
            }
            let _ = std::fs::remove_file(&zip_path);
        }

        // 2. Download Rules
        if !rules_dir.exists() {
            info!("Downloading CAPA rules (v{})...", version);
            let rules_zip = capa_dir.join("rules.zip");
            let rules_url = format!("https://github.com/mandiant/capa-rules/archive/refs/tags/v{}.zip", version);
            
            self.download_with_resume(&rules_url, &rules_zip).await?;
            
            info!("Extracting CAPA rules...");
            let temp_extract = capa_dir.join("temp_rules");
            let _ = std::fs::create_dir_all(&temp_extract);
            
            #[cfg(target_os = "windows")]
            {
                let cmd_str = format!("Expand-Archive -Path '{}' -DestinationPath '{}' -Force", rules_zip.display(), temp_extract.display());
                self.exec_with_retry("powershell", &["-NoProfile", "-NonInteractive", "-Command", &cmd_str], "CAPA Rules Extraction", 2).await?;
            }
            #[cfg(not(target_os = "windows"))]
            {
                let cmd_str = format!("unzip -o '{}' -d '{}'", rules_zip.display(), temp_extract.display());
                let mut cmd = std::process::Command::new("sh");
                cmd.args(["-c", &cmd_str]);
                let _ = self.executor.execute(cmd).await;
            }
            
            let source = temp_extract.join(format!("capa-rules-{}", version));
            if source.exists() {
                let _ = std::fs::rename(source, &rules_dir);
            }
            
            let _ = std::fs::remove_file(&rules_zip);
            let _ = std::fs::remove_dir_all(&temp_extract);
        }

        // 3. Download Signatures
        if !sigs_dir.exists() {
            info!("Downloading CAPA signatures...");
            let sigs_zip = capa_dir.join("sigs.zip");
            let sigs_url = "https://github.com/mandiant/capa/releases/download/v2.0.0/sigs.zip";
            
            if self.download_with_resume(sigs_url, &sigs_zip).await.is_ok() {
                info!("Extracting CAPA signatures...");
                let _ = std::fs::create_dir_all(&sigs_dir);
                
                #[cfg(target_os = "windows")]
                {
                    let cmd_str = format!("Expand-Archive -Path '{}' -DestinationPath '{}' -Force", sigs_zip.display(), sigs_dir.display());
                    self.exec_with_retry("powershell", &["-NoProfile", "-NonInteractive", "-Command", &cmd_str], "CAPA Signatures Extraction", 2).await?;
                }
                #[cfg(not(target_os = "windows"))]
                {
                    let cmd_str = format!("unzip -o '{}' -d '{}'", sigs_zip.display(), sigs_dir.display());
                    let mut cmd = std::process::Command::new("sh");
                    cmd.args(["-c", &cmd_str]);
                    let _ = self.executor.execute(cmd).await;
                }
                
                let _ = std::fs::remove_file(&sigs_zip);
            }
        }

        info!("CAPA provisioning complete.");
        Ok(())
    }
}
