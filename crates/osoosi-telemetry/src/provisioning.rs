//! Agent Provisioning and Installation.
//!
//! Manages the automated installation of telemetry dependencies across OS platforms.
//! Windows: Sysmon
//! Linux: Sysmon for Linux
//! macOS: Endpoint Security Framework

use std::path::Path;
use std::process::Command;
use tracing::{info, warn, error};

pub struct AgentProvisioner {
    client: reqwest::Client,
}

impl Default for AgentProvisioner {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentProvisioner {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(600))
            .no_proxy() // Crucial: avoid Windows system proxy resolution which triggers nested tokio runtime
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { client }
    }

    /// Provision the agent's telemetry dependencies based on the host OS.
    pub async fn provision_telemetry(&self) -> anyhow::Result<()> {
        #[cfg(target_os = "windows")]
        {
            self.provision_windows().await
        }
        #[cfg(target_os = "linux")]
        {
            self.provision_linux().await
        }
        #[cfg(target_os = "macos")]
        {
            self.provision_macos().await
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

    #[cfg(target_os = "windows")]
    async fn provision_windows_openssl(&self) -> anyhow::Result<()> {
        if self.command_exists_win("openssl") {
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
            
            // We use status().ok() here because winget might not exist or ID might not be found
            if let Ok(status) = cmd.status() {
                if status.success() {
                    if self.command_exists_win("openssl") {
                        info!("OpenSSL installer (ID: {}) finished successfully.", id);
                        return Ok(());
                    }
                }
            }
        }
        
        // 2. Fallback to direct download from slproweb.com
        info!("OpenSSL winget entries failed. Using direct download from slproweb.com...");
        
        let urls = [
            ("Full", "https://slproweb.com/download/Win64OpenSSL-4_0_0.exe"),
            ("Minimal (Light)", "https://slproweb.com/download/Win64OpenSSL_Light-4_0_0.exe"),
        ];

        for (name, url) in urls {
            info!("Attempting direct download of {} OpenSSL: {}...", name, url);
            let installer_path = std::env::temp_dir().join("openssl-setup.exe");
            
            if self.download_with_resume(url, &installer_path).await.is_ok() {
                info!("OpenSSL {} installer downloaded. Running silent setup...", name);
                let mut install_cmd = Command::new(&installer_path);
                install_cmd.args(["/verysilent", "/sp-", "/suppressmsgboxes", "/norestart"]);
                
                if self.exec_with_retry(install_cmd, &format!("OpenSSL {} Installation", name), 2).is_ok() {
                    let _ = std::fs::remove_file(&installer_path);
                    if self.command_exists_win("openssl") {
                        info!("OpenSSL {} installed successfully via direct installer.", name);
                        return Ok(());
                    }
                }
                let _ = std::fs::remove_file(&installer_path);
            } else {
                warn!("Failed to download {} OpenSSL from {}.", name, url);
            }
        }

        Err(anyhow::anyhow!(
            "Failed to install OpenSSL via winget or direct download variants. Please install manually from https://slproweb.com/products/Win32OpenSSL.html"
        ))
    }

    /// Helper to execute a command with a specified number of retries.
    fn exec_with_retry(&self, mut cmd: Command, name: &str, retries: usize) -> anyhow::Result<()> {
        let mut last_error = None;
        for i in 1..=retries {
            if i > 1 {
                info!("Attempt {}/{} to {}...", i, retries, name);
                std::thread::sleep(std::time::Duration::from_secs(3 * (i - 1) as u64));
            }
            match cmd.status() {
                Ok(status) if status.success() => return Ok(()),
                Ok(status) => last_error = Some(anyhow::anyhow!("Command '{}' failed with status: {}", name, status)),
                Err(e) => last_error = Some(anyhow::anyhow!("Execution error for '{}': {}", name, e)),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Failed {} after {} retries", name, retries)))
    }

    #[cfg(target_os = "windows")]
    fn command_exists_win(&self, cmd: &str) -> bool {
        Command::new("where")
            .arg(cmd)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[cfg(target_os = "linux")]
    fn provision_linux_openssl(&self) -> anyhow::Result<()> {
        if self.command_exists("openssl") {
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
            if let Ok(status) = Command::new(bin).args(*args).status() {
                if status.success() && self.command_exists("openssl") {
                    info!("Installed OpenSSL using: {} {}", bin, args.join(" "));
                    return Ok(());
                }
            }
        }

        Err(anyhow::anyhow!(
            "Failed to install OpenSSL on Linux. Please install 'openssl' manually using your package manager."
        ))
    }

    #[cfg(target_os = "macos")]
    fn provision_macos_openssl(&self) -> anyhow::Result<()> {
        if self.command_exists("openssl") || self.command_exists("/usr/local/opt/openssl/bin/openssl") {
            info!("OpenSSL already available on macOS.");
            return Ok(());
        }

        let has_brew = self.command_exists("brew");
        if has_brew {
            let status = Command::new("brew").args(["install", "openssl"]).status()?;
            if status.success() {
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
        let cfg_primary = config_dir.join("config.xml");
        let cfg_fallback = config_dir.join("sysmonconfig-export.xml");
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
        self.fix_wrong_arch_sysmon(&binary);
        let is_installed = self.sysmon_service_active();

        if is_installed {
            info!("Sysmon is already active.");
            if let Some(cfg) = config_path {
                info!("Updating Sysmon config from {}...", cfg.display());
                self.run_sysmon_with_repair(&binary, &["-accepteula", "-c"], Some(cfg))?;
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
                .is_ok()
            {
                info!("Sysmon installed successfully with config.");
                return Ok(());
            }

            // Fallback: install default then apply config
            if self
                .run_sysmon_with_repair(&binary, &["-accepteula", "-i"], None)
                .is_ok()
                && self
                    .run_sysmon_with_repair(&binary, &["-accepteula", "-c"], Some(cfg))
                    .is_ok()
                {
                    info!("Sysmon installed and config applied successfully.");
                    return Ok(());
                }
        } else if self
            .run_sysmon_with_repair(&binary, &["-accepteula", "-i"], None)
            .is_ok()
        {
            info!("Sysmon installed successfully.");
            return Ok(());
        }

        Err(anyhow::anyhow!("Sysmon installation failed."))
    }

    #[cfg(target_os = "windows")]
    fn run_sysmon_with_repair(
        &self,
        binary: &Path,
        args: &[&str],
        cfg: Option<&Path>,
    ) -> anyhow::Result<()> {
        self.run_sysmon_with_repair_once(binary, args, cfg, true)
    }

    #[cfg(target_os = "windows")]
    fn run_sysmon_with_repair_once(
        &self,
        binary: &Path,
        args: &[&str],
        cfg: Option<&Path>,
        allow_repair: bool,
    ) -> anyhow::Result<()> {
        let mut cmd = Command::new(binary);
        cmd.args(args);
        if let Some(c) = cfg {
            cmd.arg(c);
        }
        let output = cmd.output()?;
        if output.status.success() {
            return Ok(());
        }

        let mut combined = String::new();
        combined.push_str(&String::from_utf8_lossy(&output.stdout));
        combined.push('\n');
        combined.push_str(&String::from_utf8_lossy(&output.stderr));
        let combined_lc = combined.to_ascii_lowercase();

        if allow_repair && combined_lc.contains("already registered") {
            warn!("Sysmon reports an already-registered driver. Reinstalling (uninstall force -> install/update)...");
            let uninstall = Command::new(binary).args(["-accepteula", "-u", "force"]).status()?;
            if !uninstall.success() {
                return Err(anyhow::anyhow!(
                    "Sysmon uninstall (force) failed while recovering from registered driver state."
                ));
            }
            return self.run_sysmon_with_repair_once(binary, args, cfg, false);
        }

        Err(anyhow::anyhow!("Sysmon command failed: {}", combined.trim()))
    }

    #[cfg(target_os = "windows")]
    fn is_64bit_os() -> bool {
        std::env::var("PROCESSOR_ARCHITECTURE")
            .map(|a| a.eq_ignore_ascii_case("AMD64") || a.eq_ignore_ascii_case("ARM64"))
            .unwrap_or(cfg!(target_pointer_width = "64"))
    }

    #[cfg(target_os = "windows")]
    fn sysmon_service_active(&self) -> bool {
        let svc = if Self::is_64bit_os() { "Sysmon64" } else { "Sysmon" };
        let output = Command::new("sc")
            .args(["query", svc])
            .output();
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
    fn fix_wrong_arch_sysmon(&self, binary_64: &Path) {
        if !Self::is_64bit_os() {
            return;
        }
        let query = Command::new("sc")
            .args(["query", "Sysmon"])
            .output();
        let has_32bit_svc = query.map(|o| o.status.success()).unwrap_or(false);
        if !has_32bit_svc {
            return;
        }
        warn!(
            "Found 32-bit Sysmon service on 64-bit OS (causes Error 1067). \
             Uninstalling to replace with Sysmon64..."
        );
        let _ = Command::new(binary_64)
            .args(["-accepteula", "-u", "force"])
            .status();
    }

    #[cfg(target_os = "windows")]
    async fn ensure_sysmon_binary(&self) -> anyhow::Result<std::path::PathBuf> {
        let is_64 = Self::is_64bit_os();
        let (required, alt) = if is_64 {
            ("Sysmon64.exe", "Sysmon.exe")
        } else {
            ("Sysmon.exe", "Sysmon64.exe")
        };

        let required_path = Path::new(required);
        if required_path.exists() {
            return Ok(required_path.to_path_buf());
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
        let ps_script = format!("Expand-Archive -Path 'Sysmon.zip' -DestinationPath '.' -Force; Remove-Item 'Sysmon.zip'");
        let mut cmd = Command::new("powershell");
        cmd.args(["-NoProfile", "-NonInteractive", "-Command", &ps_script]);
        
        self.exec_with_retry(cmd, "Sysmon Extraction", 2)?;
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
        let mut install_cmd = Command::new("msiexec");
        install_cmd.args(["/i", &installer_path_str, "/qn", "/norestart"]);
        
        self.exec_with_retry(install_cmd, "ClamAV Installation", 2)?;

        info!("Installing ClamAV silently...");
        let install_status = Command::new("msiexec")
            .args(["/i", &installer_path_str, "/qn", "/norestart"])
            .status()?;

        let _ = std::fs::remove_file(&installer_path);

        if !install_status.success() {
            return Err(anyhow::anyhow!(
                "ClamAV installer execution failed. Ensure terminal is elevated (Administrator)."
            ));
        }

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

        if !self.linux_sysmon_installed() {
            self.install_linux_sysmon_package()?;
        }

        // Ensure daemon is started on boot and running now.
        let _ = Command::new("sudo")
            .args(["systemctl", "enable", "--now", "sysmon"])
            .status();

        if let Some(cfg) = config {
            info!("Applying Sysmon for Linux config from {}...", cfg.display());
            self.apply_linux_sysmon_config(cfg)?;
        }

        info!("Sysmon for Linux provisioning complete.");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn linux_sysmon_installed(&self) -> bool {
        let has_sysmon_cmd = Command::new("sh")
            .args(["-c", "command -v sysmon >/dev/null 2>&1"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        let has_opt_sysmon = Path::new("/opt/sysmon/sysmon").exists();
        has_sysmon_cmd || has_opt_sysmon
    }

    #[cfg(target_os = "linux")]
    fn install_linux_sysmon_package(&self) -> anyhow::Result<()> {
        warn!("Sysmon for Linux not found. Attempting package installation...");
        if let Err(e) = self.setup_linux_microsoft_repo() {
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
            if let Ok(status) = Command::new(bin).args(*args).status() {
                if status.success() && self.linux_sysmon_installed() {
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
    fn setup_linux_microsoft_repo(&self) -> anyhow::Result<()> {
        // Debian/Ubuntu family: use Microsoft bootstrap .deb package.
        if self.command_exists("apt-get") {
            let apt_repo = Path::new("/etc/apt/sources.list.d/microsoft-prod.list");
            if !apt_repo.exists() {
                info!("Bootstrapping Microsoft apt repository...");
                let bootstrap = Command::new("sh")
                    .args([
                        "-c",
                        "set -e; . /etc/os-release; \
                         curl -fsSL \"https://packages.microsoft.com/config/${ID}/${VERSION_ID}/packages-microsoft-prod.deb\" \
                         -o /tmp/packages-microsoft-prod.deb; \
                         sudo dpkg -i /tmp/packages-microsoft-prod.deb; \
                         rm -f /tmp/packages-microsoft-prod.deb",
                    ])
                    .status()?;
                if !bootstrap.success() {
                    return Err(anyhow::anyhow!("Failed to bootstrap Microsoft apt repository."));
                }
            }
            let _ = Command::new("sudo").args(["apt-get", "update"]).status();
            return Ok(());
        }

        // RHEL/Fedora family: create Microsoft yum/dnf repo file.
        if self.command_exists("dnf") || self.command_exists("yum") {
            let yum_repo = Path::new("/etc/yum.repos.d/microsoft-prod.repo");
            if !yum_repo.exists() {
                info!("Bootstrapping Microsoft yum/dnf repository...");
                let bootstrap = Command::new("sh")
                    .args([
                        "-c",
                        "set -e; sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc; \
                         printf '[packages-microsoft-com-prod]\nname=packages-microsoft-com-prod\nbaseurl=https://packages.microsoft.com/rhel/$releasever/prod/\nenabled=1\ngpgcheck=1\ngpgkey=https://packages.microsoft.com/keys/microsoft.asc\n' \
                         | sudo tee /etc/yum.repos.d/microsoft-prod.repo >/dev/null",
                    ])
                    .status()?;
                if !bootstrap.success() {
                    return Err(anyhow::anyhow!("Failed to bootstrap Microsoft yum/dnf repository."));
                }
            }
            if self.command_exists("dnf") {
                let _ = Command::new("sudo").args(["dnf", "makecache"]).status();
            } else {
                let _ = Command::new("sudo").args(["yum", "makecache"]).status();
            }
            return Ok(());
        }

        Err(anyhow::anyhow!(
            "Unsupported Linux package manager for automatic Microsoft repo bootstrap."
        ))
    }

    #[cfg(target_os = "linux")]
    fn command_exists(&self, cmd: &str) -> bool {
        Command::new("sh")
            .args(["-c", &format!("command -v {} >/dev/null 2>&1", cmd)])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[cfg(target_os = "linux")]
    fn apply_linux_sysmon_config(&self, cfg: &Path) -> anyhow::Result<()> {
        let primary = Command::new("sudo")
            .arg("sysmon")
            .arg("-c")
            .arg(cfg)
            .status();
        if let Ok(status) = primary {
            if status.success() {
                return Ok(());
            }
        }

        let fallback = Command::new("sudo")
            .arg("/opt/sysmon/sysmon")
            .arg("-c")
            .arg(cfg)
            .status()?;
        if fallback.success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Failed to apply Sysmon for Linux config."))
        }
    }

    #[cfg(target_os = "linux")]
    async fn provision_linux_clamav(&self) -> anyhow::Result<()> {
        if self.command_exists("clamscan") {
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
            if let Ok(status) = Command::new(bin).args(*args).status() {
                if status.success() && self.command_exists("clamscan") {
                    let _ = Command::new("sudo").args(["systemctl", "enable", "--now", "clamav-freshclam"]).status();
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
        let has_clam = Command::new("sh")
            .args(["-c", "command -v clamscan >/dev/null 2>&1"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if has_clam {
            info!("ClamAV already available on macOS.");
            return Ok(());
        }

        let has_brew = Command::new("sh")
            .args(["-c", "command -v brew >/dev/null 2>&1"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if has_brew {
            let status = Command::new("brew").args(["install", "clamav"]).status()?;
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
            let already_installed = self.sysmon_service_active();
            let cfg_ref = config_path.as_ref().map(|c| c.as_ref());
            if already_installed {
                self.run_sysmon_with_repair(binary, &["-accepteula", "-c"], cfg_ref)
            } else {
                self.run_sysmon_with_repair(binary, &["-accepteula", "-i"], cfg_ref)
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (binary_path, config_path);
            Err(anyhow::anyhow!("Explicit Sysmon installation is only supported on Windows. Use automated provision on this platform."));
        }
    }

    /// Provision SmolLM2-135M-Instruct models for local native inference.
    /// SmolLM2-135M-Instruct is the correct 135M ultra-lean model.
    pub async fn provision_smollm_models(&self) -> anyhow::Result<()> {
        let base_models_dir = osoosi_types::resolve_models_dir();
        let smollm_dir = base_models_dir.join("smollm");
        
        if !smollm_dir.exists() {
            std::fs::create_dir_all(&smollm_dir)?;
        }

        let model_path     = smollm_dir.join("model.safetensors");
        let tokenizer_path = smollm_dir.join("tokenizer.json");
        let config_path    = smollm_dir.join("config.json");
        let onnx_path      = smollm_dir.join("smollm2-135m-it.onnx");

        if model_path.exists() && tokenizer_path.exists() && config_path.exists() && onnx_path.exists() {
            info!("SmolLM2-135M-Instruct models already provisioned.");
            return Ok(());
        }

        info!("Provisioning SmolLM2-135M-Instruct models (public, ultra-lean, 135M params)...");

        const MODEL_REPO: &str = "HuggingFaceTB/SmolLM2-135M-Instruct";
        let files = [
            ("model.safetensors", format!("https://huggingface.co/{}/resolve/main/model.safetensors", MODEL_REPO)),
            ("tokenizer.json",    format!("https://huggingface.co/{}/resolve/main/tokenizer.json",    MODEL_REPO)),
            ("config.json",       format!("https://huggingface.co/{}/resolve/main/config.json",       MODEL_REPO)),
            ("smollm2-135m-it.onnx", format!("https://huggingface.co/{}/resolve/main/onnx/model.onnx", MODEL_REPO)),
        ];

        for (name, url) in &files {
            let dest = smollm_dir.join(name);
            if dest.exists() { continue; }

            info!("Downloading {}...", name);
            self.download_with_resume(url, &dest).await?;
        }

        // Copy tokenizer to parent models dir for ONNX-only mode if needed
        let parent_tok = base_models_dir.join("tokenizer.json");
        if !parent_tok.exists() {
            let _ = std::fs::copy(&tokenizer_path, &parent_tok);
        }

        info!("SmolLM2-135M-Instruct models provisioned successfully.");
        Ok(())
    }

    /// Provision FLOSS (FLARE Obfuscated String Solver) for deobfuscating malware strings.
    pub async fn provision_floss(&self) -> anyhow::Result<()> {
        let version = "3.1.1";
        
        #[cfg(target_os = "windows")]
        {
            let floss_exe = osoosi_types::resolve_tool_path("floss", "floss.exe");
            if self.command_exists_win("floss") || floss_exe.exists() {
                info!("FLOSS already available on Windows.");
                return Ok(());
            }

            let url = format!("https://github.com/mandiant/flare-floss/releases/download/v{}/floss-v{}-windows.zip", version, version);
            let target_dir = osoosi_types::resolve_tools_dir().join("floss");
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

            let mut cmd = Command::new("powershell");
            cmd.args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd]);
            self.exec_with_retry(cmd, "FLOSS Extraction", 2)?;
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
            let target_dir = osoosi_types::resolve_tools_dir().join("hollows_hunter");
            let target_dir_str = target_dir.to_string_lossy();
            let exe_path = target_dir.join("hollows_hunter.exe");
            
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
            let ps_cmd = format!(
                "New-Item -ItemType Directory -Force -Path '{}' | Out-Null; \
                 Expand-Archive -Path '{}' -DestinationPath '{}' -Force; \
                 Remove-Item '{}'",
                target_dir_str, zip_path.to_string_lossy(), target_dir_str, zip_path.to_string_lossy()
            );

            let mut cmd = Command::new("powershell");
            cmd.args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd]);
            self.exec_with_retry(cmd, "HollowsHunter Extraction", 2)?;
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
            let target_dir = osoosi_types::resolve_tools_dir().join("ngrep");
            let target_dir_str = target_dir.to_string_lossy();
            let exe_path = target_dir.join("ngrep.exe");

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
            let ps_cmd = format!(
                "New-Item -ItemType Directory -Force -Path '{}' | Out-Null; \
                 Expand-Archive -Path '{}' -DestinationPath '{}' -Force; \
                 if (Test-Path '{}\\ngrep.exe') {{ Move-Item -Path '{}\\ngrep.exe' -Destination '{}' -Force; }} \
                 elseif (Test-Path '{}\\ngrep-windows-x86_64\\ngrep.exe') {{ Move-Item -Path '{}\\ngrep-windows-x86_64\\ngrep.exe' -Destination '{}' -Force; }} \
                 Remove-Item '{}'; \
                 if (Test-Path '{}\\ngrep-windows-x86_64') {{ Remove-Item -Recurse -Force '{}\\ngrep-windows-x86_64' }}",
                target_dir_str, zip_path.to_string_lossy(), target_dir_str, target_dir_str, target_dir_str, target_dir_str, target_dir_str, target_dir_str, target_dir_str, zip_path.to_string_lossy(), target_dir_str, target_dir_str
            );

            let mut cmd = Command::new("powershell");
            cmd.args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd]);
            self.exec_with_retry(cmd, "ngrep Extraction", 2)?;
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
            let mut install_cmd = Command::new(&installer_path);
            install_cmd.args(["/S", "/admin_only=1", "/dot11_support=0", "/loopback_support=1"]);
            
            self.exec_with_retry(install_cmd, "Npcap Installation", 2)?;
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
            if self.command_exists("sniffglue") {
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
                if let Ok(status) = Command::new(bin).args(*args).status() {
                    if status.success() && self.command_exists("sniffglue") {
                        info!("Installed sniffglue using: {} {}", bin, args.join(" "));
                        return Ok(());
                    }
                }
            }
            
            // Fallback to cargo install
            if self.command_exists("cargo") {
                info!("Package managers failed. Attempting cargo install sniffglue...");
                let status = Command::new("cargo").args(["install", "sniffglue"]).status()?;
                if status.success() {
                    return Ok(());
                }
            }

            Err(anyhow::anyhow!("Failed to install sniffglue on Linux."))
        }
        #[cfg(target_os = "macos")]
        {
            if self.command_exists("sniffglue") {
                info!("sniffglue already available on macOS.");
                return Ok(());
            }

            if self.command_exists("brew") {
                info!("Installing sniffglue via Homebrew...");
                let status = Command::new("brew").args(["install", "sniffglue"]).status()?;
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
                
                let mut cmd = Command::new("powershell");
                cmd.args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd]);
                let _ = self.exec_with_retry(cmd, &format!("Extract YARA {}", name), 2);
            }
            #[cfg(not(target_os = "windows"))]
            {
                 let sh_cmd = format!(
                    "unzip -o {} -d {} && cp -r {}/*/* {}/ && rm -rf {}",
                    zip_path.to_string_lossy(), tmp_extract.to_string_lossy(), tmp_extract.to_string_lossy(), target_sub_dir.to_string_lossy(), tmp_extract.to_string_lossy()
                );
                let _ = Command::new("sh").args(["-c", &sh_cmd]).status();
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
        use tokio::io::AsyncWriteExt;
        use futures::StreamExt;

        let mut retries = 5;
        let mut last_error = None;

        while retries > 0 {
            let current_size = if dest.exists() {
                std::fs::metadata(dest).map(|m| m.len()).unwrap_or(0)
            } else {
                0
            };

            let mut request = self.client.get(url);
            
            // Add Hugging Face authentication if token is present
            if url.contains("huggingface.co") {
                if let Ok(token) = std::env::var("HF_TOKEN") {
                    request = request.header("Authorization", format!("Bearer {}", token));
                }
            }

            if current_size > 0 {
                request = request.header("Range", format!("bytes={}-", current_size));
                info!("Resuming download from {} (current size: {:.1} MB)...", url, current_size as f64 / 1_048_576.0);
            }

            match request.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() || status == reqwest::StatusCode::PARTIAL_CONTENT {
                        let mut file = tokio::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(dest)
                            .await?;
                        
                        // If it's a 200 OK but we had a partial file, it means server doesn't support Range,
                        // or we're starting over. Truncate if it's 200 and we have existing data.
                        if status == reqwest::StatusCode::OK && current_size > 0 {
                            let _ = file.set_len(0).await;
                        }

                        let mut stream = resp.bytes_stream();
                        while let Some(item) = stream.next().await {
                            let chunk = item?;
                            file.write_all(&chunk).await?;
                        }
                        file.flush().await?;
                        return Ok(());
                    } else if status == reqwest::StatusCode::RANGE_NOT_SATISFIABLE {
                        // Already finished or range error
                        return Ok(());
                    } else {
                        if status == reqwest::StatusCode::UNAUTHORIZED && url.contains("huggingface.co") {
                            error!("CRITICAL: 401 Unauthorized for Hugging Face download. If you just added the HF_TOKEN environment variable to your OS, you MUST RESTART YOUR TERMINAL for the changes to take effect.");
                        }
                        last_error = Some(anyhow::anyhow!("HTTP error: {}", status));
                    }
                }
                Err(e) => {
                    last_error = Some(e.into());
                }
            }

            retries -= 1;
            if retries > 0 {
                warn!("Download failed: {:?}. Retrying ({} left)...", last_error, retries);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Download failed from {}", url)))
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
            
            let status = Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd])
                .status()?;
            
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

    /// Provision ONNX Runtime shared library (required for ML inference).
    pub async fn provision_onnx_runtime(&self) -> anyhow::Result<()> {
        let version = "1.18.1";
        
        #[cfg(target_os = "windows")]
        {
            let dll_name = "onnxruntime.dll";
            if std::path::Path::new(dll_name).exists() {
                info!("ONNX Runtime (onnxruntime.dll) already present.");
                return Ok(());
            }

            info!("ONNX Runtime not found. Downloading v{} for Windows...", version);
            let url = format!("https://github.com/microsoft/onnxruntime/releases/download/v{}/onnxruntime-win-x64-{}.zip", version, version);
            let zip_path = "ort_win.zip";
            let tmp_extract = "ort_tmp_extract";

            self.download_with_resume(&url, std::path::Path::new(zip_path)).await?;

            info!("Extracting ONNX Runtime...");
            let ps_cmd = format!(
                "Expand-Archive -Path '{}' -DestinationPath '{}' -Force; \
                 Copy-Item -Path '{}\\onnxruntime-win-x64-{}\\lib\\onnxruntime.dll' -Destination '.' -Force; \
                 Remove-Item '{}'; \
                 Remove-Item -Recurse -Force '{}'",
                zip_path, tmp_extract, tmp_extract, version, zip_path, tmp_extract
            );

            let mut cmd = Command::new("powershell");
            cmd.args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd]);
            self.exec_with_retry(cmd, "ONNX Extraction", 2)?;
            info!("ONNX Runtime provisioned successfully.");
            Ok(())
        }

        #[cfg(target_os = "linux")]
        {
            let lib_name = "libonnxruntime.so";
            if std::path::Path::new(lib_name).exists() || self.command_exists("ldconfig") {
                // In reality we should check if it's on ld path, but let's just deploy locally
            }

            info!("ONNX Runtime not found. Downloading v{} for Linux...", version);
            let url = format!("https://github.com/microsoft/onnxruntime/releases/download/v{}/onnxruntime-linux-x64-{}.tgz", version, version);
            let tgz_path = "/tmp/ort.tgz";
            
            let status = Command::new("sh").args(["-c", &format!(
                "curl -L -o {} {} && tar -xzf {} -C /tmp && cp /tmp/onnxruntime-linux-x64-{}/lib/libonnxruntime.so.{} . && ln -sf libonnxruntime.so.{} libonnxruntime.so",
                tgz_path, url, tgz_path, version, version, version
            )]).status()?;

            if status.success() {
                info!("ONNX Runtime provisioned successfully.");
                Ok(())
            } else {
                Err(anyhow::anyhow!("Failed to install ONNX Runtime on Linux."))
            }
        }

        #[cfg(target_os = "macos")]
        {
             let url = format!("https://github.com/microsoft/onnxruntime/releases/download/v{}/onnxruntime-osx-universal2-{}.tgz", version, version);
             // Similar logic for macOS ...
             info!("ONNX Runtime provisioning for macOS is handled via Homebrew or manual dylib placement.");
             Ok(())
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Err(anyhow::anyhow!("ONNX Runtime provisioning not supported on this platform."))
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
}
