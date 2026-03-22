//! Agent Provisioning and Installation.
//!
//! Manages the automated installation of telemetry dependencies across OS platforms.
//! Windows: Sysmon
//! Linux: Sysmon for Linux
//! macOS: Endpoint Security Framework

use std::path::Path;
use std::process::Command;
use tracing::{info, warn};

pub struct AgentProvisioner;

impl Default for AgentProvisioner {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentProvisioner {
    pub fn new() -> Self {
        Self
    }

    /// Provision the agent's telemetry dependencies based on the host OS.
    pub fn provision_telemetry(&self) -> anyhow::Result<()> {
        #[cfg(target_os = "windows")]
        {
            self.provision_windows()
        }
        #[cfg(target_os = "linux")]
        {
            self.provision_linux()
        }
        #[cfg(target_os = "macos")]
        {
            self.provision_macos()
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Err(anyhow::anyhow!("Unsupported operating system for automated provisioning."))
        }
    }

    /// Provision ClamAV validator (best-effort install per OS).
    pub fn provision_clamav(&self) -> anyhow::Result<()> {
        #[cfg(target_os = "windows")]
        {
            self.provision_windows_clamav()
        }
        #[cfg(target_os = "linux")]
        {
            self.provision_linux_clamav()
        }
        #[cfg(target_os = "macos")]
        {
            self.provision_macos_clamav()
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Err(anyhow::anyhow!(
                "Unsupported operating system for automated ClamAV provisioning."
            ))
        }
    }

    /// Provision OpenSSL (needed for X.509 / CSR generation).
    pub fn provision_openssl(&self) -> anyhow::Result<()> {
        #[cfg(target_os = "windows")]
        {
            self.provision_windows_openssl()
        }
        #[cfg(target_os = "linux")]
        {
            self.provision_linux_openssl()
        }
        #[cfg(target_os = "macos")]
        {
            self.provision_macos_openssl()
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Err(anyhow::anyhow!(
                "Unsupported operating system for automated OpenSSL provisioning."
            ))
        }
    }

    #[cfg(target_os = "windows")]
    fn provision_windows_openssl(&self) -> anyhow::Result<()> {
        if self.command_exists_win("openssl") {
            info!("OpenSSL already available on Windows.");
            return Ok(());
        }

        info!("OpenSSL not found. Attempting to install via winget...");
        let status = Command::new("winget")
            .args(["install", "-e", "--id", "ShiningLight.OpenSSL", "--accept-source-agreements", "--accept-package-agreements"])
            .status();

        match status {
            Ok(s) if s.success() => {
                info!("OpenSSL installed successfully via winget. Note: You may need to restart your terminal or add it to PATH manually.");
                Ok(())
            }
            _ => Err(anyhow::anyhow!(
                "Failed to install OpenSSL via winget. Please install manually from https://slproweb.com/products/Win32OpenSSL.html"
            )),
        }
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
    fn provision_windows(&self) -> anyhow::Result<()> {
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
        self.ensure_windows_sysmon(config)
    }

    #[cfg(target_os = "windows")]
    fn ensure_windows_sysmon(&self, config_path: Option<&Path>) -> anyhow::Result<()> {
        let binary = self.ensure_sysmon_binary()?;
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
    fn ensure_sysmon_binary(&self) -> anyhow::Result<std::path::PathBuf> {
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
        let ps_script = "$ProgressPreference='SilentlyContinue'; \
            Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile 'Sysmon.zip'; \
            Expand-Archive -Path 'Sysmon.zip' -DestinationPath '.' -Force; \
            Remove-Item 'Sysmon.zip'";
        let download_status = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", ps_script])
            .status()?;

        if !download_status.success() {
            return Err(anyhow::anyhow!(
                "Failed to download Sysmon. Please manually place {} in the current directory.",
                required
            ));
        }
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
    fn provision_windows_clamav(&self) -> anyhow::Result<()> {
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
        let dl_cmd = format!(
            "$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -Uri '{}' -OutFile '{}'",
            download_url, installer_path_str
        );
        let download_status = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &dl_cmd])
            .status()?;
        if !download_status.success() {
            return Err(anyhow::anyhow!(
                "Failed to download ClamAV installer from {}",
                download_url
            ));
        }

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
    fn provision_linux(&self) -> anyhow::Result<()> {
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
    fn provision_linux_clamav(&self) -> anyhow::Result<()> {
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
    fn provision_macos(&self) -> anyhow::Result<()> {
        info!("Provisioning macOS telemetry (Endpoint Security Framework)...");
        info!("macOS uses native ESF. Ensure the binary is granted Full Disk Access.");
        // No explicit install needed for ESF, it's a kernel feature
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn provision_macos_clamav(&self) -> anyhow::Result<()> {
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
    pub fn install<P: AsRef<Path>>(&self, binary_path: P, config_path: Option<P>) -> anyhow::Result<()> {
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

    /// Provision Ollama for LLM analysis.
    pub fn provision_ollama(&self) -> anyhow::Result<()> {
        match Command::new("ollama").arg("list").output() {
            Ok(o) if o.status.success() => {
                info!("Ollama is already installed.");
                return Ok(());
            }
            _ => {}
        }

        info!("Ollama not found. Attempting to install Ollama...");
        #[cfg(target_os = "windows")]
        {
            let dl_cmd = "Invoke-WebRequest -Uri 'https://ollama.com/download/ollama-windows-amd64.zip' -OutFile 'ollama.zip'; Expand-Archive -Path 'ollama.zip' -DestinationPath 'ollama' -Force; Remove-Item 'ollama.zip'";
            let status = Command::new("powershell").args(["-Command", dl_cmd]).status()?;
            if status.success() {
                info!("Ollama downloaded to ./ollama. Please ensure it is in your PATH or run it directly from ./ollama/ollama.exe.");
                return Ok(());
            }
        }
        #[cfg(target_os = "linux")]
        {
            let status = Command::new("sh").args(["-c", "curl -fsSL https://ollama.com/install.sh | sh"]).status()?;
             if status.success() {
                info!("Ollama installed successfully via official script.");
                return Ok(());
            }
        }
        #[cfg(target_os = "macos")]
        {
             let status = Command::new("brew").args(["install", "ollama"]).status()?;
             if status.success() {
                info!("Ollama installed via Homebrew.");
                return Ok(());
            }
        }

        Err(anyhow::anyhow!("Ollama installation failed or not supported for automated install on this platform."))
    }

    pub fn pull_ollama_model(&self, model: &str) -> anyhow::Result<()> {
        info!("Pulling Ollama model: {}...", model);
        let status = Command::new("ollama").args(["pull", model]).status()?;
        if status.success() {
            info!("Model {} pulled successfully.", model);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Failed to pull Ollama model {}.", model))
        }
    }

    /// Provision FLOSS (FLARE Obfuscated String Solver) for deobfuscating malware strings.
    pub fn provision_floss(&self) -> anyhow::Result<()> {
        let version = "3.1.1";
        
        #[cfg(target_os = "windows")]
        {
            if self.command_exists_win("floss") || Path::new("D:\\harfile\\floss\\floss.exe").exists() {
                info!("FLOSS already available on Windows.");
                return Ok(());
            }

            let url = format!("https://github.com/mandiant/flare-floss/releases/download/v{}/floss-v{}-windows.zip", version, version);
            let target_dir = "D:\\harfile\\floss";
            let zip_path = "floss.zip";

            info!("FLOSS not found. Downloading v{} for Windows...", version);
            let ps_cmd = format!(
                "$ProgressPreference='SilentlyContinue'; \
                 New-Item -ItemType Directory -Force -Path '{}' | Out-Null; \
                 Invoke-WebRequest -Uri '{}' -OutFile '{}'; \
                 Expand-Archive -Path '{}' -DestinationPath '{}' -Force; \
                 Remove-Item '{}'",
                target_dir, url, zip_path, zip_path, target_dir, zip_path
            );

            let status = Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd])
                .status()?;

            if status.success() {
                info!("FLOSS v{} installed successfully to {}.", version, target_dir);
                Ok(())
            } else {
                Err(anyhow::anyhow!("Failed to download and extract FLOSS for Windows."))
            }
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
    pub fn provision_hollows_hunter(&self) -> anyhow::Result<()> {
        let version = "0.4.1.1";

        #[cfg(target_os = "windows")]
        {
            let target_dir = "D:\\harfile\\hollows_hunter";
            let exe_path = format!("{}\\hollows_hunter.exe", target_dir);
            
            if Path::new(&exe_path).exists() {
                info!("HollowsHunter already available at {}.", exe_path);
                return Ok(());
            }

            let url = format!(
                "https://github.com/hasherezade/hollows_hunter/releases/download/v{}/hollows_hunter64.zip",
                version
            );

            info!("HollowsHunter not found. Downloading v{} for Windows (64-bit)...", version);
            let ps_cmd = format!(
                "$ProgressPreference='SilentlyContinue'; \
                 New-Item -ItemType Directory -Force -Path '{}' | Out-Null; \
                 Invoke-WebRequest -Uri '{}' -OutFile '{}\\hh.zip'; \
                 Expand-Archive -Path '{}\\hh.zip' -DestinationPath '{}' -Force; \
                 Remove-Item '{}\\hh.zip'",
                target_dir, url, target_dir, target_dir, target_dir, target_dir
            );

            let status = Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd])
                .status()?;

            if status.success() {
                info!("HollowsHunter v{} installed to {}.", version, target_dir);
                Ok(())
            } else {
                Err(anyhow::anyhow!("Failed to download HollowsHunter for Windows."))
            }
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
}
