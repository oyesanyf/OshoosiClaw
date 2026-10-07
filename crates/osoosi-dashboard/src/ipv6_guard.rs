use tracing::{info, warn};

/// RAII Guard that temporarily suspends IPv6 binding (`ms_tcpip6`) on active Windows network adapters
/// during large AI model downloads (from Cloudflare R2 / Ollama) to avoid silent IPv6 routing timeouts,
/// and automatically re-enables IPv6 binding once downloads conclude or on drop.
pub struct Ipv6SuspensionGuard {
    disabled_adapters: Vec<String>,
}

impl Ipv6SuspensionGuard {
    pub async fn acquire() -> Self {
        #[cfg(target_os = "windows")]
        {
            let mut disabled = Vec::new();
            let probe_script = "Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object { $name = $_.Name; $b = Get-NetAdapterBinding -Name $name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue; if ($b -and $b.Enabled) { $name } }";
            let mut probe_cmd = tokio::process::Command::new("powershell");
            probe_cmd.args(["-NoProfile", "-NonInteractive", "-Command", probe_script]);
            probe_cmd.creation_flags(0x0800_0000);
            let out = probe_cmd.output().await;

            if let Ok(out) = out {
                let stdout = String::from_utf8_lossy(&out.stdout);
                for line in stdout.lines() {
                    let adapter = line.trim();
                    if adapter.is_empty() {
                        continue;
                    }
                    let escaped_adapter = adapter.replace('\'', "''");
                    info!("Temporarily disabling IPv6 on adapter '{}' for reliable model download...", adapter);
                    let direct_cmd = format!("Disable-NetAdapterBinding -Name '{}' -ComponentID ms_tcpip6 -ErrorAction Stop", escaped_adapter);
                    let mut cmd = tokio::process::Command::new("powershell");
                    cmd.args(["-NoProfile", "-NonInteractive", "-Command", &direct_cmd]);
                    cmd.creation_flags(0x0800_0000);
                    let res = cmd.output().await;

                    let mut success = res.as_ref().map(|r| r.status.success()).unwrap_or(false);

                    if !success {
                        let runas_cmd = format!(
                            "Start-Process powershell -Verb RunAs -WindowStyle Hidden -Wait -ArgumentList '-NoProfile -NonInteractive -Command Disable-NetAdapterBinding -Name ''{}'' -ComponentID ms_tcpip6'",
                            escaped_adapter
                        );
                        let mut runas_proc = tokio::process::Command::new("powershell");
                        runas_proc.args(["-NoProfile", "-NonInteractive", "-Command", &runas_cmd]);
                        runas_proc.creation_flags(0x0800_0000);
                        let runas_res = runas_proc.output().await;
                        success = runas_res.as_ref().map(|r| r.status.success()).unwrap_or(false);
                    }

                    if success {
                        info!("Successfully disabled IPv6 on '{}' for model download.", adapter);
                        disabled.push(adapter.to_string());
                    } else {
                        warn!("Could not disable IPv6 on '{}' (elevation may be required). Proceeding with download attempt.", adapter);
                    }
                }
            }

            Self {
                disabled_adapters: disabled,
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            Self {
                disabled_adapters: Vec::new(),
            }
        }
    }

    pub async fn restore(&mut self) {
        #[cfg(target_os = "windows")]
        {
            for adapter in self.disabled_adapters.drain(..) {
                let escaped_adapter = adapter.replace('\'', "''");
                info!("Re-enabling IPv6 binding on network adapter '{}'...", adapter);
                let direct_cmd = format!("Enable-NetAdapterBinding -Name '{}' -ComponentID ms_tcpip6 -ErrorAction Stop", escaped_adapter);
                let mut cmd = tokio::process::Command::new("powershell");
                cmd.args(["-NoProfile", "-NonInteractive", "-Command", &direct_cmd]);
                cmd.creation_flags(0x0800_0000);
                let res = cmd.output().await;

                let success = res.as_ref().map(|r| r.status.success()).unwrap_or(false);
                if !success {
                    let runas_cmd = format!(
                        "Start-Process powershell -Verb RunAs -WindowStyle Hidden -Wait -ArgumentList '-NoProfile -NonInteractive -Command Enable-NetAdapterBinding -Name ''{}'' -ComponentID ms_tcpip6'",
                        escaped_adapter
                    );
                    let mut runas_proc = tokio::process::Command::new("powershell");
                    runas_proc.args(["-NoProfile", "-NonInteractive", "-Command", &runas_cmd]);
                    runas_proc.creation_flags(0x0800_0000);
                    let _ = runas_proc.output().await;
                }
                info!("Re-enabled IPv6 binding on '{}'.", adapter);
            }
        }
    }

    pub fn has_disabled_adapters(&self) -> bool {
        !self.disabled_adapters.is_empty()
    }

    pub fn disabled_adapters(&self) -> &[String] {
        &self.disabled_adapters
    }
}

impl Drop for Ipv6SuspensionGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        {
            for adapter in self.disabled_adapters.drain(..) {
                let escaped_adapter = adapter.replace('\'', "''");
                let direct_cmd = format!("Enable-NetAdapterBinding -Name '{}' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue", escaped_adapter);
                let mut cmd = std::process::Command::new("powershell");
                cmd.args(["-NoProfile", "-NonInteractive", "-Command", &direct_cmd]);
                {
                    use std::os::windows::process::CommandExt;
                    cmd.creation_flags(0x0800_0000);
                }
                let _ = cmd.output();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guard_empty_disabled_adapters() {
        let guard = Ipv6SuspensionGuard {
            disabled_adapters: Vec::new(),
        };
        assert!(!guard.has_disabled_adapters());
        assert_eq!(guard.disabled_adapters().len(), 0);
    }

    #[test]
    fn test_guard_with_adapters() {
        let guard = Ipv6SuspensionGuard {
            disabled_adapters: vec!["Ethernet".to_string()],
        };
        assert!(guard.has_disabled_adapters());
        assert_eq!(guard.disabled_adapters(), &["Ethernet"]);
    }
}
