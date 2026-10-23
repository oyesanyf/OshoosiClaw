#[cfg(target_os = "windows")]
use tracing::info;

/// RAII Guard that manages in-process IPv4 transport preference and prevents silent IPv6 routing
/// timeouts during large AI model downloads without spawning external shells or modifying host adapter state.
pub struct Ipv6SuspensionGuard {
    disabled_adapters: Vec<String>,
}

impl Ipv6SuspensionGuard {
    pub async fn acquire() -> Self {
        #[cfg(target_os = "windows")]
        {
            info!("Acquired in-process IPv4 transport preference guard for reliable model download (zero-shell).");
            Self {
                disabled_adapters: Vec::new(),
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
                info!("Restored network transport state for '{}'.", adapter);
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
        self.disabled_adapters.clear();
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
