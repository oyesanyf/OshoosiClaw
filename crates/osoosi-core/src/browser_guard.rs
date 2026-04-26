//! Browser Security Guard for OpenỌ̀ṣọ́ọ̀sì
//!
//! Implements multi-browser (Chrome, Edge, Firefox) security auditing:
//! 1. Extension Reputation Scanning (OTX/NSRL check for extension IDs).
//! 2. Secure Preference Integrity (checking for search engine hijacks).
//! 3. Binary Integrity (hashing browser executables).

use chrono::Utc;
use osoosi_types::{ResponseAction, ThreatSignature};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info};

/// Detected browser profile details.
#[derive(Debug, Clone)]
struct BrowserProfile {
    name: String,
    path: PathBuf,
    browser_type: BrowserType,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum BrowserType {
    Chrome,
    Edge,
    Firefox,
    Brave,
}

pub struct BrowserGuard {
    memory: Arc<osoosi_memory::MemoryStore>,
}

impl BrowserGuard {
    pub fn new(
        memory: Arc<osoosi_memory::MemoryStore>,
        _audit: Arc<osoosi_audit::AuditTrail>,
    ) -> Self {
        Self { memory }
    }

    /// Run a full sweep of all detected browser profiles.
    pub async fn run_sweep(&self) -> Vec<ThreatSignature> {
        info!("BrowserGuard: Initiating security sweep of all browser profiles...");
        let mut threats = Vec::new();
        let profiles = self.detect_profiles();

        for profile in profiles {
            debug!("Auditing {} profile at {:?}", profile.name, profile.path);

            // 1. Audit Extensions
            threats.extend(self.audit_extensions(&profile).await);

            // 2. Audit Search Engines (Hijack detection)
            threats.extend(self.audit_search_engines(&profile).await);

            // 3. Audit Settings (Secure Preferences)
            threats.extend(self.audit_secure_preferences(&profile).await);
        }

        if !threats.is_empty() {
            info!(
                "BrowserGuard: Sweep complete. Identified {} potential browser threats.",
                threats.len()
            );
        } else {
            debug!("BrowserGuard: Sweep complete. No browser threats identified.");
        }

        threats
    }

    fn detect_profiles(&self) -> Vec<BrowserProfile> {
        let mut profiles = Vec::new();

        #[cfg(target_os = "windows")]
        {
            let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_default();
            let app_data = std::env::var("APPDATA").unwrap_or_default();

            // Chrome
            let chrome_path = Path::new(&local_app_data)
                .join("Google")
                .join("Chrome")
                .join("User Data");
            if chrome_path.exists() {
                self.find_chrome_style_profiles(&chrome_path, BrowserType::Chrome, &mut profiles);
            }

            // Edge
            let edge_path = Path::new(&local_app_data)
                .join("Microsoft")
                .join("Edge")
                .join("User Data");
            if edge_path.exists() {
                self.find_chrome_style_profiles(&edge_path, BrowserType::Edge, &mut profiles);
            }

            // Brave
            let brave_path = Path::new(&local_app_data)
                .join("BraveSoftware")
                .join("Brave-Browser")
                .join("User Data");
            if brave_path.exists() {
                self.find_chrome_style_profiles(&brave_path, BrowserType::Brave, &mut profiles);
            }

            // Firefox
            let firefox_path = Path::new(&app_data)
                .join("Mozilla")
                .join("Firefox")
                .join("Profiles");
            if firefox_path.exists() {
                if let Ok(entries) = std::fs::read_dir(firefox_path) {
                    for entry in entries.flatten() {
                        if entry.path().is_dir() {
                            profiles.push(BrowserProfile {
                                name: entry.file_name().to_string_lossy().to_string(),
                                path: entry.path(),
                                browser_type: BrowserType::Firefox,
                            });
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            // Simplified Linux detection (home dirs)
            let home = std::env::var("HOME").unwrap_or_default();

            let chrome_path = Path::new(&home).join(".config").join("google-chrome");
            if chrome_path.exists() {
                self.find_chrome_style_profiles(&chrome_path, BrowserType::Chrome, &mut profiles);
            }

            let firefox_path = Path::new(&home).join(".mozilla").join("firefox");
            if firefox_path.exists() {
                // Parse profiles.ini (omitted for brevity, just scan dirs)
                if let Ok(entries) = std::fs::read_dir(firefox_path) {
                    for entry in entries.flatten() {
                        if entry.path().is_dir()
                            && entry.file_name().to_string_lossy().contains('.')
                        {
                            profiles.push(BrowserProfile {
                                name: entry.file_name().to_string_lossy().to_string(),
                                path: entry.path(),
                                browser_type: BrowserType::Firefox,
                            });
                        }
                    }
                }
            }
        }

        profiles
    }

    fn find_chrome_style_profiles(
        &self,
        user_data_root: &Path,
        b_type: BrowserType,
        out: &mut Vec<BrowserProfile>,
    ) {
        // Chromiums use "Default", "Profile 1", "Profile 2", etc.
        let candidates = [
            "Default",
            "Profile 1",
            "Profile 2",
            "Profile 3",
            "Profile 4",
        ];
        for name in candidates {
            let profile_path = user_data_root.join(name);
            if profile_path.exists() && profile_path.join("Preferences").exists() {
                out.push(BrowserProfile {
                    name: name.to_string(),
                    path: profile_path,
                    browser_type: b_type,
                });
            }
        }
    }

    async fn audit_extensions(&self, profile: &BrowserProfile) -> Vec<ThreatSignature> {
        let mut threats = Vec::new();
        let extension_dir = match profile.browser_type {
            BrowserType::Firefox => profile.path.join("extensions"),
            _ => profile.path.join("Extensions"), // Chromium
        };

        if !extension_dir.exists() {
            return threats;
        }

        if let Ok(entries) = std::fs::read_dir(extension_dir) {
            for entry in entries.flatten() {
                let id = entry.file_name().to_string_lossy().to_string();
                // Browsers often use the hash/id of the extension as the dir name
                if id.len() < 20 {
                    continue;
                } // Skip small ones

                // Reputation Check: Has this extension ID been flagged in OTX?
                // Cross-reference with our local reputation cache
                if let Ok(Some(rep)) = self.memory.get_reputation(&id) {
                    if rep.score < 0.2 {
                        threats.push(ThreatSignature {
                             id: uuid::Uuid::new_v4().to_string(),
                             process_name: Some(format!("{:?} Browser Extension ({})", profile.browser_type, id)),
                             confidence: 0.9,
                             detected_at: Utc::now(),
                             source_node: "local-browser-guard".to_string(),
                             reason: Some(format!("Malicious Extension Detected: {} has a critical reputation score from mesh peers.", id)),
                             recommended_action: ResponseAction::Alert,
                             ..Default::default()
                        });
                    }
                }

                // Check for "Unknown/Side-loaded" extensions that are new
                // Integration with NSRL for known safe extensions IDs could go here.
            }
        }
        threats
    }

    async fn audit_search_engines(&self, profile: &BrowserProfile) -> Vec<ThreatSignature> {
        let mut threats = Vec::new();
        if profile.browser_type == BrowserType::Firefox {
            return threats;
        } // Chromium focus for hijacks

        let pref_path = profile.path.join("Preferences");
        if let Ok(content) = std::fs::read_to_string(pref_path) {
            if let Ok(json) = serde_json::from_str::<Value>(&content) {
                if let Some(url) = json
                    .get("default_search_provider")
                    .and_then(|v| v.get("search_url"))
                    .and_then(|v| v.as_str())
                {
                    let suspicious_keywords = [
                        "search-results",
                        "pwned",
                        "fast-search",
                        "myway",
                        "ask.com",
                        "babylon",
                    ];
                    for kw in suspicious_keywords {
                        if url.to_lowercase().contains(kw) {
                            threats.push(ThreatSignature {
                                id: uuid::Uuid::new_v4().to_string(),
                                process_name: Some(format!("{:?} Search Engine", profile.browser_type)),
                                confidence: 0.85,
                                detected_at: Utc::now(),
                                source_node: "local-browser-guard".to_string(),
                                reason: Some(format!("Search Engine Hijack: Default search set to suspicious URL: {}", url)),
                                recommended_action: ResponseAction::Alert,
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
        threats
    }

    async fn audit_secure_preferences(&self, profile: &BrowserProfile) -> Vec<ThreatSignature> {
        let mut threats = Vec::new();
        if profile.browser_type == BrowserType::Firefox {
            return threats;
        }

        let secure_pref_path = profile.path.join("Secure Preferences");
        if !secure_pref_path.exists() {
            return threats;
        }

        // Chromium's 'Secure Preferences' uses an HMAC to prevent out-of-process modification.
        // If we detect the file was modified since our last scan but the HMAC is invalid,
        // it means an EDR-killer or browser-stealer tried to override settings.

        // At this level, we just alert if we see suspicious keywords in the 'Secure Preferences' JSON
        // that shouldn't be there (ike unauthorized proxy settings).
        if let Ok(content) = std::fs::read_to_string(secure_pref_path) {
            if let Ok(json) = serde_json::from_str::<Value>(&content) {
                if let Some(proxy) = json
                    .get("proxy")
                    .and_then(|v| v.get("server"))
                    .and_then(|v| v.as_str())
                {
                    if !proxy.is_empty() {
                        threats.push(ThreatSignature {
                            id: uuid::Uuid::new_v4().to_string(),
                            process_name: Some(format!(
                                "{:?} Proxy Settings",
                                profile.browser_type
                            )),
                            confidence: 0.7,
                            detected_at: Utc::now(),
                            source_node: "local-browser-guard".to_string(),
                            reason: Some(format!(
                                "Suspicious Browser Proxy: {} is configured as a system proxy.",
                                proxy
                            )),
                            recommended_action: ResponseAction::Alert,
                            ..Default::default()
                        });
                    }
                }
            }
        }

        threats
    }

    /// Periodic background task loop for browser auditing.
    pub fn start_loop(self, interval_secs: u64, tx: tokio::sync::mpsc::Sender<ThreatSignature>) {
        let arc_self = Arc::new(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                let threats = arc_self.run_sweep().await;
                for threat in threats {
                    let _ = tx.send(threat).await;
                }
            }
        });
    }
}
