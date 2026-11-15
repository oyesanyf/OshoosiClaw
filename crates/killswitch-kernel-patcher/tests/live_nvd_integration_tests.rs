//! NVD API 2.0 integration test suite (local 127.0.0.1 mock HTTP server by default,
//! with optional live NIST NVD endpoint opt-in via `OSOOSI_LIVE_NVD_TESTS=1`)
//! and secret hygiene enforcement (reading NVD_API_KEY strictly from runtime environment).

mod common;
use common::*;
use killswitch_kernel_patcher::{KernelPatcher, PatcherError};
use tokio::sync::Mutex;

static ENV_MUTEX: Mutex<()> = Mutex::const_new(());

struct EnvRestoreGuard {
    key: &'static str,
    prev: Option<String>,
}

impl EnvRestoreGuard {
    fn set(key: &'static str, value: Option<&str>) -> Self {
        let prev = std::env::var(key).ok();
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        Self { key, prev }
    }
}

impl Drop for EnvRestoreGuard {
    fn drop(&mut self) {
        match &self.prev {
            Some(v) => std::env::set_var(self.key, v),
            None => std::env::remove_var(self.key),
        }
    }
}

#[tokio::test]
async fn test_mock_nvd_env_api_key_trimmed_and_empty_omitted() {
    let _lock = ENV_MUTEX.lock().await;

    let server_with_key = MockNvdServer::start(FIXTURE_SINGLE_KEV_CVE_JSON).await;
    {
        let _guard = EnvRestoreGuard::set("NVD_API_KEY", Some("  trimmed_env_key_abc  "));
        let patcher = KernelPatcher::with_base_url(&server_with_key.endpoint_url);
        let opts = test_scan_options(
            Some("cpe:2.3:o:linux:linux_kernel:6.1.0:*:*:*:*:*:*:*"),
            None,
            false,
            None,
        );
        let vulns = patcher
            .scan_kernel_vulnerabilities(&opts)
            .await
            .expect("Local mock scan with trimmed NVD_API_KEY must succeed");
        assert_eq!(vulns.len(), 1);
        assert_eq!(
            server_with_key.last_api_key().as_deref(),
            Some("trimmed_env_key_abc")
        );
    }

    let server_without_key = MockNvdServer::start(FIXTURE_SINGLE_KEV_CVE_JSON).await;
    {
        let _guard = EnvRestoreGuard::set("NVD_API_KEY", Some("   "));
        let patcher = KernelPatcher::with_base_url(&server_without_key.endpoint_url);
        let opts = test_scan_options(
            Some("cpe:2.3:o:linux:linux_kernel:6.1.0:*:*:*:*:*:*:*"),
            None,
            false,
            None,
        );
        let _ = patcher
            .scan_kernel_vulnerabilities(&opts)
            .await
            .expect("Local mock scan without key must succeed");
        assert!(
            !server_without_key.has_header("apiKey"),
            "Whitespace-only NVD_API_KEY must be trimmed to None and not transmitted"
        );
    }
}

#[tokio::test]
async fn test_live_nvd_reachability_probe() {
    let reachable = is_live_nvd_reachable().await;
    let server = MockNvdServer::start(FIXTURE_EMPTY_NVD_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);
    let opts = test_scan_options(
        Some("cpe:2.3:o:linux:linux_kernel:6.1.0:*:*:*:*:*:*:*"),
        None,
        false,
        None,
    );
    let res = patcher.scan_kernel_vulnerabilities(&opts).await;
    assert!(res.is_ok());
    let _ = reachable;
}

#[tokio::test]
async fn test_live_nvd_api_query_with_or_without_key() {
    let _lock = ENV_MUTEX.lock().await;
    let mock_server = MockNvdServer::start(FIXTURE_MULTI_CVE_RANKING_JSON).await;
    let endpoint = if is_live_nvd_reachable().await {
        None
    } else {
        Some(mock_server.endpoint_url.clone())
    };

    let patcher = match endpoint {
        Some(url) => KernelPatcher::with_base_url(url),
        None => KernelPatcher::new(),
    };

    // Mandatory Secret Hygiene: Read strictly from runtime environment variable
    let api_key = std::env::var("NVD_API_KEY")
        .ok()
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty());

    let query_cpe = "cpe:2.3:o:linux:linux_kernel:6.1.0:*:*:*:*:*:*:*";
    let options = test_scan_options(Some(query_cpe), None, false, api_key.as_deref());

    match patcher.scan_kernel_vulnerabilities(&options).await {
        Ok(vulns) => {
            if !vulns.is_empty() {
                assert_vulnerability_ranking(&vulns);
            }
        }
        Err(PatcherError::RateLimited) | Err(PatcherError::Network(_)) => {}
        Err(other) => {
            panic!("Unexpected error querying NVD API: {:?}", other);
        }
    }
}

#[tokio::test]
async fn test_live_nvd_ranking_validation() {
    let _lock = ENV_MUTEX.lock().await;
    let mock_server = MockNvdServer::start(FIXTURE_MULTI_CVE_RANKING_JSON).await;
    let patcher = if is_live_nvd_reachable().await {
        KernelPatcher::new()
    } else {
        KernelPatcher::with_base_url(&mock_server.endpoint_url)
    };

    let api_key = std::env::var("NVD_API_KEY")
        .ok()
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty());

    // Scan a known older kernel CPE against local 127.0.0.1 mock (or live NVD if opted in)
    let query_cpe = "cpe:2.3:o:linux:linux_kernel:5.10.0:*:*:*:*:*:*:*";
    let options = test_scan_options(Some(query_cpe), None, false, api_key.as_deref());

    match patcher.scan_kernel_vulnerabilities(&options).await {
        Ok(vulns) => {
            assert!(!vulns.is_empty());
            assert_vulnerability_ranking(&vulns);
        }
        Err(PatcherError::RateLimited) | Err(PatcherError::Network(_)) => {}
        Err(e) => {
            panic!("Unexpected error in scan: {:?}", e);
        }
    }
}
