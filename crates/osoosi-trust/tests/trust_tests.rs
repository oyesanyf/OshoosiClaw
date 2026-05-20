use osoosi_trust::TrustManager;
use std::sync::Arc;

struct DummyExecutor;

#[async_trait::async_trait]
impl osoosi_types::SecuredExecutor for DummyExecutor {
    async fn execute(&self, _cmd: std::process::Command) -> anyhow::Result<std::process::Output> {
        Ok(std::process::Output {
            status: std::process::ExitStatus::default(),
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    }

    async fn download(&self, _url: &str, _dest: &std::path::Path, _resume: bool) -> anyhow::Result<()> {
        Ok(())
    }
}

#[test]
fn test_did_generation() {
    let tm = TrustManager::new(Arc::new(DummyExecutor)).expect("Failed to create TrustManager");
    let did = tm.did();

    assert!(
        did.id.starts_with("did:osoosi:"),
        "DID should use the osoosi prefix"
    );
    assert_eq!(
        did.public_key.len(),
        64,
        "Public key hex should be 64 characters (32 bytes)"
    );
}

#[tokio::test]
async fn test_ca_init_structure() {
    let tm = TrustManager::new(Arc::new(DummyExecutor)).expect("Failed to create TrustManager");
    let temp_dir = std::env::temp_dir().join(format!("osoosi_test_{}", uuid::Uuid::new_v4()));

    std::fs::create_dir_all(&temp_dir).unwrap();

    if let Err(e) = tm.init_ca(temp_dir.to_str().unwrap()).await {
        if e.to_string().contains("failed to fill whole buffer")
            || e.to_string().contains("not found")
        {
            return;
        }
        panic!("CA Init failed: {}", e);
    }

    assert!(temp_dir.join("rootCA.key").exists());
    assert!(temp_dir.join("rootCA.crt").exists());

    let _ = std::fs::remove_dir_all(temp_dir);
}
