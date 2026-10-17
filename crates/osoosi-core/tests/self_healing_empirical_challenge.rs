use osoosi_audit::AuditTrail;
use osoosi_core::self_healing::SelfHealingEngine;
use osoosi_memory::MemoryStore;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn test_tamper_bypass_when_hash_file_and_audit_entry_missing() {
    let dir = tempdir().unwrap();
    let target_file = dir.path().join("system_policy.cfg");
    let backup_file = dir.path().join("system_policy.bak");

    // Existing authentic policy on target
    let authentic_content = b"LEGITIMATE_SYSTEM_POLICY_ACTIVE";
    std::fs::write(&target_file, authentic_content).unwrap();

    // Attacker drops malicious backup without any hash file or audit trail record
    let malicious_content = b"MALICIOUS_COMPROMISED_ROOTKIT_CODE";
    std::fs::write(&backup_file, malicious_content).unwrap();

    let audit = Arc::new(AuditTrail::new());
    let memory = Arc::new(MemoryStore::new(":memory:").unwrap());
    let engine = SelfHealingEngine::new(audit, memory);

    // Act: Attempt to restore when neither hash file nor audit entry exists
    let res = engine.rollback_process_actions(1337).await.unwrap();

    // Assert: Engine must fail closed. Zero files restored, target remains untouched.
    assert_eq!(res, 0, "Self-healing must fail closed when hash is missing");
    let current_content = std::fs::read(&target_file).unwrap();
    assert_eq!(
        current_content, authentic_content,
        "Target file must not be overwritten with unverified attacker payload"
    );
}

#[tokio::test]
async fn test_tamper_bypass_by_forging_local_hash_file_over_audit_trail() {
    let dir = tempdir().unwrap();
    let target_file = dir.path().join("system_policy.cfg");
    let backup_file = dir.path().join("system_policy.bak");
    let hash_file = dir.path().join("system_policy.bak.sha256");

    let authentic_content = b"GENUINE_POLICY_CONTENT";
    std::fs::write(&target_file, authentic_content).unwrap();

    let authentic_hash = hex::encode(Sha256::digest(authentic_content));

    // Audit trail immutably records the genuine backup hash
    let audit = Arc::new(AuditTrail::new());
    audit.log(
        "FILE_MODIFIED",
        serde_json::json!({
            "pid": 4242,
            "path": target_file.to_str().unwrap(),
            "backup_sha256": authentic_hash
        }),
    );

    // Attacker writes tampered backup AND writes forged adjacent .bak.sha256 matching tampered backup
    let tampered_content = b"TAMPERED_POLICY_DISABLE_FIREWALL";
    std::fs::write(&backup_file, tampered_content).unwrap();
    let forged_hash = hex::encode(Sha256::digest(tampered_content));
    std::fs::write(&hash_file, &forged_hash).unwrap();

    let memory = Arc::new(MemoryStore::new(":memory:").unwrap());
    let engine = SelfHealingEngine::new(audit, memory);

    // Act: Attempt rollback
    let res = engine.rollback_process_actions(4242).await.unwrap();

    // Assert: Audit trail primacy must detect forged hash file conflict and reject restoration
    assert_eq!(
        res, 0,
        "Self-healing must reject restore when local hash file contradicts audit trail"
    );
    let current_content = std::fs::read(&target_file).unwrap();
    assert_eq!(
        current_content, authentic_content,
        "Target file must remain authentic and reject forged backup"
    );
}

#[tokio::test]
async fn test_legitimate_restore_from_audit_trail_without_local_hash_file() {
    let dir = tempdir().unwrap();
    let target_file = dir.path().join("system_policy.cfg");
    let backup_file = dir.path().join("system_policy.bak");

    let original_content = b"GENUINE_SYSTEM_POLICY_V1";
    let original_hash = hex::encode(Sha256::digest(original_content));

    // Valid backup exists on disk
    std::fs::write(&backup_file, original_content).unwrap();

    // Target was modified by unauthorized process 9999
    std::fs::write(&target_file, b"CORRUPTED_MODIFIED_STATE").unwrap();

    // Audit trail has the authoritative hash, but NO local .bak.sha256 exists
    let audit = Arc::new(AuditTrail::new());
    audit.log(
        "FILE_MODIFIED",
        serde_json::json!({
            "pid": 9999,
            "path": target_file.to_str().unwrap(),
            "backup_sha256": original_hash
        }),
    );

    let memory = Arc::new(MemoryStore::new(":memory:").unwrap());
    let engine = SelfHealingEngine::new(audit, memory);

    // Act: Rollback process actions
    let res = engine.rollback_process_actions(9999).await.unwrap();

    // Assert: Successfully restored from backup authenticated via Merkle audit trail
    assert_eq!(res, 1, "Expected 1 file restored via audit trail");
    let current_content = std::fs::read(&target_file).unwrap();
    assert_eq!(
        current_content, original_content,
        "Target file must be restored to authentic state"
    );
}
