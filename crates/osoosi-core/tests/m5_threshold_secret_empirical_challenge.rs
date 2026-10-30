// crates/osoosi-core/tests/m5_threshold_secret_empirical_challenge.rs
//
// Empirical Adversarial Stress Test Suite for Milestone M5:
// Shamir Threshold Secret Sharing, GF(2^8) Arithmetic, Micro-Perimeters at Rest & Anti-Rollback.

use osoosi_core::threshold_secret::{
    gf256_inv, gf256_mul, verify_anti_rollback_epoch, KeyShare, MicroPerimeterCrypto,
    ShamirThresholdScheme, ThresholdSecretError, VolatilePeerShareEntry,
    VolatilePeerShareRegistry,
};
use rand::RngCore;

#[test]
fn test_empirical_gf256_axiomatic_and_boundary_correctness() {
    // 1. Zero property (annihilator) for all elements
    for a in 0..=255u8 {
        assert_eq!(gf256_mul(0, a), 0, "0 * {a} must be 0");
        assert_eq!(gf256_mul(a, 0), 0, "{a} * 0 must be 0");
    }

    // 2. Identity property
    for a in 0..=255u8 {
        assert_eq!(gf256_mul(1, a), a, "1 * {a} must be {a}");
        assert_eq!(gf256_mul(a, 1), a, "{a} * 1 must be {a}");
    }

    // 3. Boundary multiplication: 255 * 255
    // In GF(2^8) mod x^8 + x^4 + x^3 + x + 1 (0x11B),
    // (x^7 + ... + 1)^2 = x^14 + x^12 + x^10 + x^8 + x^6 + x^4 + x^2 + 1 = x^4 + x + 1 = 19 (0x13).
    let prod_255 = gf256_mul(255, 255);
    assert_eq!(prod_255, 19, "255 * 255 in GF(2^8) mod 0x11B must be 19 (0x13)");

    // 4. Commutativity across all 65,536 pairs
    for a in 0..=255u8 {
        for b in a..=255u8 {
            assert_eq!(
                gf256_mul(a, b),
                gf256_mul(b, a),
                "Commutativity failed for ({a}, {b})"
            );
        }
    }

    // 5. Fermat's Little Theorem Multiplicative Inversion: a * a^-1 == 1 for all a in 1..=255
    for a in 1..=255u8 {
        let inv = gf256_inv(a).expect("Inversion must succeed for all non-zero field elements");
        assert_eq!(
            gf256_mul(a, inv),
            1,
            "Inversion failed for {a}: inv={inv}"
        );
        // Double inversion property
        let inv_inv = gf256_inv(inv).expect("Double inversion must succeed");
        assert_eq!(inv_inv, a, "Double inversion must return original element");
    }

    // 6. Division by zero must return ThresholdSecretError::DivisionByZero without panic
    let zero_res = gf256_inv(0);
    assert_eq!(zero_res, Err(ThresholdSecretError::DivisionByZero));
}

#[test]
fn test_empirical_shamir_combinatorial_quorum_stress() {
    let mut rng = rand::rngs::OsRng;

    // Test 2-of-3: all 3 combinations of 2 shares
    {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let shares = ShamirThresholdScheme::split_secret(&secret, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);

        let pairs = [(0, 1), (0, 2), (1, 2)];
        for &(i, j) in &pairs {
            let recon = ShamirThresholdScheme::reconstruct_secret(
                &[shares[i].clone(), shares[j].clone()],
                2,
            )
            .unwrap();
            assert_eq!(recon, secret, "Quorum ({i}, {j}) failed for 2-of-3");
        }
    }

    // Test 3-of-5: all 10 combinations of 3 shares
    {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let shares = ShamirThresholdScheme::split_secret(&secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        let mut quorums_tested = 0;
        for i in 0..5 {
            for j in (i + 1)..5 {
                for k in (j + 1)..5 {
                    let recon = ShamirThresholdScheme::reconstruct_secret(
                        &[shares[i].clone(), shares[j].clone(), shares[k].clone()],
                        3,
                    )
                    .unwrap();
                    assert_eq!(recon, secret, "Quorum ({i}, {j}, {k}) failed for 3-of-5");
                    quorums_tested += 1;
                }
            }
        }
        assert_eq!(quorums_tested, 10);
    }

    // Test 4-of-7: all 35 combinations of 4 shares
    {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let shares = ShamirThresholdScheme::split_secret(&secret, 4, 7).unwrap();
        assert_eq!(shares.len(), 7);

        let mut quorums_tested = 0;
        for i in 0..7 {
            for j in (i + 1)..7 {
                for k in (j + 1)..7 {
                    for l in (k + 1)..7 {
                        let recon = ShamirThresholdScheme::reconstruct_secret(
                            &[
                                shares[i].clone(),
                                shares[j].clone(),
                                shares[k].clone(),
                                shares[l].clone(),
                            ],
                            4,
                        )
                        .unwrap();
                        assert_eq!(
                            recon, secret,
                            "Quorum ({i}, {j}, {k}, {l}) failed for 4-of-7"
                        );
                        quorums_tested += 1;
                    }
                }
            }
        }
        assert_eq!(quorums_tested, 35);
    }

    // Test 5-of-9: test with 5 shares and k >= t (e.g. 6 and 7 shares)
    {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let shares = ShamirThresholdScheme::split_secret(&secret, 5, 9).unwrap();
        assert_eq!(shares.len(), 9);

        // Exactly 5 shares
        let recon5 = ShamirThresholdScheme::reconstruct_secret(&shares[0..5], 5).unwrap();
        assert_eq!(recon5, secret);

        // 6 shares passed (k > t)
        let recon6 = ShamirThresholdScheme::reconstruct_secret(&shares[0..6], 5).unwrap();
        assert_eq!(recon6, secret);

        // 9 shares passed (all n shares)
        let recon9 = ShamirThresholdScheme::reconstruct_secret(&shares, 5).unwrap();
        assert_eq!(recon9, secret);
    }
}

#[test]
fn test_empirical_shamir_adversarial_error_cases() {
    let mut rng = rand::rngs::OsRng;
    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);

    let shares = ShamirThresholdScheme::split_secret(&secret, 3, 5).unwrap();

    // 1. Sub-threshold quorum: k < t (2 shares provided for threshold 3)
    let sub_res = ShamirThresholdScheme::reconstruct_secret(&shares[0..2], 3);
    assert_eq!(
        sub_res,
        Err(ThresholdSecretError::InsufficientShares {
            actual: 2,
            required: 3
        })
    );

    // 2. Duplicated coordinate in quorum
    let dup_res = ShamirThresholdScheme::reconstruct_secret(
        &[shares[0].clone(), shares[0].clone(), shares[1].clone()],
        3,
    );
    assert_eq!(
        dup_res,
        Err(ThresholdSecretError::DuplicateShareIndex {
            index: shares[0].index
        })
    );

    // 3. Coordinate x = 0
    let mut zero_coord = shares[0].clone();
    zero_coord.index = 0;
    let zero_res = ShamirThresholdScheme::reconstruct_secret(
        &[zero_coord, shares[1].clone(), shares[2].clone()],
        3,
    );
    assert_eq!(zero_res, Err(ThresholdSecretError::ZeroCoordinateNotAllowed));

    // 4. Inconsistent share length (truncated data)
    let mut corrupt_len = shares[0].clone();
    corrupt_len.data.pop(); // 31 bytes instead of 32
    let len_res = ShamirThresholdScheme::reconstruct_secret(
        &[corrupt_len, shares[1].clone(), shares[2].clone()],
        3,
    );
    assert_eq!(
        len_res,
        Err(ThresholdSecretError::InconsistentShareLength {
            expected: 32,
            actual: 31
        })
    );

    // 5. Corrupted share data (bit flip) triggers FingerprintMismatch
    let mut bit_flip = shares[0].clone();
    bit_flip.data[0] ^= 0x01;
    let fp_res = ShamirThresholdScheme::reconstruct_secret(
        &[bit_flip, shares[1].clone(), shares[2].clone()],
        3,
    );
    assert_eq!(fp_res, Err(ThresholdSecretError::FingerprintMismatch));

    // 6. Cross-secret share mixing triggers FingerprintMismatch
    let mut other_secret = [0u8; 32];
    rng.fill_bytes(&mut other_secret);
    let other_shares = ShamirThresholdScheme::split_secret(&other_secret, 3, 5).unwrap();
    let mixed_res = ShamirThresholdScheme::reconstruct_secret(
        &[shares[0].clone(), shares[1].clone(), other_shares[2].clone()],
        3,
    );
    assert_eq!(mixed_res, Err(ThresholdSecretError::FingerprintMismatch));
}

#[test]
fn test_empirical_micro_perimeter_crypto_adversarial_tampering() {
    let mut rng = rand::rngs::OsRng;
    let mut master_key = [0u8; 32];
    rng.fill_bytes(&mut master_key);

    let plaintext = b"oshoosi_agent_breakout_defense_sqlite_credentials_and_state";
    let target_path = "database/osoosi.db";
    let host_did = "did:oshoosi:node_alpha";
    let commit_epoch = 100;

    let envelope = MicroPerimeterCrypto::encrypt_envelope(
        plaintext,
        &master_key,
        target_path,
        host_did,
        commit_epoch,
    )
    .expect("Encryption must succeed");

    // 1. Valid roundtrip
    let (decrypted, epoch) = MicroPerimeterCrypto::decrypt_envelope(
        &envelope,
        &master_key,
        target_path,
        host_did,
    )
    .expect("Valid envelope must decrypt cleanly");
    assert_eq!(decrypted, plaintext);
    assert_eq!(epoch, commit_epoch);

    // 2. Anti-transposition: wrong target path
    let trans_path_res = MicroPerimeterCrypto::decrypt_envelope(
        &envelope,
        &master_key,
        "osoosi.toml",
        host_did,
    );
    assert!(trans_path_res.is_err());
    if let Err(ThresholdSecretError::AeadAuthenticationFailed(msg)) = trans_path_res {
        assert!(msg.contains("Anti-transposition violation"));
    } else {
        panic!("Expected AeadAuthenticationFailed with anti-transposition message");
    }

    // 3. Anti-transposition: wrong host DID
    let trans_did_res = MicroPerimeterCrypto::decrypt_envelope(
        &envelope,
        &master_key,
        target_path,
        "did:oshoosi:node_adversary",
    );
    assert!(trans_did_res.is_err());

    // 4. Ciphertext 1-bit flip tampering
    let mut tampered_ct = envelope.clone();
    let ct_pos = tampered_ct.len() - 35; // Inside ciphertext region
    tampered_ct[ct_pos] ^= 0x01;
    let ct_err = MicroPerimeterCrypto::decrypt_envelope(
        &tampered_ct,
        &master_key,
        target_path,
        host_did,
    );
    assert!(ct_err.is_err());

    // 5. Nonce 1-bit flip tampering
    let mut tampered_nonce = envelope.clone();
    tampered_nonce[35] ^= 0x02; // Inside nonce region [32..44]
    let nonce_err = MicroPerimeterCrypto::decrypt_envelope(
        &tampered_nonce,
        &master_key,
        target_path,
        host_did,
    );
    assert!(nonce_err.is_err());

    // 6. Magic corruption
    let mut bad_magic = envelope.clone();
    bad_magic[0] = b'X';
    let magic_err = MicroPerimeterCrypto::decrypt_envelope(
        &bad_magic,
        &master_key,
        target_path,
        host_did,
    );
    assert!(magic_err.is_err());

    // 7. Truncation
    let truncated = &envelope[0..40];
    let trunc_err = MicroPerimeterCrypto::decrypt_envelope(
        truncated,
        &master_key,
        target_path,
        host_did,
    );
    assert!(trunc_err.is_err());
}

#[test]
fn test_empirical_volatile_peer_registry_and_anti_rollback() {
    let registry = VolatilePeerShareRegistry::new();
    let share = KeyShare {
        index: 2,
        data: vec![0xEE; 32],
        threshold: 2,
        total_shares: 3,
        key_fingerprint: [0x77; 16],
    };
    let entry = VolatilePeerShareEntry {
        share: share.clone(),
        node_did: "did:oshoosi:peer_charlie".to_string(),
        expected_pcr0_hex: "AABBCCDD00112233".to_string(),
        expected_pcr7_hex: "445566778899AABB".to_string(),
        latest_epoch: 25,
    };
    registry.store_share("did:oshoosi:peer_charlie", entry);

    // 1. Quarantined peer rejected
    let q_err = registry.evaluate_and_release_share(
        "did:oshoosi:peer_charlie",
        "AABBCCDD00112233",
        "445566778899AABB",
        25,
        true, // quarantined
    );
    assert_eq!(
        q_err,
        Err(ThresholdSecretError::PeerQuorumRejected(
            "Node is currently in quarantine".into()
        ))
    );

    // 2. Rollback epoch rejected
    let rb_err = registry.evaluate_and_release_share(
        "did:oshoosi:peer_charlie",
        "AABBCCDD00112233",
        "445566778899AABB",
        24, // presented 24 < anchor 25
        false,
    );
    assert_eq!(
        rb_err,
        Err(ThresholdSecretError::StateRollbackDetected {
            on_disk: 24,
            anchor: 25
        })
    );

    // 3. PCR mismatch rejected
    let pcr_err = registry.evaluate_and_release_share(
        "did:oshoosi:peer_charlie",
        "0000000000000000", // Tampered PCR0
        "445566778899AABB",
        25,
        false,
    );
    assert_eq!(
        pcr_err,
        Err(ThresholdSecretError::TpmPolicyViolation(
            "PCR measurements mismatch peer baseline".into()
        ))
    );

    // 4. Legitimate attestation releases share
    let ok_share = registry
        .evaluate_and_release_share(
            "did:oshoosi:peer_charlie",
            "aabbccdd00112233", // Case-insensitive hex
            "445566778899aabb",
            25,
            false,
        )
        .expect("Valid attestation must release share");
    assert_eq!(ok_share.data, share.data);

    // 5. Monotonic epoch advancement (epoch 26 >= 25)
    let advanced_share = registry
        .evaluate_and_release_share(
            "did:oshoosi:peer_charlie",
            "aabbccdd00112233",
            "445566778899aabb",
            26,
            false,
        )
        .expect("Monotonic epoch progression must succeed");
    assert_eq!(advanced_share.data, share.data);

    // 6. Purge volatile memory
    registry.purge_all_volatile_memory();
    let purged_err = registry.evaluate_and_release_share(
        "did:oshoosi:peer_charlie",
        "aabbccdd00112233",
        "445566778899aabb",
        26,
        false,
    );
    assert!(purged_err.is_err());

    // 7. verify_anti_rollback_epoch
    assert!(verify_anti_rollback_epoch(10, 10, "state_root_1", "state_root_1").is_ok());
    assert!(verify_anti_rollback_epoch(11, 10, "state_root_2", "state_root_1").is_ok());
    assert_eq!(
        verify_anti_rollback_epoch(9, 10, "state_root_old", "state_root_current"),
        Err(ThresholdSecretError::StateRollbackDetected {
            on_disk: 9,
            anchor: 10
        })
    );
    assert_eq!(
        verify_anti_rollback_epoch(10, 10, "state_root_fork", "state_root_current"),
        Err(ThresholdSecretError::StateForkDetected { epoch: 10 })
    );
}
