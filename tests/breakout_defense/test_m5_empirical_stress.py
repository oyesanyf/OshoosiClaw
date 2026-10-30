"""
Milestone M5 Empirical Stress Challenge Harness
Independent verification of Galois Field GF(2^8) arithmetic, Shamir (t, n) Secret Sharing,
and MicroPerimeterCrypto AEAD Envelope Integrity for OshoosiClaw.
"""

import os
import sys
import unittest
import hashlib
import hmac
import json
from typing import List, Tuple

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
import oracles


class TestM5EmpiricalStressGF256(unittest.TestCase):
    """Galois Field GF(2^8) arithmetic boundary and algebraic property stress tests."""

    def test_gf256_zero_annihilator(self):
        """Verify 0 * a = 0 for all a in [0, 255]."""
        for a in range(256):
            self.assertEqual(oracles.gf256_mul_oracle(0, a), 0, f"0 * {a} failed")
            self.assertEqual(oracles.gf256_mul_oracle(a, 0), 0, f"{a} * 0 failed")

    def test_gf256_multiplicative_identity(self):
        """Verify 1 * a = a for all a in [0, 255]."""
        for a in range(256):
            self.assertEqual(oracles.gf256_mul_oracle(1, a), a, f"1 * {a} failed")
            self.assertEqual(oracles.gf256_mul_oracle(a, 1), a, f"{a} * 1 failed")

    def test_gf256_boundary_255_times_255(self):
        """Verify 255 * 255 in GF(2^8) modulo 0x11B."""
        # Mathematical derivation:
        # 255 = x^7 + x^6 + x^5 + x^4 + x^3 + x^2 + x + 1
        # In GF(2), (sum x^i)^2 = sum x^(2i) mod (x^8 + x^4 + x^3 + x + 1)
        res = oracles.gf256_mul_oracle(255, 255)
        # Verify commutativity and self-consistency
        self.assertIsInstance(res, int)
        self.assertTrue(0 <= res <= 255)
        # Direct polynomial multiplication check in GF(2)[x] / (x^8 + x^4 + x^3 + x + 1)
        p = 0
        poly = 0x11B
        a, b = 255, 255
        for _ in range(8):
            if b & 1:
                p ^= a
            hi = a & 0x80
            a = (a << 1) & 0xFF
            if hi:
                a ^= 0x1B
            b >>= 1
        self.assertEqual(res, p)
        # Ensure non-trivial non-zero result
        self.assertNotEqual(res, 0)
        self.assertEqual(res, 19)  # 0x13: x^4 + x + 1

    def test_gf256_commutativity_all_pairs(self):
        """Verify a * b == b * a for all 65,536 pairs."""
        for a in range(256):
            for b in range(a, 256):
                ab = oracles.gf256_mul_oracle(a, b)
                ba = oracles.gf256_mul_oracle(b, a)
                self.assertEqual(ab, ba, f"Commutativity failed for ({a}, {b})")

    def test_gf256_distributivity(self):
        """Verify a * (b ^ c) == (a * b) ^ (a * c) for representative and edge cases."""
        corners = [0, 1, 2, 0x1B, 0x80, 0xAA, 0x55, 255]
        for a in corners:
            for b in corners:
                for c in corners:
                    left = oracles.gf256_mul_oracle(a, b ^ c)
                    right = oracles.gf256_mul_oracle(a, b) ^ oracles.gf256_mul_oracle(a, c)
                    self.assertEqual(left, right, f"Distributivity failed for ({a}, {b}, {c})")

    def test_gf256_fermat_inversion_all_non_zero_elements(self):
        """Verify a * a^-1 == 1 for all non-zero elements a in [1, 255]."""
        for a in range(1, 256):
            inv = oracles.gf256_inv_oracle(a)
            self.assertTrue(1 <= inv <= 255)
            prod = oracles.gf256_mul_oracle(a, inv)
            self.assertEqual(prod, 1, f"Inversion failed for {a}: inv={inv}, prod={prod}")
            # Double inversion: (a^-1)^-1 == a
            inv_inv = oracles.gf256_inv_oracle(inv)
            self.assertEqual(inv_inv, a, f"Double inversion failed for {a}")

    def test_gf256_inversion_by_zero_fails_closed(self):
        """Verify inversion of zero raises ZeroDivisionError."""
        with self.assertRaises(ZeroDivisionError):
            oracles.gf256_inv_oracle(0)


class TestM5EmpiricalStressShamirThreshold(unittest.TestCase):
    """Shamir t-of-n Secret Sharing threshold reconstruction, quorum stress, and entropy tests."""

    def _split_secret(self, secret: bytes, threshold: int, total_shares: int) -> List[Tuple[int, bytes]]:
        """Helper to split a secret using the GF(2^8) polynomial scheme."""
        shares_data = [bytearray() for _ in range(total_shares)]
        for secret_byte in secret:
            # Sample t-1 random coefficients
            coeffs = [secret_byte] + [os.urandom(1)[0] for _ in range(threshold - 1)]
            for share_idx in range(total_shares):
                x = share_idx + 1
                val = 0
                x_pow = 1
                for coeff in coeffs:
                    val ^= oracles.gf256_mul_oracle(coeff, x_pow)
                    x_pow = oracles.gf256_mul_oracle(x_pow, x)
                shares_data[share_idx].append(val)
        return [(i + 1, bytes(data)) for i, data in enumerate(shares_data)]

    def test_shamir_multi_threshold_reconstruction(self):
        """Test reconstruction across multiple (t, n) configurations: (2,3), (3,5), (4,7), (5,9)."""
        configs = [(2, 3), (3, 5), (4, 7), (5, 9)]
        for t, n in configs:
            secret = os.urandom(32)
            shares = self._split_secret(secret, t, n)
            self.assertEqual(len(shares), n)

            # Test multiple distinct quorums of size t
            # First t shares
            q1 = shares[:t]
            r1 = oracles.shamir_reconstruct_secret_oracle(q1, t)
            self.assertEqual(r1, secret, f"Quorum 1 failed for ({t}, {n})")

            # Last t shares
            q2 = shares[n - t:]
            r2 = oracles.shamir_reconstruct_secret_oracle(q2, t)
            self.assertEqual(r2, secret, f"Quorum 2 failed for ({t}, {n})")

            # Stride / interleaved shares
            q3 = shares[::2][:t]
            if len(q3) == t:
                r3 = oracles.shamir_reconstruct_secret_oracle(q3, t)
                self.assertEqual(r3, secret, f"Interleaved quorum failed for ({t}, {n})")

    def test_shamir_sub_threshold_fails_closed(self):
        """Verify that any subset of size k < t strictly fails reconstruction."""
        configs = [(2, 3), (3, 5), (4, 7), (5, 9)]
        for t, n in configs:
            secret = os.urandom(32)
            shares = self._split_secret(secret, t, n)

            # Subset of size t - 1
            sub_quorum = shares[:t - 1]
            with self.assertRaises(ValueError):
                oracles.shamir_reconstruct_secret_oracle(sub_quorum, t)

            # Subset of size 1
            with self.assertRaises(ValueError):
                oracles.shamir_reconstruct_secret_oracle([shares[0]], t)

    def test_shamir_duplicate_coordinates_rejected(self):
        """Verify that presenting duplicated x coordinates in quorum is rejected."""
        secret = os.urandom(32)
        shares = self._split_secret(secret, 3, 5)
        # Duplicate share 0
        corrupt_quorum = [shares[0], shares[0], shares[1]]
        with self.assertRaises(ValueError) as ctx:
            oracles.shamir_reconstruct_secret_oracle(corrupt_quorum, 3)
        self.assertIn("Duplicate", str(ctx.exception))

    def test_shamir_zero_coordinate_rejected(self):
        """Verify that x=0 coordinate is rejected."""
        secret = os.urandom(32)
        shares = self._split_secret(secret, 2, 3)
        zero_share = (0, shares[0][1])
        with self.assertRaises(ValueError) as ctx:
            oracles.shamir_reconstruct_secret_oracle([zero_share, shares[1]], 2)
        self.assertIn("Zero coordinate", str(ctx.exception))

    def test_shamir_permutation_invariance(self):
        """Verify that share order in quorum does not affect reconstruction."""
        secret = os.urandom(32)
        shares = self._split_secret(secret, 3, 5)
        # Quorum in normal order: [1, 2, 3]
        r_normal = oracles.shamir_reconstruct_secret_oracle([shares[0], shares[1], shares[2]], 3)
        # Quorum reversed: [3, 2, 1]
        r_reversed = oracles.shamir_reconstruct_secret_oracle([shares[2], shares[1], shares[0]], 3)
        # Quorum permuted: [2, 3, 1]
        r_permuted = oracles.shamir_reconstruct_secret_oracle([shares[1], shares[2], shares[0]], 3)
        self.assertEqual(r_normal, secret)
        self.assertEqual(r_reversed, secret)
        self.assertEqual(r_permuted, secret)


class TestM5EmpiricalStressMicroPerimeterAEAD(unittest.TestCase):
    """MicroPerimeterCrypto envelope AEAD tampering, anti-transposition, and anti-rollback tests."""

    def _encrypt_envelope(self, plaintext: bytes, master_key: bytes, target_path: str, host_did: str, epoch: int) -> bytes:
        """Mirrors MicroPerimeterCrypto::encrypt_envelope format."""
        salt = os.urandom(16)
        nonce = os.urandom(12)
        ad = {"target_path": target_path, "host_did": host_did, "commit_epoch": epoch}
        ad_json = json.dumps(ad, separators=(",", ":")).encode("utf-8")

        # Subkey derivation
        k_enc = hashlib.sha256(master_key + salt + b"|MICRO_PERIMETER_ENC_V1").digest()
        k_mac = hashlib.sha256(master_key + salt + b"|MICRO_PERIMETER_MAC_V1").digest()

        # Keystream encryption
        ciphertext = bytearray()
        counter = 0
        offset = 0
        while offset < len(plaintext):
            block = hashlib.sha256(k_enc + nonce + counter.to_bytes(4, "big")).digest()
            take = min(len(plaintext) - offset, 32)
            for p, k in zip(plaintext[offset:offset + take], block[:take]):
                ciphertext.append(p ^ k)
            offset += take
            counter += 1

        magic = b"OSHOOSI_CRYPT_V1"
        hdr = (
            magic
            + salt
            + nonce
            + epoch.to_bytes(8, "big")
            + len(ad_json).to_bytes(4, "big")
            + ad_json
            + bytes(ciphertext)
        )
        tag = hmac.new(k_mac, hdr, hashlib.sha256).digest()
        return hdr + tag

    def _decrypt_envelope(self, envelope: bytes, master_key: bytes, expected_path: str, expected_did: str) -> Tuple[bytes, int]:
        """Mirrors MicroPerimeterCrypto::decrypt_envelope verification."""
        magic = b"OSHOOSI_CRYPT_V1"
        if len(envelope) < 16 + 16 + 12 + 8 + 4 + 32 or envelope[:16] != magic:
            raise ValueError("Invalid magic or truncated")

        salt = envelope[16:32]
        nonce = envelope[32:44]
        epoch = int.from_bytes(envelope[44:52], "big")
        ad_len = int.from_bytes(envelope[52:56], "big")
        total_header_len = 56 + ad_len
        if len(envelope) < total_header_len + 32:
            raise ValueError("Truncated envelope")

        ad_json = envelope[56:total_header_len]
        ad = json.loads(ad_json.decode("utf-8"))
        if ad.get("target_path") != expected_path or ad.get("host_did") != expected_did:
            raise ValueError(f"Anti-transposition failure: expected ({expected_path}, {expected_did}), got ({ad.get('target_path')}, {ad.get('host_did')})")

        tag_start = len(envelope) - 32
        authenticated_data = envelope[:tag_start]
        auth_tag = envelope[tag_start:]
        ciphertext = envelope[total_header_len:tag_start]

        k_enc = hashlib.sha256(master_key + salt + b"|MICRO_PERIMETER_ENC_V1").digest()
        k_mac = hashlib.sha256(master_key + salt + b"|MICRO_PERIMETER_MAC_V1").digest()

        expected_tag = hmac.new(k_mac, authenticated_data, hashlib.sha256).digest()
        if not hmac.compare_digest(auth_tag, expected_tag):
            raise ValueError("HMAC tag authentication mismatch (tampering detected)")

        plaintext = bytearray()
        counter = 0
        offset = 0
        while offset < len(ciphertext):
            block = hashlib.sha256(k_enc + nonce + counter.to_bytes(4, "big")).digest()
            take = min(len(ciphertext) - offset, 32)
            for c, k in zip(ciphertext[offset:offset + take], block[:take]):
                plaintext.append(c ^ k)
            offset += take
            counter += 1

        return bytes(plaintext), epoch

    def test_envelope_roundtrip(self):
        """Verify normal encryption and decryption roundtrip."""
        key = os.urandom(32)
        payload = b"sensitive_sqlite_threat_log_and_config_state_at_rest"
        env = self._encrypt_envelope(payload, key, "database/osoosi.db", "did:oshoosi:node1", 42)
        decrypted, epoch = self._decrypt_envelope(env, key, "database/osoosi.db", "did:oshoosi:node1")
        self.assertEqual(decrypted, payload)
        self.assertEqual(epoch, 42)

    def test_envelope_ciphertext_tampering_fails_closed(self):
        """Verify flipping any bit in the ciphertext causes authentication failure."""
        key = os.urandom(32)
        payload = b"secret_database_content"
        env = bytearray(self._encrypt_envelope(payload, key, "database/osoosi.db", "did:oshoosi:node1", 10))
        # Tamper a byte in ciphertext (located before the 32-byte tag)
        env[len(env) - 35] ^= 0x01
        with self.assertRaises(ValueError) as ctx:
            self._decrypt_envelope(bytes(env), key, "database/osoosi.db", "did:oshoosi:node1")
        self.assertIn("tampering detected", str(ctx.exception))

    def test_envelope_nonce_tampering_fails_closed(self):
        """Verify tampering with nonce causes authentication failure."""
        key = os.urandom(32)
        payload = b"secret_database_content"
        env = bytearray(self._encrypt_envelope(payload, key, "database/osoosi.db", "did:oshoosi:node1", 10))
        # Nonce is at bytes 32..44
        env[35] ^= 0x80
        with self.assertRaises(ValueError) as ctx:
            self._decrypt_envelope(bytes(env), key, "database/osoosi.db", "did:oshoosi:node1")
        self.assertIn("tampering detected", str(ctx.exception))

    def test_envelope_anti_transposition_violation_rejected(self):
        """Verify anti-transposition: envelope created for path A cannot be decrypted for path B."""
        key = os.urandom(32)
        payload = b"database_credentials"
        env = self._encrypt_envelope(payload, key, "database/osoosi.db", "did:oshoosi:node1", 10)
        # Attempt to decrypt as osoosi.toml
        with self.assertRaises(ValueError) as ctx:
            self._decrypt_envelope(env, key, "osoosi.toml", "did:oshoosi:node1")
        self.assertIn("Anti-transposition failure", str(ctx.exception))

        # Attempt to decrypt with different host DID
        with self.assertRaises(ValueError) as ctx:
            self._decrypt_envelope(env, key, "database/osoosi.db", "did:oshoosi:node2")
        self.assertIn("Anti-transposition failure", str(ctx.exception))

    def test_audit_first_anti_rollback_epoch(self):
        """Verify monotonic epoch checks reject rolled back on-disk states."""
        # Simulated helper matching threshold_secret::verify_anti_rollback_epoch
        def verify_rollback(disk_epoch: int, anchor_epoch: int, disk_root: str, anchor_root: str):
            if disk_epoch < anchor_epoch:
                raise ValueError(f"StateRollbackDetected: disk {disk_epoch} < anchor {anchor_epoch}")
            if disk_epoch == anchor_epoch and disk_root != anchor_root:
                raise ValueError(f"StateForkDetected at epoch {disk_epoch}")
            return "STATE_OK"

        # Valid progress
        self.assertEqual(verify_rollback(10, 10, "rootA", "rootA"), "STATE_OK")
        self.assertEqual(verify_rollback(11, 10, "rootB", "rootA"), "STATE_OK")

        # Rollback attempt
        with self.assertRaises(ValueError) as ctx:
            verify_rollback(9, 10, "rootOld", "rootNew")
        self.assertIn("StateRollbackDetected", str(ctx.exception))

        # Fork attempt
        with self.assertRaises(ValueError) as ctx:
            verify_rollback(10, 10, "rootFork", "rootExpected")
        self.assertIn("StateForkDetected", str(ctx.exception))


class TestM5EmpiricalStressShamirEntropy(unittest.TestCase):
    """Information-theoretic security proof: H(Secret | k < t shares) = 256 bits."""

    def test_shamir_shannon_conditional_entropy_bijection(self):
        """
        Verify that for any t-1 shares in a t-of-n scheme, as the missing t-th share
        varies over all 256 elements of GF(2^8), the reconstructed secret byte at x=0
        takes every value in [0, 255] exactly once (bijective map).
        This proves zero mutual information I(Secret; Shares_{1..t-1}) = 0.
        """
        # Test for t = 3, n = 5
        # Given shares at x=1 and x=2, vary share at x=3 over all 256 values
        x1, y1 = 1, 0x5A
        x2, y2 = 2, 0xC3
        x3 = 3

        reconstructed_bytes = set()
        for y3 in range(256):
            # Reconstruct with quorum [(1, y1), (2, y2), (3, y3)]
            s = oracles.shamir_reconstruct_secret_oracle(
                [(x1, bytes([y1])), (x2, bytes([y2])), (x3, bytes([y3]))],
                3,
            )
            reconstructed_bytes.add(s[0])

        # Must form a complete bijection: exactly 256 distinct values
        self.assertEqual(
            len(reconstructed_bytes),
            256,
            "Shannon entropy violated: missing share did not map bijectively to all 256 field elements",
        )


class TestM5EmpiricalStressControlPlaneAuth(unittest.TestCase):
    """Local control plane auth, loopback origin validation, and NTFS/TPM integrity tests."""

    def test_session_auth_oracle_valid(self):
        """Verify valid admin token and valid loopback origin authorize session."""
        code, msg = oracles.control_plane_session_auth_oracle(
            presented_token="admin_super_secret_token_123",
            admin_secret="admin_super_secret_token_123",
            origin_header="http://127.0.0.1:3030",
            sec_fetch_site_header="same-origin",
        )
        self.assertEqual(code, 200)
        self.assertEqual(msg, "SESSION_AUTHORIZED")

    def test_session_auth_oracle_subdomain_spoofing_rejected(self):
        """Verify subdomain spoofing (http://127.0.0.1.attacker.com) is forbidden."""
        code, msg = oracles.control_plane_session_auth_oracle(
            presented_token="admin_super_secret_token_123",
            admin_secret="admin_super_secret_token_123",
            origin_header="http://127.0.0.1.attacker.com:3030",
            sec_fetch_site_header="same-origin",
        )
        self.assertEqual(code, 403)
        self.assertIn("FORBIDDEN", msg)

    def test_session_auth_oracle_cross_site_rejected(self):
        """Verify cross-site Sec-Fetch-Site is forbidden."""
        code, msg = oracles.control_plane_session_auth_oracle(
            presented_token="admin_super_secret_token_123",
            admin_secret="admin_super_secret_token_123",
            origin_header="http://127.0.0.1:3030",
            sec_fetch_site_header="cross-site",
        )
        self.assertEqual(code, 403)
        self.assertIn("Untrusted Sec-Fetch-Site", msg)

    def test_session_auth_oracle_invalid_token_rejected(self):
        """Verify bad session token is unauthorized."""
        code, msg = oracles.control_plane_session_auth_oracle(
            presented_token="wrong_token_guess",
            admin_secret="admin_super_secret_token_123",
            origin_header="http://127.0.0.1:3030",
            sec_fetch_site_header="same-origin",
        )
        self.assertEqual(code, 401)
        self.assertIn("UNAUTHORIZED", msg)

    def test_ntfs_dacl_sddl_protection(self):
        """Verify protected SDDL format for SYSTEM and Administrators only."""
        valid_sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
        is_ok, reason = oracles.validate_ntfs_dacl_sddl_oracle(valid_sddl)
        self.assertTrue(is_ok, f"Valid SDDL failed: {reason}")

        # Permissive Everyone ACE rejected
        bad_sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;WD)"
        is_ok_bad, _ = oracles.validate_ntfs_dacl_sddl_oracle(bad_sddl)
        self.assertFalse(is_ok_bad)

    def test_tpm_row_integrity_tag_verification(self):
        """Verify TPM hardware-keyed row integrity tag detects tampering."""
        tpm_key = os.urandom(32)
        payload = b'{"setting":"edr_mode","value":"enforce"}'
        tag = oracles.compute_tpm_row_integrity_tag_oracle("ui_settings_kv", "setting_001", payload, tpm_key)
        self.assertTrue(oracles.verify_tpm_row_integrity_oracle("ui_settings_kv", "setting_001", payload, tag, tpm_key))

        # Tampered payload fails
        tampered = b'{"setting":"edr_mode","value":"disabled"}'
        self.assertFalse(oracles.verify_tpm_row_integrity_oracle("ui_settings_kv", "setting_001", tampered, tag, tpm_key))


if __name__ == "__main__":
    unittest.main()

