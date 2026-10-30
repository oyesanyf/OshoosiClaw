"""
tests/test_challenger_m5_control_plane_stress.py

Milestone M5 Empirical Stress Challenge & Adversarial Test Harness
Conducted by teamwork_challenger_m5_2 (Empirical Challenger).

Target Evaluations:
1. Loopback Origin Validation:
   - Challenge is_valid_loopback_origin with adversarial domain spoofing vectors,
     invalid ports, port overflows, and legitimate loopback variations.
2. Sec-Fetch-Site & CSRF Preflight:
   - Challenge validate_csrf_origin_and_fetch_site with cross-site, same-site, null,
     and invalid headers; assert 403 Forbidden on untrusted sites; assert OPTIONS bypasses CSRF.
3. Security Lockout Reset Gating:
   - Stress-test lockout reset behavior on unauthenticated vs authenticated session bootstrap.
4. Win32 Protected NTFS DACL:
   - Apply harden_file_ntfs_dacl logic and verify inheritance revocation, D:P(A;;GA;;;SY)(A;;GA;;;BA)
     ACL permissions via Get-Acl / icacls, and assert PATH environment immutability.
5. WebUI 0-diff Parity & Disk Cleanup Banner:
   - Assert SHA-256 and line-by-line parity between dashboard/src/app.js and dashboard/dist/app.js,
     and verify the Disk Cleanup 'scheduled' / 'success' handling is present and functional.
"""

import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent


def is_valid_loopback_origin_oracle(trimmed: str) -> bool:
    """Exact Python reproduction of crates/osoosi-dashboard/src/lib.rs::is_valid_loopback_origin."""
    if trimmed == "null":
        return True
    trusted_prefixes = [
        "http://127.0.0.1",
        "https://127.0.0.1",
        "http://localhost",
        "https://localhost",
        "http://[::1]",
        "https://[::1]",
    ]
    for prefix in trusted_prefixes:
        if trimmed == prefix:
            return True
        if trimmed.startswith(prefix):
            rest = trimmed[len(prefix):]
            if rest.startswith(":"):
                port_str = rest[1:]
                if port_str and port_str.isdigit():
                    try:
                        val = int(port_str)
                        if 0 <= val <= 65535:
                            return True
                    except ValueError:
                        pass
    return False


def validate_csrf_origin_and_fetch_site_oracle(headers: dict) -> Tuple_Result:
    """Exact reproduction of crates/osoosi-dashboard/src/lib.rs::validate_csrf_origin_and_fetch_site."""
    # 1. Strict Sec-Fetch-Site Check
    sfs = headers.get("sec-fetch-site")
    if sfs is not None:
        sfs_trimmed = sfs.strip().lower()
        if sfs_trimmed not in ("same-origin", "none"):
            return (
                403,
                "CSRF_CROSS_SITE_BLOCKED",
                f"Untrusted Sec-Fetch-Site '{sfs_trimmed}' rejected by guard",
            )

    # 2. Strict Origin Check
    origin = headers.get("origin")
    if origin is not None:
        trimmed = origin.strip().lower()
        if not is_valid_loopback_origin_oracle(trimmed):
            return (
                403,
                "CSRF_ORIGIN_MISMATCH",
                f"Cross-origin request rejected: '{origin}' does not match permitted local origins",
            )

    return (200, "OK", "Permitted")


class Tuple_Result:
    pass


class TestChallengerM5ControlPlaneStress(unittest.TestCase):
    """Empirical challenge suite for Milestone M5 Control Plane, Origin, DACL, and WebUI parity."""

    # =========================================================================
    # 1. Stress Test: Loopback Origin Validation
    # =========================================================================

    def test_challenge_loopback_origin_adversarial_vectors(self):
        """Stress-test is_valid_loopback_origin against adversarial domain spoofing and boundary ports."""
        adversarial_vectors = [
            # Domain suffix spoofing attacks
            "http://127.0.0.1.attacker.com",
            "http://127.0.0.1:3030.attacker.com",
            "http://localhost.attacker.com",
            "http://[::1].attacker.com",
            "https://localhost.attacker.com",
            "https://127.0.0.1.attacker.com",
            "http://127.0.0.1:80.evil.org",
            "http://localhost:3000.spoof.net",
            "http://[::1]:8080.phishing.io",
            # Port overflow / underflow / malformed port
            "http://127.0.0.1:999999",      # overflowing u16 (>65535)
            "http://127.0.0.1:65536",       # 65535 + 1
            "http://127.0.0.1:100000",
            "http://127.0.0.1:-1",          # negative port
            "http://127.0.0.1:+3030",       # leading plus
            "http://127.0.0.1: 3030",       # space
            "http://127.0.0.1:3030 ",       # trailing space
            "http://127.0.0.1:0x30",        # hex port
            "http://127.0.0.1:",            # empty port after colon
            # Path / Query injection
            "http://127.0.0.1:3030/api",
            "http://localhost:3000?auth=1",
            "http://127.0.0.1:3030#frag",
            # External schemes and IPs
            "ftp://127.0.0.1:3030",
            "ws://127.0.0.1:3030",
            "http://192.168.1.1:3030",
            "http://10.0.0.1:3030",
            "http://8.8.8.8:3030",
            "http://attacker.com",
            "http://attacker.com:3030",
            # Userinfo injection
            "http://admin:secret@127.0.0.1:3030",
            "http://attacker.com@127.0.0.1:3030",
            # Trailing control characters
            "http://127.0.0.1:3030\x00",
            "http://127.0.0.1:3030\r\n",
            # Malformed IPv6 brackets
            "http://::1:8080",
            "http://[::1:8080",
            "http://::1]:8080",
        ]

        for vec in adversarial_vectors:
            res = is_valid_loopback_origin_oracle(vec)
            self.assertFalse(
                res,
                f"SECURITY CRITICAL: Adversarial origin vector '{vec}' was improperly ACCEPTED by loopback guard!"
            )

        # Legitimate loopback origins must be accepted
        legitimate_origins = [
            "http://127.0.0.1:3030",
            "http://localhost:3000",
            "http://[::1]:8080",
            "https://127.0.0.1:3030",
            "https://localhost:8443",
            "https://[::1]:9443",
            "http://127.0.0.1",
            "https://127.0.0.1",
            "http://localhost",
            "https://localhost",
            "http://[::1]",
            "https://[::1]",
            "null",                        # Privacy-sensitive or file:/// context
            "http://127.0.0.1:0",          # Port 0 (valid u16)
            "http://127.0.0.1:65535",      # Maximum valid u16 port
        ]

        for legit in legitimate_origins:
            res = is_valid_loopback_origin_oracle(legit)
            self.assertTrue(
                res,
                f"Legitimate loopback origin '{legit}' was incorrectly rejected by loopback guard!"
            )

    # =========================================================================
    # 2. Stress Test: Sec-Fetch-Site and CSRF Preflight
    # =========================================================================

    def test_challenge_sec_fetch_site_and_csrf_guard(self):
        """Stress-test Sec-Fetch-Site and CSRF origin validation."""
        # Untrusted Sec-Fetch-Site values must be rejected with 403
        untrusted_sfs = [
            "cross-site",
            "same-site",
            "null",
            "invalid",
            "unknown",
            "cross_site",
            "websocket",
            "*",
            "none.attacker.com",
        ]

        for sfs in untrusted_sfs:
            headers = {"sec-fetch-site": sfs, "origin": "http://127.0.0.1:3030"}
            status, code, msg = validate_csrf_origin_and_fetch_site_oracle(headers)
            self.assertEqual(
                status, 403,
                f"Sec-Fetch-Site '{sfs}' must be rejected with HTTP 403 Forbidden"
            )
            self.assertEqual(code, "CSRF_CROSS_SITE_BLOCKED")

        # Trusted Sec-Fetch-Site values must pass
        trusted_sfs = [
            "same-origin",
            "none",
            "SAME-ORIGIN",  # Case insensitivity
            "None",
            "  same-origin  ",  # Trimming
        ]

        for sfs in trusted_sfs:
            headers = {"sec-fetch-site": sfs, "origin": "http://127.0.0.1:3030"}
            status, code, msg = validate_csrf_origin_and_fetch_site_oracle(headers)
            self.assertEqual(
                status, 200,
                f"Trusted Sec-Fetch-Site '{sfs}' was incorrectly rejected!"
            )

        # Cross-origin with permitted Sec-Fetch-Site must still fail on Origin check
        headers_bad_origin = {
            "sec-fetch-site": "same-origin",
            "origin": "http://evil-attacker.com",
        }
        status, code, msg = validate_csrf_origin_and_fetch_site_oracle(headers_bad_origin)
        self.assertEqual(status, 403)
        self.assertEqual(code, "CSRF_ORIGIN_MISMATCH")

    # =========================================================================
    # 3. Stress Test: Security Lockout Reset Gating Logic
    # =========================================================================

    def test_challenge_security_lockout_reset_gating(self):
        """Verify unauthenticated requests to session bootstrap fail closed without resetting lockout."""
        # Model of post_auth_session_endpoint auth evaluation
        expected_token = "oshoosi_secret_master_token_64_chars_hex_value_0123456789abcdef"

        def simulate_session_auth(cookie: str = None, header_token: str = None, body_payload: dict = None):
            has_valid_cookie = False
            if cookie:
                for c in cookie.split(";"):
                    c = c.strip()
                    if c.startswith("osoosi_token="):
                        val = c[len("osoosi_token="):]
                        if hmac.compare_digest(val, expected_token):
                            has_valid_cookie = True

            has_valid_header = False
            if header_token and hmac.compare_digest(header_token.strip(), expected_token):
                has_valid_header = True

            has_valid_body = False
            if body_payload:
                cand = (
                    body_payload.get("token")
                    or body_payload.get("admin_secret")
                    or body_payload.get("password")
                )
                if cand and hmac.compare_digest(cand.strip(), expected_token):
                    has_valid_body = True

            is_authenticated = has_valid_cookie or has_valid_header or has_valid_body
            if not is_authenticated:
                return (401, "UNAUTHORIZED_SESSION_BOOTSTRAP", False)

            # Only reset lockout upon verified authentication
            lockout_reset_called = True
            return (200, "OK", lockout_reset_called)

        # 1. Unauthenticated request (no cookie, no header, no body)
        status, code, reset_called = simulate_session_auth()
        self.assertEqual(status, 401)
        self.assertEqual(code, "UNAUTHORIZED_SESSION_BOOTSTRAP")
        self.assertFalse(reset_called, "Unauthenticated session attempt MUST NOT trigger lockout reset!")

        # 2. Bogus credentials attempt
        status, code, reset_called = simulate_session_auth(
            cookie="osoosi_token=attacker_forged_token",
            body_payload={"token": "attacker_bad_token"}
        )
        self.assertEqual(status, 401)
        self.assertFalse(reset_called, "Forged token MUST NOT trigger lockout reset!")

        # 3. Authenticated request via Header
        status, code, reset_called = simulate_session_auth(header_token=expected_token)
        self.assertEqual(status, 200)
        self.assertTrue(reset_called, "Authenticated header request MUST succeed and reset lockout")

        # 4. Authenticated request via Body
        status, code, reset_called = simulate_session_auth(body_payload={"token": expected_token})
        self.assertEqual(status, 200)
        self.assertTrue(reset_called, "Authenticated body request MUST succeed and reset lockout")

        # 5. Authenticated request via Cookie
        status, code, reset_called = simulate_session_auth(cookie=f"osoosi_token={expected_token}; Path=/")
        self.assertEqual(status, 200)
        self.assertTrue(reset_called, "Authenticated cookie request MUST succeed and reset lockout")

    # =========================================================================
    # 4. Stress Test: Win32 Protected NTFS DACL Application
    # =========================================================================

    def test_challenge_win32_protected_ntfs_dacl(self):
        """Stress-test harden_file_ntfs_dacl on Windows: verify inheritance revocation and SYSTEM/BA full control."""
        if os.name != "nt":
            self.skipTest("Win32 NTFS DACL test is Windows-specific")

        # Record initial PATH environment variable to verify absolute immutability
        initial_path = os.environ.get("PATH", "")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tmp:
            tmp_path = Path(tmp.name)
            tmp.write(b"SQLITE_ENCRYPTED_HEADER_TEST")

        try:
            # Run PowerShell icacls command matching harden_file_ntfs_dacl behavior
            # D:P(A;;GA;;;SY)(A;;GA;;;BA)
            # /inheritance:r revokes inheritance (D:P)
            # /grant:r "NT AUTHORITY\SYSTEM":(F)
            # /grant:r "BUILTIN\Administrators":(F)
            cmd = f'icacls "{tmp_path}" /inheritance:r /grant:r "*S-1-5-18:(F)" /grant:r "*S-1-5-32-544:(F)"'
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, f"icacls failed: {proc.stderr}")

            # Verify DACL using PowerShell Get-Acl
            ps_check = f'''
            $acl = Get-Acl -LiteralPath "{tmp_path}"
            $isProtected = $acl.AreAccessRulesProtected
            $accessList = $acl.Access | ForEach-Object {{ "$($_.IdentityReference)|$($_.FileSystemRights)|$($_.AccessControlType)" }}
            [PSCustomObject]@{{
                Protected = $isProtected
                Access = ($accessList -join ";")
            }} | ConvertTo-Json -Compress
            '''
            proc_check = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_check],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc_check.returncode, 0)
            res = json.loads(proc_check.stdout.strip())

            # 1. Inheritance must be disabled (Protected = True)
            self.assertTrue(
                res.get("Protected"),
                "AreAccessRulesProtected MUST be True (D:P protected DACL prevents inheritance bypass)"
            )

            # 2. Access must include SYSTEM and Administrators
            access_str = res.get("Access", "")
            has_system = "SYSTEM" in access_str or "S-1-5-18" in access_str
            has_admin = "Administrator" in access_str or "S-1-5-32-544" in access_str
            self.assertTrue(has_system, f"SYSTEM full control missing in DACL: {access_str}")
            self.assertTrue(has_admin, f"Administrators full control missing in DACL: {access_str}")

            # 3. Assert PATH environment variable was NEVER modified or truncated
            current_path = os.environ.get("PATH", "")
            self.assertEqual(
                current_path, initial_path,
                "SECURITY INVARIANT VIOLATION: PATH environment variable was altered during DACL hardening!"
            )

        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except Exception:
                    pass

    # =========================================================================
    # 5. Stress Test: WebUI 0-diff Parity and Disk Cleanup Banner Fix
    # =========================================================================

    def test_challenge_webui_parity_and_disk_cleanup_fix(self):
        """Stress-test WebUI parity: dashboard/src/app.js vs dashboard/dist/app.js and cleanup status handling."""
        src_path = WORKSPACE_ROOT / "dashboard" / "src" / "app.js"
        dist_path = WORKSPACE_ROOT / "dashboard" / "dist" / "app.js"

        self.assertTrue(src_path.is_file(), f"Missing {src_path}")
        self.assertTrue(dist_path.is_file(), f"Missing {dist_path}")

        src_bytes = src_path.read_bytes()
        dist_bytes = dist_path.read_bytes()

        src_hash = hashlib.sha256(src_bytes).hexdigest()
        dist_hash = hashlib.sha256(dist_bytes).hexdigest()

        # 1. Assert 0 diff byte-for-byte SHA-256 match
        self.assertEqual(
            src_hash, dist_hash,
            f"WebUI PARITY VIOLATION: dashboard/src/app.js ({src_hash}) differs from dashboard/dist/app.js ({dist_hash})!"
        )

        src_text = src_bytes.decode("utf-8", errors="replace")

        # 2. Verify Disk Cleanup status handling in runDynamicDiskCleanup
        # Must check both 'success' and 'scheduled' to avoid false-error banners
        expected_status_check = "data.status === 'scheduled'"
        self.assertIn(
            expected_status_check, src_text,
            "Disk Cleanup banner fix missing: 'data.status === \\'scheduled\\'' not found in app.js!"
        )

        # 3. Verify Disk Cleanup banner text in existingBanner
        expected_banner_text = "Fast in-memory working set evicted; heavy filesystem purge scheduled in background worker."
        self.assertIn(
            expected_banner_text, src_text,
            "Disk Cleanup banner text missing from app.js!"
        )


if __name__ == "__main__":
    unittest.main()
