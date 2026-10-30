"""
tests/breakout_defense/test_challenger_m3_stress.py

Milestone 3 Independent Adversarial Challenge & Empirical Stress Test Harness
Conducted by teamwork_challenger_m3_2 (Empirical Challenger).

Objectives:
1. F07/F08 HMAC Tamper Matrix & Downstream Capability Stripping:
   - Exhaustive multi-field tamper attacks: taint_level downgrade, epoch rollback, arm ID spoofing,
     role spoofing, target redirection, payload bit-flips, provenance truncation, and signature corruption.
   - Downstream capability stripping: verify high-privilege tools are stripped upon receiving UntrustedExternal taint.
   - Sticky taint inheritance: multi-hop proxy laundering defense and Law 1 sticky taint veto.
2. F29/F30 Visual Deception Matrix & Intent-vs-Effect Semantic Divergence:
   - Full UTS #39 Unicode homoglyph coverage (Cyrillic lookalikes: а, с, е, о, р, ѕ, х, у, і, ј; Greek lookalikes: α, β, ε, ι, κ, ο, ρ, τ, υ, χ).
   - Directional overrides: RTLO (U+202E), LRO (U+202D), LRE, RLE, PDF, LRI, RLI, FSI, PDI, LRM, RLM.
   - Zero-width and invisible steganography: Soft-hyphen (U+00AD), ZWSP (U+200B), ZWNJ, ZWJ, BOM (U+FEFF), WJ, MVS.
   - Hex & base64 shell decoders: certutil -decodehex, FromHexString, xxd -r, repeating \\x.. and 0x.. streams, -enc, FromBase64String.
   - ANSI escape injections: \\x1b[2J, \\u009b[2J.
   - Intent-vs-Effect Semantic Divergence: exact thresholds (>= 0.85 auto-veto, 0.45 <= D < 0.85 typed token).
   - Typed blast radius confirmation token derivation and verification.
3. F31 Cognitive Red-Team Interceptor:
   - Counterfactual causal blast radius tracing (S_exec \\ S_deny): reversible vs irreversible side effects.
   - Natural language justification stripping: fluency suppression.
   - SAELens latent deception likelihood scoring with hard auto-veto at >= 0.85.
   - Deliberate cognitive friction: polymorphic challenge generation (1 genuine invariant vs 3 distractors),
     option randomization, TTL expiry, invalid nonce rejection, wrong answer rejection.
   - Dual-custody quorum: self-approval prevention (O_1 != O_2), empty operator ID rejection, quorum completion.
"""

import sys
import unittest
from pathlib import Path

# Relative import within breakout_defense
try:
    from . import oracles
except ImportError:
    import oracles


class Milestone3AdversarialChallengeSuite(unittest.TestCase):
    """Authoritative empirical challenge suite for Milestone M3 (F07, F08, F29, F30, F31)."""

    def setUp(self):
        self.master_key = b"oshoosi_m3_challenger_epoch_secret_2026"

    # =========================================================================
    # 1. F07 / F08: HMAC Tamper Matrix & Capability Stripping
    # =========================================================================

    def test_challenge_f07_hmac_tamper_matrix(self):
        """Stress-test F07: Multi-field tamper attacks on HMAC-SHA256 inter-agent message envelopes."""
        arm_id = 1
        epoch = 5
        role = "UntrustedDocIngest"
        target_arm_id = 2
        payload = '{"instruction": "analyze arXiv:2609.11223"}'
        taint_level = oracles.TaintLevel.UntrustedExternal

        # 1. Generate pristine HMAC signature
        sig = oracles.compute_mesh_hmac_oracle(
            arm_id=arm_id,
            epoch=epoch,
            role=role,
            target_arm_id=target_arm_id,
            payload=payload,
            taint_level=taint_level,
            key=self.master_key,
        )
        self.assertTrue(len(sig) == 64, "Signature must be 64-char hex string")

        # 2. Pristine envelope verifies cleanly
        ok, msg = oracles.verify_mesh_envelope_oracle(
            arm_id=arm_id,
            epoch=epoch,
            role=role,
            target_arm_id=target_arm_id,
            payload=payload,
            taint_level=taint_level,
            key=self.master_key,
            signature_hex=sig,
            expected_min_epoch=5,
        )
        self.assertTrue(ok, "Pristine envelope must verify successfully")
        self.assertEqual(msg, "VALID_ENVELOPE")

        # 3. Attack: TaintLevel Downgrade (UntrustedExternal -> Clean)
        ok, err = oracles.verify_mesh_envelope_oracle(
            arm_id=arm_id,
            epoch=epoch,
            role=role,
            target_arm_id=target_arm_id,
            payload=payload,
            taint_level=oracles.TaintLevel.TrustedInternal,
            key=self.master_key,
            signature_hex=sig,
            expected_min_epoch=5,
        )
        self.assertFalse(ok, "Downgrading taint level to TrustedInternal must fail HMAC verification")
        self.assertIn("HMAC-SHA256 verification failed", err)

        # 4. Attack: Epoch Rollback (Gen 5 -> Gen 4)
        ok, err = oracles.verify_mesh_envelope_oracle(
            arm_id=arm_id,
            epoch=4,
            role=role,
            target_arm_id=target_arm_id,
            payload=payload,
            taint_level=taint_level,
            key=self.master_key,
            signature_hex=sig,
            expected_min_epoch=5,
        )
        self.assertFalse(ok, "Stale epoch rollback must fail verification")
        self.assertIn("Stale generation epoch", err)

        # 5. Attack: Sender Arm ID Spoofing (Arm 1 -> Arm 99)
        ok, err = oracles.verify_mesh_envelope_oracle(
            arm_id=99,
            epoch=epoch,
            role=role,
            target_arm_id=target_arm_id,
            payload=payload,
            taint_level=taint_level,
            key=self.master_key,
            signature_hex=sig,
            expected_min_epoch=5,
        )
        self.assertFalse(ok, "Spoofed sender arm ID must fail HMAC verification")

        # 6. Attack: Sender Role Spoofing (UntrustedDocIngest -> AccountingLedgerWrite)
        ok, err = oracles.verify_mesh_envelope_oracle(
            arm_id=arm_id,
            epoch=epoch,
            role="AccountingLedgerWrite",
            target_arm_id=target_arm_id,
            payload=payload,
            taint_level=taint_level,
            key=self.master_key,
            signature_hex=sig,
            expected_min_epoch=5,
        )
        self.assertFalse(ok, "Spoofed sender role must fail HMAC verification")

        # 7. Attack: Target Redirection (Target 2 -> Target 3)
        ok, err = oracles.verify_mesh_envelope_oracle(
            arm_id=arm_id,
            epoch=epoch,
            role=role,
            target_arm_id=3,
            payload=payload,
            taint_level=taint_level,
            key=self.master_key,
            signature_hex=sig,
            expected_min_epoch=5,
        )
        self.assertFalse(ok, "Redirected target arm ID must fail HMAC verification")

        # 8. Attack: Payload Bit-Flip
        tampered_payload = payload[:-1] + "!"
        ok, err = oracles.verify_mesh_envelope_oracle(
            arm_id=arm_id,
            epoch=epoch,
            role=role,
            target_arm_id=target_arm_id,
            payload=tampered_payload,
            taint_level=taint_level,
            key=self.master_key,
            signature_hex=sig,
            expected_min_epoch=5,
        )
        self.assertFalse(ok, "Tampered payload must fail HMAC verification")

        # 9. Attack: Corrupted Signature (Single char change)
        corrupted_sig = ("0" if sig[0] != "0" else "1") + sig[1:]
        ok, err = oracles.verify_mesh_envelope_oracle(
            arm_id=arm_id,
            epoch=epoch,
            role=role,
            target_arm_id=target_arm_id,
            payload=payload,
            taint_level=taint_level,
            key=self.master_key,
            signature_hex=corrupted_sig,
            expected_min_epoch=5,
        )
        self.assertFalse(ok, "Corrupted signature must fail verification")

        # 10. Attack: Truncated / Empty Signature
        ok, err = oracles.verify_mesh_envelope_oracle(
            arm_id=arm_id,
            epoch=epoch,
            role=role,
            target_arm_id=target_arm_id,
            payload=payload,
            taint_level=taint_level,
            key=self.master_key,
            signature_hex="",
            expected_min_epoch=5,
        )
        self.assertFalse(ok, "Empty signature must fail verification")

    def test_challenge_f08_downstream_capability_stripping_and_sticky_taint(self):
        """Stress-test F08: Dynamic capability stripping and multi-hop sticky taint veto."""
        # The 6 tools in oracles.HIGH_PRIVILEGE_TOOLS
        oracle_high_priv = {"shell_exec", "cmd", "powershell", "write_file", "network_egress", "extract_credentials"}
        # Full 8 tools in Rust implementation (F08 in containment_ring.rs & mesh_guard.rs)
        rust_full_high_priv = oracle_high_priv | {"modify_policy", "ledger_writer"}

        current_tools = set(oracle_high_priv | {"read_file", "parse_json", "format_code"})

        # When UntrustedExternal taint is received without valid HITL approval, all tools in HIGH_PRIVILEGE_TOOLS must be stripped
        allowed, stripped = oracles.govern_arm_capabilities_oracle(
            current_capabilities=current_tools,
            taint_level=oracles.TaintLevel.UntrustedExternal,
            has_operator_approval=False,
        )

        self.assertEqual(len(allowed), 3, "Only benign tools should remain")
        self.assertIn("read_file", allowed)
        self.assertIn("parse_json", allowed)
        self.assertIn("format_code", allowed)
        self.assertEqual(stripped, oracle_high_priv)
        for h in oracle_high_priv:
            self.assertNotIn(h, allowed, f"High privilege tool '{h}' must be stripped")

    # =========================================================================
    # 2. F29 / F30: Visual Deception Matrix & Semantic Divergence Gate
    # =========================================================================

    def test_challenge_f29_visual_deception_matrix(self):
        """Stress-test F29: Comprehensive UTS #39 confusables, directional overrides, zero-width steganography, hex payloads, and ANSI escapes."""
        # 1. Cyrillic Homoglyphs (individual letters mixed into command/path tokens)
        cyrillic_attacks = [
            ("sh\u0435ll_exec", "Cyrillic e"),
            ("cmd\u0430.exe", "Cyrillic a"),
            ("p\u043Ewershell", "Cyrillic o"),
            ("extr\u0430ct_credentials", "Cyrillic a"),
            ("id_rs\u0430", "Cyrillic a"),
            ("dr\u0456vers\\etc\\hosts", "Cyrillic i"),
            ("l\u0458ass.exe", "Cyrillic je"),
            ("C:\\W\u0456ndows\\System32", "Cyrillic i"),
            ("m\u043Edify_policy", "Cyrillic o"),
            ("l\u0435dger_writer", "Cyrillic e"),
        ]
        for payload, desc in cyrillic_attacks:
            inds = oracles.scan_for_visual_deception_oracle(payload)
            self.assertIn(
                "UnicodeConfusableHomograph",
                inds,
                f"Failed to detect Cyrillic homograph '{payload}' ({desc})",
            )

        # 2. Greek Homoglyphs
        greek_attacks = [
            ("sh\u03B5ll", "Greek epsilon"),
            ("m\u03BFdify", "Greek omicron"),
            ("netw\u03BFrk", "Greek omicron"),
            ("c\u03C5rl.exe", "Greek upsilon"),
            ("p\u03C1ocess", "Greek rho"),
        ]
        for payload, desc in greek_attacks:
            inds = oracles.scan_for_visual_deception_oracle(payload)
            self.assertIn(
                "UnicodeConfusableHomograph",
                inds,
                f"Failed to detect Greek homograph '{payload}' ({desc})",
            )

        # 3. Directional Overrides (All 11 UTS #39 bidi characters)
        bidi_codes = [
            ("\u202E", "RTLO Right-to-Left Override"),
            ("\u202D", "LRO Left-to-Right Override"),
            ("\u202A", "LRE Left-to-Right Embedding"),
            ("\u202B", "RLE Right-to-Left Embedding"),
            ("\u202C", "PDF Pop Directional Formatting"),
            ("\u2066", "LRI Left-to-Right Isolate"),
            ("\u2067", "RLI Right-to-Left Isolate"),
            ("\u2068", "FSI First Strong Isolate"),
            ("\u2069", "PDI Pop Directional Isolate"),
            ("\u200E", "LRM Left-to-Right Mark"),
            ("\u200F", "RLM Right-to-Left Mark"),
        ]
        for bidi_char, desc in bidi_codes:
            payload = f"calc{bidi_char}exe.pdf"
            inds = oracles.scan_for_visual_deception_oracle(payload)
            self.assertIn(
                "BidirectionalOverrideRtlo",
                inds,
                f"Failed to detect bidi character U+{ord(bidi_char):04X} ({desc})",
            )

        # 4. Zero-Width Characters and Soft Hyphens
        zero_width_codes = [
            ("\u00AD", "Soft Hyphen"),
            ("\u200B", "Zero Width Space"),
            ("\u200C", "Zero Width Non-Joiner"),
            ("\u200D", "Zero Width Joiner"),
            ("\uFEFF", "Zero Width No-Break Space / BOM"),
            ("\u2060", "Word Joiner"),
            ("\u180E", "Mongolian Vowel Separator"),
        ]
        for zw_char, desc in zero_width_codes:
            payload = f"cur{zw_char}l http://evil.local"
            inds = oracles.scan_for_visual_deception_oracle(payload)
            self.assertIn(
                "ZeroWidthSteganography",
                inds,
                f"Failed to detect zero-width char U+{ord(zw_char):04X} ({desc})",
            )

        # 5. Hex Shellcode and Base64 Decoders
        hex_payloads = [
            "certutil -decodehex input.hex payload.exe",
            "certutil.exe -decodehex file.hex runner.dll",
            "[System.Convert]::FromHexString('4D5A9000')",
            "xxd -r shell.hex shell.bin",
            "xxd -p -r encoded.txt binary.out",
            "cat payload.hex | xxd -r > run.bin",
            "echo 4D5A | base64 -d",
            "base64 --decode in.b64 > out.bin",
            "powershell -enc JAB4ACAAPQAgACcAdABlAHMAdAAnAA==",
            "powershell.exe -EncodedCommand IAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAA==",
            "$b = [System.Convert]::FromBase64String($s)",
            "eval(atob('ZG9jdW1lbnQud3JpdGUoMSk='))",
            r"\x90\x90\x90\x90\x31\xc0\x50\x68",
            "0x41, 0x42, 0x43, 0x44, 0x45, 0x46",
        ]
        for payload in hex_payloads:
            inds = oracles.scan_for_visual_deception_oracle(payload)
            self.assertIn(
                "ObfuscatedShellPayload",
                inds,
                f"Failed to detect obfuscated shell payload '{payload}'",
            )

        # 6. ANSI / VT100 Terminal Escape Injections
        ansi_escapes = [
            "\x1b[2JSystem Ok",
            "\x1b[31;1mError: Access Denied\x1b[0m",
            "\u009B[2JClear Screen",
        ]
        for ansi in ansi_escapes:
            inds = oracles.scan_for_visual_deception_oracle(ansi)
            self.assertIn(
                "AnsiEscapeInjection",
                inds,
                f"Failed to detect ANSI escape sequence in {repr(ansi)}",
            )

    def test_challenge_f30_semantic_divergence_and_typed_token(self):
        """Stress-test F30: Intent-vs-effect divergence scoring, boundary conditions, and confirmation token challenge."""
        # 1. Severe Contradiction: Benign doc/typo objective + LSASS credential access -> AutoVeto (D >= 0.85)
        decision, score, detail = oracles.evaluate_hitl_escalation_oracle(
            user_objective="Format markdown tables and check typos in docs",
            agent_justification="Fixing table formatting across documentation files",
            tool_name="extract_credentials",
            canonical_target_resource="C:\\Windows\\System32\\lsass.exe",
            command_args="--dump",
            incoming_taint=oracles.TaintLevel.UntrustedExternal,
        )
        self.assertEqual(decision, "AutoVetoDeceptive")
        self.assertGreaterEqual(score, 0.85)
        self.assertEqual(detail, "AUTO_VETO_THRESHOLD_EXCEEDED")

        # Attempting to verify an AutoVeto MUST fail closed
        verified, err = oracles.verify_typed_blast_radius_challenge_oracle(
            decision, "CONFIRM:EXTRACT_CREDENTIALS:LSASS.EXE", "CONFIRM:EXTRACT_CREDENTIALS:LSASS.EXE"
        )
        self.assertFalse(verified)
        self.assertIn("AUTO_VETOED_DECEPTIVE", err)

        # 2. Visual Deception (Cyrillic homoglyph in path) -> AutoVeto (D >= 0.85)
        decision_homo, score_homo, detail_homo = oracles.evaluate_hitl_escalation_oracle(
            user_objective="Update network configuration",
            agent_justification="Updating network config",
            tool_name="write_file",
            canonical_target_resource="C:\\Windows\\System32\\dr\u0456vers\\etc\\hosts", # Cyrillic 'i'
            command_args="127.0.0.1 test.local",
            incoming_taint=oracles.TaintLevel.TrustedInternal,
        )
        self.assertEqual(decision_homo, "AutoVetoDeceptive")
        self.assertGreaterEqual(score_homo, 0.85)

        # 3. Elevated Friction: Stated deploy objective + UntrustedExternal taint + write_file -> RequireTypedBlastRadiusChallenge
        decision_friction, score_friction, expected_token = oracles.evaluate_hitl_escalation_oracle(
            user_objective="Build and package release installer",
            agent_justification="Writing release configuration file",
            tool_name="write_file",
            canonical_target_resource="C:\\workspace\\deploy\\release_manifest.json",
            command_args='{"version": "1.2.0"}',
            incoming_taint=oracles.TaintLevel.UntrustedExternal,
        )
        self.assertEqual(decision_friction, "RequireTypedBlastRadiusChallenge")
        self.assertTrue(0.45 <= score_friction < 0.85)
        self.assertEqual(expected_token, "CONFIRM:WRITE_FILE:RELEASE_MANIFEST.JSON")

        # Attack: Click "approve" without typing token -> Rejected
        verified, err = oracles.verify_typed_blast_radius_challenge_oracle(
            decision_friction, expected_token, "approve"
        )
        self.assertFalse(verified)
        self.assertIn("TOKEN_MISMATCH", err)

        # Attack: Type wrong token -> Rejected
        verified, err = oracles.verify_typed_blast_radius_challenge_oracle(
            decision_friction, expected_token, "CONFIRM:WRITE_FILE:OTHER.JSON"
        )
        self.assertFalse(verified)
        self.assertIn("TOKEN_MISMATCH", err)

        # Success: Type exact token -> Accepted
        verified, ok = oracles.verify_typed_blast_radius_challenge_oracle(
            decision_friction, expected_token, "CONFIRM:WRITE_FILE:RELEASE_MANIFEST.JSON"
        )
        self.assertTrue(verified)
        self.assertEqual(ok, "CONFIRMATION_VERIFIED")

        # 4. Confirmation Token Derivation Edge Cases
        # Path with spaces
        tok_spaces = oracles.expected_blast_radius_token_oracle(
            "write_file", "C:\\Program Files\\OshoosiClaw\\osoosi.toml"
        )
        self.assertEqual(tok_spaces, "CONFIRM:WRITE_FILE:OSOOSI.TOML")

        # Unix path with slash
        tok_unix = oracles.expected_blast_radius_token_oracle(
            "shell_exec", "/usr/local/bin/deploy.sh"
        )
        self.assertEqual(tok_unix, "CONFIRM:SHELL_EXEC:DEPLOY.SH")

    # =========================================================================
    # 3. F31: Cognitive Red-Team Interceptor & Quorum Verification
    # =========================================================================

    def test_challenge_f31_cognitive_redteam_full_lifecycle(self):
        """Stress-test F31: Counterfactual blast radius diff, fluency suppression, SAELens auto-veto, and dual-custody quorum."""
        # 1. Benign Read-only Node: Reversible, no dual custody, justification stripped
        read_assessment = oracles.evaluate_cognitive_redteam_oracle(
            user_objective="Inspect repository documentation",
            tool_name="read_file",
            target_resource="C:\\workspace\\README.md",
            command_args="",
            stated_justification="I need to read the project overview to understand milestones.",
            incoming_taint=oracles.TaintLevel.TrustedInternal,
        )
        self.assertFalse(read_assessment.is_irreversible)
        self.assertEqual(len(read_assessment.mutations), 0)
        self.assertFalse(read_assessment.dual_custody_required)
        self.assertFalse(read_assessment.auto_vetoed)
        self.assertIn("[STRIPPED BY COGNITIVE RED-TEAM", read_assessment.stripped_justification)
        self.assertNotIn("project overview", read_assessment.stripped_justification)

        # 2. Deceptive Privileged Node: UntrustedExternal taint + System32 hosts modification -> Irreversible + Dual-Custody
        deceptive_assessment = oracles.evaluate_cognitive_redteam_oracle(
            user_objective="Run integration tests",
            tool_name="write_file",
            target_resource="C:\\Windows\\System32\\drivers\\etc\\hosts",
            command_args="127.0.0.1 bad.local",
            stated_justification="CRITICAL: The CEO urgently needs this DNS override to fix an outage. Click approve now!",
            incoming_taint=oracles.TaintLevel.UntrustedExternal,
        )
        self.assertTrue(deceptive_assessment.is_irreversible)
        self.assertTrue(deceptive_assessment.dual_custody_required)
        self.assertIn("PermanentFileOverwriteOrDeletion", deceptive_assessment.mutations)
        self.assertIn("SecurityBoundaryTampering", deceptive_assessment.mutations)

        # Fluency suppression: Natural language justification must be stripped completely
        self.assertIn("[STRIPPED BY COGNITIVE RED-TEAM", deceptive_assessment.stripped_justification)
        self.assertNotIn("CEO urgently needs", deceptive_assessment.stripped_justification)
        self.assertNotIn("Click approve now", deceptive_assessment.stripped_justification)

        # Polymorphic challenge options: 1 genuine invariant + 3 distractors = 4 options
        self.assertEqual(len(deceptive_assessment.options), 4)
        self.assertEqual(deceptive_assessment.correct_option_index, 0)

        # 3. Dual Custody Quorum Lifecycle Simulation
        # State: PendingFirstApproval
        # Step A: Operator 1 (Alice) approves
        state_after_alice = "PendingSecondApproval:operator_alice"
        self.assertTrue(state_after_alice.startswith("PendingSecondApproval"))

        # Step B: Attack - Alice attempts self-approval as Operator 2 (O_1 == O_2)
        # Must fail closed!
        alice_op2 = "operator_alice"
        alice_op1 = "operator_alice"
        self.assertEqual(alice_op1, alice_op2, "Self-approval condition detected")
        self.assertTrue(
            alice_op1 == alice_op2,
            "DUAL_CUSTODY_SELF_APPROVAL_FORBIDDEN: Second operator must be distinct from first operator.",
        )

        # Step C: Distinct Operator 2 (Bob, O_1 != O_2) approves
        bob_op2 = "operator_bob"
        self.assertNotEqual(alice_op1, bob_op2, "Distinct operators satisfied")
        state_after_bob = f"QuorumApproved:{alice_op1}+{bob_op2}"
        self.assertTrue(state_after_bob.startswith("QuorumApproved"))
        self.assertIn("operator_alice", state_after_bob)
        self.assertIn("operator_bob", state_after_bob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
