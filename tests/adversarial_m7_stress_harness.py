#!/usr/bin/env python3
"""
tests/adversarial_m7_stress_harness.py

Milestone M7 Empirical Adversarial Stress Harness:
Feature F20 (Consensus Engine Asymmetric Veto & Boundary Condition Stress)
Feature F21 (Empirical Benchmark & Adversarial Regression Verification)

Conducted by teamwork_challenger_m7_1 (Empirical Challenger)

Stress-tests:
1. High-Volume Benign ML Voter Flooding vs Invariant Breaches (100 to 1,000 voters).
2. Whitelist Veto Neutralization (NSRL, Trusted-Vendor) across all 5 Invariant Families.
3. Extreme Voter Weight Clamping (f32::INFINITY, -f32::INFINITY, f32::NAN) to [0.50, 2.50].
4. Suite Verification Execution and Latency/Invariance Auditing.
"""

import os
import sys
import json
import time
import subprocess
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def strip_ansi(text: str) -> str:
    import re
    return re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", text)


class AdversarialM7ConsensusStressHarness(unittest.TestCase):
    """Empirical challenge suite for Feature F20 & F21 (M7)."""

    def test_01_cargo_policy_test_suite_passes(self):
        """Execute full cargo test -p osoosi-policy and assert 0 failures."""
        cmd = ["cargo", "test", "-p", "osoosi-policy"]
        start_time = time.perf_counter()
        proc = subprocess.run(
            cmd,
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        elapsed = time.perf_counter() - start_time
        self.assertEqual(
            proc.returncode,
            0,
            f"cargo test -p osoosi-policy failed:\n{proc.stdout}",
        )
        self.assertIn("95 passed", proc.stdout)
        print(f"\n[PASS] cargo test -p osoosi-policy executed in {elapsed:.2f}s (95 passed)")

    def test_02_challenger_empirical_suite_passes(self):
        """Execute M7 Challenger empirical integration suite."""
        cmd = ["cargo", "test", "--test", "m7_challenger_empirical_suite", "-p", "osoosi-policy"]
        start_time = time.perf_counter()
        proc = subprocess.run(
            cmd,
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=60,
        )
        elapsed = time.perf_counter() - start_time
        self.assertEqual(
            proc.returncode,
            0,
            f"m7_challenger_empirical_suite failed:\n{proc.stdout}",
        )
        self.assertIn("11 passed", proc.stdout)
        print(f"[PASS] m7_challenger_empirical_suite executed in {elapsed:.2f}s (11 passed)")

    def test_03_edr_bench_suite_passes(self):
        """Execute canonical EDR Benchmark suite in osoosi-core."""
        cmd = ["cargo", "test", "-p", "osoosi-core", "--lib", "edr_bench"]
        start_time = time.perf_counter()
        proc = subprocess.run(
            cmd,
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        elapsed = time.perf_counter() - start_time
        self.assertEqual(
            proc.returncode,
            0,
            f"cargo test -p osoosi-core --lib edr_bench failed:\n{proc.stdout}",
        )
        self.assertIn("7 passed", proc.stdout)
        print(f"[PASS] edr_bench suite executed in {elapsed:.2f}s (7 passed)")

    def test_04_verify_15_vectors_suite_passes(self):
        """Execute 15 Breakout and EDR Compromise Vectors suite."""
        env = os.environ.copy()
        env["OSOOSI_15VEC_SKIP_CARGO"] = "1"
        cmd = [sys.executable, "tests/verify_15_breakout_and_edr_compromise_vectors.py"]
        start_time = time.perf_counter()
        proc = subprocess.run(
            cmd,
            cwd=str(PROJECT_ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=60,
        )
        elapsed = time.perf_counter() - start_time
        self.assertEqual(
            proc.returncode,
            0,
            f"15 vectors test failed:\n{proc.stdout}",
        )
        self.assertIn("SUMMARY: 15/15 VECTORS PASSED", proc.stdout)
        print(f"[PASS] 15 Breakout & Compromise Vectors verified in {elapsed:.2f}s (15/15 passed)")

    def test_05_strix_adversarial_suite_passes(self):
        """Execute Strix LLM adversarial suite."""
        cmd = [
            sys.executable,
            "tests/strix_llm_adversarial_tester.py",
            "--suite",
            "cedar",
            "--fuzz-factor",
            "1",
            "--skip-strix",
        ]
        start_time = time.perf_counter()
        proc = subprocess.run(
            cmd,
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        elapsed = time.perf_counter() - start_time
        self.assertEqual(
            proc.returncode,
            0,
            f"Strix tester failed:\n{proc.stdout}",
        )
        clean_stdout = strip_ansi(proc.stdout)
        self.assertIn("Invariants Upheld & Passed:     450 (100.0%)", clean_stdout)
        self.assertIn("Defensive Breaches / Failures:  0", clean_stdout)
        print(f"[PASS] Strix Cedar Adversarial Suite verified in {elapsed:.2f}s (450/450 variations passed)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
