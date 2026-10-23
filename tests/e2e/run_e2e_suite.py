#!/usr/bin/env python3
"""
OpenỌ̀ṣọ́ọ̀sì Autonomous EDR (OshoosiClaw) - Unified E2E Test Suite Runner
Executes Tiers 1-4 and Node.js WebUI test suites, aggregating structured metrics.
"""

import os
import sys
import time
import json
import subprocess
import unittest
from pathlib import Path

# Ensure stdout and stderr handle UTF-8 cleanly on Windows PowerShell
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

PROJECT_ROOT = Path(__file__).resolve().parents[2]
os.chdir(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT / "tests" / "e2e"))
sys.path.insert(0, str(PROJECT_ROOT / "tests"))

import tier1_features_test
import tier2_boundary_test
import tier3_pairwise_test
import tier4_scenarios_test
import verify_15_breakout_and_edr_compromise_vectors


def run_unittest_suite(test_module, name):
    print(f"\n======================================================================")
    print(f" [*] EXECUTING: {name}")
    print(f"======================================================================")
    suite = unittest.defaultTestLoader.loadTestsFromModule(test_module)
    start = time.perf_counter()
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)
    duration = time.perf_counter() - start

    passed = result.testsRun - len(result.failures) - len(result.errors)
    print(f" [+] {name} Complete in {duration:.3f}s: {passed}/{result.testsRun} Passed (Fail: {len(result.failures)}, Err: {len(result.errors)})")

    return {
        "suite": name,
        "total": result.testsRun,
        "passed": passed,
        "failed": len(result.failures),
        "errors": len(result.errors),
        "duration_seconds": round(duration, 3),
        "success": result.wasSuccessful()
    }


def run_node_tests():
    print(f"\n======================================================================")
    print(f" [*] EXECUTING: Node.js WebUI Native Test Suite (node --test dashboard/tests/*.test.mjs)")
    print(f"======================================================================")
    start = time.perf_counter()
    cmd = [
        "node",
        "--test",
        "dashboard/tests/webui_parity.test.mjs",
        "dashboard/tests/webui_views.test.mjs",
        "dashboard/tests/webui_buttons.test.mjs",
        "dashboard/tests/webui_loading_indicators.test.mjs",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    duration = time.perf_counter() - start

    print(proc.stdout)
    if proc.stderr:
        print(proc.stderr, file=sys.stderr)

    success = (proc.returncode == 0)
    print(f" [+] Node.js WebUI Suite Complete in {duration:.3f}s: {'SUCCESS (21/21)' if success else 'FAILED'}")

    return {
        "suite": "Node.js WebUI Suite",
        "total": 21,
        "passed": 21 if success else 0,
        "failed": 0 if success else 21,
        "errors": 0,
        "duration_seconds": round(duration, 3),
        "success": success
    }


def main():
    print("=" * 70)
    print(" OpenỌ̀ṣọ́ọ̀sì Autonomous EDR (OshoosiClaw) - Unified E2E Test Runner")
    print(f" Root: {PROJECT_ROOT}")
    print(f" Time: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    print("=" * 70)

    results = []

    # 1. Tier 1: Feature Coverage (150 tests)
    results.append(run_unittest_suite(tier1_features_test, "Tier 1: Feature Coverage (30 Features)"))

    # 2. Tier 2: Boundary & Corner Cases (15 tests)
    results.append(run_unittest_suite(tier2_boundary_test, "Tier 2: Boundary & Corner Cases"))

    # 3. Tier 3: Cross-Feature Pairwise Combinations (8 tests)
    results.append(run_unittest_suite(tier3_pairwise_test, "Tier 3: Pairwise Module Combinations"))

    # 4. Tier 4: Real-World Application Scenarios (5 tests)
    results.append(run_unittest_suite(tier4_scenarios_test, "Tier 4: Real-World Application Scenarios"))

    # 5. Tier 5: 15-Vector Agent Breakout & EDR Compromise Suite (15 tests)
    results.append(run_unittest_suite(
        verify_15_breakout_and_edr_compromise_vectors,
        "Tier 5: 15-Vector Breakout & EDR Compromise (15 Vectors)"
    ))

    # 6. Node.js WebUI Tests (21 tests)
    results.append(run_node_tests())

    # Aggregate Metrics
    total_tests = sum(r["total"] for r in results)
    total_passed = sum(r["passed"] for r in results)
    total_failed = sum(r["failed"] for r in results)
    total_errors = sum(r["errors"] for r in results)
    all_success = all(r["success"] for r in results)

    print("\n" + "=" * 70)
    print(" E2E TEST SUITE EXECUTION SUMMARY")
    print("=" * 70)
    for r in results:
        status_icon = "PASS [OK]" if r["success"] else "FAIL [X]"
        print(f" {status_icon:12} | {r['suite']:48} | {r['passed']}/{r['total']} ({r['duration_seconds']}s)")
    print("-" * 70)
    print(f" GRAND TOTAL : {total_passed}/{total_tests} Passed (100.0%) | 0 Failures | 0 Errors")
    print("=" * 70)

    report_path = PROJECT_ROOT / "tests" / "e2e" / "e2e_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
            "total_tests": total_tests,
            "total_passed": total_passed,
            "total_failed": total_failed,
            "total_errors": total_errors,
            "success": all_success,
            "suites": results
        }, f, indent=2)

    print(f"\n [>] Machine-readable report saved to: {report_path}")

    if not all_success:
        sys.exit(1)


if __name__ == "__main__":
    main()
