#!/usr/bin/env python3
"""
CAGE Governance Substrate E2E Test Suite Runner.
Executes Tiers 1-4 across all 15 features, validating compliance with TEST_INFRA.md,
and writes structured metrics to tests/e2e_cage_governance/cage_e2e_report.json.
"""

import argparse
import json
import os
import sys
import time
import unittest
from pathlib import Path

# Ensure UTF-8 output encoding on Windows PowerShell
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

PROJECT_ROOT = Path(__file__).resolve().parents[2]
os.chdir(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT / "tests" / "e2e_cage_governance"))
sys.path.insert(0, str(PROJECT_ROOT / "tests"))

import tier1_feature_coverage
import tier2_boundary_corner
import tier3_cross_feature
import tier4_real_world_scenarios


def run_suite(module, name):
    print(f"\n{'='*70}")
    print(f" [*] EXECUTING: {name}")
    print(f"{'='*70}")
    suite = unittest.defaultTestLoader.loadTestsFromModule(module)
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


def main():
    parser = argparse.ArgumentParser(description="CAGE Governance Substrate E2E Test Runner")
    parser.add_argument("--tier", type=int, choices=[1, 2, 3, 4], help="Run a specific tier only")
    args = parser.parse_args()

    overall_start = time.perf_counter()
    suite_results = []

    print("======================================================================")
    print(" Google Cybernetic Agent Governance Engine (CAGE) Native Substrate")
    print(" Unified E2E Requirement & Opaque-Box Test Suite Execution")
    print(f" Root: {PROJECT_ROOT}")
    print("======================================================================")

    if args.tier is None or args.tier == 1:
        suite_results.append(run_suite(tier1_feature_coverage, "Tier 1: Feature Coverage (F1-F15)"))
    if args.tier is None or args.tier == 2:
        suite_results.append(run_suite(tier2_boundary_corner, "Tier 2: Boundary & Corner Cases (F1-F15)"))
    if args.tier is None or args.tier == 3:
        suite_results.append(run_suite(tier3_cross_feature, "Tier 3: Cross-Feature Interactions"))
    if args.tier is None or args.tier == 4:
        suite_results.append(run_suite(tier4_real_world_scenarios, "Tier 4: Real-World Scenarios (1-8)"))

    overall_duration = time.perf_counter() - overall_start

    total_tests = sum(s["total"] for s in suite_results)
    total_passed = sum(s["passed"] for s in suite_results)
    total_failed = sum(s["failed"] for s in suite_results)
    total_errors = sum(s["errors"] for s in suite_results)
    all_success = all(s["success"] for s in suite_results)

    # Print Summary Table
    print("\n" + "="*70)
    print(" CAGE GOVERNANCE SUBSTRATE E2E EXECUTION SUMMARY")
    print("="*70)
    print(f" {'Suite':<42} | {'Total':<6} | {'Passed':<6} | {'Status'}")
    print("-" * 70)
    for s in suite_results:
        status_str = "PASS" if s["success"] else "FAIL"
        print(f" {s['suite']:<42} | {s['total']:<6} | {s['passed']:<6} | {status_str}")
    print("-" * 70)
    print(f" {'TOTAL':<42} | {total_tests:<6} | {total_passed:<6} | {'ALL PASS' if all_success else 'FAILED'}")
    print(f" Duration: {overall_duration:.3f}s")
    print("="*70)

    # Write report
    report = {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_tests": total_tests,
        "total_passed": total_passed,
        "total_failed": total_failed,
        "total_errors": total_errors,
        "duration_seconds": round(overall_duration, 3),
        "overall_success": all_success,
        "suites": suite_results
    }

    report_path = PROJECT_ROOT / "tests" / "e2e_cage_governance" / "cage_e2e_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"\n[+] Report written to {report_path}")

    sys.exit(0 if all_success else 1)


if __name__ == "__main__":
    main()
