#!/usr/bin/env python3
"""
OshoosiClaw Continuous Agent Breakout Defense - Unified E2E Test Suite Runner
Executes Tiers 1-4 across Requirements R1-R7 from ORIGINAL_REQUEST.md and PROJECT.md:
- Tier 1: Feature Coverage (>=5 tests per requirement: R1–R7)
- Tier 2: Boundary & Corner Cases (>=5 tests per requirement: R1–R7)
- Tier 3: Cross-Feature Interactions (Pairwise combinations)
- Tier 4: Real-World Application Scenarios (>=5 multi-step breakout attempts)

Aggregates structured pass/fail metrics into logs/breakout_defense_e2e_report.json.
"""

import argparse
import json
import os
import sys
import time
import unittest
from pathlib import Path

# Ensure UTF-8 clean output on Windows PowerShell
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
os.chdir(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT / "tests" / "breakout_defense"))
sys.path.insert(0, str(PROJECT_ROOT / "tests"))

import tier1_breakout_features
import tier2_breakout_boundary
import tier3_breakout_pairwise
import tier4_breakout_scenarios


def run_unittest_suite(test_module, name: str, verbosity: int = 1) -> dict:
    print("\n" + "=" * 70)
    print(f" [*] EXECUTING: {name}")
    print("=" * 70)
    suite = unittest.defaultTestLoader.loadTestsFromModule(test_module)
    start = time.perf_counter()
    runner = unittest.TextTestRunner(verbosity=verbosity)
    result = runner.run(suite)
    duration = time.perf_counter() - start

    passed = result.testsRun - len(result.failures) - len(result.errors)
    status_str = "SUCCESS" if result.wasSuccessful() else "FAILED"
    print(
        f" [+] {name} Complete in {duration:.3f}s: {passed}/{result.testsRun} Passed "
        f"(Failures: {len(result.failures)}, Errors: {len(result.errors)}) [{status_str}]"
    )

    return {
        "suite": name,
        "total": result.testsRun,
        "passed": passed,
        "failed": len(result.failures),
        "errors": len(result.errors),
        "duration_seconds": round(duration, 3),
        "success": result.wasSuccessful(),
    }


def main():
    parser = argparse.ArgumentParser(
        description="OshoosiClaw Continuous Agent Breakout Defense Unified E2E Test Runner"
    )
    parser.add_argument("--tier1-only", action="store_true", help="Run Tier 1 Feature Coverage tests only")
    parser.add_argument("--tier2-only", action="store_true", help="Run Tier 2 Boundary tests only")
    parser.add_argument("--tier3-only", action="store_true", help="Run Tier 3 Pairwise tests only")
    parser.add_argument("--tier4-only", action="store_true", help="Run Tier 4 Scenarios only")
    parser.add_argument("--json", action="store_true", help="Output summary report as JSON to stdout")
    parser.add_argument(
        "--report",
        type=str,
        default=str(PROJECT_ROOT / "logs" / "breakout_defense_e2e_report.json"),
        help="Path for generated JSON report file",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose test execution output")
    args = parser.parse_args()

    verbosity = 2 if args.verbose else 1

    print("=" * 70)
    print(" OshoosiClaw Continuous Agent Breakout Defense - Unified E2E Test Runner")
    print(f" Root: {PROJECT_ROOT}")
    print(f" Time: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    print(" Requirements Covered: R1–R7 (Tiers 1–4)")
    print("=" * 70)

    results = []

    if args.tier1_only:
        results.append(run_unittest_suite(tier1_breakout_features, "Tier 1: Feature Coverage (R1–R7)", verbosity))
    elif args.tier2_only:
        results.append(run_unittest_suite(tier2_breakout_boundary, "Tier 2: Boundary & Corner Cases (R1–R7)", verbosity))
    elif args.tier3_only:
        results.append(run_unittest_suite(tier3_breakout_pairwise, "Tier 3: Cross-Feature Pairwise Interactions", verbosity))
    elif args.tier4_only:
        results.append(run_unittest_suite(tier4_breakout_scenarios, "Tier 4: Real-World Application Scenarios", verbosity))
    else:
        results.append(run_unittest_suite(tier1_breakout_features, "Tier 1: Feature Coverage (R1–R7)", verbosity))
        results.append(run_unittest_suite(tier2_breakout_boundary, "Tier 2: Boundary & Corner Cases (R1–R7)", verbosity))
        results.append(run_unittest_suite(tier3_breakout_pairwise, "Tier 3: Cross-Feature Pairwise Interactions", verbosity))
        results.append(run_unittest_suite(tier4_breakout_scenarios, "Tier 4: Real-World Application Scenarios", verbosity))

    total_tests = sum(r["total"] for r in results)
    total_passed = sum(r["passed"] for r in results)
    total_failed = sum(r["failed"] for r in results)
    total_errors = sum(r["errors"] for r in results)
    total_duration = sum(r["duration_seconds"] for r in results)
    all_success = all(r["success"] for r in results)

    summary = {
        "title": "OshoosiClaw Continuous Agent Breakout Defense E2E Verification Report",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "requirements": ["R1", "R2", "R3", "R4", "R5", "R6", "R7"],
        "total_tests": total_tests,
        "total_passed": total_passed,
        "total_failed": total_failed,
        "total_errors": total_errors,
        "pass_percentage": round((total_passed / total_tests * 100) if total_tests > 0 else 0.0, 2),
        "total_duration_seconds": round(total_duration, 3),
        "all_passed": all_success,
        "tier_results": results,
    }

    # Write report file
    report_path = Path(args.report)
    try:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"\n [✓] Structured execution report written to: {report_path}")
    except Exception as e:
        print(f" [!] Warning: Could not write report file {report_path}: {e}", file=sys.stderr)

    print("\n" + "=" * 70)
    print(" FINAL BREAKOUT DEFENSE E2E SUITE EXECUTION SUMMARY")
    print("=" * 70)
    print(f" Total Tests Run:  {total_tests}")
    print(f" Total Passed:     {total_passed} ({summary['pass_percentage']}%)")
    print(f" Total Failed:     {total_failed}")
    print(f" Total Errors:     {total_errors}")
    print(f" Total Duration:   {total_duration:.3f}s")
    print(f" Overall Status:   {'PASSED [100%]' if all_success else 'FAILED'}")
    print("=" * 70)

    if args.json:
        print(json.dumps(summary, indent=2))

    sys.exit(0 if all_success else 1)


if __name__ == "__main__":
    main()
