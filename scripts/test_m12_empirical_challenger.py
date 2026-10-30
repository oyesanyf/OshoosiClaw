#!/usr/bin/env python3
"""
Empirical Challenger Test Harness - Milestone M12
Verifying:
1. Adversarial Recency Probing (2024 & older preprints fail-closed, 2025-2026 accepted)
2. Canary False Positive Stress Test (0% FPR against CANARY_BENIGN_TELEMETRY_CORPUS)
3. AST Tighten-Only Defense Guard Verification (format, indentation, fail-closed quarantine)
4. SQLite & JSON Configuration Consistency
5. Unit Test Latent Defect Analysis (line 4755 inspection)
"""

import os
import sys
import json
import sqlite3
import re

MIN_CURRENT_RESEARCH_ARXIV_YY = 25

CANARY_BENIGN_TELEMETRY_CORPUS = [
    r"C:\Windows\System32\svchost.exe -k netsvcs -p -s Schedule",
    r"C:\Windows\System32\lsass.exe",
    r"C:\Windows\System32\services.exe",
    r"C:\Windows\Explorer.EXE",
    "cargo build --workspace --release",
    "cargo test -p osoosi-core --lib",
    "rustc --edition 2021 src/lib.rs --crate-type lib",
    "git status -s && git diff --stat",
    "python -m unittest discover -s tests",
    "node --test dashboard/tests/webui_parity.test.mjs",
    "http://127.0.0.1:11434/api/tags",
    "http://127.0.0.1:3030/api/health",
]

def normalize_base_arxiv_id(raw: str) -> str:
    s = raw.strip()
    if len(s) >= 6 and s[:6].lower() == "arxiv:":
        s = s[6:]
    s = s.strip()
    if s.startswith("abs/"):
        s = s[4:].strip()
    if "v" in s:
        parts = s.rsplit("v", 1)
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0].strip().lower()
    return s.lower()

def parse_arxiv_year_month(arxiv_id: str):
    base = normalize_base_arxiv_id(arxiv_id)
    if "." not in base:
        return None
    dot_pos = base.find(".")
    yymm = base[:dot_pos]
    if len(yymm) == 4 and yymm.isdigit():
        yy = int(yymm[:2])
        mm = int(yymm[2:])
        if 1 <= mm <= 12:
            return (2000 + yy, mm)
    return None

def is_current_research_arxiv_id(arxiv_id: str) -> bool:
    base = normalize_base_arxiv_id(arxiv_id)
    # Strictly reject all 2024 and older preprints
    if (base.startswith("24") or base.startswith("23") or
        base.startswith("22") or base.startswith("21") or base.startswith("20")):
        return False
    # Canonical 2025-2026 preprints
    if (base.startswith("2603.02277") or base.startswith("2501.18492") or
        base.startswith("2503.00061") or base.startswith("2511.10720")):
        return True
    ym = parse_arxiv_year_month(arxiv_id)
    if ym:
        year, _ = ym
        return year >= 2000 + MIN_CURRENT_RESEARCH_ARXIV_YY
    elif len(base) >= 2:
        try:
            yy = int(base[:2])
            return yy >= MIN_CURRENT_RESEARCH_ARXIV_YY
        except ValueError:
            return False
    return False

def validate_research_rule_acceptance_sim(rule: dict):
    arxiv_id = rule.get("arxiv_id", "")
    if not is_current_research_arxiv_id(arxiv_id):
        return {
            "accepted": False,
            "rejection_code": "RejectedOutdatedResearch",
            "rejection_reason": f"Outdated research rejected: arXiv:{arxiv_id} is from prior years; only current 2025-2026 frontier security research is accepted"
        }
    pat = rule.get("indicator_pattern", "").strip()
    cedar = rule.get("cedar_forbid_policy", "")
    if "permit(" in cedar or "forbid(" not in cedar:
        return {
            "accepted": False,
            "rejection_code": "RejectedConflictsWithExistingProtection",
            "rejection_reason": "Cedar policy must contain 'forbid(' and cannot contain 'permit('"
        }
    if len(pat) < 6:
        return {
            "accepted": False,
            "rejection_code": "RejectedConflictsWithExistingProtection",
            "rejection_reason": f"Indicator pattern '{pat}' is too short (< 6 characters)"
        }
    return {"accepted": True, "rejection_code": None, "rejection_reason": None}

def main():
    print("=" * 70)
    print("RUNNING EMPIRICAL CHALLENGER VERIFICATION HARNESS (MILESTONE M12)")
    print("=" * 70)
    failures = 0

    # -------------------------------------------------------------------------
    # TEST 1: Adversarial Recency Probing
    # -------------------------------------------------------------------------
    print("\n[TEST 1] Adversarial Recency Probing:")
    
    # 2024 Preprints that MUST be rejected fail-closed
    outdated_2024 = [
        "2403.04651",
        "2406.11036",
        "2406.13352",
        "2406.07392",
        "2403.04651v1",
        "2406.11036v2",
        "arXiv:2406.13352v1",
        "abs/2406.07392v1",
    ]
    for aid in outdated_2024:
        accepted = is_current_research_arxiv_id(aid)
        verdict = validate_research_rule_acceptance_sim({"arxiv_id": aid, "indicator_pattern": "valid_pattern", "cedar_forbid_policy": "forbid(a, b, c);"})
        if accepted or verdict["rejection_code"] != "RejectedOutdatedResearch":
            print(f"  FAIL: 2024 preprint {aid} was NOT rejected as RejectedOutdatedResearch! (accepted={accepted}, code={verdict['rejection_code']})")
            failures += 1
        else:
            print(f"  PASS: 2024 preprint {aid} successfully rejected as {verdict['rejection_code']}")

    # Older Preprints (2020-2023) that MUST be rejected fail-closed
    older_preprints = [
        "2310.12345",
        "2312.00001v1",
        "2201.00001",
        "2105.12345v2",
        "2001.00001",
    ]
    for aid in older_preprints:
        accepted = is_current_research_arxiv_id(aid)
        verdict = validate_research_rule_acceptance_sim({"arxiv_id": aid, "indicator_pattern": "valid_pattern", "cedar_forbid_policy": "forbid(a, b, c);"})
        if accepted or verdict["rejection_code"] != "RejectedOutdatedResearch":
            print(f"  FAIL: Older preprint {aid} was NOT rejected as RejectedOutdatedResearch! (accepted={accepted}, code={verdict['rejection_code']})")
            failures += 1
        else:
            print(f"  PASS: Older preprint {aid} successfully rejected as {verdict['rejection_code']}")

    # 2025-2026 Preprints that MUST be accepted
    current_preprints = [
        "2501.18492",
        "2501.18492v2",
        "2503.00061",
        "2503.00061v2",
        "2511.10720",
        "2511.10720v1",
        "2603.02277",
        "2603.02277v3",
        "2506.12345",
        "2601.00001",
        "arXiv:2512.99999",
    ]
    for aid in current_preprints:
        accepted = is_current_research_arxiv_id(aid)
        verdict = validate_research_rule_acceptance_sim({"arxiv_id": aid, "indicator_pattern": "valid_pattern", "cedar_forbid_policy": "forbid(a, b, c);"})
        if not accepted or not verdict["accepted"]:
            print(f"  FAIL: Current preprint {aid} was unexpectedly rejected! (accepted={accepted}, code={verdict['rejection_code']})")
            failures += 1
        else:
            print(f"  PASS: Current preprint {aid} successfully accepted")

    # -------------------------------------------------------------------------
    # TEST 2: Canary False Positive Stress Test (0% FPR)
    # -------------------------------------------------------------------------
    print("\n[TEST 2] Canary False Positive Stress Test against CANARY_BENIGN_TELEMETRY_CORPUS:")
    config_path = "crates/osoosi-agent-anomaly/config/ingested_research_defenses.json"
    if not os.path.exists(config_path):
        config_path = "config/ingested_research_defenses.json"
    
    with open(config_path, "r", encoding="utf-8") as f:
        rules = json.load(f)

    print(f"  Loaded {len(rules)} canonical rules from {config_path}")
    total_comparisons = 0
    fp_count = 0

    for rule in rules:
        rule_id = rule["rule_id"]
        indicators = [p.strip().lower() for p in rule["indicator_pattern"].split("|") if len(p.strip()) >= 4]
        for ind in indicators:
            for canary in CANARY_BENIGN_TELEMETRY_CORPUS:
                total_comparisons += 1
                canary_lc = canary.lower()
                if ind in canary_lc:
                    print(f"  FAIL: False Positive detected! Rule {rule_id} indicator '{ind}' matched canary sample '{canary}'")
                    fp_count += 1
                    failures += 1

    fpr = (fp_count / total_comparisons * 100.0) if total_comparisons > 0 else 0.0
    print(f"  Total indicator-canary evaluations: {total_comparisons}")
    print(f"  False Positives: {fp_count} (FPR: {fpr:.2f}%)")
    if fp_count == 0:
        print("  PASS: 0% False Positive Rate verified against clean baseline telemetry corpus.")

    # -------------------------------------------------------------------------
    # TEST 3: AST Tighten-Only Guard Verification
    # -------------------------------------------------------------------------
    print("\n[TEST 3] AST Tighten-Only Defense Guard Verification:")
    for rule in rules:
        rule_id = rule["rule_id"]
        snippet = rule.get("generated_code_snippet", "")
        if not snippet:
            print(f"  FAIL: Rule {rule_id} has empty generated_code_snippet!")
            failures += 1
            continue

        checks = [
            ("// [TIGHTEN-ONLY DEFENSE GUARD]", "Header marker"),
            ("Enforced in: osoosi-agent-anomaly::", "Crate target"),
            ("Threat Vector:", "Threat vector documentation"),
            ("research_defense_registry().read()", "Safe registry read"),
            ("const INDICATORS: &[&str] = &[", "Indicators array declaration"),
            ("tech_res.is_clean = false;", "Fail-closed is_clean flag"),
            ("tech_res.sandbox_quarantine_required = true;", "Sandbox quarantine requirement"),
            ("tech_res.detected_vectors.push(", "Telemetry vector emission"),
            ("break;", "Loop termination"),
        ]

        forbidden = ["permit(", "unsafe", "std::process::Command", "std::env::set_var"]

        all_checks_passed = True
        for marker, desc in checks:
            if marker not in snippet:
                print(f"  FAIL: Rule {rule_id} snippet missing {desc} ('{marker}')")
                all_checks_passed = False
                failures += 1

        for bad in forbidden:
            if bad in snippet:
                print(f"  FAIL: Rule {rule_id} snippet contains forbidden token '{bad}'!")
                all_checks_passed = False
                failures += 1

        # Check indentation: INDICATORS should be indented by 8 spaces
        lines = snippet.splitlines()
        indicators_block = False
        proper_indent = True
        for line in lines:
            if "const INDICATORS:" in line:
                indicators_block = True
                continue
            if indicators_block:
                if line.strip().startswith("];"):
                    indicators_block = False
                    continue
                if line.strip() and not line.startswith("        \""):
                    proper_indent = False

        if not proper_indent:
            print(f"  FAIL: Rule {rule_id} snippet indicators not indented with 8 spaces!")
            failures += 1
        elif all_checks_passed:
            print(f"  PASS: Rule {rule_id} AST tighten-only guard snippet is valid, solid, and fail-closed.")

    # -------------------------------------------------------------------------
    # TEST 4: SQLite Database Invariant Verification
    # -------------------------------------------------------------------------
    print("\n[TEST 4] SQLite Database Content Verification (database/osoosi.db):")
    db_path = "database/osoosi.db"
    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        
        # Check for 2024 or older preprints
        cur.execute("SELECT rule_id, base_arxiv_id FROM enforced_research_rules WHERE base_arxiv_id LIKE '24%' OR CAST(SUBSTR(base_arxiv_id, 1, 2) AS INTEGER) < 25;")
        outdated_rows = cur.fetchall()
        if outdated_rows:
            print(f"  FAIL: Found {len(outdated_rows)} outdated rules in SQLite: {outdated_rows}")
            failures += 1
        else:
            print("  PASS: Zero 2024 or older preprints exist in database/osoosi.db")

        # Check total active rules count
        cur.execute("SELECT rule_id, base_arxiv_id, has_code_repo, code_repo_url FROM enforced_research_rules;")
        active_rows = cur.fetchall()
        print(f"  Active enforced rules count in SQLite: {len(active_rows)}")
        for r in active_rows:
            print(f"    - {r[0]} (arXiv:{r[1]}): has_code_repo={r[2]}, repo={r[3]}")
            if r[2] != 1 or not r[3].startswith("https://github.com/"):
                print(f"    FAIL: Rule {r[0]} does not have verified github repo!")
                failures += 1
        conn.close()
    else:
        print(f"  WARN: {db_path} does not exist.")

    # -------------------------------------------------------------------------
    # TEST 5: Latent Defect Analysis of line 4755
    # -------------------------------------------------------------------------
    print("\n[TEST 5] Latent Defect Analysis of breakout_defense.rs line 4755:")
    breakout_path = "crates/osoosi-agent-anomaly/src/breakout_defense.rs"
    with open(breakout_path, "r", encoding="utf-8") as f:
        breakout_content = f.read()

    line_4755_match = 'assert!(!is_current_research_arxiv_id("arXiv:2512.99999"));' in breakout_content
    if line_4755_match:
        print("  FINDING: Detected line 4755: 'assert!(!is_current_research_arxiv_id(\"arXiv:2512.99999\"));'")
        eval_2512 = is_current_research_arxiv_id("arXiv:2512.99999")
        print(f"  Evaluation of is_current_research_arxiv_id(\"arXiv:2512.99999\"): {eval_2512}")
        if eval_2512:
            print("  CRITICAL / LATENT TEST BUG: is_current_research_arxiv_id('arXiv:2512.99999') is TRUE under the 1-year window (YY >= 25),")
            print("  but line 4755 in test_current_research_recency_gate asserts '!is_current_research_arxiv_id(...)'.")
            print("  This would cause 'cargo test' to fail on test_current_research_recency_gate!")
            failures += 1
    else:
        print("  PASS: Line 4755 assertion not present or already corrected.")

    # -------------------------------------------------------------------------
    # SUMMARY
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print(f"EMPIRICAL HARNESS SUMMARY: {failures} FAILURES DETECTED")
    print("=" * 70)
    return failures

if __name__ == "__main__":
    sys.exit(main())
