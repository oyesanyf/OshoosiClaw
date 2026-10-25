#!/usr/bin/env python3
"""
scripts/seed_good_first_issues.py
---------------------------------
Parses, validates, and seeds the 12 curated starter tasks from docs/GOOD_FIRST_ISSUES.md.

Usage:
    python scripts/seed_good_first_issues.py --verify
    python scripts/seed_good_first_issues.py --export-json issues.json
    python scripts/seed_good_first_issues.py --dry-run
    python scripts/seed_good_first_issues.py --seed
"""

import sys
import re
import os
import argparse
import json

sys.stdout.reconfigure(encoding='utf-8')

def parse_issues(doc_path="docs/GOOD_FIRST_ISSUES.md"):
    if not os.path.exists(doc_path):
        raise FileNotFoundError(f"Could not find {doc_path}")

    with open(doc_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Split into sections by heading ### GFI-XX: ...
    issue_pattern = r'###\s+(GFI-\d{2}):\s+([^\n]+)'
    splits = list(re.finditer(issue_pattern, content))

    issues = []
    for i, match in enumerate(splits):
        gfi_id = match.group(1)
        title = match.group(2).strip()
        start_pos = match.end()
        end_pos = splits[i+1].start() if i + 1 < len(splits) else content.find("## 🚀 How to Claim an Issue", start_pos)
        if end_pos == -1:
            end_pos = len(content)

        body = content[start_pos:end_pos].strip()

        # Extract File
        file_match = re.search(r'\-\s+\*\*File\*\*:\s+\[`([^`]+)`\]\(([^)]+)\)', body)
        target_file = file_match.group(1) if file_match else None

        # Extract Subsystem
        subsystem_match = re.search(r'\-\s+\*\*Subsystem\*\*:\s+([^\n]+)', body)
        subsystem = subsystem_match.group(1).strip() if subsystem_match else "General"

        # Extract Verification Command
        cmd_match = re.search(r'```bash\s*\n(.*?)\n```', body, re.DOTALL)
        verification_cmd = cmd_match.group(1).strip() if cmd_match else None

        issues.append({
            "id": gfi_id,
            "title": f"[{gfi_id}]: {title}",
            "raw_title": title,
            "file": target_file,
            "subsystem": subsystem,
            "verification_cmd": verification_cmd,
            "body": body,
            "labels": ["good first issue", "help wanted", "onboarding"]
        })

    return issues

def verify_issues(issues):
    print("=" * 80)
    print("AUDITING CURATED GOOD FIRST ISSUES CATALOG (docs/GOOD_FIRST_ISSUES.md)")
    print("=" * 80)

    if len(issues) != 12:
        print(f"❌ Error: Expected 12 issues, found {len(issues)}", file=sys.stderr)
        return False

    errors = []
    seen_ids = set()

    print(f"{'ID':<8} | {'Subsystem':<20} | {'Target File':<35} | Status")
    print("-" * 80)

    for iss in issues:
        gfi_id = iss["id"]
        target_file = iss["file"]

        if gfi_id in seen_ids:
            errors.append(f"Duplicate issue ID: {gfi_id}")
        seen_ids.add(gfi_id)

        if not target_file:
            errors.append(f"{gfi_id}: Missing target file reference")
            print(f"{gfi_id:<8} | {iss['subsystem']:<20} | {'MISSING':<35} | ❌ MISSING FILE")
            continue

        # Strip line numbers or anchors
        clean_file = target_file.split('#')[0]
        # Check if file exists relative to repo root
        if not os.path.exists(clean_file):
            errors.append(f"{gfi_id}: Referenced file does not exist: {clean_file}")
            print(f"{gfi_id:<8} | {iss['subsystem']:<20} | {clean_file:<35} | ❌ NOT FOUND")
        else:
            print(f"{gfi_id:<8} | {iss['subsystem']:<20} | {clean_file:<35} | ✔ VALID")

    print("-" * 80)

    if errors:
        print(f"\n❌ Validation failed with {len(errors)} error(s):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return False

    print(f"\n✔ All {len(issues)} Good First Issues verified successfully with real target files!")
    return True

def main():
    parser = argparse.ArgumentParser(description="OshoosiClaw Good First Issues Seeder & Verifier")
    parser.add_argument("--verify", action="store_true", help="Verify all issues in docs/GOOD_FIRST_ISSUES.md")
    parser.add_argument("--export-json", type=str, help="Export parsed issues to JSON file")
    parser.add_argument("--dry-run", action="store_true", help="Simulate seeding issues to GitHub")
    parser.add_argument("--seed", action="store_true", help="Seed issues to GitHub via gh CLI")
    args = parser.parse_args()

    try:
        issues = parse_issues()
    except Exception as e:
        print(f"❌ Failed to parse issues: {e}", file=sys.stderr)
        sys.exit(1)

    if args.verify or (not args.export_json and not args.dry_run and not args.seed):
        success = verify_issues(issues)
        if not success:
            sys.exit(1)

    if args.export_json:
        with open(args.export_json, 'w', encoding='utf-8') as f:
            json.dump(issues, f, indent=2)
        print(f"Exported {len(issues)} issues to {args.export_json}")

    if args.dry_run:
        print("\n[DRY RUN] Would seed the following issues to GitHub:")
        for iss in issues:
            print(f"  gh issue create --title \"{iss['title']}\" --label \"good first issue,help wanted\"")

    if args.seed:
        import subprocess
        print("\nSeeding issues to GitHub via gh CLI...")
        for iss in issues:
            cmd = [
                "gh", "issue", "create",
                "--title", iss["title"],
                "--body", iss["body"],
                "--label", "good first issue,help wanted,onboarding"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode == 0:
                print(f"✔ Created issue {iss['id']}: {res.stdout.strip()}")
            else:
                print(f"❌ Failed to create {iss['id']}: {res.stderr.strip()}", file=sys.stderr)

if __name__ == '__main__':
    main()
