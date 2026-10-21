#!/usr/bin/env python3
"""
OshoosiClaw Repository Clarity & Language Distribution Verification Gate
-------------------------------------------------------------------------
Asserts:
1. Git-tracked files match .gitattributes filtering for linguist attributes.
2. Rust is #1 language by detectable source code bytes.
3. Python is #2 language by detectable source code bytes.
4. Rust + Python compose >= 90.0% of total detectable source code bytes.
5. README.md top 250 lines include executive onboarding sections, capabilities, and mermaid diagram.
6. dashboard/src/style.css defines dark-theme controls and .btn-secondary.
"""

import sys
import os
import subprocess
import fnmatch
import re

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

def parse_gitattributes(gitattributes_path='.gitattributes'):
    rules = []
    if not os.path.exists(gitattributes_path):
        raise FileNotFoundError(f"Missing {gitattributes_path}")
    with open(gitattributes_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            pattern = parts[0]
            attrs = parts[1:]
            rules.append((pattern, attrs))
    return rules

def pattern_matches(path, pattern):
    norm_path = path.replace('\\', '/')
    filename = os.path.basename(norm_path)
    if '/' not in pattern:
        return fnmatch.fnmatch(filename, pattern)
    p = pattern.lstrip('/')
    if p.endswith('/**'):
        prefix = p[:-3]
        if norm_path == prefix or norm_path.startswith(prefix + '/'):
            return True
    regex = '^' + re.escape(p).replace(r'\*\*/', r'.*?').replace(r'\*\*', r'.*').replace(r'\*', r'[^/]*').replace(r'\?', r'.') + '$'
    return bool(re.match(regex, norm_path))

def is_path_linguist_ignored(path, rules):
    ignored = False
    for pat, attrs in rules:
        if pattern_matches(path, pat):
            for attr in attrs:
                if any(attr.startswith(x) for x in ('linguist-generated=true', 'linguist-vendored=true', 'linguist-documentation=true')):
                    ignored = True
                elif attr == 'linguist-detectable=true':
                    ignored = False
    return ignored

def verify_language_distribution():
    print("=" * 80)
    print("STEP 1: Evaluating Repository Language Distribution via .gitattributes")
    print("=" * 80)

    rules = parse_gitattributes()
    res = subprocess.run(['git', 'ls-files'], capture_output=True, text=True, check=True)
    all_files = res.stdout.splitlines()

    lang_ext = {
        '.rs': 'Rust',
        '.py': 'Python',
        '.c': 'C',
        '.h': 'C',
        '.cpp': 'C++',
        '.hpp': 'C++',
        '.go': 'Go',
        '.java': 'Java',
        '.sh': 'Shell',
        '.ps1': 'PowerShell',
    }

    counts = {}
    ignored_count = 0
    detectable_count = 0

    for path in all_files:
        if is_path_linguist_ignored(path, rules):
            ignored_count += 1
            continue
        _, ext = os.path.splitext(path.lower())
        if ext in lang_ext:
            lang = lang_ext[ext]
            size = os.path.getsize(path) if os.path.exists(path) else 0
            counts[lang] = counts.get(lang, 0) + size
            detectable_count += 1

    total_bytes = sum(counts.values())
    if total_bytes == 0:
        raise ValueError("Error: Total detectable source code bytes is 0!")

    sorted_langs = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    print(f"Total Git-Tracked Files   : {len(all_files):,}")
    print(f"Filtered (Vendored/Gen/Doc): {ignored_count:,}")
    print(f"Detectable Source Files    : {detectable_count:,}")
    print(f"Total Detectable Bytes     : {total_bytes:,} bytes\n")

    print(f"{'Language':<16} | {'Bytes':>12} | {'Percentage':>10}")
    print("-" * 44)
    for lang, sz in sorted_langs:
        pct = (sz / total_bytes) * 100
        print(f"{lang:<16} | {sz:>12,d} | {pct:>9.2f}%")
    print("-" * 44)

    rust_bytes = counts.get('Rust', 0)
    python_bytes = counts.get('Python', 0)
    rp_total = rust_bytes + python_bytes
    rp_pct = (rp_total / total_bytes) * 100

    print(f"\nCombined Rust + Python: {rp_total:,} bytes ({rp_pct:.2f}% of total)\n")

    # Assertions
    assert sorted_langs[0][0] == 'Rust', f"Expected Rust to be #1 language, got {sorted_langs[0][0]}"
    assert sorted_langs[1][0] == 'Python', f"Expected Python to be #2 language, got {sorted_langs[1][0]}"
    assert rp_pct >= 90.0, f"Expected Rust + Python >= 90.0%, got {rp_pct:.2f}%"

    print("✔ Assertion PASSED: Rust is #1 language by bytes.")
    print("✔ Assertion PASSED: Python is #2 language by bytes.")
    print(f"✔ Assertion PASSED: Rust + Python ({rp_pct:.2f}%) >= 90.0% of detectable source code.")

def verify_readme_clarity():
    print("\n" + "=" * 80)
    print("STEP 2: Evaluating README.md Top 250 Lines Plain-English Onboarding")
    print("=" * 80)

    readme_path = 'README.md'
    if not os.path.exists(readme_path):
        raise FileNotFoundError("README.md not found!")

    with open(readme_path, 'r', encoding='utf-8') as f:
        lines = [f.readline() for _ in range(250)]

    top_text = "".join(lines)
    print(f"Read first {len(lines)} lines of {readme_path} ({len(top_text)} chars).")

    required_phrases = [
        "What is OshoosiClaw",
        "Core Capabilities",
        "Rust",
        "Python",
        "60-Second Quick Start",
        "#har-traffic",
        "mermaid",
    ]

    for phrase in required_phrases:
        assert phrase in top_text, f"Missing required onboarding element in top 250 lines: '{phrase}'"
        print(f"✔ Confirmed present in first 250 lines: '{phrase}'")

def verify_style_dark_theme():
    print("\n" + "=" * 80)
    print("STEP 3: Evaluating Dark-Theme Typography & Button Contrast Rules")
    print("=" * 80)

    style_path = 'dashboard/src/style.css'
    if not os.path.exists(style_path):
        raise FileNotFoundError(f"{style_path} not found!")

    with open(style_path, 'r', encoding='utf-8') as f:
        style_content = f.read()

    assert ".btn-secondary" in style_content, "Missing .btn-secondary definition in style.css"
    print("✔ Confirmed .btn-secondary defined in dashboard/src/style.css")

    assert "select option" in style_content, "Missing 'select option' dark-theme style rule in style.css"
    print("✔ Confirmed 'select option' dark-theme style rule present in dashboard/src/style.css")

    assert "--text-muted: #94a3b8;" in style_content, "Missing upgraded high-contrast --text-muted in style.css"
    print("✔ Confirmed upgraded --text-muted: #94a3b8 in dashboard/src/style.css")

def main():
    try:
        verify_language_distribution()
        verify_readme_clarity()
        verify_style_dark_theme()
        print("\n" + "=" * 80)
        print("ALL VERIFICATIONS COMPLETED SUCCESSFULLY (0 ERRORS)")
        print("=" * 80)
    except AssertionError as e:
        print(f"\n❌ VERIFICATION FAILURE: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == '__main__':
    main()
