#!/usr/bin/env python3
"""
scripts/verify_license_guard.py

License Guard Verification Script for OshoosiClaw CAGE Governance.
Verifies Apache-2.0 / MIT license compatibility, third-party component attribution
integrity in THIRD_PARTY_NOTICES.md, and workspace license compliance.
"""

import os
import sys
import argparse
import re
from pathlib import Path

# Ensure UTF-8 output encoding on Windows PowerShell
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Permissive open-source licenses compatible with OshoosiClaw distribution
ALLOWED_LICENSES = {
    "apache-2.0",
    "mit",
    "bsd-2-clause",
    "bsd-3-clause",
    "cc0-1.0",
    "cc-by-sa-4.0",
    "isc",
    "zlib",
    "unicode-3.0",
    "unlicense",
}

# Boolean operators and separators in SPDX license expressions
OPERATORS = {"or", "and", "with"}

# Required attributions and third-party components in THIRD_PARTY_NOTICES.md
REQUIRED_NOTICES = [
    {
        "name": "Google Cybernetic Agent Governance Engine (CAGE)",
        "markers": [
            "cybernetic agent governance engine",
            "google llc",
            "apache license",
            "apache-2.0",
        ],
    },
    {
        "name": "Microsoft Agent Coordination Service (ACS)",
        "markers": [
            "microsoft",
            "behavior declarations",
        ],
    },
    {
        "name": "Linux Foundation Agent Interoperability Framework (AAIF)",
        "markers": [
            "linux foundation",
            "governedrunloop",
        ],
    },
    {
        "name": "NIST OSCAL",
        "markers": [
            "nist",
            "oscal",
        ],
    },
    {
        "name": "Defense Unicorns Lula",
        "markers": [
            "lula",
            "lulavalidation",
        ],
    },
    {
        "name": "System-Theoretic Process Analysis (STPA)",
        "markers": [
            "stpa",
            "unsafe control actions",
        ],
    },
    {
        "name": "Cedar Policy Language",
        "markers": [
            "cedar",
            "amazon.com",
        ],
    },
]


def check_file_exists(file_path: Path, min_bytes: int = 100) -> bool:
    """Verify that a required file exists and is not empty."""
    if not file_path.is_file():
        print(f"[FAIL] Required file not found: {file_path}")
        return False
    size = file_path.stat().st_size
    if size < min_bytes:
        print(f"[FAIL] File too small ({size} bytes): {file_path}")
        return False
    return True


def verify_third_party_notices(notices_path: Path, verbose: bool = False) -> bool:
    """Verify attribution integrity in THIRD_PARTY_NOTICES.md."""
    if not check_file_exists(notices_path, min_bytes=500):
        return False

    content = notices_path.read_text(encoding="utf-8").lower()
    all_passed = True

    print(f"[*] Auditing attribution notices in {notices_path.name}...")
    for item in REQUIRED_NOTICES:
        name = item["name"]
        missing = [m for m in item["markers"] if m.lower() not in content]
        if missing:
            print(f"  [-] MISSING attribution markers for '{name}': {missing}")
            all_passed = False
        else:
            if verbose:
                print(f"  [+] Attribution verified: {name}")

    if all_passed:
        print(f"[PASS] All {len(REQUIRED_NOTICES)} required third-party attributions verified.")
    return all_passed


def validate_spdx_expression(expr: str) -> tuple[bool, list[str]]:
    """
    Validate an SPDX license expression against ALLOWED_LICENSES.

    - Strips enclosing quotes, whitespace, and parentheses.
    - Splits into tokens while handling operators (OR, AND, /, WITH).
    - Filters out boolean operators (or, and, with).
    - Validates that every individual license identifier token (normalized to lowercase)
      is present in ALLOWED_LICENSES.
    - Returns (True, []) if all tokens are allowed, or (False, [disallowed_tokens]).
    """
    if not expr or not expr.strip():
        return False, ["<empty>"]

    # Strip enclosing quotes and whitespace
    cleaned = expr.strip().strip("\"'")
    # Replace separators and parentheses with space
    cleaned = re.sub(r'[/(),]', ' ', cleaned)
    raw_tokens = cleaned.split()

    disallowed = []
    license_tokens = []
    for token in raw_tokens:
        t_clean = token.strip("\"'").lower()
        if not t_clean or t_clean in OPERATORS:
            continue
        license_tokens.append(t_clean)
        if t_clean not in ALLOWED_LICENSES:
            disallowed.append(t_clean)

    if not license_tokens:
        return False, ["<no-license-tokens>"]
    if disallowed:
        return False, disallowed
    return True, []


def extract_workspace_default_license(cargo_toml: Path) -> str | None:
    """Extract default license expression from root Cargo.toml."""
    if tomllib is not None:
        try:
            with open(cargo_toml, "rb") as f:
                data = tomllib.load(f)
            ws_pkg = data.get("workspace", {}).get("package", {})
            if "license" in ws_pkg and isinstance(ws_pkg["license"], str):
                return ws_pkg["license"].strip()
            pkg = data.get("package", {})
            if "license" in pkg and isinstance(pkg["license"], str):
                return pkg["license"].strip()
        except Exception:
            pass

    # Fallback regex parsing
    try:
        content = cargo_toml.read_text(encoding="utf-8")
        ws_pkg_match = re.search(
            r'\[workspace\.package\][^\[]*?license\s*=\s*["\']([^"\']+)["\']',
            content,
            re.DOTALL,
        )
        if ws_pkg_match:
            return ws_pkg_match.group(1).strip()
        pkg_match = re.search(
            r'\[package\][^\[]*?license\s*=\s*["\']([^"\']+)["\']',
            content,
            re.DOTALL,
        )
        if pkg_match:
            return pkg_match.group(1).strip()
    except Exception:
        pass
    return None


def extract_crate_license_info(crate_toml: Path) -> tuple[str, str | None, bool]:
    """
    Extract crate name and license specification from a crate's Cargo.toml.
    Returns (crate_name, explicit_license, inherits_workspace).
    """
    name = crate_toml.parent.name
    explicit_lic = None
    inherits_ws = False

    if tomllib is not None:
        try:
            with open(crate_toml, "rb") as f:
                data = tomllib.load(f)
            pkg = data.get("package", {})
            name = pkg.get("name", name)
            lic = pkg.get("license")
            if isinstance(lic, dict) and lic.get("workspace") is True:
                inherits_ws = True
            elif isinstance(lic, str):
                explicit_lic = lic.strip()
            elif lic is None:
                # Omitted in member crate -> inherits workspace default
                inherits_ws = True
            return name, explicit_lic, inherits_ws
        except Exception:
            pass

    try:
        content = crate_toml.read_text(encoding="utf-8")
        name_m = re.search(r'\[package\][^\[]*?name\s*=\s*["\']([^"\']+)["\']', content, re.DOTALL)
        if name_m:
            name = name_m.group(1).strip()
        if re.search(r'license\.workspace\s*=\s*true', content) or re.search(
            r'\[package\.license\][^\[]*?workspace\s*=\s*true', content
        ):
            inherits_ws = True
        else:
            lic_m = re.search(r'\[package\][^\[]*?license\s*=\s*["\']([^"\']+)["\']', content, re.DOTALL)
            if lic_m:
                explicit_lic = lic_m.group(1).strip()
            else:
                inherits_ws = True
    except Exception:
        pass

    return name, explicit_lic, inherits_ws


def find_all_crate_manifests(root_path: Path) -> list[Path]:
    """Find all member crate Cargo.toml paths in the workspace."""
    manifests = set()
    cargo_toml = root_path / "Cargo.toml"

    if tomllib is not None and cargo_toml.is_file():
        try:
            with open(cargo_toml, "rb") as f:
                data = tomllib.load(f)
            members = data.get("workspace", {}).get("members", [])
            for member in members:
                if "*" in member or "?" in member:
                    for m_path in root_path.glob(member):
                        candidate = m_path / "Cargo.toml" if m_path.is_dir() else m_path
                        if candidate.is_file() and candidate != cargo_toml:
                            manifests.add(candidate.resolve())
                else:
                    candidate = root_path / member / "Cargo.toml"
                    if candidate.is_file() and candidate != cargo_toml:
                        manifests.add(candidate.resolve())
        except Exception:
            pass

    # Also glob crates/*/Cargo.toml
    crates_dir = root_path / "crates"
    if crates_dir.is_dir():
        for candidate in crates_dir.glob("*/Cargo.toml"):
            if candidate.is_file() and candidate != cargo_toml:
                manifests.add(candidate.resolve())

    return sorted(list(manifests), key=lambda p: str(p).lower())


def verify_workspace_licenses(root_path: Path, verbose: bool = False) -> bool:
    """Verify license files and crate metadata across the workspace."""
    print("[*] Auditing workspace license files...")
    # Check for primary LICENSE file
    license_candidates = [
        root_path / "LICENSE",
        root_path / "LICENSE.txt",
        root_path / "LICENSE.md",
    ]
    primary_license = next((p for p in license_candidates if p.is_file()), None)
    if not primary_license:
        print("[FAIL] No primary LICENSE file found at project root.")
        return False
    print(f"[PASS] Primary license file located: {primary_license.name}")

    # Inspect workspace Cargo.toml
    cargo_toml = root_path / "Cargo.toml"
    if not cargo_toml.is_file():
        print("[FAIL] Root Cargo.toml not found.")
        return False

    ws_license = extract_workspace_default_license(cargo_toml)
    if not ws_license:
        print("[FAIL] No workspace default license specified in root Cargo.toml.")
        return False

    ws_valid, ws_disallowed = validate_spdx_expression(ws_license)
    if not ws_valid:
        print(f"[FAIL] Root Cargo.toml workspace license '{ws_license}' is disallowed (disallowed tokens: {ws_disallowed}).")
        return False
    print(f"[PASS] Workspace default license validated: '{ws_license}'")

    # Iterate over member crate manifests
    crate_manifests = find_all_crate_manifests(root_path)
    print(f"[*] Auditing {len(crate_manifests)} member crate manifests across workspace...")
    if not crate_manifests:
        print("[FAIL] No member crate manifests found in workspace.")
        return False

    crates_passed = True
    for c_path in crate_manifests:
        try:
            rel_path = c_path.relative_to(root_path)
        except ValueError:
            rel_path = c_path

        name, explicit_lic, inherits_ws = extract_crate_license_info(c_path)
        if explicit_lic is not None:
            c_valid, c_disallowed = validate_spdx_expression(explicit_lic)
            if not c_valid:
                print(f"[FAIL] Crate {name} at {rel_path} has disallowed license: {explicit_lic} (disallowed tokens: {c_disallowed})")
                crates_passed = False
            else:
                if verbose:
                    print(f"  [+] Crate {name} ({rel_path}): validated license '{explicit_lic}'")
        elif inherits_ws:
            if verbose:
                print(f"  [+] Crate {name} ({rel_path}): inherits validated workspace license '{ws_license}'")
        else:
            print(f"[FAIL] Crate {name} at {rel_path} has no valid license declaration.")
            crates_passed = False

    if not crates_passed:
        print("[FAIL] One or more member crates have disallowed or missing licenses.")
        return False

    print(f"[PASS] All {len(crate_manifests)} member crate licenses verified against ALLOWED_LICENSES.")
    return True


def verify_license_guard(verbose: bool = False) -> bool:
    """Run full license guard verification."""
    print("=" * 70)
    print(" OshoosiClaw CAGE License Guard & Attribution Verification")
    print("=" * 70)

    notices_file = PROJECT_ROOT / "THIRD_PARTY_NOTICES.md"
    notices_ok = verify_third_party_notices(notices_file, verbose=verbose)
    workspace_ok = verify_workspace_licenses(PROJECT_ROOT, verbose=verbose)

    passed = notices_ok and workspace_ok
    print("-" * 70)
    if passed:
        print("[PASS] License Guard audit complete: all licenses compatible and attribution verified.")
    else:
        print("[FAIL] License Guard audit failed. Please address missing attributions or licenses.")
    print("=" * 70)
    return passed


def main():
    parser = argparse.ArgumentParser(description="Verify third-party licenses and attribution notices")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    success = verify_license_guard(verbose=args.verbose)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
