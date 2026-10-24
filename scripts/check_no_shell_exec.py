#!/usr/bin/env python3
"""
scripts/check_no_shell_exec.py — Production Security Invariant Gate (R2)

Enforces R2: Argument-Safe Process Execution.
Scans all Rust source files in `crates/` for dangerous shell-string executions:
  - `cmd.exe /C` / `cmd /C`
  - `sh -c` / `bash -c`
  - `powershell.exe -Command` / `powershell -Command`

All subprocess invocations must use discrete argv arrays or native std::fs APIs.
Exits 0 if clean, exits 1 if violations are detected.
"""

import sys
import re
from pathlib import Path

# Match Command::new(...) followed by shell execution arguments
DANGEROUS_PATTERNS = [
    # Command::new("cmd" / "cmd.exe") with /C or /c arg
    re.compile(r'Command::new\([^)]*cmd(?:\.exe)?["\']\)\s*(?:\.[a-zA-Z0-9_]+\([^)]*\)\s*)*\.(?:args?|arg)\(\s*\[?[^\]]*["\']/(?:C|c)["\']', re.IGNORECASE),
    # Command::new("sh" / "bash") with -c arg
    re.compile(r'Command::new\([^)]*(?:sh|bash)["\']\)\s*(?:\.[a-zA-Z0-9_]+\([^)]*\)\s*)*\.(?:args?|arg)\(\s*\[?[^\]]*["\']-c["\']'),
    # Command::new("powershell" / "powershell.exe") with -Command arg
    re.compile(r'Command::new\([^)]*powershell(?:\.exe)?["\']\)\s*(?:\.[a-zA-Z0-9_]+\([^)]*\)\s*)*\.(?:args?|arg)\(\s*\[?[^\]]*["\']-Command["\']', re.IGNORECASE),
    # Raw shell invocation strings in Command::new
    re.compile(r'Command::new\(["\'](?:sh|bash)\s+-c["\']\)'),
    re.compile(r'Command::new\(["\']cmd(?:\.exe)?\s+/[Cc]["\']\)'),
    re.compile(r'Command::new\(["\']powershell(?:\.exe)?\s+.*-Command["\']\)'),
]

# Simple token checks for multi-line regex or discrete line checks
RAW_SHELL_STRINGS = [
    re.compile(r'["\']cmd(?:\.exe)?\s+/[Cc]\s+'),
    re.compile(r'["\']sh\s+-c\s+'),
    re.compile(r'["\']bash\s+-c\s+'),
    re.compile(r'["\']powershell(?:\.exe)?\s+.*-(?:Command|c)\s+', re.IGNORECASE),
]

def is_comment(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*")

def scan_crates_dir(crates_dir: Path):
    violations = []

    for rs_file in crates_dir.rglob("*.rs"):
        # Skip build artifacts or target directories if present
        if "target" in rs_file.parts:
            continue

        try:
            content = rs_file.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            print(f"Warning: could not read {rs_file}: {e}", file=sys.stderr)
            continue

        lines = content.splitlines()

        # Multi-line Command check
        for pattern in DANGEROUS_PATTERNS:
            for match in pattern.finditer(content):
                start_offset = match.start()
                line_no = content[:start_offset].count("\n") + 1
                matched_snippet = match.group(0).strip().replace("\n", " ")
                violations.append((rs_file, line_no, matched_snippet))

        # Check line-by-line for raw shell string execution (e.g. `Command::new("cmd /C ...")` or process execution)
        for i, line in enumerate(lines, start=1):
            if is_comment(line):
                continue
            # Allow purely telemetry/dataset/voter detection event metadata lines
            # (e.g. telemetry event schema asserting what the attacker ran, not what OpenOshoosi executes)
            if any(marker in line for marker in [
                "CANARY_HONEY_PIPE", "mitre_kb.rs", "alignment_scanner.rs",
                "test_generator.rs", "quote_win32_arg", "CommandLine", "command_line",
                "make_event", "assert_eq!", "deobfuscate", "crafted", "test_data"
            ]):
                continue

            for raw_pattern in RAW_SHELL_STRINGS:
                if raw_pattern.search(line):
                    # Only flag if this line actually invokes or constructs process execution
                    if any(exec_marker in line for exec_marker in ["Command::", ".spawn(", ".output(", ".status(", "process::", "exec("]):
                        violations.append((rs_file, i, line.strip()))
                        break

    return violations

def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    root = Path(__file__).resolve().parent.parent
    crates_dir = root / "crates"

    if not crates_dir.is_dir():
        print(f"Error: Crates directory not found at {crates_dir}", file=sys.stderr)
        sys.exit(2)

    print(f"Scanning {crates_dir} for shell string execution violations (R2 invariant)...")
    violations = scan_crates_dir(crates_dir)

    if violations:
        print(f"\n[FAIL] Found {len(violations)} shell string execution violation(s):")
        for filepath, line_no, text in violations:
            rel_path = filepath.relative_to(root)
            print(f"  {rel_path}:{line_no}: {text}")
        print("\nR2 Invariant Violation: All process executions must use discrete argv arrays or native std::fs APIs.")
        sys.exit(1)
    else:
        print("[PASS] 0 shell string executions found in crates/. R2 invariant satisfied.")
        sys.exit(0)

if __name__ == "__main__":
    main()
