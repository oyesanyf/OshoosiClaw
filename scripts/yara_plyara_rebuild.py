#!/usr/bin/env python3
"""
Optional YARA cleanup: parse with plyara (classic YARA grammar) and rebuild source.
Used when OSOOSI_YARA_PLYARA=1 and osoosi-model pipes rule text on stdin.

Install: pip install plyara

Exit codes: 0 ok, 1 parse/rebuild failed, 2 plyara not installed.
"""
from __future__ import annotations

import sys

try:
    import plyara
    from plyara.utils import rebuild_yara_rule
except ImportError:
    sys.exit(2)


def main() -> None:
    data = sys.stdin.read()
    if not data.strip():
        sys.stdout.write(data)
        return
    parser = plyara.Plyara()
    try:
        rules = parser.parse_string(data)
    except Exception:
        sys.exit(1)
    if not rules:
        sys.stdout.write(data)
        return
    parts = []
    for rule in rules:
        parts.append(rebuild_yara_rule(rule, condition_indents=True))
    out = "\n\n".join(parts)
    sys.stdout.write(out)
    if out and not out.endswith("\n"):
        sys.stdout.write("\n")


if __name__ == "__main__":
    main()
