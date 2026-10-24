import os
import re
import sys
from typing import Dict, List, Set, Tuple

# Match rule declarations: optional global/private + rule + identifier
RULE_DECL_RE = re.compile(r"^(\s*(?:(?:global|private)\s+)*rule\s+)([A-Za-z0-9_]+)\b")
ANDRO_IMPORT_RE = re.compile(r'^\s*import\s+["\']androguard["\']')
PE_EXPORTS_CHAR_RE = re.compile(
    r'pe\.exports\s*\(\s*["\']([Cc]rash)["\']\s*\)\s*&\s*pe\.characteristics'
)

# Match a genuine YARA regex string definition: $ident = /body/modifiers
REGEX_DEF_RE = re.compile(
    r"^(\s*\$[A-Za-z0-9_]*\s*=\s*/)(.+)(/[A-Za-z0-9\s]*?(?:\s*(?://.*|/\*.*\*/))?)$"
)

# Match a double-quoted YARA string definition: $ident = "..."
QUOTED_DEF_RE = re.compile(r'^\s*\$[A-Za-z0-9_]*\s*=\s*"')

# Odd number of backslashes before { or } inside a double-quoted string (invalid in YARA)
ODD_BACKSLASH_BRACE_RE = re.compile(r"(?<!\\)((?:\\\\)*)\\([{}])")
# Odd number of backslashes before / inside a double-quoted string (invalid in YARA)
ODD_BACKSLASH_SLASH_RE = re.compile(r"(?<!\\)((?:\\\\)*)\\/")

# Windows path/GUID prefixes where \\{ in a double-quoted string is a legitimate path separator + {
WINDOWS_PATH_BRACE_PREFIXES = (
    "Global\\\\{",
    "Local\\\\{",
    "Device\\\\{",
    "DosDevices\\\\{",
    "Network\\\\{",
    "Logmein\\\\{",
    "Classes\\\\{",
    "CLSID\\\\{",
    "Interface\\\\{",
    "TypeLib\\\\{",
    "{0}\\\\{1",
    "\"\\\\\\\\{",
)

# Unsupported external variable clauses sometimes found in community rules
EXTERNAL_CLAUSE_AND_PREFIX_RE = re.compile(
    r'\b(?:filename|filepath|extension|filetype)\s*(?:==|!=|matches|contains|icontains)\s*(?:"[^"]*"|/[^/]+/)\s+(?:and|or)\s+',
    re.IGNORECASE,
)
EXTERNAL_CLAUSE_AND_SUFFIX_RE = re.compile(
    r'\s+(?:and|or)\s+\b(?:filename|filepath|extension|filetype)\s*(?:==|!=|matches|contains|icontains)\s*(?:"[^"]*"|/[^/]+/)',
    re.IGNORECASE,
)


def escape_unpaired_braces_in_regex_body(body: str) -> str:
    """
    Escapes `{` and `}` inside a YARA regular expression `/body/` ONLY when they:
      1. Are not already escaped (`\\{` or `\\}`),
      2. Are not inside a character class `[...]`, and
      3. Do not form a valid counted repetition quantifier `{N}`, `{N,}`, or `{N,M}`.
    """
    out: List[str] = []
    i = 0
    n = len(body)
    in_char_class = False

    while i < n:
        ch = body[i]

        # 1. Preserve any escaped character verbatim
        if ch == "\\" and i + 1 < n:
            out.append(body[i : i + 2])
            i += 2
            continue

        # 2. Track regex character classes [...]
        if ch == "[" and not in_char_class:
            in_char_class = True
            out.append(ch)
            i += 1
            continue
        if ch == "]" and in_char_class:
            in_char_class = False
            out.append(ch)
            i += 1
            continue
        if in_char_class:
            out.append(ch)
            i += 1
            continue

        # 3. Check if `{` starts a valid counted quantifier `{d}` / `{d,}` / `{d,d}`
        if ch == "{":
            m = re.match(r"^\{(\d+(?:,\d*)?)\}", body[i:])
            if m:
                out.append(m.group(0))
                i += len(m.group(0))
                continue
            out.append("\\{")
            i += 1
            continue

        # 4. Any unescaped `}` reached here was not consumed by a valid `{d,d}` quantifier
        if ch == "}":
            out.append("\\}")
            i += 1
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def repair_or_harden_string_line(line: str) -> Tuple[str, bool]:
    """
    - If `line` is a double-quoted string definition (`$s = "..."`), repairs any
      invalid `\\{`, `\\}`, or `\\/` escapes that were previously injected by naive
      slash/brace replacement, ensuring quoted string bytes match real targets.
    - If `line` is a regex definition (`$r = /.../`), escapes only non-quantifier
      unescaped `{` and `}` inside the regex body.
    """
    if QUOTED_DEF_RE.match(line):
        fixed = ODD_BACKSLASH_BRACE_RE.sub(r"\1\2", line)
        fixed = ODD_BACKSLASH_SLASH_RE.sub(r"\1/", fixed)

        # Also repair double-escaped `\\{` / `\\}` in JS/CSS exploit strings containing `/`
        # that are not Windows path/GUID separators
        if ("\\\\{" in fixed or "\\\\}" in fixed) and "/" in fixed:
            if not any(pref in fixed for pref in WINDOWS_PATH_BRACE_PREFIXES):
                fixed = fixed.replace("\\\\{", "{").replace("\\\\}", "}")

        return fixed, (fixed != line)

    regex_match = REGEX_DEF_RE.match(line)
    if regex_match:
        prefix, body, suffix = regex_match.groups()
        # Ensure we didn't accidentally match a double-quoted string containing two slashes
        if not prefix.lstrip().startswith("$") or '"' in prefix:
            return line, False
        fixed_body = escape_unpaired_braces_in_regex_body(body)
        if fixed_body != body:
            return f"{prefix}{fixed_body}{suffix}", True

    return line, False


def comment_out_vacuous_rules(lines: List[str]) -> Tuple[List[str], int]:
    """
    Detects rules whose condition body was reduced to `false`, `true`, or empty
    (e.g. rules that had no `strings:` and only `androguard.*` conditions) and
    cleanly comments out the entire vacuous rule so it never compiles as a dead
    rule that detects nothing.
    """
    result = list(lines)
    vacuous_fixed = 0
    i = 0
    n = len(result)

    while i < n:
        line = result[i]
        trimmed = line.strip()
        if not trimmed.startswith("//") and RULE_DECL_RE.match(line):
            rule_start = i
            depth = 0
            started_brace = False
            rule_end = i
            cond_idx = None

            for j in range(i, n):
                t = result[j].strip()
                if t.startswith("//"):
                    continue
                if re.match(r"^condition\s*:", t, re.IGNORECASE):
                    cond_idx = j
                # Count braces outside comments/strings roughly at block level
                if not t.startswith("$"):
                    for ch in t:
                        if ch == "{":
                            depth += 1
                            started_brace = True
                        elif ch == "}":
                            depth -= 1
                if started_brace and depth <= 0:
                    rule_end = j
                    break

            if cond_idx is not None and rule_end > cond_idx:
                # Gather active condition lines between `condition:` and closing `}`
                cond_header = result[cond_idx].strip()
                inline_after_colon = cond_header.split(":", 1)[1].strip() if ":" in cond_header else ""
                if "//" in inline_after_colon:
                    inline_after_colon = inline_after_colon.split("//", 1)[0].strip()

                active_cond_parts: List[str] = []
                if inline_after_colon:
                    active_cond_parts.append(inline_after_colon)

                for k in range(cond_idx + 1, rule_end):
                    ct = result[k].strip()
                    if not ct or ct.startswith("//") or ct.startswith("/*") or ct.startswith("*"):
                        continue
                    if "//" in ct:
                        ct = ct.split("//", 1)[0].strip()
                    if ct:
                        active_cond_parts.append(ct)

                combined_cond = " ".join(active_cond_parts).strip()
                if combined_cond.lower() in ("", "false", "true", "(false)", "(true)"):
                    for k in range(rule_start, rule_end + 1):
                        if not result[k].strip().startswith("//"):
                            result[k] = f"// {result[k]} (Disabled: vacuous condition without evaluatable strings/modules)"
                    vacuous_fixed += 1
                    i = rule_end + 1
                    continue

            i = max(i + 1, rule_end + 1)
        else:
            i += 1

    return result, vacuous_fixed


def harden_yara(yara_dir: str) -> Dict[str, int]:
    global_seen_rules: Dict[str, int] = {}
    stats = {
        "files_scanned": 0,
        "files_fixed": 0,
        "strings_repaired_or_hardened": 0,
        "duplicates_renamed": 0,
        "vacuous_rules_disabled": 0,
    }

    if not os.path.exists(yara_dir):
        print(f"Directory '{yara_dir}' does not exist, skipping.")
        return stats

    print(f"Starting semantic-preserving YARA sanitization of '{yara_dir}'...")

    for root, _, files in os.walk(yara_dir):
        for file in sorted(files):
            if not file.endswith((".yar", ".yara", ".rule")):
                continue
            if file.endswith("index.yar") or file.endswith("_index.yar"):
                continue

            file_path = os.path.join(root, file)
            stats["files_scanned"] += 1
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception as e:
                print(f"Skipping {file_path}: {e}")
                continue

            lines = content.splitlines()
            new_lines: List[str] = []
            changed = False
            file_seen_rules: Dict[str, int] = {}

            for i, line in enumerate(lines):
                trimmed = line.strip()
                new_line = line

                if trimmed.startswith("//"):
                    new_lines.append(new_line)
                    continue

                # 1. Comment out unsupported androguard imports
                if ANDRO_IMPORT_RE.search(new_line):
                    new_line = f"// {new_line} (Disabled by Oshoosi Hardener)"
                    changed = True
                    new_lines.append(new_line)
                    continue

                # 2. Exact-token Duplicate Rule Detection & Renaming (within-file & cross-file)
                rule_match = RULE_DECL_RE.match(new_line)
                if rule_match:
                    prefix, name = rule_match.groups()
                    effective_name = name

                    if name in file_seen_rules:
                        file_seen_rules[name] += 1
                        effective_name = f"{name}_v{file_seen_rules[name]}"
                    else:
                        file_seen_rules[name] = 1

                    if effective_name in global_seen_rules:
                        global_seen_rules[effective_name] += 1
                        effective_name = f"{effective_name}_Duplicate_{global_seen_rules[effective_name]}"
                    else:
                        global_seen_rules[effective_name] = 1

                    if effective_name != name:
                        new_line = RULE_DECL_RE.sub(rf"\g<1>{effective_name}", new_line, count=1)
                        stats["duplicates_renamed"] += 1
                        changed = True

                # 3. Fix APT_CrashOverride.yar pe.exports & pe.characteristics boolean/bitwise expression
                pe_match = PE_EXPORTS_CHAR_RE.search(new_line)
                if pe_match:
                    export_arg = pe_match.group(1)
                    new_line = PE_EXPORTS_CHAR_RE.sub(
                        f'pe.exports("{export_arg}") and (pe.characteristics != 0)',
                        new_line,
                    )
                    changed = True

                # 4. Repair corrupted double-quoted strings OR escape non-quantifier braces in regexes
                repaired_line, str_changed = repair_or_harden_string_line(new_line)
                if str_changed:
                    new_line = repaired_line
                    stats["strings_repaired_or_hardened"] += 1
                    changed = True

                # 5. Surgically strip unsupported external variable conjuncts (`and filename == "..."`)
                #    so valid string conditions on the same line remain active!
                if any(ext in new_line for ext in ("filename", "filepath", "extension")) and not QUOTED_DEF_RE.match(new_line):
                    stripped_ext = EXTERNAL_CLAUSE_AND_PREFIX_RE.sub("", new_line)
                    stripped_ext = EXTERNAL_CLAUSE_AND_SUFFIX_RE.sub("", stripped_ext)
                    if stripped_ext != new_line:
                        new_line = stripped_ext
                        changed = True
                    elif ("filename ==" in new_line or "filename==" in new_line) and not new_line.strip().startswith("$"):
                        new_line = f"// {new_line} (Identifier fixed/disabled by Oshoosi Hardener)"
                        changed = True

                # 6. Comment out `androguard.*` condition lines
                if "androguard." in new_line and not new_line.strip().startswith("$"):
                    new_line = f"// {new_line} (Identifier fixed/disabled by Oshoosi Hardener)"
                    changed = True

                # 7. Fix trailing extra closing brace at EOF
                if trimmed == "}" and i == len(lines) - 1 and content.count("{") < content.count("}"):
                    new_line = f"// {new_line} (Redundant brace removed)"
                    changed = True

                new_lines.append(new_line)

            # 8. Disable any rule whose condition became vacuous (`condition: false` / empty)
            new_lines, vac_count = comment_out_vacuous_rules(new_lines)
            if vac_count > 0:
                stats["vacuous_rules_disabled"] += vac_count
                changed = True

            if changed:
                try:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write("\n".join(new_lines) + "\n")
                    stats["files_fixed"] += 1
                except Exception as e:
                    print(f"Error writing to {file_path}: {e}")

    print(
        f"Sanitization of '{yara_dir}' complete: "
        f"scanned={stats['files_scanned']}, fixed={stats['files_fixed']}, "
        f"strings_repaired={stats['strings_repaired_or_hardened']}, "
        f"duplicates_renamed={stats['duplicates_renamed']}, "
        f"vacuous_disabled={stats['vacuous_rules_disabled']}."
    )
    return stats


def verify_hardened_rules(yara_dir: str) -> Tuple[int, int, int]:
    """
    Audits all `.yar`/`.yara` files in `yara_dir` and returns:
      (active_rules_count, corrupted_quoted_strings_count, vacuous_false_conditions_count)
    """
    active_rules = 0
    corrupted_quoted = 0
    vacuous_conditions = 0

    if not os.path.exists(yara_dir):
        return (0, 0, 0)

    for root, _, files in os.walk(yara_dir):
        for file in files:
            if not file.endswith((".yar", ".yara", ".rule")):
                continue
            if file.endswith("index.yar") or file.endswith("_index.yar"):
                continue
            path = os.path.join(root, file)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except Exception:
                continue

            for line in text.splitlines():
                s = line.strip()
                if s.startswith("//"):
                    continue
                if RULE_DECL_RE.match(line):
                    active_rules += 1
                if QUOTED_DEF_RE.match(line) and ODD_BACKSLASH_BRACE_RE.search(line):
                    corrupted_quoted += 1

            # Check for active `condition: false`
            for m in re.finditer(r"^\s*condition\s*:\s*\n?([^\n}]*)", text, re.MULTILINE):
                body = m.group(1).strip()
                if body == "false" or body.startswith("false ") or body.startswith("false\n"):
                    vacuous_conditions += 1

    print(
        f"[Verify '{yara_dir}'] active_rules={active_rules}, "
        f"corrupted_quoted_braces={corrupted_quoted}, "
        f"vacuous_false_conditions={vacuous_conditions}"
    )
    return active_rules, corrupted_quoted, vacuous_conditions


if __name__ == "__main__":
    targets = sys.argv[1:] if len(sys.argv) > 1 else ["yara", "rules", "deploy/yara", "deploy/rules", "bin/yara"]
    total_corrupted = 0
    total_vacuous = 0
    for target in targets:
        if os.path.exists(target):
            harden_yara(target)
            _, corr, vac = verify_hardened_rules(target)
            total_corrupted += corr
            total_vacuous += vac

    if total_corrupted > 0 or total_vacuous > 0:
        print(f"ERROR: Verification found {total_corrupted} corrupted quoted strings and {total_vacuous} vacuous conditions!")
        sys.exit(1)
    print("All YARA rule directories verified clean and semantically active.")
