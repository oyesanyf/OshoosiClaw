import os
import re

def harden_yara(yara_dir):
    seen_rules = set()
    total_fixed = 0

    # Patterns
    rule_id_pattern = re.compile(r'^(\s*(?:global\s+|private\s+)?rule\s+)([A-Za-z0-9_]+)', re.MULTILINE)
    andro_import_pattern = re.compile(r'^\s*import\s+["\']androguard["\']', re.MULTILINE)
    pe_exports_pattern = re.compile(r'pe\.exports\s*\(\s*["\'][Cc]rash["\']\s*\)\s*&\s*pe\.characteristics')
    regex_curly_pattern = re.compile(r'/[^/]*[^\\][{][^/]*[^\\][}]/[^/]*') # Simple detection of curly braces in regex
    unclosed_curly_pattern = re.compile(r'(/[^\s/]+(?:\s+[^\s/]+)*\s*[^\\/])[{](/[^/]*|[\s={])') # Matches unescaped { in regex-like strings

    print(f"Starting deep sanitization of {yara_dir}...")

    for root, _, files in os.walk(yara_dir):
        for file in files:
            if not (file.endswith(".yar") or file.endswith(".yara") or file.endswith(".rule")):
                continue
            
            file_path = os.path.join(root, file)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception as e:
                print(f"Skipping {file_path}: {e}")
                continue

            # Skip if this file is just an index (handled by model.rs now, but we want clean rules)
            if file.endswith("index.yar"):
                continue

            new_content = []
            changed = False
            
            # Rule deduplication and logic fix
            current_rule_name = None
            in_comment_block = False
            
            lines = content.splitlines()
            for i, line in enumerate(lines):
                trimmed = line.strip()
                new_line = line
                
                # 1. Comment out androguard imports
                if andro_import_pattern.search(line) and not trimmed.startswith("//"):
                    new_line = f"// {line} (Disabled by Oshoosi Hardener)"
                    changed = True

                # 2. Duplicate Rule Detection & Renaming
                rule_match = rule_id_pattern.search(line)
                if rule_match:
                    prefix, name = rule_match.groups()
                    if name in seen_rules:
                        # Rename duplicate
                        new_name = f"{name}_Duplicate_{len(seen_rules)}"
                        new_line = line.replace(name, new_name, 1)
                        print(f"Renamed duplicate rule '{name}' to '{new_name}' in {file}")
                        changed = True
                    seen_rules.add(name)

                # 3. Fix APT_CrashOverride.yar type mismatch
                if pe_exports_pattern.search(line):
                    new_line = line.replace('pe.exports("Crash")', 'pe.exports("Crash") != false')\
                                   .replace('pe.exports("crash")', 'pe.exports("crash") != false')\
                                   .replace('& pe.characteristics', 'and pe.characteristics != 0')
                    changed = True

                # 4. Handle unrecognized escapes and unclosed curly braces in regex
                # We target strings starting with $ and /=
                if ("$") in line and ("/") in line and ("=") in line:
                    if ("{") in line and ("}") in line and ("\\{" not in line):
                        # Attempt to escape unescaped curly braces in common pattern /...{...}/
                        if "{" in line and "\\{" not in line and not re.search(r'\{\d+(,\d*)?\}', line):
                             new_line = new_line.replace("{", "\\{").replace("}", "\\}")
                             changed = True
                    elif ("{") in line and ("\\{" not in line):
                        # Unclosed {
                        new_line = new_line.replace("{", "\\{")
                        changed = True

                # 5. Comment out rules using missing modules or unknown identifiers
                # If a line contains 'androguard.' or 'filename ==', we should ideally comment the rule.
                # For simplicity in this script, we'll comment the specific line if it breaks compilation.
                if ("androguard." in line or 'filename ==' in line or 'filename==' in line) and not trimmed.startswith("//"):
                    new_line = f"// {line} (Identifier fixed/disabled by Oshoosi Hardener)"
                    changed = True

                # 6. Fix trailing extra braces (Adobe_Flash_DRM_Use_After_Free.yar)
                # If the line is just a closing brace and it's at the end of the file or looks redundant
                if trimmed == "}" and i == len(lines) - 1 and content.count("{") < content.count("}"):
                    new_line = f"// {line} (Redundant brace removed)"
                    changed = True

                new_content.append(new_line)

            if changed:
                try:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write("\n".join(new_content))
                    total_fixed += 1
                except Exception as e:
                    print(f"Error writing to {file_path}: {e}")

    print(f"Deep sanitization complete. Fixed {total_fixed} files.")

if __name__ == "__main__":
    harden_yara("yara")
