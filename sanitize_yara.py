import os
import re

def sanitize_content(content):
    # 1. Fix invalid escapes in strings: \% -> \\%, \m -> \\m, etc.
    # We look for a backslash that is NOT followed by a valid escape char.
    # Standard YARA escapes: n, r, t, \, ", x, u, U
    # Regex additional: d, w, s, D, W, S, b, B
    
    # Heuristic for string declarations: $name = "..."
    # This regex attempts to find content inside quotes
    def fix_escapes(match):
        s = match.group(0)
        # Standard valid escapes
        valid = r'nrt\\"\'xuUdwsDWSbB0123456789$^*+?()[]{}|.^/ '
        result = []
        i = 0
        while i < len(s):
            if s[i] == '\\' and i + 1 < len(s):
                if s[i+1] not in valid:
                    result.append('\\\\')
                    result.append(s[i+1])
                    i += 2
                    continue
            result.append(s[i])
            i += 1
        return "".join(result)

    # Apply fix_escapes to the whole content but specifically target possible string/regex values
    # Regex to find string values: $... = "... " or /.../
    content = re.sub(r'".*?"', fix_escapes, content)
    content = re.sub(r'/.*?/', fix_escapes, content)

    # 2. Fix unescaped forward slashes in regex: /.../.../ -> /...\/.../
    # This specifically looks for /.../.../ where the middle / is not escaped
    def fix_regex_slashes(match):
        r = match.group(0)
        if len(r) < 3: return r
        internal = r[1:-1]
        # Escape any unescaped / in the internal part
        fixed_internal = ""
        j = 0
        while j < len(internal):
            if internal[j] == '/' and (j == 0 or internal[j-1] != '\\'):
                fixed_internal += '\\/'
            else:
                fixed_internal += internal[j]
            j += 1
        return f"/{fixed_internal}/"

    content = re.sub(r'/[^ \n].*?/[ ]*(wide|ascii|nocase|fullword|\n|;)', fix_regex_slashes, content)

    # 3. Fix empty alternatives: |/ -> / and /| -> / and || -> |
    content = content.replace('|/', '/')
    content = content.replace('/|', '/')
    content = content.replace('||', '|')
    
    return content

def main():
    search_paths = [
        os.path.join("target", "debug", "yara"),
        "yara"
    ]
    
    count = 0
    for base_path in search_paths:
        if not os.path.exists(base_path):
            continue
            
        for root, dirs, files in os.walk(base_path):
            for file in files:
                if file.endswith(".yar"):
                    path = os.path.join(root, file)
                    try:
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        sanitized = sanitize_content(content)
                        
                        if sanitized != content:
                            with open(path, 'w', encoding='utf-8') as f:
                                f.write(sanitized)
                            count += 1
                            print(f"Sanitized: {path}")
                    except Exception as e:
                        print(f"Error processing {path}: {e}")
    
    print(f"Total files sanitized: {count}")

if __name__ == "__main__":
    main()
