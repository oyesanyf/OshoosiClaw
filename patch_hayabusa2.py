#!/usr/bin/env python3
"""Fix the duplicate dummy() and AhoCorasick API issues"""
import sys

path = r"d:\harfile\OshoosiClaw\vendor\hayabusa\src\detections\configs.rs"

with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# 1. Remove the old duplicate dummy() at the end of the file
old_dummy = """
impl StoredStatic {
    pub fn dummy() -> Self {
        Self::create_static_data(None)
    }
}
"""
# Try with CRLF
old_dummy_crlf = old_dummy.replace('\n', '\r\n')
if old_dummy_crlf in content:
    content = content.replace(old_dummy_crlf, '\r\n')
    print("Removed old CRLF dummy()")
elif old_dummy in content:
    content = content.replace(old_dummy, '\n')
    print("Removed old LF dummy()")
else:
    print("WARNING: Could not find old dummy() to remove")
    # Try partial match
    for variant in [
        'impl StoredStatic {\r\n    pub fn dummy() -> Self {\r\n        Self::create_static_data(None)\r\n    }\r\n}\r\n',
        'impl StoredStatic {\n    pub fn dummy() -> Self {\n        Self::create_static_data(None)\n    }\n}\n',
    ]:
        if variant in content:
            content = content.replace(variant, '')
            print("Removed old dummy() (variant match)")
            break

# 2. Fix the AhoCorasick API: .build::<&str>(&[]) -> .build(&[""; 0])  
# The correct API for aho-corasick 1.x is .build([""].iter().take(0))
# or just .build::<_,_>(std::iter::empty::<&str>())
content = content.replace(
    '.build::<&str>(&[])',
    '.build([""].iter().copied().take(0))'
)
print("Fixed AhoCorasick API")

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("SUCCESS")
