with open("crates/osoosi-core/src/agentmesh/mod.rs", "rb") as f:
    data = f.read()

lines = data.splitlines(keepends=True)
# Inspect lines 48-62
for i, line in enumerate(lines[48:62], 49):
    print(f"{i}: {line}")

# Keep up to line 50 (index 50) and skip lines 51 to 60 (indices 50..60)
new_lines = lines[:50] + lines[60:]
with open("crates/osoosi-core/src/agentmesh/mod.rs", "wb") as f:
    f.writelines(new_lines)
print("Removed lines 51-60 successfully")
