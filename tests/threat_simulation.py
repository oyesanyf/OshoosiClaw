import os
import time
import urllib.request
import json
import subprocess
from pathlib import Path

print("=" * 60)
print("       OSHOOSI CLAW LIVE THREAT SIMULATION")
print("=" * 60)

# 1. Trigger Deception / Canary Tampering
print("\n[*] 1. Simulating Deception Canary Trap Access...")
base_traps = Path("traps").resolve()
trap_target = (base_traps / "Production_DB_Keys.env").resolve()
if not trap_target.is_relative_to(base_traps):
    raise ValueError(f"Path traversal detected for trap: {trap_target}")
trap_file = str(trap_target)
if trap_target.exists():
    try:
        with open(trap_file, "a") as f:
            f.write("\n# ADVERSARY_PROBE=EXFILTRATION_TEST\n")
        print(f" [+] Tampered with honeypot decoy: {trap_file}")
    except Exception as e:
        print(f" [-] Could not touch trap: {e}")
else:
    print(" [!] Traps folder not found in current directory.")

# 2. Trigger YARA / Malware Scanner with EICAR test string
print("\n[*] 2. Simulating EICAR Anti-Malware Detection Drop...")
base_temp = Path(os.environ.get("TEMP", ".")).resolve()
eicar_target = (base_temp / "test_eicar_threat.com").resolve()
if not eicar_target.is_relative_to(base_temp):
    raise ValueError(f"Path traversal detected for EICAR artifact: {eicar_target}")
eicar_path = str(eicar_target)
eicar_string = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
try:
    with open(eicar_path, "w") as f:
        f.write(eicar_string)
    print(f" [+] Dropped EICAR test artifact at: {eicar_path}")
    
    # Run standalone scanner
    scan_res = subprocess.run(["target\\release\\osoosi.exe", "scan", eicar_path], capture_output=True, text=True)
    print(" [>] Scanner output snippet:")
    for line in scan_res.stdout.splitlines()[:10]:
        print(f"     {line}")
except Exception as e:
    print(f" [-] Error in EICAR drop: {e}")

# 3. Simulate Path Poisoning Binary Scan
print("\n[*] 3. Simulating Poison-Path Binary Scan...")
sample_bin = "tests/poison_tests/Nested/Path/With (x86)/And & Chars/test_binary.exe"
if os.path.exists(sample_bin):
    scan_res = subprocess.run(["target\\release\\osoosi.exe", "scan", sample_bin], capture_output=True, text=True)
    print(f" [+] Scanned: {sample_bin}")
    for line in scan_res.stdout.splitlines()[:8]:
        print(f"     {line}")

# 4. Give background telemetry 3 seconds to process
print("\n[*] 4. Waiting for real-time telemetry consensus...")
time.sleep(3)

# 5. Fetch Dashboard Threat Feed
print("\n[*] 5. Querying Live Dashboard API (http://127.0.0.1:3030/api/threats)...")
try:
    req = urllib.request.Request("http://127.0.0.1:3030/api/threats")
    with urllib.request.urlopen(req, timeout=5) as response:
        threats = json.loads(response.read().decode())
        print(f" [+] Total Active Threats in Dashboard: {len(threats)}")
        for i, t in enumerate(threats[:5], 1):
            name = t.get("name") or t.get("description") or "Unknown Threat"
            severity = t.get("severity") or t.get("confidence") or "N/A"
            action = t.get("action") or t.get("status") or "Detected"
            print(f"     {i}. [{severity}] {name} -> Action: {action}")
except Exception as e:
    print(f" [-] Could not query dashboard API: {e}")

print("\n" + "=" * 60)
print(" [+] Simulation Complete! Check your Dashboard UI at http://127.0.0.1:3030")
print("=" * 60)
