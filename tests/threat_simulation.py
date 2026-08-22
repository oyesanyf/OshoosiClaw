import os
import time
import urllib.request
import json
import subprocess

print("=" * 60)
print("       OSHOOSI CLAW LIVE THREAT SIMULATION")
print("=" * 60)

# 1. Trigger Deception / Canary Tampering
print("\n[*] 1. Simulating Deception Canary Trap Access...")
trap_file = os.path.join("traps", "Production_DB_Keys.env")
if os.path.exists(trap_file):
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
temp_dir = os.environ.get("TEMP", ".")
eicar_path = os.path.join(temp_dir, "test_eicar_threat.com")
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
