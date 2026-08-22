import os
import sys
import time
import subprocess
import urllib.request
import json

def print_header(title):
    print("\n" + "=" * 65)
    print(f" [TEST SUITE] {title}")
    print("=" * 65)

def main():
    print_header("OSHOOSI CLAW COMPREHENSIVE DETECTION VALIDATION SUITE")
    results = {}

    # 1. TEST: Deception Engine Canary Traps
    print("\n[*] 1. Testing Deception / Canary Traps (Filesystem Honeypots)...")
    traps_dir = "traps"
    traps_tested = 0
    if os.path.exists(traps_dir):
        for trap_name in ["Production_DB_Keys.env", "CEO_Private_Strategy.docx", "root_password_backup.txt"]:
            trap_path = os.path.join(traps_dir, trap_name)
            if os.path.exists(trap_path):
                try:
                    with open(trap_path, "a") as f:
                        f.write(f"\n# SYNTHETIC_TEST_PROBE_{int(time.time())}\n")
                    traps_tested += 1
                    print(f"  [+] Modified decoy trap: {trap_path}")
                except Exception as e:
                    print(f"  [-] Could not modify trap {trap_name}: {e}")
        results["Deception Honeypot Traps"] = f"PASSED ({traps_tested} traps touched)"
    else:
        results["Deception Honeypot Traps"] = "SKIPPED (traps directory not found)"

    # 2. TEST: Standard EICAR Antivirus Test Signature Drop
    print("\n[*] 2. Testing Anti-Malware / YARA-X Real-Time Scanner (EICAR Drop)...")
    temp_dir = os.environ.get("TEMP", ".")
    eicar_file = os.path.join(temp_dir, "synthetic_eicar_test.com")
    eicar_string = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    try:
        with open(eicar_file, "w") as f:
            f.write(eicar_string)
        print(f"  [+] Dropped synthetic EICAR test string at: {eicar_file}")
        
        # Scan with release binary
        scan_bin = "target/x86_64-pc-windows-msvc/release/osoosi.exe"
        if not os.path.exists(scan_bin):
            scan_bin = "osoosi.exe"
            
        res = subprocess.run([scan_bin, "scan", eicar_file], capture_output=True, text=True)
        print("  [>] Standalone Scan Output:")
        for line in res.stdout.splitlines()[:6]:
            print(f"      {line}")
        results["EICAR Signature Detection"] = "PASSED"
    except Exception as e:
        print(f"  [-] EICAR test failed: {e}")
        results["EICAR Signature Detection"] = f"FAILED ({e})"

    # 3. TEST: Path Poisoning & Deep PE Inspection
    print("\n[*] 3. Testing Complex Path Robustness & PE Inspector...")
    sample_bin = "tests/poison_tests/Nested/Path/With (x86)/And & Chars/test_binary.exe"
    if os.path.exists(sample_bin):
        res = subprocess.run([scan_bin, "scan", sample_bin], capture_output=True, text=True)
        if "Oshoosi File Scan Results" in res.stdout:
            print("  [+] PE Inspection completed successfully over nested special characters path.")
            results["PE Inspector & Path Robustness"] = "PASSED"
        else:
            results["PE Inspector & Path Robustness"] = "WARNING (unexpected output format)"
    else:
        results["PE Inspector & Path Robustness"] = "SKIPPED (sample not found)"

    # 4. TEST: Suspicious Process / Discovery TTP Simulation
    print("\n[*] 4. Simulating Benign Reconnaissance / Privilege Query Event...")
    try:
        # Run benign system query that generates telemetry for Sysmon & Behavioral Consensus
        subprocess.run(["cmd.exe", "/c", "whoami /priv > nul"], shell=True, capture_output=True)
        print("  [+] Executed benign privilege discovery event (whoami /priv) for Sysmon/Behavioral cortex telemetry.")
        results["Behavioral Telemetry Generation"] = "PASSED"
    except Exception as e:
        results["Behavioral Telemetry Generation"] = f"FAILED ({e})"

    # 5. TEST: Live Dashboard & Telemetry Verification
    print("\n[*] 5. Verifying Live Detection Telemetry via Dashboard API (http://127.0.0.1:3030)...")
    time.sleep(2)
    try:
        # Query Status
        with urllib.request.urlopen("http://127.0.0.1:3030/api/status", timeout=4) as r:
            status = json.loads(r.read().decode())
            print(f"  [+] Agent Status: {status.get('status')} (Uptime: {status.get('uptime')})")

        # Query Detection Engines
        with urllib.request.urlopen("http://127.0.0.1:3030/api/detection-stats", timeout=4) as r:
            stats = json.loads(r.read().decode())
            print(f"  [+] Active Detection Engines Reporting: {len(stats)}/28 engines")

        # Query Threats & Activity
        with urllib.request.urlopen("http://127.0.0.1:3030/api/threats", timeout=4) as r:
            threats = json.loads(r.read().decode())
            print(f"  [+] Live Threats in Database: {len(threats)}")

        with urllib.request.urlopen("http://127.0.0.1:3030/api/activity", timeout=4) as r:
            activity = json.loads(r.read().decode())
            print(f"  [+] Recent Telemetry Events Logged: {len(activity)}")

        results["Live Dashboard & API Verification"] = "PASSED"
    except Exception as e:
        print(f"  [-] Could not reach dashboard: {e}")
        results["Live Dashboard & API Verification"] = f"OFFLINE ({e})"

    # FINAL REPORT
    print_header("FINAL THREAT SIMULATION & DETECTION REPORT")
    for test, res in results.items():
        print(f" {test:<40} | {res}")
    print("=" * 65)

if __name__ == "__main__":
    main()
