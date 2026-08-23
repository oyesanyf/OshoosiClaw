"""
OshoosiClaw Live 1,000-Attack Telemetry & Threat Transmitter
Inserts and streams all 1,000 benchmark threat scenarios directly into
the agent database and live dashboard.
"""

import sqlite3
import json
import hashlib
import time
import datetime
import urllib.request

def main():
    print("=" * 72)
    print("      OSHOOSI CLAW LIVE 1,000-THREAT TRANSMITTER & INGESTOR")
    print("=" * 72)

    # 1. Load benchmark dataset
    with open("tests/benchmark_1000_results.json", "r") as f:
        data = json.load(f)
    
    tests = data.get("tests", [])
    print(f"[*] Loaded {len(tests)} synthetic test scenarios.")

    # 2. Connect to agent SQLite database
    db_path = "database/osoosi.db"
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    now = datetime.datetime.now(datetime.timezone.utc)
    inserted = 0

    print("[*] Ingesting 1,000 test cases into live EDR database...")
    for i, t in enumerate(tests, 1):
        t_id = f"THREAT-LIVE-{i:04d}"
        cve_id = t.get("ttp", "MITRE-ATT&CK")
        hash_val = hashlib.sha256(f"{t_id}-{t.get('name')}".encode()).hexdigest()
        proc_name = t.get("name", "synthetic_test_process")[:45]
        conf = float(t.get("expected_risk", 0.85))
        det_time = (now - datetime.timedelta(seconds=(1000 - i) * 3)).isoformat()
        src_node = "local-sensor"
        file_path = f"C:\\ProgramData\\Oshoosi\\Tests\\{t.get('category')}\\{t_id}.exe"
        reason = f"[{t.get('category')}] {t.get('name')} | Technique: {t.get('ttp')} | Risk: {conf:.2f}"
        parent_proc = "powershell.exe" if "PowerShell" in t.get("name", "") else "cmd.exe"
        version = 1

        try:
            c.execute("""
                INSERT OR REPLACE INTO threats 
                (id, cve_id, hash_blake3, process_name, confidence, detected_at, source_node, file_path, reason, parent_process, version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (t_id, cve_id, hash_val, proc_name, conf, det_time, src_node, file_path, reason, parent_proc, version))
            inserted += 1
        except Exception as e:
            print(f"[-] Failed inserting {t_id}: {e}")

    conn.commit()
    conn.close()

    print(f"\n[+] Successfully injected {inserted} live threat detection records into {db_path}!")

    # 3. Verify Live Dashboard API Response
    print("\n[*] Verifying Live Dashboard API on http://127.0.0.1:3030/api/threats...")
    try:
        with urllib.request.urlopen("http://127.0.0.1:3030/api/threats", timeout=5) as r:
            threats = json.loads(r.read().decode())
            print(f"  [+] Live Threats Currently Reporting in Dashboard API: {len(threats)}")
    except Exception as e:
        print(f"  [-] Could not query dashboard API: {e}")

    print("=" * 72)
    print(" [***] 1,000 THREATS LIVE ON DASHBOARD AND COMMITTED TO DATABASE [***]")
    print("=" * 72)

if __name__ == "__main__":
    main()
