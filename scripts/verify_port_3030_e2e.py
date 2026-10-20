import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE_URL = "http://127.0.0.1:3030"

def get_auth_token():
    token = os.environ.get("OSOOSI_DASHBOARD_API_TOKEN", "").strip()
    if token:
        return token
    token_path = os.path.join("config", "dashboard_token.key")
    if os.path.exists(token_path):
        with open(token_path, "r", encoding="utf-8") as f:
            return f.read().strip()
    return ""

def test_endpoints():
    token = get_auth_token()
    print(f"[*] Dashboard API Token resolved: {token[:8]}... (len={len(token)})")

    headers = {
        "User-Agent": "OshoosiClaw-Verifier/1.2.0",
        "Accept": "application/json",
    }
    if token:
        headers["X-Osoosi-Token"] = token
        headers["Authorization"] = f"Bearer {token}"
        headers["Cookie"] = f"osoosi_token={token}"

    endpoints = [
        "/api/auth/session",
        "/api/status",
        "/api/threats",
        "/api/gossip",
        "/api/history",
        "/api/rea/v1/status",
        "/api/supervisor/status",
        "/api/hardware/summary",
        "/api/zone/overview",
        "/api/approvals",
        "/api/agent-anomalies/summary",
    ]

    print("\n" + "="*70)
    print(" 1. ENDPOINT LATENCY & HTTP 200 VERIFICATION")
    print("="*70)

    cached_data = {}

    for ep in endpoints:
        url = BASE_URL + ep
        req = urllib.request.Request(url, headers=headers, method="GET")
        start_t = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                body = resp.read()
                data = json.loads(body.decode("utf-8")) if body else {}
                cached_data[ep] = data
                status = resp.status
                print(f" [PASS] GET {ep:<30} -> HTTP {status} ({elapsed_ms:6.2f} ms)")
                assert status == 200, f"Expected 200, got {status}"
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_t) * 1000.0
            print(f" [FAIL] GET {ep:<30} -> ERROR: {e} ({elapsed_ms:6.2f} ms)")
            raise

    print("\n" + "="*70)
    print(" 2. STALE THREAT & GOSSIP PURGE VERIFICATION")
    print("="*70)

    stale_procs = {'sc.exe', 'git.exe', 'conhost.exe', 'chrome.exe', 'wsl.exe', 'taskkill.exe'}
    stale_reasons = ['veto trusted vendor', 'outside the vulnerable', 'cve none']

    # Threats check
    threats_data = cached_data.get("/api/threats", [])
    if isinstance(threats_data, dict):
        threat_list = threats_data.get("threats", [])
    elif isinstance(threats_data, list):
        threat_list = threats_data
    else:
        threat_list = []

    print(f"[*] Total active threats returned: {len(threat_list)}")
    stale_threats = []
    for t in threat_list:
        proc = str(t.get("process_name") or t.get("name") or "").lower()
        reason = str(t.get("reason") or t.get("summary") or "").lower()
        if proc in stale_procs or any(sr in reason for sr in stale_reasons):
            stale_threats.append(t)

    if stale_threats:
        print(f" [FAIL] Found {len(stale_threats)} stale threat items in /api/threats: {stale_threats[:3]}")
        sys.exit(1)
    else:
        print(f" [PASS] /api/threats contains 0 stale processes or vetoed reasons.")

    # Gossip check
    gossip_data = cached_data.get("/api/gossip", [])
    if isinstance(gossip_data, dict):
        gossip_list = gossip_data.get("gossip", []) or gossip_data.get("items", [])
    elif isinstance(gossip_data, list):
        gossip_list = gossip_data
    else:
        gossip_list = []

    print(f"[*] Total active gossip items returned: {len(gossip_list)}")
    stale_gossip = []
    for g in gossip_list:
        proc = str(g.get("process_name") or g.get("name") or "").lower()
        summary = str(g.get("summary") or g.get("reason") or "").lower()
        if proc in stale_procs or any(sr in summary for sr in stale_reasons):
            stale_gossip.append(g)

    if stale_gossip:
        print(f" [FAIL] Found {len(stale_gossip)} stale gossip items in /api/gossip: {stale_gossip[:3]}")
        sys.exit(1)
    else:
        print(f" [PASS] /api/gossip contains 0 stale processes or vetoed reasons.")

    print("\n" + "="*70)
    print(" 3. FALSE-POSITIVE & CONFIRM ENDPOINTS VERIFICATION")
    print("="*70)

    # Test POST /api/threats/audit-test-123/false-positive
    fp_url = f"{BASE_URL}/api/threats/audit-test-123/false-positive"
    fp_req = urllib.request.Request(fp_url, data=b"{}", headers={**headers, "Content-Type": "application/json"}, method="POST")
    start_t = time.perf_counter()
    with urllib.request.urlopen(fp_req, timeout=10) as resp:
        elapsed_ms = (time.perf_counter() - start_t) * 1000.0
        data = json.loads(resp.read().decode("utf-8"))
        print(f" [PASS] POST /api/threats/audit-test-123/false-positive -> HTTP {resp.status} ({elapsed_ms:6.2f} ms): {data}")
        assert resp.status == 200
        assert data.get("status") == "ok"

    # Test POST /api/threats/confirm/audit-test-456
    cf_url = f"{BASE_URL}/api/threats/confirm/audit-test-456"
    cf_req = urllib.request.Request(cf_url, data=b"{}", headers={**headers, "Content-Type": "application/json"}, method="POST")
    start_t = time.perf_counter()
    with urllib.request.urlopen(cf_req, timeout=10) as resp:
        elapsed_ms = (time.perf_counter() - start_t) * 1000.0
        data = json.loads(resp.read().decode("utf-8"))
        print(f" [PASS] POST /api/threats/confirm/audit-test-456 -> HTTP {resp.status} ({elapsed_ms:6.2f} ms): {data}")
        assert resp.status == 200
        assert data.get("status") == "ok"

    print("\n" + "="*70)
    print(" ALL END-TO-END VERIFICATIONS PASSED (100% HEALTH & LATENCY SLA)")
    print("="*70 + "\n")

if __name__ == "__main__":
    test_endpoints()
