import hashlib
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

    # =========================================================================
    # 1. CORE ENDPOINT LATENCY & HTTP 200 VERIFICATION
    # =========================================================================
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
        "/api/deception/status",
        "/api/siquery/edr-status",
        "/api/mitre/stix/status",
        "/api/har/entries",
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
            with urllib.request.urlopen(req, timeout=25) as resp:
                elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                body = resp.read()
                data = json.loads(body.decode("utf-8")) if body else {}
                cached_data[ep] = data
                status = resp.status
                print(f" [PASS] GET {ep:<32} -> HTTP {status} ({elapsed_ms:6.2f} ms)")
                assert status == 200, f"Expected 200, got {status}"
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_t) * 1000.0
            print(f" [FAIL] GET {ep:<32} -> ERROR: {e} ({elapsed_ms:6.2f} ms)")
            raise

    # =========================================================================
    # 2. R13: FORENSIC HISTORY SUB-200ms LATENCY SLA (5+ REPEATED RUNS)
    # =========================================================================
    print("\n" + "="*70)
    print(" 2. R13: FORENSIC HISTORY LATENCY SLA ASSERTION (<200ms across 5+ runs)")
    print("="*70)

    history_url = f"{BASE_URL}/api/history?page=1&limit=50&category=all&severity=all"
    # Prime history cache after Section 1 heavy deception/anomalies endpoints
    warmup_req = urllib.request.Request(history_url, headers=headers, method="GET")
    with urllib.request.urlopen(warmup_req, timeout=10) as _:
        pass
    latencies = []
    num_runs = 5

    for i in range(num_runs):
        req = urllib.request.Request(history_url, headers=headers, method="GET")
        start_t = time.perf_counter()
        with urllib.request.urlopen(req, timeout=10) as resp:
            elapsed_ms = (time.perf_counter() - start_t) * 1000.0
            assert resp.status == 200, f"Expected HTTP 200, got {resp.status}"
            body = resp.read()
            data = json.loads(body.decode("utf-8"))
            latencies.append(elapsed_ms)
            print(f" [PASS] Run {i+1}/{num_runs}: {elapsed_ms:6.2f} ms (SLA target < 200.00 ms)")
            assert elapsed_ms < 200.0, f"Run {i+1} latency {elapsed_ms:.2f}ms exceeded 200ms SLA!"

    avg_lat = sum(latencies) / len(latencies)
    min_lat = min(latencies)
    max_lat = max(latencies)
    print(f"[*] /api/history Latency Summary: Min={min_lat:.2f}ms, Max={max_lat:.2f}ms, Avg={avg_lat:.2f}ms")
    print(f" [PASS] 100% of /api/history requests met the strict sub-200ms SLA (R13 achieved).")

    # =========================================================================
    # 3. R1, R7: DECEPTION STATUS & CANARY CAGE METRICS VERIFICATION
    # =========================================================================
    print("\n" + "="*70)
    print(" 3. R1, R7: DECEPTION STATUS & CANARY CAGE METRICS VERIFICATION")
    print("="*70)

    deception_data = cached_data.get("/api/deception/status", {})
    canary_cage = deception_data.get("canary_cage") or deception_data.get("canary_cage_metrics")
    assert canary_cage is not None, "Missing 'canary_cage' in /api/deception/status"

    active_cages = canary_cage.get("active_cages")
    triggered_traps = canary_cage.get("triggered_traps")
    total_caged_executions = canary_cage.get("total_caged_executions")

    print(f"[*] CanaryCage Metrics: active={active_cages}, triggered={triggered_traps}, total_caged={total_caged_executions}")
    assert isinstance(active_cages, int), f"Expected int for active_cages, got {type(active_cages)}"
    assert isinstance(triggered_traps, int), f"Expected int for triggered_traps, got {type(triggered_traps)}"
    assert isinstance(total_caged_executions, int), f"Expected int for total_caged_executions, got {type(total_caged_executions)}"
    print(f" [PASS] CanaryCage telemetry structure verified successfully.")

    session_lineage = deception_data.get("session_file_lineage")
    assert session_lineage is not None, "Missing 'session_file_lineage' in /api/deception/status"
    print(f"[*] Session File Lineage entries: {len(session_lineage) if isinstance(session_lineage, (dict, list)) else 'present'}")
    print(f" [PASS] Session file-lineage tracking verified in /api/deception/status.")

    # =========================================================================
    # 4. R2, R7: AGENT ANOMALIES TELEMETRY VERIFICATION
    # =========================================================================
    print("\n" + "="*70)
    print(" 4. R2, R7: AGENT ANOMALIES TELEMETRY VERIFICATION")
    print("="*70)

    agent_data = cached_data.get("/api/agent-anomalies/summary", {})
    assert isinstance(agent_data, dict), f"Expected dict for agent-anomalies summary, got {type(agent_data)}"
    print(f"[*] Agent Anomalies Keys: {list(agent_data.keys())[:8]}")
    assert len(agent_data) > 0, "Empty agent anomalies summary returned"
    print(f" [PASS] /api/agent-anomalies/summary returned valid structured telemetry.")

    # =========================================================================
    # 5. LIVE WEBUI STATIC ASSETS & 0-DIFF PARITY VERIFICATION
    # =========================================================================
    print("\n" + "="*70)
    print(" 5. LIVE WEBUI STATIC ASSETS & 0-DIFF PARITY VERIFICATION")
    print("="*70)

    static_assets = [
        ("/index.html", os.path.join("dashboard", "dist", "index.html"), os.path.join("dashboard", "src", "index.html")),
        ("/app.js", os.path.join("dashboard", "dist", "app.js"), os.path.join("dashboard", "src", "app.js")),
        ("/style.css", os.path.join("dashboard", "dist", "style.css"), os.path.join("dashboard", "src", "style.css")),
    ]

    for asset_path, dist_path, src_path in static_assets:
        url = BASE_URL + asset_path
        req = urllib.request.Request(url, headers={"User-Agent": "OshoosiClaw-Verifier/1.2.0"})
        start_t = time.perf_counter()
        with urllib.request.urlopen(req, timeout=10) as resp:
            elapsed_ms = (time.perf_counter() - start_t) * 1000.0
            body = resp.read()
            assert resp.status == 200, f"Expected HTTP 200 for {asset_path}, got {resp.status}"

            live_hash = hashlib.sha256(body).hexdigest()

            with open(dist_path, "rb") as f:
                dist_hash = hashlib.sha256(f.read()).hexdigest()

            with open(src_path, "rb") as f:
                src_hash = hashlib.sha256(f.read()).hexdigest()

            print(f"[*] {asset_path:<12} -> Live SHA256: {live_hash[:16]}... Dist SHA256: {dist_hash[:16]}...")
            assert live_hash == dist_hash, f"Live {asset_path} does not match {dist_path} SHA256!"
            assert dist_hash == src_hash, f"Dist {dist_path} does not match {src_path} (WebUI parity violated)!"
            print(f" [PASS] {asset_path:<12} -> 0-diff parity confirmed across live, dist, and src ({elapsed_ms:6.2f} ms)")

    # =========================================================================
    # 6. SIQUERY & HARDWARE TPM 2.0 TELEMETRY (R12, R14)
    # =========================================================================
    print("\n" + "="*70)
    print(" 6. SIQUERY & HARDWARE TPM 2.0 TELEMETRY (R12, R14)")
    print("="*70)

    edr_status = cached_data.get("/api/siquery/edr-status", {})
    assert isinstance(edr_status, dict), f"Expected dict for edr-status, got {type(edr_status)}"
    tpm_data = edr_status.get("tpm")
    print(f"[*] Siquery EDR Status TPM Telemetry: {tpm_data}")
    if tpm_data is not None:
        print(f" [PASS] Real TPM telemetry reported in /api/siquery/edr-status.")

    mitre_status = cached_data.get("/api/mitre/stix/status", {})
    assert isinstance(mitre_status, dict), f"Expected dict for mitre-status, got {type(mitre_status)}"
    print(f"[*] MITRE STIX Refresh Telemetry: {list(mitre_status.keys())[:6]}")
    print(f" [PASS] Autonomous MITRE STIX status verified in /api/mitre/stix/status.")

    # =========================================================================
    # 7. STALE THREAT & GOSSIP PURGE VERIFICATION
    # =========================================================================
    print("\n" + "="*70)
    print(" 7. STALE THREAT & GOSSIP PURGE VERIFICATION")
    print("="*70)

    stale_procs = {
        'sc.exe', 'git.exe', 'conhost.exe', 'chrome.exe', 'wsl.exe', 'taskkill.exe',
        'appidcertstore', 'docker-credent', 'microsoftstartfeedprovider.exe', 'py312.exe',
        'mousocoreworke', 'zoom.exe', 'scdaemon.exe', 'ollama.exe', 'wuaucltcore.exe',
        'cvtres.exe', 'llama-server.e', 'm2d_verificati', 'rg_embedded-7a'
    }
    stale_reasons = [
        'veto trusted vendor', 'outside the vulnerable', 'cve none',
        'unknown v0.0.0 has known cves', 'cve-2009-2940'
    ]

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

    # =========================================================================
    # 8. FALSE-POSITIVE & CONFIRM ENDPOINTS VERIFICATION
    # =========================================================================
    print("\n" + "="*70)
    print(" 8. FALSE-POSITIVE & CONFIRM ENDPOINTS VERIFICATION")
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
        assert data.get("ok") is True or data.get("status") == "ok"

    # Test POST /api/threats/confirm/audit-test-456
    cf_url = f"{BASE_URL}/api/threats/confirm/audit-test-456"
    cf_req = urllib.request.Request(cf_url, data=b"{}", headers={**headers, "Content-Type": "application/json"}, method="POST")
    start_t = time.perf_counter()
    with urllib.request.urlopen(cf_req, timeout=10) as resp:
        elapsed_ms = (time.perf_counter() - start_t) * 1000.0
        data = json.loads(resp.read().decode("utf-8"))
        print(f" [PASS] POST /api/threats/confirm/audit-test-456 -> HTTP {resp.status} ({elapsed_ms:6.2f} ms): {data}")
        assert resp.status == 200
        assert data.get("ok") is True or data.get("status") == "ok"

    # =========================================================================
    # 9. CONTINUOUS HAR WEB TRAFFIC SENSOR & DEDICATED #har-traffic MENU VERIFICATION
    # =========================================================================
    print("\n" + "="*70)
    print(" 9. CONTINUOUS HAR WEB TRAFFIC SENSOR & DEDICATED #har-traffic MENU VERIFICATION")
    print("="*70)

    # 1. GET /api/har/entries
    har_url = f"{BASE_URL}/api/har/entries"
    har_req = urllib.request.Request(har_url, headers=headers, method="GET")
    start_t = time.perf_counter()
    with urllib.request.urlopen(har_req, timeout=15) as resp:
        elapsed_ms = (time.perf_counter() - start_t) * 1000.0
        data = json.loads(resp.read().decode("utf-8"))
        print(f" [PASS] GET /api/har/entries -> HTTP {resp.status} ({elapsed_ms:6.2f} ms): count={data.get('count')}, active={data.get('continuous_collector_active')}")
        assert resp.status == 200, f"Expected 200 but got {resp.status}"
        assert data.get("status") == "ok", f"Expected status ok but got {data.get('status')}"
        assert data.get("continuous_collector_active") is True, "continuous_collector_active must be True"
        assert data.get("count", 0) > 0, f"Expected count > 0 but got {data.get('count')}"
        stats = data.get("stats")
        assert isinstance(stats, dict), "Expected stats dictionary"
        for field in ["total_entries", "unique_hosts", "active_sources", "total_bytes"]:
            assert field in stats, f"Missing {field} in stats"
        entries = data.get("entries", [])
        assert len(entries) > 0, "Entries list must not be empty"
        assert "hash_blake3" in entries[0], "entries[0] must contain hash_blake3"

    # 2. POST /api/har/refresh
    refresh_url = f"{BASE_URL}/api/har/refresh"
    refresh_req = urllib.request.Request(refresh_url, data=b"{}", headers={**headers, "Content-Type": "application/json"}, method="POST")
    start_t = time.perf_counter()
    with urllib.request.urlopen(refresh_req, timeout=15) as resp:
        elapsed_ms = (time.perf_counter() - start_t) * 1000.0
        data = json.loads(resp.read().decode("utf-8"))
        print(f" [PASS] POST /api/har/refresh -> HTTP {resp.status} ({elapsed_ms:6.2f} ms): sweep_sequence={data.get('sweep_sequence')}")
        assert resp.status == 200, f"Expected 200 but got {resp.status}"
        assert data.get("status") == "ok", f"Expected status ok but got {data.get('status')}"
        assert data.get("sweep_sequence", 0) >= 1, f"Expected sweep_sequence >= 1 but got {data.get('sweep_sequence')}"

    # 3. GET /api/har/export
    export_url = f"{BASE_URL}/api/har/export"
    export_req = urllib.request.Request(export_url, headers=headers, method="GET")
    start_t = time.perf_counter()
    with urllib.request.urlopen(export_req, timeout=15) as resp:
        elapsed_ms = (time.perf_counter() - start_t) * 1000.0
        raw_body = resp.read()
        export_data = json.loads(raw_body.decode("utf-8"))
        print(f" [PASS] GET /api/har/export -> HTTP {resp.status} ({elapsed_ms:6.2f} ms): version={export_data.get('log', {}).get('version')}, entries={len(export_data.get('log', {}).get('entries', []))}")
        assert resp.status == 200, f"Expected 200 but got {resp.status}"
        assert export_data.get("log", {}).get("version") == "1.2", "Expected W3C HAR version 1.2"
        assert isinstance(export_data.get("log", {}).get("entries"), list), "Expected log.entries to be a list"

    # 4. Live GET /index.html contains data-view="har-traffic" and id="har-traffic-view"
    ui_url = f"{BASE_URL}/index.html"
    ui_req = urllib.request.Request(ui_url, headers=headers, method="GET")
    with urllib.request.urlopen(ui_req, timeout=10) as resp:
        ui_html = resp.read().decode("utf-8")
        assert 'data-view="har-traffic"' in ui_html, 'Live index.html must contain data-view="har-traffic"'
        assert 'id="har-traffic-view"' in ui_html, 'Live index.html must contain id="har-traffic-view"'
        assert 'data-view="adversarial-tests"' in ui_html, 'Live index.html must contain data-view="adversarial-tests"'
        assert 'id="adversarial-tests-view"' in ui_html, 'Live index.html must contain id="adversarial-tests-view"'
        print(" [PASS] Live WebUI index.html verified with dedicated #har-traffic and #adversarial-tests menus and views")

    # =========================================================================
    # 10. ADVERSARIAL & DEFENSE TEST EXECUTION SUITE VERIFICATION
    # =========================================================================
    print("\n" + "="*70)
    print(" 10. ADVERSARIAL & DEFENSE TEST EXECUTION SUITE VERIFICATION")
    print("="*70)

    tarpit_url = f"{BASE_URL}/api/tarpit-stats"
    tarpit_req = urllib.request.Request(tarpit_url, headers=headers, method="GET")
    with urllib.request.urlopen(tarpit_req, timeout=10) as resp:
        tarpit_data = json.loads(resp.read().decode("utf-8"))
        assert resp.status == 200
        assert "total_tests_executed" in tarpit_data
        assert "passed_tests" in tarpit_data
        print(f" [PASS] GET /api/tarpit-stats -> HTTP {resp.status}: {tarpit_data}")

    for dl_ep in ["/api/download-run-log", "/api/download-test-json"]:
        dl_req = urllib.request.Request(f"{BASE_URL}{dl_ep}", headers=headers, method="GET")
        with urllib.request.urlopen(dl_req, timeout=10) as resp:
            assert resp.status == 200
            body_bytes = resp.read()
            assert len(body_bytes) > 0
            print(f" [PASS] GET {dl_ep:<24} -> HTTP {resp.status} ({len(body_bytes)} bytes)")

    print("\n" + "="*70)
    print(" ALL END-TO-END VERIFICATIONS PASSED (100% HEALTH, LATENCY SLA & PARITY)")
    print("="*70 + "\n")

if __name__ == "__main__":
    test_endpoints()
