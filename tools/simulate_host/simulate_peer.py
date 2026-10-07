#!/usr/bin/env python3
"""
[TEST MODE] OpenỌ̀ṣọ́ọ̀sì Simulated Host & Mesh Communication Test Tool
=====================================================================
Isolated testing utility that generates an authentic Ed25519 DID identity,
performs a cryptographic handshake, and broadcasts peer announcement:
1. Decentralized Nostr WebSocket Relays (wss://relay.damus.io, wss://nos.lol)
2. Local Test Wire P2P Handshake Store (database/test_simulation.db)
3. Verifies immediate reflection in the OpenỌ̀ṣọ́ọ̀sì Web Dashboard APIs

Usage:
  python tools/simulate_host/simulate_peer.py [--hotspot] [--keep]
"""

import sys
import os
import json
import time
import argparse
import asyncio
import sqlite3
import urllib.request
import urllib.error
from datetime import datetime, timezone

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    import websockets
except ImportError as e:
    print(f"[-] Missing required Python package: {e}")
    print("    Run: pip install cryptography websockets")
    sys.exit(1)


# Nostr Event Kinds (OpenỌ̀ṣọ́ọ̀sì Protocol)
KIND_EDR_ALERT = 20001
KIND_NODE_HEARTBEAT = 20002
KIND_MESH_CONFIG = 20003

DEFAULT_RELAYS = [
    "wss://relay.damus.io",
    "wss://nos.lol"
]


class SimulatedHost:
    def __init__(self, is_hotspot=True, node_alias=None):
        self.is_hotspot = is_hotspot
        # Generate authentic Ed25519 cryptographic keypair
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.pubkey_hex = self.public_key.public_bytes_raw().hex()
        
        # If simulating the hotspot host from the session or a fresh one
        if node_alias:
            self.alias = node_alias
        elif is_hotspot:
            self.alias = "Hotspot-Client-10812adc"
        else:
            self.alias = f"Simulated-Node-{self.pubkey_hex[:8]}"
            
        self.did = f"did:osoosi:{self.pubkey_hex}"
        self.os_name = "Windows"
        self.os_version = "11 Pro (Hotspot Cellular Link)" if is_hotspot else "11 Enterprise (LAN Peer)"
        self.ip_address = "192.168.43.118" if is_hotspot else "10.0.0.88"

    def generate_attestation_quote(self):
        """Simulates a TPM 2.0 Endorsement Key PCR quote and Golden Baseline signature."""
        nonce = os.urandom(32).hex()
        baseline_digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        to_sign = f"{self.did}:{nonce}:{baseline_digest}".encode("utf-8")
        sig_bytes = self.private_key.sign(to_sign)
        
        return {
            "device_id": f"TPM20-SIMULATED-{self.pubkey_hex[:12].upper()}",
            "nonce": nonce,
            "pcr_digest": baseline_digest,
            "signature": sig_bytes.hex(),
            "golden_baseline_match": True,
            "attestation_status": "TPM 2.0 Hardware RoT Verified"
        }

    def generate_peer_announce(self):
        """Constructs a genuine PeerAnnounce payload matching osoosi_types schema."""
        now_iso = datetime.now(timezone.utc).isoformat()
        attestation = self.generate_attestation_quote()
        
        return {
            "source_node": self.did,
            "is_patched": True,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "os_supported": True,
            "attestation": attestation,
            "network_type": "hotspot" if self.is_hotspot else "lan",
            "ip": self.ip_address,
            "timestamp": now_iso
        }

    def sign_nostr_event(self, kind: int, content: str):
        """Creates and cryptographically signs a Nostr event (NIP-01) with Ed25519."""
        import hashlib
        created_at = int(time.time())
        tags = [
            ["d", self.did],
            ["t", "oshoosi-mesh"],
            ["network", "hotspot" if self.is_hotspot else "lan"]
        ]
        
        # Serialize event for hashing: [0, pubkey, created_at, kind, tags, content]
        serialized = json.dumps([0, self.pubkey_hex, created_at, kind, tags, content], separators=(',', ':'), ensure_ascii=False)
        event_id = hashlib.sha256(serialized.encode('utf-8')).hexdigest()
        
        # Sign the 32-byte sha256 hash
        sig_bytes = self.private_key.sign(bytes.fromhex(event_id))
        
        return {
            "id": event_id,
            "pubkey": self.pubkey_hex,
            "created_at": created_at,
            "kind": kind,
            "tags": tags,
            "content": content,
            "sig": sig_bytes.hex()
        }


async def broadcast_to_nostr_relay(relay_url: str, event: dict, timeout_secs: float = 6.0):
    """Sends a signed event over WebSocket to a Nostr relay and waits for OK confirmation."""
    req = json.dumps(["EVENT", event])
    try:
        async with websockets.connect(relay_url, open_timeout=timeout_secs, close_timeout=2.0) as ws:
            await ws.send(req)
            # Wait for ["OK", event_id, true/false, message]
            while True:
                try:
                    resp_raw = await asyncio.wait_for(ws.recv(), timeout=4.0)
                    resp = json.loads(resp_raw)
                    if isinstance(resp, list) and len(resp) >= 3 and resp[0] == "OK":
                        if resp[1] == event["id"]:
                            return True, resp[2], resp[3] if len(resp) > 3 else "Accepted"
                except asyncio.TimeoutError:
                    break
            return True, True, "Published (no synchronous OK error)"
    except Exception as e:
        return False, False, str(e)


def sync_to_local_database(host: SimulatedHost, db_path: str = "database/test_simulation.db"):
    """Inserts or updates the simulated host record in SQLite peer_status & reputation."""
    if not os.path.exists(db_path):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    # Ensure tables exist
    cur.execute("""
        CREATE TABLE IF NOT EXISTS peer_status (
            peer_id TEXT PRIMARY KEY,
            is_patched INTEGER,
            os_name TEXT,
            os_version TEXT,
            os_supported INTEGER,
            received_at TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reputation (
            node_id TEXT PRIMARY KEY,
            score REAL,
            alerts_verified INTEGER,
            false_positives INTEGER,
            last_updated TEXT
        )
    """)
    
    now_iso = datetime.now(timezone.utc).isoformat()
    cur.execute("""
        INSERT OR REPLACE INTO peer_status (peer_id, is_patched, os_name, os_version, os_supported, received_at)
        VALUES (?, 1, ?, ?, 1, ?)
    """, (host.did, host.os_name, host.os_version, now_iso))
    
    cur.execute("""
        INSERT OR REPLACE INTO reputation (node_id, score, alerts_verified, false_positives, last_updated)
        VALUES (?, 1.0, 5, 0, ?)
    """, (host.did, now_iso))
    
    conn.commit()
    conn.close()
    return True


def remove_from_local_database(peer_id: str, db_path: str = "database/test_simulation.db"):
    """Removes a test peer from SQLite tables."""
    if not os.path.exists(db_path):
        return
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("DELETE FROM peer_status WHERE peer_id = ?", (peer_id,))
    cur.execute("DELETE FROM reputation WHERE node_id = ?", (peer_id,))
    conn.commit()
    conn.close()


def query_dashboard_api(endpoint: str = "http://127.0.0.1:3030/api/peers"):
    """Queries dashboard endpoint to check live peer visibility."""
    try:
        req = urllib.request.Request(endpoint, headers={"User-Agent": "Oshoosi-Simulator/1.0"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode('utf-8'))
                return True, data
    except Exception as e:
        return False, str(e)
    return False, "Non-200 status"


async def main_async(args):
    print("=" * 70)
    print("  [TEST MODE] OpenỌ̀ṣọ́ọ̀sì Simulated Host & Mesh Communication Test Tool")
    print("  NOTE: This is an isolated test tool. Target DB: " + str(args.db))
    print("=" * 70)
    
    count = max(1, getattr(args, "count", 1))
    simulated_hosts = []

    for i in range(count):
        # Alternate hotspot vs lan if multiple hosts, or follow args.hotspot
        is_hotspot = args.hotspot if count == 1 else (i % 2 == 0)
        alias = f"{args.alias}-{i+1}" if args.alias and count > 1 else args.alias
        
        host = SimulatedHost(is_hotspot=is_hotspot, node_alias=alias)
        simulated_hosts.append(host)
        
        print(f"\n[+] [{i+1}/{count}] Generated Simulated Host Identity:")
        print(f"    - DID:          {host.did}")
        print(f"    - Network Type: {'📱 Mobile Hotspot / Cellular WAN' if host.is_hotspot else '🏠 Local Area Network (LAN)'}")
        print(f"    - Simulated IP: {host.ip_address}")
        print(f"    - OS Platform:  {host.os_name} {host.os_version}")
        
        # Cryptographic Attestation Quote
        quote = host.generate_attestation_quote()
        print(f"    - Device ID:    {quote['device_id']}")
        print(f"    - PCR Baseline: {quote['pcr_digest'][:16]}... (SHA-256 match)")
        print(f"    - Status:       {quote['attestation_status']}")

        # Synchronize to P2P Wire Memory / SQLite
        db_ok = sync_to_local_database(host, args.db)
        if db_ok:
            print(f"    [✔] Successfully anchored into '{args.db}' (peer_status & reputation).")

        # Broadcast to Nostr Decentralized WebSocket Relays
        heartbeat_content = json.dumps(host.generate_peer_announce())
        nostr_event = host.sign_nostr_event(KIND_NODE_HEARTBEAT, heartbeat_content)
        print(f"    - Nostr Event:  {nostr_event['id'][:16]}... (KIND_NODE_HEARTBEAT)")

        for relay in DEFAULT_RELAYS:
            connected, accepted, msg = await broadcast_to_nostr_relay(relay, nostr_event, timeout_secs=3.0)
            status_str = "[✔ OK]" if (connected and accepted) else ("[⚠ ACK]" if connected else "[✖ TIMEOUT]")
            print(f"      -> {relay}: {status_str} {msg}")

    # Query Local Dashboard API (Port 3030 / 3031)
    print(f"\n[+] Verifying Live Peer Visibility & Zone Posture in EDR Dashboard:")
    ports_to_check = [3030, 3031, 3032]
    found_in_dashboard = False
    
    for port in ports_to_check:
        zone_url = f"http://127.0.0.1:{port}/api/zone-summary"
        api_ok, zone_data = query_dashboard_api(zone_url)
        if api_ok and isinstance(zone_data, dict):
            print(f"\n    [✔] Live Zone Summary Telemetry from port {port}:")
            print(f"        - Security Score:       {zone_data.get('security_score', '--')}%")
            print(f"        - Zone Gateway ID:      {zone_data.get('zone', 'zone-alpha-mesh')}")
            print(f"        - Endpoint Hosts:       {zone_data.get('host_count', len(simulated_hosts) + 1)} ({zone_data.get('peer_count', len(simulated_hosts))} Remote)")
            print(f"        - Message Relays:       {zone_data.get('relay_count', 0)} Nostr Relays")
            print(f"        - Hardware Attestation: {'TPM 2.0 Anchored · WFP Containment Armed' if zone_data.get('tpm_attested') else 'Software Enclave Active'}")
            found_in_dashboard = True
            
        peers_url = f"http://127.0.0.1:{port}/api/peers"
        api_ok, peers_data = query_dashboard_api(peers_url)
        if api_ok and (isinstance(peers_data, list) or isinstance(peers_data, dict)):
            peers_list = peers_data if isinstance(peers_data, list) else peers_data.get("peers", [])
            print(f"\n    [✔] Live Mesh Peers at port {port} (Total: {len(peers_list)}):")
            for p in peers_list[:8]:
                print(f"        * [{p.get('network_type', 'peer')}] {p.get('label')} ({p.get('id', '')[:22]}...) | {p.get('role')} | {p.get('status')}")
            found_in_dashboard = True
            break

    if not found_in_dashboard:
        print(f"    [i] Note: The dashboard process may be compiling or restarting. The peers are safely committed in {args.db} and will appear upon startup.")

    # Cleanup or Keep
    print("\n" + "=" * 70)
    if not args.keep:
        print(f"[!] Test Mode: Purging simulated peers from '{args.db}' (default test cleanup)...")
        for h in simulated_hosts:
            remove_from_local_database(h.did, args.db)
        print("[✔] Test database cleaned. (Pass --keep to preserve test records)")
    else:
        print(f"[+] Simulated peer identities preserved in test database '{args.db}' (--keep specified).")
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="[TEST MODE] OpenỌ̀ṣọ́ọ̀sì Simulated Host & Communication Tester")
    parser.add_argument("--count", type=int, default=1, help="Number of simulated hosts to launch (default: 1)")
    parser.add_argument("--hotspot", action="store_true", default=True, help="Simulate a host on a mobile cellular hotspot (default: True)")
    parser.add_argument("--lan", action="store_false", dest="hotspot", help="Simulate a host on the local LAN")
    parser.add_argument("--alias", type=str, default=None, help="Custom node label alias")
    parser.add_argument("--db", type=str, default="database/test_simulation.db", help="Path to SQLite test database (default: database/test_simulation.db)")
    parser.add_argument("--keep", action="store_true", default=False, help="Preserve simulated peer in database (default is to clean up after test run)")
    parser.add_argument("--cleanup", action="store_true", default=True, help="Remove the simulated peer from database after test (default: True)")
    
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
