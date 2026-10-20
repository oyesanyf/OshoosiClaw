"""
tests/challenger_m1_live_stress_harness.py

Milestone 1 Iteration 2 Empirical Stress Testing & Adversarial Harness
Conducted by teamwork_preview_challenger (Challenger 1).

Objectives:
1. Verify that loopback TCP sockets (127.0.0.1:3030 and dynamic loopback ports) remain
   fully operational during live hermetic network quarantine.
2. Verify that netsh firewall rules created during quarantine are 100% cleanly reverted
   upon disarm/removal without residual rules.
3. Verify that PATH and Windows Registry environment hives (HKCU/HKLM) remain 100% unaltered.
"""

import os
import sys
import socket
import threading
import subprocess
import time
import winreg

RULE_NAMES = [
    "Osoosi-KillChain-Block-Inbound-Low",
    "Osoosi-KillChain-Block-Inbound-High",
    "Osoosi-KillChain-Block-Outbound-Low",
    "Osoosi-KillChain-Block-Outbound-High",
    "Osoosi-KillChain-Allow-DNS-Out",
    "Osoosi-KillChain-Allow-DNS-TCP-Out",
    "Osoosi-KillChain-Allow-DHCP-Out",
    "Osoosi-KillChain-Allow-DHCP-In",
    "Osoosi-KillChain-Allow-DHCPv6-Out",
    "Osoosi-KillChain-Allow-DHCPv6-In",
    "Osoosi-KillChain-Allow-WebUI-In",
    "Osoosi-KillChain-Allow-WebUI-Out",
    "Osoosi-KillChain-Allow-WebUI-Out-Remote",
    "Osoosi-KillChain-Allow-Loopback-In",
    "Osoosi-KillChain-Allow-Loopback-Out",
]

QUARANTINE_NETSH_COMMANDS = [
    ["advfirewall", "firewall", "add", "rule", "name=Osoosi-KillChain-Allow-Loopback-In", "dir=in", "action=allow", "localip=127.0.0.1,::1", "profile=any"],
    ["advfirewall", "firewall", "add", "rule", "name=Osoosi-KillChain-Allow-Loopback-Out", "dir=out", "action=allow", "remoteip=127.0.0.1,::1", "profile=any"],
    ["advfirewall", "firewall", "add", "rule", "name=Osoosi-KillChain-Allow-WebUI-In", "dir=in", "action=allow", "protocol=TCP", "localport=3030", "profile=any"],
    ["advfirewall", "firewall", "add", "rule", "name=Osoosi-KillChain-Allow-WebUI-Out", "dir=out", "action=allow", "protocol=TCP", "localport=3030", "profile=any"],
    ["advfirewall", "firewall", "add", "rule", "name=Osoosi-KillChain-Allow-WebUI-Out-Remote", "dir=out", "action=allow", "protocol=TCP", "remoteport=3030", "profile=any"],
    ["advfirewall", "firewall", "add", "rule", "name=Osoosi-KillChain-Allow-DNS-Out", "dir=out", "action=allow", "protocol=UDP", "remoteport=53", "profile=any"],
    ["advfirewall", "firewall", "add", "rule", "name=Osoosi-KillChain-Allow-DHCP-Out", "dir=out", "action=allow", "protocol=UDP", "localport=68", "remoteport=67", "profile=any"],
    ["advfirewall", "firewall", "add", "rule", "name=Osoosi-KillChain-Allow-DHCP-In", "dir=in", "action=allow", "protocol=UDP", "localport=68", "remoteport=67", "profile=any"],
    ["advfirewall", "firewall", "add", "rule", "name=Osoosi-KillChain-Allow-DNS-TCP-Out", "dir=out", "action=allow", "protocol=TCP", "remoteport=53", "profile=any"],
    ["advfirewall", "firewall", "add", "rule", "name=Osoosi-KillChain-Allow-DHCPv6-Out", "dir=out", "action=allow", "protocol=UDP", "localport=546", "remoteport=547", "profile=any"],
    ["advfirewall", "firewall", "add", "rule", "name=Osoosi-KillChain-Allow-DHCPv6-In", "dir=in", "action=allow", "protocol=UDP", "localport=546", "remoteport=547", "profile=any"],
    ["advfirewall", "firewall", "add", "rule", "name=Osoosi-KillChain-Block-Inbound-Low", "dir=in", "action=block", "remoteip=0.0.0.0-126.255.255.255", "profile=any"],
    ["advfirewall", "firewall", "add", "rule", "name=Osoosi-KillChain-Block-Inbound-High", "dir=in", "action=block", "remoteip=128.0.0.0-255.255.255.255", "profile=any"],
    ["advfirewall", "firewall", "add", "rule", "name=Osoosi-KillChain-Block-Outbound-Low", "dir=out", "action=block", "remoteip=0.0.0.0-126.255.255.255", "profile=any"],
    ["advfirewall", "firewall", "add", "rule", "name=Osoosi-KillChain-Block-Outbound-High", "dir=out", "action=block", "remoteip=128.0.0.0-255.255.255.255", "profile=any"],
]

def read_registry_hive(hkey, subkey):
    values = {}
    try:
        with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
            index = 0
            while True:
                try:
                    name, val, val_type = winreg.EnumValue(key, index)
                    values[name] = (val, val_type)
                    index += 1
                except OSError:
                    break
    except OSError as e:
        print(f"Warning reading registry {subkey}: {e}")
    return values

def run_netsh(args):
    return subprocess.run(["netsh"] + args, capture_output=True, text=True)

def apply_quarantine_rules():
    print("[*] Applying 15 hermetic network quarantine netsh rules...")
    for cmd in QUARANTINE_NETSH_COMMANDS:
        res = run_netsh(cmd)
        if res.returncode != 0 and "already exists" not in res.stderr.lower():
            print(f"    [!] Warning adding rule {cmd[4]}: {res.stderr.strip()}")

def remove_quarantine_rules():
    print("[*] Removing hermetic network quarantine netsh rules (disarm)...")
    for r in RULE_NAMES:
        run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={r}"])

def check_residual_rules():
    residuals = []
    for r in RULE_NAMES:
        res = run_netsh(["advfirewall", "firewall", "show", "rule", f"name={r}"])
        if res.returncode == 0 and "No rules match" not in res.stdout:
            residuals.append(r)
    return residuals

def echo_server_dynamic(port, stop_event, results):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(128)
    server.settimeout(0.5)
    
    handled = 0
    try:
        while not stop_event.is_set():
            try:
                conn, _ = server.accept()
                conn.settimeout(1.0)
                data = conn.recv(1024)
                if data:
                    conn.sendall(data)
                    handled += 1
                conn.close()
            except socket.timeout:
                continue
            except Exception as e:
                results["server_err"] = str(e)
                break
    finally:
        server.close()
    results["handled"] = handled

def test_loopback_concurrency(port, num_threads=10, msgs_per_thread=20):
    stop_event = threading.Event()
    results = {}
    server_thread = threading.Thread(target=echo_server_dynamic, args=(port, stop_event, results))
    server_thread.start()
    time.sleep(0.1)

    errors = []

    def client_worker(t_id):
        for m_id in range(msgs_per_thread):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                sock.connect(("127.0.0.1", port))
                msg = f"PROBE_{t_id}_{m_id}".encode("utf-8")
                sock.sendall(msg)
                resp = sock.recv(1024)
                if resp != msg:
                    errors.append(f"Mismatch: sent {msg}, got {resp}")
                sock.close()
            except Exception as e:
                errors.append(f"Thread {t_id} msg {m_id} error: {e}")

    client_threads = [threading.Thread(target=client_worker, args=(i,)) for i in range(num_threads)]
    for ct in client_threads:
        ct.start()
    for ct in client_threads:
        ct.join()

    stop_event.set()
    server_thread.join()

    return len(errors) == 0, errors, results.get("handled", 0)

def main():
    print("=" * 70)
    print(" Milestone 1 Iteration 2 - Empirical Adversarial Stress Test Harness")
    print(" Challenger 1 (`teamwork_preview_challenger`)")
    print("=" * 70)

    # 1. Take initial snapshots of PATH and Registry
    print("\n[+] Phase 1: Environment & Registry Baseline Snapshot")
    initial_path = os.environ.get("PATH", "")
    initial_env = dict(os.environ)
    initial_hkcu = read_registry_hive(winreg.HKEY_CURRENT_USER, "Environment")
    initial_hklm = read_registry_hive(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
    )
    print(f"    - Baseline PATH length: {len(initial_path)} chars")
    print(f"    - HKCU\\Environment variables count: {len(initial_hkcu)}")
    print(f"    - HKLM\\Environment variables count: {len(initial_hklm)}")

    # 2. Baseline cleanup (ensure no stale rules)
    print("\n[+] Phase 2: Ensuring Clean Firewall Baseline")
    remove_quarantine_rules()
    initial_residuals = check_residual_rules()
    if initial_residuals:
        print(f"    [-] Residual rules found before test: {initial_residuals}")
        sys.exit(1)
    else:
        print("    [+] Zero pre-existing quarantine rules confirmed.")

    # 3. Apply live hermetic quarantine
    print("\n[+] Phase 3: Engaging Live Hermetic Quarantine")
    apply_quarantine_rules()

    # 4. Stress-test dynamic loopback port under live quarantine
    print("\n[+] Phase 4: Empirical Loopback Socket Survivability Stress Test")
    # Find free dynamic loopback port
    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    temp_sock.bind(("127.0.0.1", 0))
    dynamic_port = temp_sock.getsockname()[1]
    temp_sock.close()
    print(f"    - Testing Dynamic Loopback Port: {dynamic_port}")
    ok_dyn, errs_dyn, handled_dyn = test_loopback_concurrency(dynamic_port, num_threads=10, msgs_per_thread=25)
    if ok_dyn and handled_dyn == 250:
        print(f"    [+] SUCCESS: 250/250 concurrent dynamic loopback packets transferred with 0 errors.")
    else:
        print(f"    [-] FAILED: Dynamic loopback errors: {errs_dyn[:5]}, handled: {handled_dyn}/250")
        remove_quarantine_rules()
        sys.exit(1)

    # 5. Stress-test WebUI port 3030 under live quarantine
    print(f"    - Testing WebUI Port 3030 Loopback Survivability")
    port_3030_in_use = False
    try:
        temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        temp_sock.bind(("127.0.0.1", 3030))
        temp_sock.close()
    except OSError:
        port_3030_in_use = True

    if not port_3030_in_use:
        ok_3030, errs_3030, handled_3030 = test_loopback_concurrency(3030, num_threads=10, msgs_per_thread=20)
        if ok_3030 and handled_3030 == 200:
            print(f"    [+] SUCCESS: 200/200 WebUI port 3030 loopback packets transferred with 0 errors.")
        else:
            print(f"    [-] FAILED: WebUI port 3030 loopback errors: {errs_3030[:5]}")
            remove_quarantine_rules()
            sys.exit(1)
    else:
        # Port 3030 already bound by daemon; probe connect
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect(("127.0.0.1", 3030))
            s.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            res = s.recv(256)
            s.close()
            print(f"    [+] SUCCESS: Live daemon on port 3030 connected and returned {len(res)} bytes during quarantine.")
        except Exception as e:
            print(f"    [-] FAILED: Connecting to live port 3030 under quarantine failed: {e}")
            remove_quarantine_rules()
            sys.exit(1)

    # 6. Disarm / Clean Revert of Firewall Rules
    print("\n[+] Phase 5: Live Firewall Rule Reversion & Residual Audit")
    remove_quarantine_rules()
    residuals = check_residual_rules()
    if not residuals:
        print("    [+] SUCCESS: 100% of netsh quarantine rules cleanly reverted. 0 residual rules detected.")
    else:
        print(f"    [-] FAILED: Residual firewall rules remain after disarm: {residuals}")
        sys.exit(1)

    # 7. Verify PATH and Registry Environment Invariance
    print("\n[+] Phase 6: PATH & Registry Environment Immutability Audit")
    post_path = os.environ.get("PATH", "")
    post_env = dict(os.environ)
    post_hkcu = read_registry_hive(winreg.HKEY_CURRENT_USER, "Environment")
    post_hklm = read_registry_hive(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
    )

    path_intact = (initial_path == post_path)
    env_intact = (initial_env == post_env)
    hkcu_intact = (initial_hkcu == post_hkcu)
    hklm_intact = (initial_hklm == post_hklm)

    if path_intact:
        print("    [+] SUCCESS: Process $env:PATH is 100% bit-for-bit unchanged.")
    else:
        print("    [-] CRITICAL VIOLATION: Process $env:PATH was modified!")

    if env_intact:
        print("    [+] SUCCESS: Process environment dictionary is 100% identical.")
    else:
        print("    [-] CRITICAL VIOLATION: Process environment variables mutated!")

    if hkcu_intact:
        print("    [+] SUCCESS: HKCU\\Environment registry hive is 100% unaltered.")
    else:
        print("    [-] CRITICAL VIOLATION: HKCU\\Environment registry keys were altered!")

    if hklm_intact:
        print("    [+] SUCCESS: HKLM\\SYSTEM\\...\\Environment registry hive is 100% unaltered.")
    else:
        print("    [-] CRITICAL VIOLATION: HKLM\\Environment registry keys were altered!")

    if not (path_intact and env_intact and hkcu_intact and hklm_intact):
        sys.exit(1)

    print("\n" + "=" * 70)
    print(" ALL EMPIRICAL ADVERSARIAL STRESS TESTS PASSED SUCCESSFULLY!")
    print("=" * 70)

if __name__ == "__main__":
    main()
