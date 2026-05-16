import ctypes
import json
import time
import sys

PIPE_NAME = r'\\.\pipe\osoosi_injection'

def send_to_pipe(data):
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3
    INVALID_HANDLE_VALUE = -1
    
    handle = ctypes.windll.kernel32.CreateFileW(
        PIPE_NAME,
        GENERIC_WRITE,
        0,
        None,
        OPEN_EXISTING,
        0,
        None
    )
    
    if handle == INVALID_HANDLE_VALUE:
        return False
    
    encoded_data = json.dumps(data).encode('utf-8')
    bytes_written = ctypes.c_ulong(0)
    
    res = ctypes.windll.kernel32.WriteFile(
        handle,
        encoded_data,
        len(encoded_data),
        ctypes.byref(bytes_written),
        None
    )
    
    ctypes.windll.kernel32.CloseHandle(handle)
    return res != 0

def run_stress_test(count=10000):
    print(f"[*] OshoosiClaw 10,000-Event Stress Test")
    print(f"[*] Targeting: {PIPE_NAME}")
    
    # Check if pipe exists first
    if not os.path.exists(PIPE_NAME):
        print("[!] ERROR: Named pipe not found. Is Oshoosi agent running?")
        sys.exit(1)

    start_time = time.time()
    success_count = 0
    
    for i in range(count):
        event = {
            "api": "NtProtectVirtualMemory",
            "ProcessId": 1234,
            "TargetAddress": "0x10000000",
            "Size": 4096,
            "NewProtect": "PAGE_EXECUTE_READWRITE",
            "OldProtect": "PAGE_READWRITE",
            "Reason": "Automated Stress Test",
            "Timestamp": time.time(),
            "Index": i
        }
        
        if send_to_pipe(event):
            success_count += 1
        else:
            # Short sleep and retry if pipe is busy
            time.sleep(0.001)
            if send_to_pipe(event):
                success_count += 1
            else:
                print(f"[!] Critical Failure at event {i}. Pipe may have closed.")
                break
                
        if i > 0 and i % 1000 == 0:
            elapsed = time.time() - start_time
            eps = i / elapsed
            print(f" [+] Progress: {i}/{count} events sent. Current EPS: {eps:.2f}")

    end_time = time.time()
    total_elapsed = end_time - start_time
    final_eps = success_count / total_elapsed
    
    print("\n" + "="*50)
    print(" STRESS TEST RESULTS")
    print("="*50)
    print(f" Total Events Sent: {success_count}")
    print(f" Total Time:        {total_elapsed:.2f} seconds")
    print(f" Average EPS:       {final_eps:.2f}")
    print("="*50)
    
    if final_eps > 500:
        print("\n[***] VERDICT: BURST THRESHOLD EXCEEDED (500 EPS). Check EDR logs for 'Mode: Normal -> SILENT' transition. [***]\n")
    else:
        print("\n[!!!] VERDICT: EPS TOO LOW to trigger Burst Mode. System may be too slow or pipe is bottlenecking. [!!!]\n")

if __name__ == "__main__":
    import os
    run_stress_test()
