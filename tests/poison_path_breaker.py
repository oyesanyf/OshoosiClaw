import os
import shutil
import subprocess
import time
import sys

"""
OshoosiClaw Stress Test: The "Poison Path" Breaker
This script creates intentionally difficult file paths (spaces, parentheses, special characters)
to verify that the OshoosiClaw agent's new native Trust Engine and shell remediation are robust.
"""

# Path to the compiled Oshoosi executable
OSOOSI_EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "target", "release", "osoosi.exe"))
TEST_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "poison_tests"))

POISON_PATHS = [
    "Simple Space",
    "Program Files (x86)",
    "Parentheses (and) Spaces",
    "Special_&_Chars",
    "Nested/Path/With (x86)/And & Chars",
    "Extreme!@#$%^()_+-=[]{};',.~`Path",
]

def setup():
    print(f"[*] Setting up test environment at {TEST_ROOT}...")
    if os.path.exists(TEST_ROOT):
        shutil.rmtree(TEST_ROOT)
    os.makedirs(TEST_ROOT)

    # Create dummy executables in each poison path
    # We use a copy of a real signed binary (like git.exe or cmd.exe) to test the Trust Engine
    source_exe = "C:\\Windows\\System32\\cmd.exe"
    
    for path in POISON_PATHS:
        full_dir = os.path.join(TEST_ROOT, path.replace("/", os.sep))
        os.makedirs(full_dir, exist_ok=True)
        target_exe = os.path.join(full_dir, "test_binary.exe")
        shutil.copy2(source_exe, target_exe)
        print(f" [+] Created: {target_exe}")

def run_scans():
    print(f"\n[*] Running scans using {OSOOSI_EXE}...")
    if not os.path.exists(OSOOSI_EXE):
        print(f"[!] ERROR: Oshoosi executable not found at {OSOOSI_EXE}")
        print("Please run 'cargo build --release' first.")
        sys.exit(1)

    results = []
    for path in POISON_PATHS:
        full_dir = os.path.join(TEST_ROOT, path.replace("/", os.sep))
        target_exe = os.path.join(full_dir, "test_binary.exe")
        
        print(f" [>] Scanning: {target_exe}")
        
        # Run the scan command
        # Before the fix, this would have failed with "The filename, directory name... is incorrect"
        try:
            process = subprocess.run(
                [OSOOSI_EXE, "scan", target_exe],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Check for the dreaded CMD syntax error in stderr or stdout
            syntax_error = "syntax is incorrect" in process.stderr.lower() or "syntax is incorrect" in process.stdout.lower()
            
            if syntax_error:
                print(f"  [!!] FAILURE: Syntax error detected for {path}")
                results.append((path, "FAILED (Syntax Error)"))
            elif process.returncode != 0:
                print(f"  [!] WARNING: Scan returned non-zero code {process.returncode}")
                print(f"      Stderr: {process.stderr.strip()}")
                results.append((path, f"WARNING (Code {process.returncode})"))
            else:
                # Look for successful Trust Engine output
                # In debug mode, it should show verified publisher info
                print(f"  [+] SUCCESS: Path handled correctly.")
                results.append((path, "PASSED"))
                
        except subprocess.TimeoutExpired:
            print(f"  [!] TIMEOUT: Scan hung on {path}")
            results.append((path, "TIMEOUT"))
        except Exception as e:
            print(f"  [!] ERROR: {str(e)}")
            results.append((path, f"ERROR: {type(e).__name__}"))

    return results

def print_report(results):
    print("\n" + "="*50)
    print(" OSHOOSI CLAW PATH ROBUSTNESS REPORT")
    print("="*50)
    passed = 0
    for path, status in results:
        print(f" {path:<40} | {status}")
        if status == "PASSED":
            passed += 1
    print("="*50)
    print(f" TOTAL: {passed}/{len(results)} PASSED")
    print("="*50)
    
    if passed == len(results):
        print("\n[***] VERDICT: OSHOOSI IS NOW POISON-PATH PROOF! [***]\n")
    else:
        print("\n[!!!] VERDICT: ROBUSTNESS ISSUES DETECTED [!!!]\n")

if __name__ == "__main__":
    setup()
    results = run_scans()
    print_report(results)
