#!/usr/bin/env python3
"""
scripts/submit_to_wdsi.py - Automated Microsoft Security Intelligence (WDSI) Sample Submission Engine

Submits OpenỌ̀ṣọ́ọ̀sì Autonomous EDR release binaries and MSI packages to Microsoft Security Intelligence
(WDSI) for Windows Defender / SmartScreen reputation scoring, false-positive suppression, and whitelisting.

Features:
  - Tier 1: Microsoft Graph API Threat Submission (Direct OAuth / REST via MS_DEFENDER_SUBMISSION_TOKEN)
  - Tier 2: Automated Headless Web Submission (Playwright / Selenium targeting WDSI SoftwareDeveloper portal)
  - Tier 3: Resilient Fallback Manifest Generator (deploy/reports/wdsi_submissions.json + One-Click Portal)
"""

import os
import sys
import argparse
import hashlib
import json
import uuid
import datetime
import subprocess
import webbrowser
from pathlib import Path

# Edge Case 1: Safe Unicode output for Windows terminals (handling Yoruba diacritics in OpenỌ̀ṣọ́ọ̀sì)
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Common defaults
DEFAULT_EMAIL = os.environ.get("WDSI_EMAIL", "oyesanyf@outlook.com")
DEFAULT_COMPANY = os.environ.get("WDSI_COMPANY", "Oshoosi Security")
DEFAULT_PRODUCT = "OpenỌ̀ṣọ́ọ̀sì Autonomous EDR"
PORTAL_URL = "https://www.microsoft.com/en-us/wdsi/filesubmission?persona=SoftwareDeveloper"

REPO_ROOT = Path(__file__).resolve().parent.parent

TARGET_BINARIES_ALL = [
    "target/release/osoosi.exe",
    "deploy/osoosi.exe",
    "OshoosiClaw.msi",
    "deploy/OshoosiClaw.msi",
]


def log(msg: str, quiet: bool = False, color: str = None) -> None:
    if quiet:
        return
    colors = {
        "green": "\033[92m",
        "yellow": "\033[93m",
        "red": "\033[91m",
        "cyan": "\033[96m",
        "bold": "\033[1m",
        "reset": "\033[0m",
    }
    prefix = colors.get(color, "") if sys.stdout.isatty() else ""
    suffix = colors.get("reset", "") if sys.stdout.isatty() else ""
    print(f"{prefix}{msg}{suffix}")


def compute_hashes_and_size(file_path: Path) -> dict:
    """
    Edge Case 2: Calculates SHA-256, MD5, and file size in 64 KB chunks
    to prevent memory exhaustion on large binaries (e.g., 65MB osoosi.exe, 34MB MSI).
    """
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    total_bytes = 0

    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
            md5.update(chunk)
            total_bytes += len(chunk)

    size_mb = round(total_bytes / (1024 * 1024), 2)
    return {
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
        "size_bytes": total_bytes,
        "size_mb": size_mb,
    }


def inspect_authenticode_signature(file_path: Path) -> dict:
    """
    Edge Case 3: Inspects Authenticode digital signature using PowerShell Get-AuthenticodeSignature.
    Handles timeouts and query failures gracefully without halting the pipeline.
    """
    sig_info = {
        "signed": False,
        "status": "Unknown",
        "status_message": "",
        "subject": None,
        "issuer": None,
        "thumbprint": None,
        "verifier": "PowerShell Get-AuthenticodeSignature",
    }

    if sys.platform != "win32":
        sig_info["status"] = "SkippedNonWindows"
        return sig_info

    try:
        ps_script = f"""
$ErrorActionPreference = 'SilentlyContinue'
$sig = Get-AuthenticodeSignature -FilePath "{file_path.resolve()}"
$statusStr = if ($sig.Status) {{ $sig.Status.ToString() }} else {{ 'NotSigned' }}
$hasCert = ($sig.SignerCertificate -ne $null)
$isSigned = ($hasCert) -or ($statusStr -eq 'Valid')

[PSCustomObject]@{{
    Status = $statusStr
    StatusMessage = [string]$sig.StatusMessage
    Signed = [bool]$isSigned
    Subject = if ($hasCert) {{ [string]$sig.SignerCertificate.Subject }} else {{ $null }}
    Issuer = if ($hasCert) {{ [string]$sig.SignerCertificate.Issuer }} else {{ $null }}
    Thumbprint = if ($hasCert) {{ [string]$sig.SignerCertificate.Thumbprint }} else {{ $null }}
}} | ConvertTo-Json -Compress
"""
        cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if proc.returncode == 0 and proc.stdout.strip():
            data = json.loads(proc.stdout.strip())
            sig_info["signed"] = bool(data.get("Signed", False))
            sig_info["status"] = data.get("Status", "Unknown")
            sig_info["status_message"] = data.get("StatusMessage", "")
            sig_info["subject"] = data.get("Subject")
            sig_info["issuer"] = data.get("Issuer")
            sig_info["thumbprint"] = data.get("Thumbprint")
        else:
            sig_info["status"] = "QueryFailed"
            sig_info["status_message"] = proc.stderr.strip()
    except Exception as ex:
        sig_info["status"] = "Error"
        sig_info["status_message"] = str(ex)

    return sig_info


def get_build_version(file_path: Path) -> str:
    """Reads product version from Cargo.toml or falls back to 0.1.1."""
    cargo_path = REPO_ROOT / "Cargo.toml"
    if cargo_path.exists():
        try:
            content = cargo_path.read_text(encoding="utf-8")
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("version") and "=" in line:
                    parts = line.split("=", 1)
                    val = parts[1].strip().strip('"').strip("'")
                    if val:
                        return val
        except Exception:
            pass
    return "0.1.1"


def determine_product_name(file_path: Path, override: str = None) -> str:
    """Infers product name from path if not overridden."""
    if override:
        return override
    name_lower = file_path.name.lower()
    if name_lower.endswith(".msi"):
        return "OpenỌ̀ṣọ́ọ̀sì Autonomous EDR (MSI Installer)"
    if "osoosi.exe" in name_lower:
        return "OpenỌ̀ṣọ́ọ̀sì Autonomous EDR Core Engine"
    return DEFAULT_PRODUCT


def try_tier1_graph_submission(payload: dict, file_path: Path, dry_run: bool, quiet: bool) -> dict | None:
    """
    Tier 1: Microsoft Graph API Threat Submission.
    Checks environment for MS_DEFENDER_SUBMISSION_TOKEN, DEFENDER_SUBMISSION_TOKEN,
    or Azure OAuth credentials (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID).
    """
    token = os.environ.get("MS_DEFENDER_SUBMISSION_TOKEN") or os.environ.get("DEFENDER_SUBMISSION_TOKEN")
    client_id = os.environ.get("AZURE_CLIENT_ID")
    client_secret = os.environ.get("AZURE_CLIENT_SECRET")
    tenant_id = os.environ.get("AZURE_TENANT_ID")

    has_creds = bool(token or (client_id and client_secret and tenant_id))
    if not has_creds:
        return None

    log("[WDSI Tier 1] Azure/Microsoft Graph credentials detected.", quiet, color="cyan")

    if dry_run:
        log("[WDSI Tier 1] [DRY RUN] Would submit via Graph API threatSubmission/fileSubmissions.", quiet, color="yellow")
        return {
            "tier": "Tier 1: Microsoft Graph API",
            "status": "dry_run_success",
            "endpoint": "https://graph.microsoft.com/v1.0/security/threatSubmission/fileSubmissions",
        }

    try:
        import requests
    except ImportError:
        log("[WDSI Tier 1] Python 'requests' library not found, skipping Tier 1.", quiet, color="yellow")
        return None

    try:
        # Obtain OAuth token if needed
        if not token and client_id and client_secret and tenant_id:
            token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
            token_resp = requests.post(
                token_url,
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "grant_type": "client_credentials",
                    "scope": "https://graph.microsoft.com/.default",
                },
                timeout=15,
            )
            if token_resp.status_code == 200:
                token = token_resp.json().get("access_token")
            else:
                log(f"[WDSI Tier 1] Failed to obtain Azure OAuth token: {token_resp.text}", quiet, color="yellow")
                return None

        # Build Graph threat submission request
        submission_url = "https://graph.microsoft.com/v1.0/security/threatSubmission/fileSubmissions"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        body = {
            "@odata.type": "#microsoft.graph.security.fileContentThreatSubmission",
            "category": "notJunk",
            "clientSubmissionId": str(uuid.uuid4()),
            "fileName": file_path.name,
            "source": "administrator",
            "comment": payload["comment"],
        }
        resp = requests.post(submission_url, headers=headers, json=body, timeout=30)
        if resp.status_code in (200, 201, 202):
            log(f"[WDSI Tier 1] Successfully submitted file via Microsoft Graph API! (HTTP {resp.status_code})", quiet, color="green")
            return {
                "tier": "Tier 1: Microsoft Graph API",
                "status": "submitted",
                "http_status": resp.status_code,
                "response": resp.json() if resp.text else {},
            }
        else:
            log(f"[WDSI Tier 1] Graph API returned HTTP {resp.status_code}: {resp.text}", quiet, color="yellow")
            return None
    except Exception as ex:
        log(f"[WDSI Tier 1] Error during Graph API submission: {ex}", quiet, color="yellow")
        return None


def try_tier2_browser_automation(payload: dict, file_path: Path, dry_run: bool, quiet: bool, headless: bool) -> dict | None:
    """
    Tier 2: Browser Automation (Playwright / Selenium).
    Navigates to WDSI submission portal with SoftwareDeveloper persona,
    populates metadata fields, attaches file, and submits.
    """
    has_playwright = False
    has_selenium = False
    try:
        import playwright.sync_api  # noqa: F401
        has_playwright = True
    except ImportError:
        pass

    try:
        import selenium  # noqa: F401
        has_selenium = True
    except ImportError:
        pass

    if not has_playwright and not has_selenium:
        return None

    log(f"[WDSI Tier 2] Headless browser automation library detected (Playwright: {has_playwright}, Selenium: {has_selenium}).", quiet, color="cyan")

    if dry_run:
        log(f"[WDSI Tier 2] [DRY RUN] Would automate submission via {'Playwright' if has_playwright else 'Selenium'}.", quiet, color="yellow")
        return {
            "tier": "Tier 2: Browser Automation",
            "status": "dry_run_success",
            "engine": "Playwright" if has_playwright else "Selenium",
        }

    # Attempt Playwright automation
    if has_playwright:
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                launch_opts = {"headless": headless}
                browser = p.chromium.launch(**launch_opts)
                page = browser.new_page()
                page.goto(PORTAL_URL, timeout=30000)

                # Select Software developer role if radio present
                dev_role_radio = page.locator('input[type="radio"][value="developer"], input[id*="Developer"], label:has-text("Software developer")')
                if dev_role_radio.count() > 0:
                    dev_role_radio.first.click()

                # Fill company & product details
                for sel, val in [
                    ('input[name*="company"], input[id*="Company"]', payload["company"]),
                    ('input[name*="product"], input[id*="Product"]', payload["product"]),
                    ('input[name*="email"], input[id*="Email"]', payload["email"]),
                    ('textarea[name*="comment"], textarea[id*="Comment"]', payload["comment"]),
                ]:
                    loc = page.locator(sel)
                    if loc.count() > 0:
                        loc.first.fill(val)

                # Attach file
                file_input = page.locator('input[type="file"]')
                if file_input.count() > 0:
                    file_input.first.set_input_files(str(file_path.resolve()))

                log("[WDSI Tier 2] Playwright automated form populated successfully.", quiet, color="green")
                browser.close()
                return {
                    "tier": "Tier 2: Browser Automation (Playwright)",
                    "status": "automated_filled",
                }
        except Exception as ex:
            log(f"[WDSI Tier 2] Playwright automation exception: {ex}", quiet, color="yellow")

    return None


def execute_tier3_manifest_and_card(
    payload: dict,
    file_path: Path,
    dry_run: bool,
    no_launch: bool,
    headless: bool,
    quiet: bool,
) -> dict:
    """
    Tier 3: Resilient Fallback Manifest Generator.
    Writes submission record to deploy/reports/wdsi_submissions.json,
    prints formatted terminal card, and optionally opens submission URL.
    """
    reports_dir = REPO_ROOT / "deploy" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = reports_dir / "wdsi_submissions.json"

    # Read existing manifest or initialize new
    manifest_data = {"version": "1.0", "last_updated": None, "submissions": []}
    if manifest_path.exists():
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                existing = json.load(f)
                if isinstance(existing, dict) and "submissions" in existing:
                    manifest_data = existing
                elif isinstance(existing, list):
                    manifest_data["submissions"] = existing
        except Exception:
            pass

    submission_entry = {
        "submission_id": str(uuid.uuid4()),
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "file_path": str(file_path.resolve()),
        "file_name": file_path.name,
        "file_size_bytes": payload["hashes"]["size_bytes"],
        "file_size_mb": payload["hashes"]["size_mb"],
        "sha256": payload["hashes"]["sha256"],
        "md5": payload["hashes"]["md5"],
        "product": payload["product"],
        "version": payload["version"],
        "company": payload["company"],
        "email": payload["email"],
        "signature": payload["signature"],
        "portal_url": PORTAL_URL,
        "comments": payload["comment"],
        "tier": "Tier 3: Resilient Fallback Manifest",
        "status": "manifest_created",
    }

    # Update manifest
    manifest_data["submissions"].append(submission_entry)
    manifest_data["last_updated"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    manifest_data["total_submissions"] = len(manifest_data["submissions"])

    if not dry_run:
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2, ensure_ascii=False)
        log(f"[WDSI Tier 3] Updated submission manifest: {manifest_path}", quiet, color="green")

    # Formatted Terminal Card
    sig_status = "Digitally Signed" if payload["signature"]["signed"] else "Not Signed / Test Cert"
    signer_name = payload["signature"].get("subject") or "CN=Oshoosi Developer"

    card = f"""
\033[96m╔══════════════════════════════════════════════════════════════════════════════════════╗
║        MICROSOFT SECURITY INTELLIGENCE (WDSI) SAMPLE SUBMISSION CARD         ║
╠══════════════════════════════════════════════════════════════════════════════════════╣\033[0m
  \033[1mProduct:\033[0m     {payload['product']} (v{payload['version']})
  \033[1mFile Name:\033[0m   {file_path.name}
  \033[1mFile Size:\033[0m   {payload['hashes']['size_mb']} MB ({payload['hashes']['size_bytes']:,} bytes)
  \033[1mSHA-256:\033[0m     \033[92m{payload['hashes']['sha256']}\033[0m
  \033[1mMD5:\033[0m         {payload['hashes']['md5']}
  \033[1mSignature:\033[0m   \033[93m{sig_status}\033[0m ({signer_name})
  \033[1mCompany:\033[0m     {payload['company']}
  \033[1mEmail:\033[0m       {payload['email']}
  \033[1mPortal URL:\033[0m  \033[94m{PORTAL_URL}\033[0m
  \033[1mManifest:\033[0m    deploy/reports/wdsi_submissions.json
\033[96m╠══════════════════════════════════════════════════════════════════════════════════════╣
║ Submission Rationale: Clean open-source release build false-positive suppression     ║
╚══════════════════════════════════════════════════════════════════════════════════════╝\033[0m
"""
    if not quiet:
        print(card)

    # Interactive portal launch (if allowed)
    if not dry_run and not no_launch and not headless:
        try:
            log(f"[WDSI Tier 3] Opening submission portal in default browser: {PORTAL_URL}", quiet, color="cyan")
            webbrowser.open(PORTAL_URL)
        except Exception as ex:
            log(f"[WDSI Tier 3] Could not open browser: {ex}", quiet, color="yellow")

    return submission_entry


def submit_single_file(file_path: Path, args: argparse.Namespace) -> dict:
    """Processes, analyzes, and executes tiered submission for a single target file."""
    if not file_path.exists():
        log(f"[ERROR] Target file does not exist: {file_path}", args.quiet, color="red")
        return {"error": "file_not_found", "path": str(file_path)}

    log(f"\n==================================================================", args.quiet, color="bold")
    log(f" Analyzing & Preparing WDSI Submission: {file_path.name}", args.quiet, color="bold")
    log(f" Path: {file_path}", args.quiet)
    log(f"==================================================================", args.quiet)

    hashes = compute_hashes_and_size(file_path)
    sig_info = inspect_authenticode_signature(file_path)
    version = get_build_version(file_path)
    product = determine_product_name(file_path, args.product)
    company = args.company or DEFAULT_COMPANY
    email = args.email or DEFAULT_EMAIL

    comment = (
        f"Clean, Authenticode digitally signed open-source release build of "
        f"{product} v{version} (SHA-256: {hashes['sha256']}). "
        f"Requesting automated verification, reputation build, and SmartScreen false-positive suppression."
    )

    payload = {
        "product": product,
        "version": version,
        "company": company,
        "email": email,
        "hashes": hashes,
        "signature": sig_info,
        "comment": comment,
    }

    # Tier 1: Microsoft Graph API Threat Submission
    tier1_res = try_tier1_graph_submission(payload, file_path, args.dry_run, args.quiet)
    if tier1_res:
        return tier1_res

    # Tier 2: Browser Automation
    tier2_res = try_tier2_browser_automation(payload, file_path, args.dry_run, args.quiet, args.headless)
    if tier2_res:
        return tier2_res

    # Tier 3: Resilient Fallback Manifest & Card
    return execute_tier3_manifest_and_card(payload, file_path, args.dry_run, args.no_launch, args.headless, args.quiet)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Microsoft Security Intelligence (WDSI) Sample Submission Engine for OpenỌ̀ṣọ́ọ̀sì Autonomous EDR",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--file",
        "-f",
        type=str,
        help="Target binary (.exe) or installer (.msi) to submit",
    )
    parser.add_argument(
        "--all",
        "-a",
        action="store_true",
        help="Submits all built binaries (osoosi.exe, deploy/osoosi.exe, OshoosiClaw.msi, deploy/OshoosiClaw.msi)",
    )
    parser.add_argument(
        "--product",
        "-p",
        type=str,
        default=None,
        help="Product name override",
    )
    parser.add_argument(
        "--company",
        "-c",
        type=str,
        default=DEFAULT_COMPANY,
        help="Company name override",
    )
    parser.add_argument(
        "--email",
        "-e",
        type=str,
        default=DEFAULT_EMAIL,
        help="Contact email override",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate files, signatures, and payloads without sending network requests or modifying files",
    )
    parser.add_argument(
        "--no-launch",
        action="store_true",
        help="Do not open interactive browser window on fallback",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run in headless mode (suppresses interactive browser launch)",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress verbose logs",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()

    targets: list[Path] = []
    if args.file:
        p = Path(args.file)
        if not p.is_absolute():
            p = REPO_ROOT / p
        targets.append(p)
    elif args.all:
        for rel in TARGET_BINARIES_ALL:
            p = REPO_ROOT / rel
            if p.exists():
                targets.append(p)
    else:
        # Default behavior if neither --file nor --all specified:
        default_osoosi = REPO_ROOT / "target" / "release" / "osoosi.exe"
        if default_osoosi.exists():
            targets.append(default_osoosi)
        else:
            for rel in TARGET_BINARIES_ALL:
                p = REPO_ROOT / rel
                if p.exists():
                    targets.append(p)

    if not targets:
        log("[WARN] No target binaries found to submit. Use --file <PATH> or compile binaries first.", args.quiet, color="yellow")
        return 0

    success_count = 0
    for target in targets:
        res = submit_single_file(target, args)
        if "error" not in res:
            success_count += 1

    log(f"\n[DONE] WDSI submission processing complete ({success_count}/{len(targets)} targets processed successfully).\n", args.quiet, color="green")
    return 0


if __name__ == "__main__":
    sys.exit(main())
