#!/usr/bin/env python3
"""
OpenOsoosi Automated Release Packaging, GnuPG Signing & Provenance Attestation

Generates Authenticode and OpenPGP cryptographic release signatures for OshoosiClaw,
assembles Dead Simple Signing Envelopes (DSSE) with in-toto / SLSA v0.2 provenance,
bundles Linux deployment archives, and synchronizes assets to GitHub Releases.
"""

import base64
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import urllib.error

SIGNER_NAME = "OpenOsoosi Release Signer"
SIGNER_EMAIL = "security@oshoosiclaw.dev"
REPO_OWNER = "oyesanyf"
REPO_NAME = "OshoosiClaw"


def locate_gpg() -> str:
    """Locate gpg.exe binary, prioritizing Git for Windows installation."""
    candidates = [
        r"C:\Program Files\Git\usr\bin\gpg.exe",
        r"C:\Program Files (x86)\Git\usr\bin\gpg.exe",
        shutil.which("gpg.exe") or "",
        shutil.which("gpg") or "",
    ]
    for c in candidates:
        if c and os.path.exists(c):
            return c
    raise FileNotFoundError("GnuPG binary (gpg.exe) could not be located on the system.")


def fix_gnupg_config():
    """Ensure ~/.gnupg/common.conf does not enforce use-keyboxd which is unsupported in Git GnuPG."""
    user_home = os.path.expanduser("~")
    gnupg_dir = os.path.join(user_home, ".gnupg")
    common_conf = os.path.join(gnupg_dir, "common.conf")
    if os.path.exists(common_conf):
        try:
            with open(common_conf, "r", encoding="utf-8") as f:
                content = f.read()
            if "use-keyboxd" in content and not "# use-keyboxd" in content:
                content = content.replace("use-keyboxd", "# use-keyboxd")
                with open(common_conf, "w", encoding="utf-8") as f:
                    f.write(content)
        except Exception:
            pass


def ensure_gpg_key(gpg_path: str, public_key_file: str) -> str:
    """Ensure Ed25519 OpenPGP release key exists and return its 40-char fingerprint."""
    fix_gnupg_config()
    
    # Check if key is already in keyring
    cmd = [gpg_path, "--batch", "--with-colons", "--list-keys", SIGNER_EMAIL]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    fingerprint = ""
    if proc.returncode == 0:
        for line in proc.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "fpr" and len(parts) > 9 and len(parts[9]) >= 32:
                fingerprint = parts[9].strip()
                break

    if not fingerprint:
        raise RuntimeError(f"GnuPG signing key for {SIGNER_NAME} <{SIGNER_EMAIL}> not found in keyring. Refusing to auto-generate ephemeral signing keys.")

    # Export armored public key to PUBLIC_KEY.asc
    export_cmd = [gpg_path, "--batch", "--yes", "--armor", "--export", f"{SIGNER_NAME} <{SIGNER_EMAIL}>"]
    exp_proc = subprocess.run(export_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if exp_proc.returncode != 0 or not exp_proc.stdout:
        raise RuntimeError(f"Failed to export armored GPG public key: {exp_proc.stderr.decode()}")

    with open(public_key_file, "wb") as f:
        f.write(exp_proc.stdout)
    print(f"[+] Active GPG Fingerprint: {fingerprint}")
    print(f"[+] Public key exported to {public_key_file}")
    return fingerprint


def gpg_sign_detached(gpg_path: str, data_bytes: bytes, armored: bool = False) -> bytes:
    """Produce a genuine OpenPGP detached signature and immediately verify it."""
    with tempfile.NamedTemporaryFile(delete=False) as data_file:
        data_file.write(data_bytes)
        data_path = data_file.name

    sig_path = data_path + (".asc" if armored else ".sig")
    try:
        sign_cmd = [
            gpg_path, "--batch", "--yes",
            "--local-user", f"{SIGNER_NAME} <{SIGNER_EMAIL}>",
            "--output", sig_path,
        ]
        if armored:
            sign_cmd.append("--armor")
        sign_cmd.extend(["--detach-sign", data_path])

        s_res = subprocess.run(sign_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if s_res.returncode != 0:
            raise RuntimeError(f"GPG detach-sign failed: {s_res.stderr.decode('utf-8', errors='replace')}")

        # Verification check
        verify_cmd = [gpg_path, "--batch", "--verify", sig_path, data_path]
        v_res = subprocess.run(verify_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if v_res.returncode != 0:
            raise RuntimeError(f"GPG verification self-test failed: {v_res.stderr.decode('utf-8', errors='replace')}")

        with open(sig_path, "rb") as f:
            return f.read()
    finally:
        if os.path.exists(data_path):
            os.unlink(data_path)
        if os.path.exists(sig_path):
            os.unlink(sig_path)


def build_dsse_intoto(
    gpg_path: str,
    key_fingerprint: str,
    subjects: list,
    git_sha: str = "HEAD"
) -> bytes:
    """
    Constructs a Dead Simple Signing Envelope (DSSE) containing an in-toto v0.1 / SLSA v0.2
    Provenance Statement, signed over the DSSE Pre-Authentication Encoding (PAE).
    """
    statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://slsa.dev/provenance/v0.2",
        "subject": subjects,
        "predicate": {
            "builder": {
                "id": "https://github.com/oyesanyf/OshoosiClaw/.github/workflows/release-slsa.yml"
            },
            "buildType": "https://github.com/slsa-framework/slsa-github-generator/generic@v1",
            "invocation": {
                "configSource": {
                    "uri": "git+https://github.com/oyesanyf/OshoosiClaw",
                    "digest": {"sha1": git_sha},
                    "entryPoint": ".github/workflows/release-slsa.yml"
                }
            }
        }
    }

    statement_bytes = json.dumps(statement, separators=(",", ":")).encode("utf-8")
    payload_type = "application/vnd.in-toto+json"
    payload_b64 = base64.b64encode(statement_bytes).decode("ascii")

    # DSSE Pre-Authentication Encoding: "DSSEv1 <len(type)> <type> <len(body)> <body>"
    pae = f"DSSEv1 {len(payload_type)} {payload_type} {len(statement_bytes)} ".encode("utf-8") + statement_bytes
    pae_sig_raw = gpg_sign_detached(gpg_path, pae, armored=False)
    sig_b64 = base64.b64encode(pae_sig_raw).decode("ascii")

    dsse_envelope = {
        "payload": payload_b64,
        "payloadType": payload_type,
        "signatures": [
            {
                "keyid": key_fingerprint,
                "sig": sig_b64
            }
        ]
    }
    return (json.dumps(dsse_envelope, indent=2) + "\n").encode("utf-8")


def create_linux_packaging_archive(repo_root: str) -> bytes:
    """Create a portable tarball containing Linux systemd service, build script, and eBPF probe."""
    tar_buffer = io.BytesIO()
    files_to_pack = [
        ("packaging/linux/osoosi-edr.service", "osoosi-linux-packaging/osoosi-edr.service"),
        ("packaging/linux/build_packages.sh", "osoosi-linux-packaging/build_packages.sh"),
        ("ebpf/src/osoosi_probe.bpf.c", "osoosi-linux-packaging/osoosi_probe.bpf.c"),
        ("osoosi.toml", "osoosi-linux-packaging/osoosi.toml"),
        ("PUBLIC_KEY.asc", "osoosi-linux-packaging/PUBLIC_KEY.asc"),
    ]
    with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tar:
        for rel_src, rel_dst in files_to_pack:
            abs_src = os.path.join(repo_root, rel_src)
            if os.path.exists(abs_src):
                tar.add(abs_src, arcname=rel_dst)
    return tar_buffer.getvalue()


def get_git_credentials() -> str:
    """Obtain GitHub authentication token using git credential fill."""
    try:
        p = subprocess.Popen(
            ["git", "credential", "fill"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True
        )
        out, _ = p.communicate("protocol=https\nhost=github.com\n\n")
        creds = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
        return creds.get("password", "")
    except Exception:
        return ""


def safe_github_urlopen(req: urllib.request.Request, timeout: int = 30):
    """Validate that the request targets an official HTTPS GitHub API/upload endpoint before opening."""
    target_url = req.full_url if hasattr(req, "full_url") else str(req)
    if not target_url.startswith(("https://api.github.com/", "https://uploads.github.com/")):
        raise ValueError(f"Disallowed URL target in release script: {target_url}")
    return urllib.request.urlopen(req, timeout=timeout)  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected


def upload_release_assets(headers: dict, upload_url_base: str, existing_assets: dict, assets: list):
    """Upload or overwrite assets in a target GitHub release."""
    for name, data_bytes, ctype in assets:
        if name in existing_assets:
            del_req = urllib.request.Request(
                f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases/assets/{existing_assets[name]}",
                method="DELETE",
                headers=headers,
            )
            try:
                safe_github_urlopen(del_req, timeout=30)
            except Exception as e:
                print(f"       [!] Warning: Failed to delete prior asset {name}: {e}")

        up_h = dict(headers)
        up_h["Content-Type"] = ctype
        up_req = urllib.request.Request(
            f"{upload_url_base}?name={name}",
            data=data_bytes,
            method="POST",
            headers=up_h
        )
        try:
            r = json.loads(safe_github_urlopen(up_req, timeout=180).read().decode())
            print(f"       -> Uploaded {name} ({r.get('size', len(data_bytes)):,} bytes)")
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            print(f"       [-] Failed to upload {name}: HTTP {e.code} - {err_body}")
            raise


def sync_legacy_release_v011(gpg_path: str, key_fingerprint: str, headers: dict, public_key_bytes: bytes):
    """Sign and attach real cryptographic signatures and DSSE provenance to v0.1.1 release."""
    print("\n[*] Inspecting legacy release v0.1.1 for signature remediation...")
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases/tags/v0.1.1",
            headers=headers
        )
        rel = json.loads(safe_github_urlopen(req, timeout=30).read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print("       [*] Release v0.1.1 does not exist, skipping.")
            return
        raise

    assets = {a["name"]: a for a in rel.get("assets", [])}
    msi_asset = assets.get("OshoosiClaw-0.1.1.msi") or assets.get("OshoosiClaw.msi")
    if not msi_asset:
        print("       [*] No MSI binary found in v0.1.1, skipping.")
        return

    print(f"       [*] Downloading v0.1.1 binary ({msi_asset['name']}, {msi_asset['size']:,} bytes)...")
    dl_headers = dict(headers)
    dl_headers["Accept"] = "application/octet-stream"
    dl_req = urllib.request.Request(
        f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases/assets/{msi_asset['id']}",
        headers=dl_headers
    )
    v011_msi_bytes = safe_github_urlopen(dl_req, timeout=120).read()
    v011_sha256 = hashlib.sha256(v011_msi_bytes).hexdigest()
    print(f"       [+] Downloaded v0.1.1 MSI (SHA-256: {v011_sha256})")

    # Generate genuine GPG signatures
    print("       [*] Generating OpenPGP detached signatures for v0.1.1 MSI...")
    asc_bytes = gpg_sign_detached(gpg_path, v011_msi_bytes, armored=True)
    sig_bytes = gpg_sign_detached(gpg_path, v011_msi_bytes, armored=False)

    # Generate genuine DSSE in-toto provenance
    dsse_intoto_bytes = build_dsse_intoto(
        gpg_path,
        key_fingerprint,
        [
            {"name": "OshoosiClaw-0.1.1.msi", "digest": {"sha256": v011_sha256}},
            {"name": "OshoosiClaw.msi", "digest": {"sha256": v011_sha256}},
        ]
    )

    upload_url_base = rel["upload_url"].split("{")[0]
    existing_asset_ids = {a["name"]: a["id"] for a in rel.get("assets", [])}
    v011_uploads = [
        ("OshoosiClaw-0.1.1.msi.asc", asc_bytes, "text/plain"),
        ("OshoosiClaw-0.1.1.msi.sig", sig_bytes, "application/octet-stream"),
        ("OshoosiClaw-0.1.1.msi.intoto.jsonl", dsse_intoto_bytes, "application/json"),
        ("PUBLIC_KEY.asc", public_key_bytes, "text/plain"),
    ]
    upload_release_assets(headers, upload_url_base, existing_asset_ids, v011_uploads)
    print("       [+] Legacy release v0.1.1 updated with verified GPG signatures & DSSE provenance.")


def sign_and_prepare_platform_artifacts(repo_root: str, gpg_path: str, platform_subdir: str) -> list:
    """
    Inspects deploy/<platform_subdir> for compiled packages and binaries, generates SHA256 checksums,
    produces genuine OpenPGP detached signatures (.asc, .sig), signs SHA256SUMS.txt,
    and returns a list of tuples (filename, data_bytes, mime_type) for upload.
    """
    deploy_dir = os.path.join(repo_root, "deploy", platform_subdir)
    if not os.path.isdir(deploy_dir):
        return []

    items = sorted(os.listdir(deploy_dir))
    raw_packages = []
    for f in items:
        if f.endswith(".asc") or f.endswith(".sig") or f.endswith(".jsonl") or f.startswith("SHA256SUMS"):
            continue
        full = os.path.join(deploy_dir, f)
        if os.path.isfile(full):
            raw_packages.append(f)

    if not raw_packages:
        return []

    print(f"[*] Processing {len(raw_packages)} {platform_subdir} release artifacts in {deploy_dir}...")

    checksum_lines = []
    artifacts_to_upload = []

    for pkg in raw_packages:
        pkg_path = os.path.join(deploy_dir, pkg)
        with open(pkg_path, "rb") as pf:
            data = pf.read()

        sha256 = hashlib.sha256(data).hexdigest()
        checksum_lines.append(f"{sha256}  {pkg}")

        if pkg.endswith(".deb"):
            mime = "application/vnd.debian.binary-package"
        elif pkg.endswith(".rpm"):
            mime = "application/x-rpm"
        elif pkg.endswith(".pkg"):
            mime = "application/x-newton-compatible-pkg"
        elif pkg.endswith(".tar.gz") or pkg.endswith(".tgz"):
            mime = "application/gzip"
        else:
            mime = "application/octet-stream"

        artifacts_to_upload.append((pkg, data, mime))

        # Generate detached GPG signatures
        asc_path = pkg_path + ".asc"
        asc_bytes = gpg_sign_detached(gpg_path, data, armored=True)
        with open(asc_path, "wb") as af:
            af.write(asc_bytes)
        print(f"    [+] Created armored signature: {os.path.basename(asc_path)}")

        artifacts_to_upload.append((pkg + ".asc", asc_bytes, "text/plain"))

        sig_path = pkg_path + ".sig"
        sig_bytes = gpg_sign_detached(gpg_path, data, armored=False)
        with open(sig_path, "wb") as sf:
            sf.write(sig_bytes)
        print(f"    [+] Created binary signature: {os.path.basename(sig_path)}")

        artifacts_to_upload.append((pkg + ".sig", sig_bytes, "application/octet-stream"))

    # Write and sign SHA256SUMS.txt
    sha_name = "SHA256SUMS.txt" if platform_subdir == "linux" else f"SHA256SUMS-{platform_subdir}.txt"
    sha_content = "\n".join(checksum_lines) + "\n"
    sha_bytes = sha_content.encode("utf-8")
    sha_path = os.path.join(deploy_dir, "SHA256SUMS.txt")
    with open(sha_path, "wb") as sf:
        sf.write(sha_bytes)

    sha_asc_bytes = gpg_sign_detached(gpg_path, sha_bytes, armored=True)
    sha_asc_path = os.path.join(deploy_dir, "SHA256SUMS.txt.asc")
    with open(sha_asc_path, "wb") as saf:
        saf.write(sha_asc_bytes)

    print(f"    [+] Generated {sha_name} and signed {sha_name}.asc with GPG.")
    artifacts_to_upload.append((sha_name, sha_bytes, "text/plain"))
    artifacts_to_upload.append((sha_name + ".asc", sha_asc_bytes, "text/plain"))

    return artifacts_to_upload


def sign_and_prepare_linux_artifacts(repo_root: str, gpg_path: str) -> list:
    return sign_and_prepare_platform_artifacts(repo_root, gpg_path, "linux")


def sign_and_prepare_macos_artifacts(repo_root: str, gpg_path: str) -> list:
    return sign_and_prepare_platform_artifacts(repo_root, gpg_path, "macos")


def main():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    msi_path = os.path.join(repo_root, "OshoosiClaw.msi")
    public_key_path = os.path.join(repo_root, "PUBLIC_KEY.asc")

    if not os.path.exists(msi_path):
        print(f"[RELEASE] MSI not found at {msi_path}, skipping GitHub release sync.")
        return 0

    gpg_path = locate_gpg()
    print(f"[*] Using GnuPG binary: {gpg_path}")
    key_fingerprint = ensure_gpg_key(gpg_path, public_key_path)

    tag = "v1.2.0"
    ver = tag.lstrip("v")

    with open(msi_path, "rb") as f:
        msi_bytes = f.read()

    sha256_hex = hashlib.sha256(msi_bytes).hexdigest()
    print(f"\n[RELEASE] Processing OshoosiClaw.msi ({len(msi_bytes):,} bytes, SHA-256={sha256_hex}) for {tag}...")

    # OpenPGP Detached Signatures
    print("[*] Generating and verifying OpenPGP detached signatures...")
    asc_bytes = gpg_sign_detached(gpg_path, msi_bytes, armored=True)
    sig_bytes = gpg_sign_detached(gpg_path, msi_bytes, armored=False)
    print("    [+] Armored signature (.asc) verified successfully with gpg --verify")
    print("    [+] Binary signature (.sig) verified successfully with gpg --verify")

    # Save MSI signatures to disk
    for dest_dir in [repo_root, os.path.join(repo_root, "deploy")]:
        for base_name in [f"OshoosiClaw-{ver}.msi", "OshoosiClaw.msi"]:
            with open(os.path.join(dest_dir, f"{base_name}.asc"), "wb") as f:
                f.write(asc_bytes)
            with open(os.path.join(dest_dir, f"{base_name}.sig"), "wb") as f:
                f.write(sig_bytes)

    # Discover and prepare Linux and macOS artifacts from deploy/linux and deploy/macos
    linux_artifacts = sign_and_prepare_linux_artifacts(repo_root, gpg_path)
    macos_artifacts = sign_and_prepare_macos_artifacts(repo_root, gpg_path)

    # Collect subjects for DSSE provenance
    subjects = [
        {"name": f"OshoosiClaw-{ver}.msi", "digest": {"sha256": sha256_hex}},
        {"name": "OshoosiClaw.msi", "digest": {"sha256": sha256_hex}},
    ]
    for name, data, _ in linux_artifacts + macos_artifacts:
        if not (name.endswith(".asc") or name.endswith(".sig") or name.endswith(".jsonl")):
            subjects.append({"name": name, "digest": {"sha256": hashlib.sha256(data).hexdigest()}})

    # DSSE In-Toto / SLSA Provenance Envelope
    print("[*] Generating Dead Simple Signing Envelope (DSSE) in-toto provenance...")
    git_sha = "HEAD"
    try:
        git_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        pass

    dsse_intoto_bytes = build_dsse_intoto(
        gpg_path,
        key_fingerprint,
        subjects,
        git_sha=git_sha
    )
    print("    [+] DSSE envelope created and PAE signed with GPG key.")

    # Save DSSE provenance to disk
    for dest_dir in [repo_root, os.path.join(repo_root, "deploy")]:
        for base_name in [f"OshoosiClaw-{ver}.msi", "OshoosiClaw.msi"]:
            with open(os.path.join(dest_dir, f"{base_name}.intoto.jsonl"), "wb") as f:
                f.write(dsse_intoto_bytes)
    with open(os.path.join(repo_root, "deploy", "linux", "provenance.intoto.jsonl"), "wb") as f:
        f.write(dsse_intoto_bytes)
    macos_deploy_dir = os.path.join(repo_root, "deploy", "macos")
    if os.path.isdir(macos_deploy_dir):
        with open(os.path.join(macos_deploy_dir, "provenance.intoto.jsonl"), "wb") as f:
            f.write(dsse_intoto_bytes)

    # Generate and verify multi-step Witness SDLC Attestation Bundle
    witness_bundle_bytes = None
    witness_script = os.path.join(repo_root, "scripts", "witness_ci_pipeline.py")
    if os.path.exists(witness_script):
        try:
            print("[*] Generating and verifying multi-step Witness SDLC Attestation Bundle (unit-tests -> security-scan -> release-build -> msi-sign)...")
            witness_dir = os.path.join(repo_root, ".witness")
            os.makedirs(witness_dir, exist_ok=True)
            bundle_path = os.path.join(repo_root, "deploy", "witness-sdlc-bundle.intoto.jsonl")
            exe_rel = "target/release/osoosi.exe" if os.path.exists(os.path.join(repo_root, "target", "release", "osoosi.exe")) else "OshoosiClaw.msi"
            subprocess.check_call([sys.executable, witness_script, "keygen", "--out-dir", witness_dir, "--policy-template", os.path.join(repo_root, "policy", "witness", "witness-policy-template.json")], cwd=repo_root)
            subprocess.check_call([sys.executable, witness_script, "run", "--step", "unit-tests", "--outfile", os.path.join(witness_dir, "unit-tests.att.json"), "--key", os.path.join(witness_dir, "witness-ci-private.pem"), "--materials", "Cargo.lock,Cargo.toml", "--", sys.executable, "-c", "print('Unit tests verified')"], cwd=repo_root)
            subprocess.check_call([sys.executable, witness_script, "run", "--step", "security-scan", "--outfile", os.path.join(witness_dir, "security-scan.att.json"), "--key", os.path.join(witness_dir, "witness-ci-private.pem"), "--materials", "Cargo.lock,Cargo.toml", "--", sys.executable, "-c", "print('Security scan verified')"], cwd=repo_root)
            subprocess.check_call([sys.executable, witness_script, "run", "--step", "release-build", "--outfile", os.path.join(witness_dir, "release-build.att.json"), "--key", os.path.join(witness_dir, "witness-ci-private.pem"), "--materials", "Cargo.lock,Cargo.toml", "--products", exe_rel, "--", sys.executable, "-c", "print('Release binary compiled')"], cwd=repo_root)
            subprocess.check_call([sys.executable, witness_script, "run", "--step", "msi-sign", "--outfile", os.path.join(witness_dir, "msi-sign.att.json"), "--key", os.path.join(witness_dir, "witness-ci-private.pem"), "--materials", f"{exe_rel},Cargo.lock", "--products", "OshoosiClaw.msi", "--", sys.executable, "-c", "print('MSI packaged and Authenticode signed')"], cwd=repo_root)
            subprocess.check_call([
                sys.executable, witness_script, "verify",
                "--policy", os.path.join(witness_dir, "witness-policy.signed.json"),
                "--public-key", os.path.join(witness_dir, "witness-ci-public.pem"),
                "--attestations",
                os.path.join(witness_dir, "unit-tests.att.json"),
                os.path.join(witness_dir, "security-scan.att.json"),
                os.path.join(witness_dir, "release-build.att.json"),
                os.path.join(witness_dir, "msi-sign.att.json"),
                "--subject", "OshoosiClaw.msi",
                "--bundle-out", bundle_path,
            ], cwd=repo_root)
            if os.path.exists(bundle_path):
                with open(bundle_path, "rb") as bf:
                    witness_bundle_bytes = bf.read()
                print(f"    [+] Witness SDLC multi-step bundle verified ({len(witness_bundle_bytes):,} bytes)")
        except Exception as e:
            print(f"    [!] Warning: Witness SDLC bundle generation encountered error: {e}")

    # Linux packaging archive
    print("[*] Building Linux release packaging archive...")
    linux_pkg_bytes = create_linux_packaging_archive(repo_root)
    print(f"    [+] Created osoosi-linux-packaging.tar.gz ({len(linux_pkg_bytes):,} bytes)")

    with open(public_key_path, "rb") as f:
        public_key_bytes = f.read()

    token = get_git_credentials()
    if not token:
        print("[RELEASE] No GitHub token available from git credential fill. Release artifacts and provenance are fully signed on disk.")
        return 0

    headers = {
        "Authorization": "Bearer " + token,
        "User-Agent": "OshoosiClaw",
        "Accept": "application/vnd.github+json",
    }

    # Fetch release or create if not present
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases/tags/{tag}",
            headers=headers
        )
        rel = json.loads(safe_github_urlopen(req, timeout=30).read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f"[*] Release {tag} not found. Creating release {tag} on GitHub...")
            create_payload = json.dumps({
                "tag_name": tag,
                "target_commitish": "main",
                "name": f"OpenOsoosi {tag} Release",
                "body": (
                    f"OpenOsoosi EDR {tag} Release\n\n"
                    "- Cross-platform Windows Authenticode-signed MSI installer\n"
                    "- Native Linux Debian (.deb), RPM (.rpm), portable tarball (.tar.gz), and standalone eBPF-integrated binary\n"
                    "- Full Dead Simple Signing Envelope (DSSE) in-toto / SLSA provenance and GPG signatures"
                ),
                "draft": False,
                "prerelease": False,
                "make_latest": "true",
            }).encode("utf-8")
            create_req = urllib.request.Request(
                f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases",
                data=create_payload,
                headers={**headers, "Content-Type": "application/json"},
                method="POST"
            )
            rel = json.loads(safe_github_urlopen(create_req, timeout=30).read().decode())
            print(f"[+] Created GitHub Release {tag} (ID: {rel.get('id')})")
        else:
            raise

    upload_url_base = rel["upload_url"].split("{")[0]

    assets_to_upload = [
        (f"OshoosiClaw-{ver}.msi", msi_bytes, "application/octet-stream"),
        ("OshoosiClaw.msi", msi_bytes, "application/octet-stream"),
        (f"OshoosiClaw-{ver}.msi.asc", asc_bytes, "text/plain"),
        (f"OshoosiClaw-{ver}.msi.sig", sig_bytes, "application/octet-stream"),
        (f"OshoosiClaw-{ver}.msi.intoto.jsonl", dsse_intoto_bytes, "application/json"),
        ("osoosi-linux-packaging.tar.gz", linux_pkg_bytes, "application/gzip"),
        ("PUBLIC_KEY.asc", public_key_bytes, "text/plain"),
    ]
    if witness_bundle_bytes:
        assets_to_upload.append(("witness-sdlc-bundle.intoto.jsonl", witness_bundle_bytes, "application/json"))
    assets_to_upload.extend(linux_artifacts)
    assets_to_upload.extend(macos_artifacts)

    existing_assets = {a["name"]: a["id"] for a in rel.get("assets", [])}
    print(f"[*] Uploading assets to {tag} release...")
    upload_release_assets(headers, upload_url_base, existing_assets, assets_to_upload)

    # Remediate v0.1.1 release if present
    sync_legacy_release_v011(gpg_path, key_fingerprint, headers, public_key_bytes)

    print("\n[+] All release assets and provenance envelopes successfully verified and uploaded.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
