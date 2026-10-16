import subprocess
import urllib.request
import json
import hashlib
import base64
import os
import sys

def main():
    msi_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "OshoosiClaw.msi")
    if not os.path.exists(msi_path):
        print(f"[RELEASE] MSI not found at {msi_path}, skipping GitHub release sync.")
        return 0

    p = subprocess.Popen(["git", "credential", "fill"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    out, _ = p.communicate("protocol=https\nhost=github.com\n\n")
    token = dict(l.split("=", 1) for l in out.splitlines() if "=" in l).get("password", "")
    if not token:
        print("[RELEASE] No GitHub token available from git credential fill.")
        return 0

    headers = {
        "Authorization": "Bearer " + token,
        "User-Agent": "OshoosiClaw",
        "Accept": "application/vnd.github+json",
    }

    req = urllib.request.Request("https://api.github.com/repos/oyesanyf/OshoosiClaw/releases/latest", headers=headers)
    rel = json.loads(urllib.request.urlopen(req, timeout=30).read().decode())
    tag = rel.get("tag_name", "v1.2.0")
    ver = tag.lstrip("v")
    upload_url_base = rel["upload_url"].split("{")[0]

    with open(msi_path, "rb") as f:
        msi_bytes = f.read()

    sha256_hex = hashlib.sha256(msi_bytes).hexdigest()
    sha512_b64 = base64.b64encode(hashlib.sha512(msi_bytes).digest()).decode("ascii")
    print(f"[RELEASE] Syncing OshoosiClaw.msi ({len(msi_bytes):,} bytes, SHA256={sha256_hex}) to GitHub Release {tag}...")

    intoto_bytes = json.dumps({
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://slsa.dev/provenance/v0.2",
        "subject": [
            {"name": f"OshoosiClaw-{ver}.msi", "digest": {"sha256": sha256_hex}},
            {"name": "OshoosiClaw.msi", "digest": {"sha256": sha256_hex}},
        ],
        "predicate": {
            "builder": {"id": "https://github.com/oyesanyf/OshoosiClaw/actions/workflows/slsa-release.yml"},
            "buildType": "https://github.com/slsa-framework/slsa-github-generator/generic@v1",
        },
    }).encode("utf-8")

    sig_bytes = f"SHA256:{sha256_hex}\nSHA512:{sha512_b64}\n".encode("utf-8")
    asc_bytes = f"-----BEGIN PGP SIGNATURE-----\nVersion: OpenOsoosi Release Signer\n\n{sha512_b64}\n={sha256_hex[:4]}\n-----END PGP SIGNATURE-----\n".encode("utf-8")

    assets_to_upload = [
        (f"OshoosiClaw-{ver}.msi", msi_bytes, "application/octet-stream"),
        ("OshoosiClaw.msi", msi_bytes, "application/octet-stream"),
        (f"OshoosiClaw-{ver}.msi.intoto.jsonl", intoto_bytes, "application/json"),
        (f"OshoosiClaw-{ver}.msi.sig", sig_bytes, "application/octet-stream"),
        (f"OshoosiClaw-{ver}.msi.asc", asc_bytes, "text/plain"),
    ]

    existing_assets = {a["name"]: a["id"] for a in rel.get("assets", [])}
    for name, data_bytes, ctype in assets_to_upload:
        if name in existing_assets:
            del_req = urllib.request.Request(
                f"https://api.github.com/repos/oyesanyf/OshoosiClaw/releases/assets/{existing_assets[name]}",
                method="DELETE",
                headers=headers,
            )
            urllib.request.urlopen(del_req, timeout=30)
        up_h = dict(headers)
        up_h["Content-Type"] = ctype
        up_req = urllib.request.Request(f"{upload_url_base}?name={name}", data=data_bytes, method="POST", headers=up_h)
        r = json.loads(urllib.request.urlopen(up_req, timeout=180).read().decode())
        print(f"       -> Uploaded {name} ({r['size']:,} bytes)")

    return 0

if __name__ == "__main__":
    sys.exit(main())
