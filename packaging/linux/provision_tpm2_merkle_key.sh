#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# OpenỌ̀ṣọ́ọ̀sì EDR — TPM 2.0 Hardware-Signed BLAKE3 Merkle Root Provisioner
# ==============================================================================
# Implements the 4-step hardware root-of-trust workflow on Linux (/dev/tpmrm0):
#   1. Provision a non-exportable primary & child ECC P-256 signing key inside
#      the TPM 2.0 Owner hierarchy and persist it at handle 0x81010002, plus
#      initialize the NV Monotonic Audit Counter at handle 0x01800001.
#   2. Compute the 32-byte raw BLAKE3 Merkle root of the target binary
#      (b3sum --raw) and sign SHA256(BLAKE3_Root) using the hardware-bound key
#      at 0x81010002 (tpm2_sign -c 0x81010002 -g sha256).
#   3. Enable Linux kernel fs-verity (fsverity enable) on the binary so the VFS
#      verifies 4 KB Merkle pages in-kernel and exposes the root to eBPF LSM
#      (bpf_get_fsverity_digest).
#   4. Verify the hardware signature offline/at runtime via tpm2_verifysignature.
# ==============================================================================

BINARY_PATH="${1:-/usr/local/bin/osoosi}"
TPM_PERSISTENT_HANDLE="${TPM_PERSISTENT_HANDLE:-0x81010002}"
TPM_NV_COUNTER_HANDLE="${TPM_NV_COUNTER_HANDLE:-0x01800001}"
WORK_DIR="$(mktemp -d -t osoosi-tpm2-merkle.XXXXXX)"
trap 'rm -rf "${WORK_DIR}"' EXIT

echo "[*] OpenỌ̀ṣọ́ọ̀sì TPM 2.0 BLAKE3 Merkle Root Provisioning & Signing"
echo "[*] Target Binary     : ${BINARY_PATH}"
echo "[*] Persistent Handle : ${TPM_PERSISTENT_HANDLE}"
echo "[*] NV Counter Handle : ${TPM_NV_COUNTER_HANDLE}"

if [ ! -e "/dev/tpmrm0" ] && [ ! -e "/dev/tpm0" ]; then
    echo "[!] Warning: /dev/tpmrm0 not detected on this host. Skipping physical tpm2-tools invocation." >&2
    exit 0
fi

for cmd in tpm2_createprimary tpm2_create tpm2_load tpm2_evictcontrol tpm2_sign tpm2_verifysignature b3sum; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[-] Required tool '$cmd' not found in PATH." >&2
        exit 1
    fi
done

# ------------------------------------------------------------------------------
# Step 1: Provision Persistent Signing Key (0x81010002) & NV Counter (0x01800001)
# ------------------------------------------------------------------------------
if ! tpm2_readpublic -c "${TPM_PERSISTENT_HANDLE}" >/dev/null 2>&1; then
    echo "[1/4] Provisioning non-exportable ECC P-256 signing key inside TPM 2.0 (${TPM_PERSISTENT_HANDLE})..."
    # Create Primary Key in the Owner Hierarchy
    tpm2_createprimary -C o -g sha256 -G ecc -c "${WORK_DIR}/primary.ctx"

    # Create child signing key (fixedtpm | fixedparent | sensitiveDataOrigin | userWithAuth | sign)
    tpm2_create -C "${WORK_DIR}/primary.ctx" -g sha256 -G ecc \
        -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign" \
        -u "${WORK_DIR}/merkle_key.pub" \
        -r "${WORK_DIR}/merkle_key.priv"

    # Load key into TPM and make it persistent at 0x81010002
    tpm2_load -C "${WORK_DIR}/primary.ctx" \
        -u "${WORK_DIR}/merkle_key.pub" \
        -r "${WORK_DIR}/merkle_key.priv" \
        -c "${WORK_DIR}/merkle_key.ctx"
    tpm2_evictcontrol -C o -c "${WORK_DIR}/merkle_key.ctx" "${TPM_PERSISTENT_HANDLE}"
    echo "    [+] Persistent signing key provisioned at ${TPM_PERSISTENT_HANDLE}."
else
    echo "[1/4] Persistent signing key already active at ${TPM_PERSISTENT_HANDLE}."
fi

# Provision & increment NV Monotonic Counter (Policy 3: Anti-Rollback Protection)
if ! tpm2_nvreadpublic "${TPM_NV_COUNTER_HANDLE}" >/dev/null 2>&1; then
    echo "    [*] Defining TPM 2.0 NV Monotonic Counter at ${TPM_NV_COUNTER_HANDLE}..."
    tpm2_nvdefine "${TPM_NV_COUNTER_HANDLE}" -C o -s 8 -a "ownerwrite|ownerread|nt=counter" || true
fi
echo "    [*] Incrementing TPM 2.0 NV Monotonic Counter (${TPM_NV_COUNTER_HANDLE})..."
tpm2_nvincrement "${TPM_NV_COUNTER_HANDLE}" -C o || true

# ------------------------------------------------------------------------------
# Step 2: Compute Raw 32-Byte BLAKE3 Root & Sign SHA256(BLAKE3_Root) in Hardware
# ------------------------------------------------------------------------------
if [ ! -f "${BINARY_PATH}" ]; then
    echo "[-] Target binary not found at ${BINARY_PATH}" >&2
    exit 1
fi

B3_OUT="${BINARY_PATH}.b3"
SIG_OUT="${BINARY_PATH}.sig"

echo "[2/4] Computing 32-byte raw BLAKE3 Merkle root -> ${B3_OUT}"
b3sum --raw "${BINARY_PATH}" > "${B3_OUT}"

echo "    [*] Signing SHA256(BLAKE3_Root) via TPM 2.0 handle ${TPM_PERSISTENT_HANDLE} -> ${SIG_OUT}"
rm -f "${SIG_OUT}"
tpm2_sign -c "${TPM_PERSISTENT_HANDLE}" -g sha256 -s ecdsa -o "${SIG_OUT}" "${B3_OUT}"

# ------------------------------------------------------------------------------
# Step 3: Enable Linux Kernel fs-verity on the Binary (if supported by FS)
# ------------------------------------------------------------------------------
echo "[3/4] Enabling Linux kernel fs-verity on ${BINARY_PATH}..."
if command -v fsverity >/dev/null 2>&1; then
    fsverity enable "${BINARY_PATH}" 2>/dev/null || echo "    [i] fsverity already enabled or filesystem does not support verity ioctl."
else
    echo "    [i] 'fsverity' utility not installed; skipping VFS verity ioctl."
fi

# ------------------------------------------------------------------------------
# Step 4: Verify Hardware Signature at Runtime
# ------------------------------------------------------------------------------
echo "[4/4] Verifying TPM 2.0 hardware signature against ${B3_OUT}..."
tpm2_verifysignature -c "${TPM_PERSISTENT_HANDLE}" -g sha256 -s ecdsa -m "${B3_OUT}" -s "${SIG_OUT}"
echo "[+] SUCCESS: ${BINARY_PATH} BLAKE3 Merkle Root is hardware-signed and verified by TPM 2.0 (${TPM_PERSISTENT_HANDLE})."
