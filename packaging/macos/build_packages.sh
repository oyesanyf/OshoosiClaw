#!/usr/bin/env bash
set -eu

# OpenOsoosi macOS Packaging Script
# Generates macOS portable (.tar.gz), application bundle (.app.tar.gz), and installer (.pkg) artifacts.

BINARY_PATH="${1:-target/release/osoosi}"
VERSION="${2:-1.2.0}"
INPUT_ARCH="${3:-universal}"
DIST_DIR="${4:-dist-macos}"
PACKAGE_NAME="${5:-oshoosiclaw}"

case "$INPUT_ARCH" in
    aarch64|arm64)
        MACOS_ARCH="arm64"
        ;;
    x86_64|amd64)
        MACOS_ARCH="x86_64"
        ;;
    *)
        MACOS_ARCH="universal"
        ;;
esac

echo "[*] Packaging OpenOsoosi EDR v${VERSION} for macOS (${MACOS_ARCH})"
echo "[*] Binary source: ${BINARY_PATH}"

if [ ! -f "$BINARY_PATH" ]; then
    echo "[-] Error: Binary not found at ${BINARY_PATH}" >&2
    exit 1
fi

BINARY_PATH="$(cd "$(dirname "${BINARY_PATH}")" && pwd)/$(basename "${BINARY_PATH}")"
mkdir -p "${DIST_DIR}"
DIST_DIR="$(cd "${DIST_DIR}" && pwd)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PLIST_DEV_FILE="${SCRIPT_DIR}/dev.oshoosiclaw.edr.plist"
PLIST_COM_FILE="${SCRIPT_DIR}/com.oshoosiclaw.edr.plist"
CONFIG_FILE="${ROOT_DIR}/osoosi.toml"
PUBLIC_KEY_FILE="${ROOT_DIR}/PUBLIC_KEY.asc"
INSTALL_SH="${SCRIPT_DIR}/install.sh"
UNINSTALL_SH="${SCRIPT_DIR}/uninstall.sh"

# 1. Portable macOS Tarball (.tar.gz)
TAR_STAGING="$(mktemp -d)/${PACKAGE_NAME}-${VERSION}-macos-${MACOS_ARCH}"
mkdir -p "${TAR_STAGING}"

install -m 755 "${BINARY_PATH}" "${TAR_STAGING}/osoosi"
if [ -f "${PLIST_COM_FILE}" ]; then
    install -m 644 "${PLIST_COM_FILE}" "${TAR_STAGING}/com.oshoosiclaw.edr.plist"
fi
if [ -f "${PLIST_DEV_FILE}" ]; then
    install -m 644 "${PLIST_DEV_FILE}" "${TAR_STAGING}/dev.oshoosiclaw.edr.plist"
fi
if [ -f "${CONFIG_FILE}" ]; then
    install -m 640 "${CONFIG_FILE}" "${TAR_STAGING}/osoosi.toml"
fi
if [ -f "${PUBLIC_KEY_FILE}" ]; then
    install -m 644 "${PUBLIC_KEY_FILE}" "${TAR_STAGING}/PUBLIC_KEY.asc"
fi
if [ -f "${INSTALL_SH}" ]; then
    install -m 755 "${INSTALL_SH}" "${TAR_STAGING}/install.sh"
fi
if [ -f "${UNINSTALL_SH}" ]; then
    install -m 755 "${UNINSTALL_SH}" "${TAR_STAGING}/uninstall.sh"
fi

TAR_OUT="${DIST_DIR}/${PACKAGE_NAME}-${VERSION}-macos-${MACOS_ARCH}.tar.gz"
tar -czf "${TAR_OUT}" -C "$(dirname "${TAR_STAGING}")" "$(basename "${TAR_STAGING}")"
echo "[+] Created: ${TAR_OUT}"

# Mirror only the single canonical artifact to deploy/macos
DEPLOY_MACOS="${ROOT_DIR}/deploy/macos"
mkdir -p "${DEPLOY_MACOS}"
rm -f "${DEPLOY_MACOS}/${PACKAGE_NAME}-${VERSION}-darwin-${MACOS_ARCH}.tar.gz"* \
      "${DEPLOY_MACOS}/osoosi-edr-${VERSION}-macos-${MACOS_ARCH}.tar.gz"* 2>/dev/null || true
cp -f "${TAR_OUT}" "${DEPLOY_MACOS}/${PACKAGE_NAME}-${VERSION}-macos-${MACOS_ARCH}.tar.gz"

rm -rf "$(dirname "${TAR_STAGING}")"
echo "[+] macOS packaging complete (single canonical artifact per format). Artifacts in ${DIST_DIR}:"
ls -la "${DIST_DIR}"
