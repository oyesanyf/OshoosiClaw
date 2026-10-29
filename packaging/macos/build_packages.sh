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
cp -f "${TAR_OUT}" "${DIST_DIR}/osoosi-edr-${VERSION}-macos-${MACOS_ARCH}.tar.gz" 2>/dev/null || true
cp -f "${TAR_OUT}" "${DIST_DIR}/${PACKAGE_NAME}-${VERSION}-darwin-${MACOS_ARCH}.tar.gz" 2>/dev/null || true

# Mirror to deploy/macos if exists or requested
DEPLOY_MACOS="${ROOT_DIR}/deploy/macos"
mkdir -p "${DEPLOY_MACOS}"
cp -f "${TAR_OUT}" "${DEPLOY_MACOS}/${PACKAGE_NAME}-${VERSION}-darwin-${MACOS_ARCH}.tar.gz"
cp -f "${TAR_OUT}" "${DEPLOY_MACOS}/${PACKAGE_NAME}-${VERSION}-macos-${MACOS_ARCH}.tar.gz"
cp -f "${TAR_OUT}" "${DEPLOY_MACOS}/osoosi-edr-${VERSION}-macos-${MACOS_ARCH}.tar.gz" 2>/dev/null || true

# 2. macOS Application Bundle (OshoosiClaw.app.tar.gz)
APP_STAGING="$(mktemp -d)"
APP_BUNDLE="${APP_STAGING}/OshoosiClaw.app/Contents"
mkdir -p "${APP_BUNDLE}/MacOS" "${APP_BUNDLE}/Resources"
install -m 755 "${BINARY_PATH}" "${APP_BUNDLE}/MacOS/osoosi"
if [ -f "${CONFIG_FILE}" ]; then
    install -m 640 "${CONFIG_FILE}" "${APP_BUNDLE}/Resources/osoosi.toml"
fi
cat <<EOF > "${APP_BUNDLE}/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>osoosi</string>
    <key>CFBundleIdentifier</key>
    <string>dev.oshoosiclaw.edr</string>
    <key>CFBundleName</key>
    <string>OshoosiClaw</string>
    <key>CFBundleDisplayName</key>
    <string>OshoosiClaw Autonomous EDR</string>
    <key>CFBundleVersion</key>
    <string>${VERSION}</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
</dict>
</plist>
EOF

APP_OUT="${DIST_DIR}/OshoosiClaw-${VERSION}-macos-${MACOS_ARCH}.app.tar.gz"
tar -czf "${APP_OUT}" -C "${APP_STAGING}" "OshoosiClaw.app"
echo "[+] Created: ${APP_OUT}"

# 3. macOS Installer Package (.pkg) if pkgbuild is available, or portable xar/cpio fallback
PKG_OUT="${DIST_DIR}/OshoosiClaw-${VERSION}-macos-${MACOS_ARCH}.pkg"
if command -v pkgbuild >/dev/null 2>&1; then
    PKG_ROOT="$(mktemp -d)/pkgroot"
    mkdir -p "${PKG_ROOT}/usr/local/bin" "${PKG_ROOT}/etc/osoosi" "${PKG_ROOT}/Library/LaunchDaemons"
    install -m 755 "${BINARY_PATH}" "${PKG_ROOT}/usr/local/bin/osoosi"
    if [ -f "${CONFIG_FILE}" ]; then
        install -m 640 "${CONFIG_FILE}" "${PKG_ROOT}/etc/osoosi/osoosi.toml"
    fi
    if [ -f "${PLIST_COM_FILE}" ]; then
        install -m 644 "${PLIST_COM_FILE}" "${PKG_ROOT}/Library/LaunchDaemons/com.oshoosiclaw.edr.plist"
    elif [ -f "${PLIST_DEV_FILE}" ]; then
        install -m 644 "${PLIST_DEV_FILE}" "${PKG_ROOT}/Library/LaunchDaemons/dev.oshoosiclaw.edr.plist"
    fi
    pkgbuild --root "${PKG_ROOT}" \
        --identifier "dev.oshoosiclaw.edr" \
        --version "${VERSION}" \
        --install-location "/" \
        "${PKG_OUT}"
    rm -rf "$(dirname "${PKG_ROOT}")"
    echo "[+] Created: ${PKG_OUT} (via pkgbuild)"
fi

# 4. Standalone Binary
install -m 755 "${BINARY_PATH}" "${DIST_DIR}/osoosi-macos-${MACOS_ARCH}"

rm -rf "$(dirname "${TAR_STAGING}")" "${APP_STAGING}"
echo "[+] macOS packaging complete. Artifacts in ${DIST_DIR}:"
ls -la "${DIST_DIR}"
