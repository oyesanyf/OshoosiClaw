#!/usr/bin/env bash
# OshoosiClaw Autonomous EDR - macOS LaunchDaemon Installation Script
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[*] Installing OshoosiClaw Autonomous EDR for macOS..."

# Ensure root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "[-] This script must be run as root. Re-running with sudo..." >&2
    exec sudo "$0" "$@"
fi

# Create system directories
mkdir -p /usr/local/bin /etc/osoosi /var/lib/osoosi /var/log/osoosi /Library/LaunchDaemons

# Install executable
if [ -f "${SCRIPT_DIR}/osoosi" ]; then
    install -m 755 "${SCRIPT_DIR}/osoosi" /usr/local/bin/osoosi
    echo "[+] Installed /usr/local/bin/osoosi"
else
    echo "[-] Warning: ${SCRIPT_DIR}/osoosi not found." >&2
fi

# Install configuration if not present
if [ -f "${SCRIPT_DIR}/osoosi.toml" ] && [ ! -f /etc/osoosi/osoosi.toml ]; then
    install -m 640 "${SCRIPT_DIR}/osoosi.toml" /etc/osoosi/osoosi.toml
    echo "[+] Installed /etc/osoosi/osoosi.toml"
fi

# Install LaunchDaemon property list
PLIST_SRC=""
if [ -f "${SCRIPT_DIR}/com.oshoosiclaw.edr.plist" ]; then
    PLIST_SRC="${SCRIPT_DIR}/com.oshoosiclaw.edr.plist"
elif [ -f "${SCRIPT_DIR}/dev.oshoosiclaw.edr.plist" ]; then
    PLIST_SRC="${SCRIPT_DIR}/dev.oshoosiclaw.edr.plist"
fi

if [ -n "${PLIST_SRC}" ]; then
    TARGET_PLIST="/Library/LaunchDaemons/com.oshoosiclaw.edr.plist"
    # Unload existing daemon if running
    launchctl unload -w "${TARGET_PLIST}" 2>/dev/null || true
    install -m 644 "${PLIST_SRC}" "${TARGET_PLIST}"
    echo "[+] Installed ${TARGET_PLIST}"
    launchctl load -w "${TARGET_PLIST}" || true
    echo "[+] LaunchDaemon com.oshoosiclaw.edr loaded into launchd."
fi

echo "[+] OshoosiClaw Autonomous EDR successfully installed on macOS."
