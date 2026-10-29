#!/usr/bin/env bash
# OshoosiClaw Autonomous EDR - macOS LaunchDaemon Uninstallation Script
set -euo pipefail

echo "[*] Uninstalling OshoosiClaw Autonomous EDR from macOS..."

# Ensure root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "[-] This script must be run as root. Re-running with sudo..." >&2
    exec sudo "$0" "$@"
fi

# Stop and unload LaunchDaemon
for PLIST in /Library/LaunchDaemons/com.oshoosiclaw.edr.plist /Library/LaunchDaemons/dev.oshoosiclaw.edr.plist; do
    if [ -f "${PLIST}" ]; then
        echo "[*] Unloading ${PLIST}..."
        launchctl unload -w "${PLIST}" 2>/dev/null || true
        rm -f "${PLIST}"
        echo "[+] Removed ${PLIST}"
    fi
done

# Terminate running daemon processes if still alive
pkill -TERM -f "/usr/local/bin/osoosi" 2>/dev/null || true

# Remove executable
if [ -f /usr/local/bin/osoosi ]; then
    rm -f /usr/local/bin/osoosi
    echo "[+] Removed /usr/local/bin/osoosi"
fi

echo "[*] Preserving /etc/osoosi configuration and /var/lib/osoosi state database for forensic audit."
echo "[+] OshoosiClaw Autonomous EDR uninstalled successfully."
