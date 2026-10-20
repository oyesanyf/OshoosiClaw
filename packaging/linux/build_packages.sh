#!/usr/bin/env bash
set -eu

# OpenOsoosi Linux Packaging Script
# Generates Debian (.deb), RedHat (.rpm), and portable (.tar.gz) packages for Linux deployments.

BINARY_PATH="${1:-target/release/osoosi}"
VERSION="${2:-1.2.0}"
INPUT_ARCH="${3:-amd64}"
DIST_DIR="${4:-dist}"
PACKAGE_NAME="${5:-oshoosiclaw}"

# Normalize architecture names
case "$INPUT_ARCH" in
    x86_64|amd64)
        DEB_ARCH="amd64"
        RPM_ARCH="x86_64"
        ;;
    aarch64|arm64)
        DEB_ARCH="arm64"
        RPM_ARCH="aarch64"
        ;;
    *)
        DEB_ARCH="$INPUT_ARCH"
        RPM_ARCH="$INPUT_ARCH"
        ;;
esac

echo "[*] Packaging OpenOsoosi EDR v${VERSION} (${DEB_ARCH} / ${RPM_ARCH})"
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

SERVICE_FILE="${SCRIPT_DIR}/osoosi-edr.service"
CONFIG_FILE="${ROOT_DIR}/osoosi.toml"
PUBLIC_KEY_FILE="${ROOT_DIR}/PUBLIC_KEY.asc"
EBPF_PROBE_FILE="${ROOT_DIR}/ebpf/osoosi_probe.bpf.o"

# ---------------------------------------------------------
# 1. Portable Tarball (.tar.gz)
# ---------------------------------------------------------
echo "[*] Building portable tarball..."
TAR_STAGING="$(mktemp -d)/${PACKAGE_NAME}-${VERSION}-linux-${RPM_ARCH}"
mkdir -p "${TAR_STAGING}"

install -m 755 "${BINARY_PATH}" "${TAR_STAGING}/osoosi"
install -m 644 "${SERVICE_FILE}" "${TAR_STAGING}/osoosi-edr.service"
if [ -f "${CONFIG_FILE}" ]; then
    install -m 640 "${CONFIG_FILE}" "${TAR_STAGING}/osoosi.toml"
fi
if [ -f "${PUBLIC_KEY_FILE}" ]; then
    install -m 644 "${PUBLIC_KEY_FILE}" "${TAR_STAGING}/PUBLIC_KEY.asc"
fi
if [ -f "${EBPF_PROBE_FILE}" ]; then
    mkdir -p "${TAR_STAGING}/usr/lib/osoosi"
    install -m 644 "${EBPF_PROBE_FILE}" "${TAR_STAGING}/usr/lib/osoosi/osoosi-ebpf.o"
    install -m 644 "${EBPF_PROBE_FILE}" "${TAR_STAGING}/osoosi-ebpf.o"
fi

TAR_OUT="${DIST_DIR}/${PACKAGE_NAME}-${VERSION}-linux-${RPM_ARCH}.tar.gz"
tar -czf "${TAR_OUT}" -C "$(dirname "${TAR_STAGING}")" "$(basename "${TAR_STAGING}")"
echo "[+] Created: ${TAR_OUT}"
if [ "${PACKAGE_NAME}" != "osoosi-edr" ]; then
    cp -f "${TAR_OUT}" "${DIST_DIR}/osoosi-edr-${VERSION}-linux-${DEB_ARCH}.tar.gz" 2>/dev/null || true
fi
rm -rf "$(dirname "${TAR_STAGING}")"

# ---------------------------------------------------------
# 2. Debian Package (.deb)
# ---------------------------------------------------------
echo "[*] Building Debian package..."
DEB_STAGING="$(mktemp -d)/deb_build"
mkdir -p "${DEB_STAGING}/DEBIAN"
mkdir -p "${DEB_STAGING}/usr/bin"
mkdir -p "${DEB_STAGING}/usr/lib/osoosi"
mkdir -p "${DEB_STAGING}/lib/systemd/system"
mkdir -p "${DEB_STAGING}/etc/osoosi"
mkdir -p "${DEB_STAGING}/var/lib/osoosi"

cat <<EOF > "${DEB_STAGING}/DEBIAN/control"
Package: ${PACKAGE_NAME}
Provides: osoosi-edr
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${DEB_ARCH}
Maintainer: OpenOsoosi Security Team <security@oshoosiclaw.dev>
Homepage: https://github.com/oyesanyf/OshoosiClaw
Description: OpenOsoosi Autonomous EDR Daemon
 OpenOsoosi is a high-assurance, hardware-speed endpoint detection and
 autonomous active defense daemon combining Linux eBPF CO-RE LSM probes,
 behavioral consensus modeling, and tamper-resistant local telemetry.
EOF

cat <<'EOF' > "${DEB_STAGING}/DEBIAN/postinst"
#!/bin/sh
set -e

if [ "$1" = "configure" ]; then
    mkdir -p /var/lib/osoosi /var/log/osoosi /etc/osoosi
    chmod 750 /var/lib/osoosi /var/log/osoosi
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload || true
    fi
fi
exit 0
EOF
chmod 755 "${DEB_STAGING}/DEBIAN/postinst"

cat <<'EOF' > "${DEB_STAGING}/DEBIAN/prerm"
#!/bin/sh
set -e

if [ "$1" = "remove" ]; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop osoosi-edr.service || true
        systemctl disable osoosi-edr.service || true
    fi
fi
exit 0
EOF
chmod 755 "${DEB_STAGING}/DEBIAN/prerm"

install -m 755 "${BINARY_PATH}" "${DEB_STAGING}/usr/bin/osoosi"
install -m 644 "${SERVICE_FILE}" "${DEB_STAGING}/lib/systemd/system/osoosi-edr.service"
if [ -f "${CONFIG_FILE}" ]; then
    install -m 640 "${CONFIG_FILE}" "${DEB_STAGING}/etc/osoosi/osoosi.toml"
fi
if [ -f "${EBPF_PROBE_FILE}" ]; then
    install -m 644 "${EBPF_PROBE_FILE}" "${DEB_STAGING}/usr/lib/osoosi/osoosi-ebpf.o"
fi

DEB_OUT="${DIST_DIR}/${PACKAGE_NAME}_${VERSION}_${DEB_ARCH}.deb"
if command -v dpkg-deb >/dev/null 2>&1; then
    dpkg-deb --build --root-owner-group "${DEB_STAGING}" "${DEB_OUT}"
    echo "[+] Created: ${DEB_OUT}"
    if [ "${PACKAGE_NAME}" != "osoosi-edr" ]; then
        cp -f "${DEB_OUT}" "${DIST_DIR}/osoosi-edr_${VERSION}_${DEB_ARCH}.deb" 2>/dev/null || true
    fi
else
    echo "[!] dpkg-deb not found. Creating deb archive via ar/tar fallback..."
    (
        cd "${DEB_STAGING}"
        echo "2.0" > debian-binary
        tar -czf control.tar.gz -C DEBIAN control postinst prerm
        tar -czf data.tar.gz --exclude=DEBIAN --exclude=debian-binary --exclude=control.tar.gz usr lib etc var
        ar -rc "${DEB_OUT}" debian-binary control.tar.gz data.tar.gz
    )
    echo "[+] Created: ${DEB_OUT} (via ar fallback)"
    if [ "${PACKAGE_NAME}" != "osoosi-edr" ]; then
        cp -f "${DEB_OUT}" "${DIST_DIR}/osoosi-edr_${VERSION}_${DEB_ARCH}.deb" 2>/dev/null || true
    fi
fi
rm -rf "${DEB_STAGING}"

# ---------------------------------------------------------
# 3. RedHat Package (.rpm)
# ---------------------------------------------------------
RPM_OUT="${DIST_DIR}/${PACKAGE_NAME}-${VERSION}-1.${RPM_ARCH}.rpm"
if command -v rpmbuild >/dev/null 2>&1; then
    echo "[*] Building RPM package with rpmbuild..."
    RPM_TOP="$(mktemp -d)/rpmtop"
    mkdir -p "${RPM_TOP}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS,BUILDROOT}
    
    cat <<EOF > "${RPM_TOP}/SPECS/${PACKAGE_NAME}.spec"
Name:           ${PACKAGE_NAME}
Provides:       osoosi-edr
Version:        ${VERSION}
Release:        1%{?dist}
Summary:        OpenOsoosi Autonomous EDR Daemon
License:        Apache-2.0 OR MIT
URL:            https://github.com/oyesanyf/OshoosiClaw
AutoReqProv:    no
%define __strip /bin/true
%define _build_id_links none
%global __os_install_post %{nil}

%description
OpenOsoosi is a high-assurance, hardware-speed endpoint detection and
autonomous active defense daemon.

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/usr/lib/systemd/system
mkdir -p %{buildroot}/etc/osoosi
mkdir -p %{buildroot}/var/lib/osoosi
mkdir -p %{buildroot}/usr/lib/osoosi

install -m 755 ${BINARY_PATH} %{buildroot}/usr/bin/osoosi
install -m 644 ${SERVICE_FILE} %{buildroot}/usr/lib/systemd/system/osoosi-edr.service
if [ -f "${CONFIG_FILE}" ]; then
    install -m 640 ${CONFIG_FILE} %{buildroot}/etc/osoosi/osoosi.toml
fi
if [ -f "${EBPF_PROBE_FILE}" ]; then
    install -m 644 ${EBPF_PROBE_FILE} %{buildroot}/usr/lib/osoosi/osoosi-ebpf.o
fi

%post
if [ \$1 -eq 1 ]; then
    systemctl daemon-reload >/dev/null 2>&1 || :
fi

%preun
if [ \$1 -eq 0 ]; then
    systemctl --no-reload disable --now osoosi-edr.service >/dev/null 2>&1 || :
fi

%files
/usr/bin/osoosi
/usr/lib/systemd/system/osoosi-edr.service
%config(noreplace) /etc/osoosi/osoosi.toml
%dir /var/lib/osoosi
%dir /usr/lib/osoosi
/usr/lib/osoosi/osoosi-ebpf.o

%changelog
* Fri Oct 16 2026 OpenOsoosi Security Team <security@oshoosiclaw.dev> - ${VERSION}-1
- Release ${VERSION} with eBPF CO-RE LSM telemetry and hardened systemd service.
EOF

    rpmbuild --define "_topdir ${RPM_TOP}" -bb "${RPM_TOP}/SPECS/${PACKAGE_NAME}.spec"
    find "${RPM_TOP}/RPMS" -type f -name "*.rpm" -exec cp -f {} "${DIST_DIR}/" \;
    if [ -f "${DIST_DIR}/${PACKAGE_NAME}-${VERSION}-1.${RPM_ARCH}.rpm" ] && [ "${PACKAGE_NAME}" != "osoosi-edr" ]; then
        cp -f "${DIST_DIR}/${PACKAGE_NAME}-${VERSION}-1.${RPM_ARCH}.rpm" "${DIST_DIR}/osoosi-edr-${VERSION}-1.${RPM_ARCH}.rpm" 2>/dev/null || true
    fi
    echo "[+] RPM package created in ${DIST_DIR}"
    rm -rf "${RPM_TOP}"
elif command -v fpm >/dev/null 2>&1; then
    echo "[*] Building RPM package with fpm..."
    FPM_CMD=(
        fpm -s dir -t rpm
        -n "${PACKAGE_NAME}"
        -v "${VERSION}"
        -a "${RPM_ARCH}"
        --description "OpenOsoosi Autonomous EDR Daemon"
        --url "https://github.com/oyesanyf/OshoosiClaw"
        --after-install <(echo "systemctl daemon-reload || true")
        --before-remove <(echo "systemctl stop osoosi-edr.service || true")
        -p "${RPM_OUT}"
        "${BINARY_PATH}=/usr/bin/osoosi"
        "${SERVICE_FILE}=/usr/lib/systemd/system/osoosi-edr.service"
        "${CONFIG_FILE}=/etc/osoosi/osoosi.toml"
    )
    if [ -f "${EBPF_PROBE_FILE}" ]; then
        FPM_CMD+=("${EBPF_PROBE_FILE}=/usr/lib/osoosi/osoosi-ebpf.o")
    fi
    "${FPM_CMD[@]}"
    echo "[+] Created: ${RPM_OUT}"
    if [ "${PACKAGE_NAME}" != "osoosi-edr" ]; then
        cp -f "${RPM_OUT}" "${DIST_DIR}/osoosi-edr-${VERSION}-1.${RPM_ARCH}.rpm" 2>/dev/null || true
    fi
else
    echo "[!] Neither rpmbuild nor fpm found. Skipping .rpm generation."
fi

# ---------------------------------------------------------
# 4. Standalone Stripped ELF Binary
# ---------------------------------------------------------
echo "[*] Copying standalone stripped binary..."
if [ "${BINARY_PATH}" != "${DIST_DIR}/osoosi-linux-${RPM_ARCH}" ]; then
    install -m 755 "${BINARY_PATH}" "${DIST_DIR}/osoosi-linux-${RPM_ARCH}"
fi
if [ "${RPM_ARCH}" = "x86_64" ] && [ "${BINARY_PATH}" != "${DIST_DIR}/osoosi-linux-amd64" ]; then
    cp -f "${DIST_DIR}/osoosi-linux-${RPM_ARCH}" "${DIST_DIR}/osoosi-linux-amd64" 2>/dev/null || true
fi

echo "[+] Linux packaging complete. Artifacts in ${DIST_DIR}:"
ls -la "${DIST_DIR}"

