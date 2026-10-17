#!/bin/bash
# Linux Firewall Setup for OpenỌ̀ṣọ́ọ̀sì Mesh Defense
# Run as root/sudo

MESH_PORT=4001
DASHBOARD_PORT=3030

echo "Configuring Linux Firewall for Mesh (Port $MESH_PORT)..."
echo "Note: Dashboard (Port $DASHBOARD_PORT) binds strictly to 127.0.0.1 (loopback) and is not exposed externally."

# 1. UFW (Ubuntu/Debian)
if command -v ufw > /dev/null; then
    echo "  Applying UFW rules..."
    sudo ufw allow $MESH_PORT/tcp
    sudo ufw allow $MESH_PORT/udp
    sudo ufw reload
fi

# 2. Firewalld (CentOS/RHEL/Fedora)
if command -v firewall-cmd > /dev/null; then
    echo "  Applying Firewalld rules..."
    sudo firewall-cmd --permanent --add-port=$MESH_PORT/tcp
    sudo firewall-cmd --permanent --add-port=$MESH_PORT/udp
    sudo firewall-cmd --reload
fi

echo "✅ Firewall configuration complete."
