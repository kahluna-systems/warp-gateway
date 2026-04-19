#!/bin/bash
# ============================================================================
# WARP OS Finalization Script
# Runs inside the chroot. Cleans up and minimizes image size.
# ============================================================================
set -euo pipefail

echo "-- Finalizing image --"

# Clean APT cache
apt-get clean
rm -rf /var/lib/apt/lists/*

# Remove temporary files
rm -rf /tmp/*
rm -rf /var/tmp/*

# Clear logs
find /var/log -type f -exec truncate -s 0 {} \;

# Remove machine-id (regenerated on first boot)
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id

# Remove SSH host keys (regenerated on first boot)
rm -f /etc/ssh/ssh_host_*

# Ensure startup-config does NOT exist (triggers first-boot wizard)
rm -f /etc/warp-gateway/startup-config
rm -f /opt/warp-gateway/startup-config

# Create the warp-gateway config directory
mkdir -p /etc/warp-gateway

# Zero free space for better compression
dd if=/dev/zero of=/zero bs=1M 2>/dev/null || true
rm -f /zero

echo "-- Finalization complete --"
