#!/bin/bash
# ============================================================================
# WARP OS Security Hardening Script
# Runs inside the chroot. Applies security best practices.
# ============================================================================
set -euo pipefail

echo "-- Applying security hardening --"

# ── SSH hardening ────────────────────────────────────────────────────────────

echo "-- Hardening SSH --"
cp /tmp/warp-config/sshd_config /etc/ssh/sshd_config

# ── Sysctl hardening ────────────────────────────────────────────────────────

echo "-- Applying sysctl hardening --"
cp /tmp/warp-config/sysctl-hardening.conf /etc/sysctl.d/99-warp-hardening.conf

# ── Boot-time iptables rules ────────────────────────────────────────────────

echo "-- Installing boot-time firewall rules --"
mkdir -p /etc/iptables
cp /tmp/warp-config/iptables-boot.rules /etc/iptables/rules.v4

# Install iptables-persistent to load rules on boot
apt-get install -y --no-install-recommends iptables-persistent || true

# ── Enable automatic security updates ────────────────────────────────────────

echo "-- Enabling unattended upgrades --"
apt-get install -y --no-install-recommends unattended-upgrades
cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

# ── Disable unnecessary services ─────────────────────────────────────────────

echo "-- Disabling unnecessary services --"
for svc in avahi-daemon cups bluetooth ModemManager; do
    systemctl disable "$svc" 2>/dev/null || true
    systemctl mask "$svc" 2>/dev/null || true
done

# ── File permissions ─────────────────────────────────────────────────────────

chmod 600 /etc/ssh/sshd_config
chmod 700 /root

echo "-- Security hardening complete --"
