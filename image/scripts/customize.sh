#!/bin/bash
# ============================================================================
# WARP OS Customization Script
# Runs inside the chroot. Installs packages, copies app, creates users.
# ============================================================================
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

echo "-- Configuring APT sources --"
cat > /etc/apt/sources.list << 'EOF'
deb http://archive.ubuntu.com/ubuntu jammy main restricted universe
deb http://archive.ubuntu.com/ubuntu jammy-updates main restricted universe
deb http://archive.ubuntu.com/ubuntu jammy-security main restricted universe
EOF

apt-get update

# ── Install required packages ────────────────────────────────────────────────

echo "-- Installing required packages --"
apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip \
    wireguard wireguard-tools \
    dnsmasq \
    iptables \
    iproute2 \
    tcpdump \
    iperf3 \
    mtr-tiny \
    traceroute \
    dnsutils \
    openssh-server \
    sudo \
    systemd \
    systemd-sysv \
    linux-image-generic \
    grub-pc \
    net-tools \
    curl \
    ca-certificates \
    locales \
    less \
    vim-tiny

# Generate locale
locale-gen en_US.UTF-8

# ── Exclude unnecessary packages ─────────────────────────────────────────────

echo "-- Removing unnecessary packages --"
apt-get purge -y snapd cloud-init cloud-guest-utils || true
apt-get autoremove -y

# ── Set up Python virtual environment ────────────────────────────────────────

echo "-- Setting up Python environment --"
python3 -m venv /opt/warp-gateway/venv
/opt/warp-gateway/venv/bin/pip install --no-cache-dir -r /opt/warp-gateway/requirements.txt

# ── Create system user ───────────────────────────────────────────────────────

echo "-- Creating warp system user --"
useradd -r -m -s /opt/warp-gateway/cli_entry.py -G sudo warp || true
echo "warp ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/warp

# ── Install systemd units ────────────────────────────────────────────────────

echo "-- Installing systemd units --"
cp /tmp/warp-config/warp-gateway.service /etc/systemd/system/
cp /tmp/warp-config/warp-cli@.service /etc/systemd/system/

systemctl enable warp-gateway.service
systemctl enable warp-cli@tty1.service

# ── Configure console auto-login to CLI shell ────────────────────────────────

echo "-- Configuring console auto-login --"
mkdir -p /etc/systemd/system/getty@tty1.service.d
cat > /etc/systemd/system/getty@tty1.service.d/override.conf << 'EOF'
[Service]
ExecStart=
ExecStart=-/opt/warp-gateway/venv/bin/python /opt/warp-gateway/cli_entry.py
StandardInput=tty
StandardOutput=tty
TTYPath=/dev/tty1
TTYReset=yes
TTYVHangup=yes
Type=idle
EOF

# ── Configure MOTD and banners ───────────────────────────────────────────────

echo "-- Configuring banners --"
cp /tmp/warp-config/motd.sh /etc/update-motd.d/10-warp-gateway
chmod +x /etc/update-motd.d/10-warp-gateway

# Remove default MOTD scripts
rm -f /etc/update-motd.d/00-header
rm -f /etc/update-motd.d/10-help-text
rm -f /etc/update-motd.d/50-motd-news
rm -f /etc/update-motd.d/91-release-upgrade

cp /tmp/warp-config/banner.txt /etc/ssh/banner.txt

# ── Set hostname ─────────────────────────────────────────────────────────────

echo "warp-gw" > /etc/hostname
echo "127.0.0.1 warp-gw" >> /etc/hosts

# ── Disable dnsmasq auto-start (gateway manages it) ─────────────────────────

systemctl disable dnsmasq || true

echo "-- Customization complete --"
