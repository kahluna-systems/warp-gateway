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
    isc-dhcp-client \
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
# Use a wrapper script as login shell (not the Python script directly)
cat > /opt/warp-gateway/warp-shell.sh << 'SHELL_EOF'
#!/bin/bash
cd /opt/warp-gateway
exec /opt/warp-gateway/venv/bin/python /opt/warp-gateway/cli_entry.py
SHELL_EOF
chmod +x /opt/warp-gateway/warp-shell.sh

useradd -r -m -s /opt/warp-gateway/warp-shell.sh -G sudo warp || true
echo "warp ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/warp

# ── Create data directories ──────────────────────────────────────────────────

echo "-- Creating data directories --"
mkdir -p /var/lib/warp-gateway
mkdir -p /etc/warp-gateway
chown root:root /var/lib/warp-gateway
chmod 755 /var/lib/warp-gateway

# ── Disable systemd-resolved (conflicts with dnsmasq on port 53) ─────────────

echo "-- Disabling systemd-resolved --"
systemctl disable systemd-resolved 2>/dev/null || true
systemctl mask systemd-resolved 2>/dev/null || true
rm -f /etc/resolv.conf
echo "nameserver 1.1.1.1" > /etc/resolv.conf

# ── Install systemd units ────────────────────────────────────────────────────

echo "-- Installing systemd units --"
cp /tmp/warp-config/warp-gateway.service /etc/systemd/system/

# Note: We use the getty override for tty1, NOT warp-cli@tty1.service
# to avoid two services fighting over the same TTY
cp /tmp/warp-config/warp-cli@.service /etc/systemd/system/

systemctl enable warp-gateway.service
# Do NOT enable warp-cli@tty1 -- the getty override handles tty1

# Enable CLI on serial console (ttyS0) for headless appliances
systemctl enable warp-cli@ttyS0.service 2>/dev/null || true

# Configure serial console getty as fallback
mkdir -p /etc/systemd/system/serial-getty@ttyS0.service.d
cat > /etc/systemd/system/serial-getty@ttyS0.service.d/override.conf << 'EOF'
[Service]
ExecStart=
ExecStart=-/opt/warp-gateway/warp-shell.sh
StandardInput=tty
StandardOutput=tty
TTYPath=/dev/ttyS0
TTYReset=yes
TTYVHangup=yes
Type=idle
EOF
systemctl enable serial-getty@ttyS0.service 2>/dev/null || true

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

# ── Install boot splash (Plymouth) and GRUB theme ────────────────────────────

echo "-- Installing boot splash --"
if [ -d /tmp/warp-config/../plymouth ]; then
    bash /tmp/warp-config/../plymouth/install.sh || echo "WARNING: Plymouth install failed (non-fatal)"
fi
if [ -d /tmp/warp-config/../grub ]; then
    bash /tmp/warp-config/../grub/install.sh || echo "WARNING: GRUB theme install failed (non-fatal)"
fi

# ── Disable dnsmasq auto-start (gateway manages it) ─────────────────────────

systemctl disable dnsmasq || true

echo "-- Customization complete --"
