#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────────
# WARP Gateway — Setup Script
# Installs system dependencies, creates Python venv, initializes the database,
# creates the initial admin user, and installs as a systemd service.
#
# Usage:
#   sudo bash setup.sh                          # Interactive setup
#   sudo bash setup.sh --token <TOKEN>          # Pre-provisioned (auto-register)
#   sudo bash setup.sh --token <TOKEN> --platform-url https://api.kahluna.com
#
# Supports: Ubuntu 22.04+, Debian 12+, ARM64 and x86_64
# ──────────────────────────────────────────────────────────────────────────────
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Parse arguments ──────────────────────────────────────────────────────────

PROVISION_TOKEN=""
PLATFORM_URL="https://api.kahluna.com"
GATEWAY_NAME=""
SKIP_SERVICE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --token)
            PROVISION_TOKEN="$2"
            shift 2
            ;;
        --platform-url)
            PLATFORM_URL="$2"
            shift 2
            ;;
        --name)
            GATEWAY_NAME="$2"
            shift 2
            ;;
        --skip-service)
            SKIP_SERVICE=true
            shift
            ;;
        -h|--help)
            echo "Usage: sudo bash setup.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --token TOKEN        Provisioning token for auto-registration with Platform Core"
            echo "  --platform-url URL   Platform Core API URL (default: https://api.kahluna.com)"
            echo "  --name NAME          Gateway hostname (default: auto-detected or warp-gw)"
            echo "  --skip-service       Don't install/enable the systemd service"
            echo "  -h, --help           Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "============================================"
echo "  WARP Gateway — Setup"
echo "============================================"
echo ""

# ── Check root ───────────────────────────────────────────────────────────────

if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root (or with sudo)."
    echo "Usage: sudo bash setup.sh"
    exit 1
fi

# ── Detect architecture ──────────────────────────────────────────────────────

ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)
echo "  Architecture: $ARCH"
echo "  OS: $(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
echo ""

# ── Install system dependencies ──────────────────────────────────────────────

echo "[1/9] Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq \
    wireguard \
    wireguard-tools \
    dnsmasq \
    iptables \
    iproute2 \
    tcpdump \
    iperf3 \
    mtr-tiny \
    traceroute \
    dnsutils \
    python3 \
    python3-venv \
    python3-pip \
    python3-dev \
    gcc \
    openssh-server \
    curl \
    > /dev/null 2>&1
echo "  System packages installed."

# ── Disable system dnsmasq (gateway manages it) ─────────────────────────────

echo "[2/9] Configuring dnsmasq..."
systemctl stop dnsmasq 2>/dev/null || true
systemctl disable dnsmasq 2>/dev/null || true
echo "  dnsmasq disabled (gateway will manage it)."

# ── Enable IP forwarding persistently ────────────────────────────────────────

echo "[3/9] Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 > /dev/null
mkdir -p /etc/sysctl.d
cat > /etc/sysctl.d/99-warp-gateway.conf << 'EOF'
# KahLuna WARP Gateway
net.ipv4.ip_forward=1
EOF
echo "  IP forwarding enabled and persisted."

# ── Create Python virtual environment ────────────────────────────────────────

echo "[4/9] Setting up Python environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
echo "  Python venv created and packages installed."

# ── Create directories and configuration ─────────────────────────────────────

echo "[5/9] Creating configuration..."

# Data directories
mkdir -p /var/lib/warp-gateway
mkdir -p /etc/warp-gateway
chmod 700 /etc/warp-gateway

# WireGuard config directory
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

# dnsmasq config directory
mkdir -p /etc/dnsmasq.d

# Generate secret key if not exists
if [ ! -f "/etc/warp-gateway/secret.key" ]; then
    python3 -c "import secrets; print(secrets.token_hex(32))" > /etc/warp-gateway/secret.key
    chmod 600 /etc/warp-gateway/secret.key
    echo "  Secret key generated."
else
    echo "  Secret key already exists, skipping."
fi

# Create .env if not exists
if [ ! -f ".env" ]; then
    cat > .env << EOF
SECRET_KEY_FILE=/etc/warp-gateway/secret.key
DATABASE_URL=sqlite:////var/lib/warp-gateway/gateway.db
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
FLASK_DEBUG=false
EOF
    echo "  .env file created."
else
    echo "  .env file already exists, skipping."
fi

# ── Initialize database ──────────────────────────────────────────────────────

echo "[6/9] Initializing database..."
PYTHONPATH="$SCRIPT_DIR" ./venv/bin/python3 -c "
import os
os.environ.setdefault('SECRET_KEY', 'setup')
os.environ.setdefault('DATABASE_URL', 'sqlite:////var/lib/warp-gateway/gateway.db')
from gateway import create_app
app = create_app()
with app.app_context():
    from database import db
    db.create_all()
    print('  Database tables created.')
"

# ── Create initial admin user ────────────────────────────────────────────────

echo "[7/9] Creating admin user..."
ADMIN_PASSWORD=$(python3 -c "import secrets, string; print(''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16)))")

PYTHONPATH="$SCRIPT_DIR" ./venv/bin/python3 -c "
import os
os.environ.setdefault('SECRET_KEY', 'setup')
os.environ.setdefault('DATABASE_URL', 'sqlite:////var/lib/warp-gateway/gateway.db')
from gateway import create_app
from database import db
from models_new import User
app = create_app()
with app.app_context():
    existing = User.query.filter_by(username='admin').first()
    if existing:
        print('  Admin user already exists, skipping.')
    else:
        user = User(username='admin', email='admin@warp.local', role='admin')
        user.set_password('${ADMIN_PASSWORD}')
        db.session.add(user)
        db.session.commit()
        print('  Admin user created.')
"

# ── Install systemd service ──────────────────────────────────────────────────

echo "[8/9] Installing systemd service..."

if [ "$SKIP_SERVICE" = false ]; then
    # Install the main gateway service
    cat > /etc/systemd/system/warp-gateway.service << EOF
[Unit]
Description=KahLuna WARP Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${SCRIPT_DIR}/venv/bin/python gateway.py
Restart=on-failure
RestartSec=5
Environment=SECRET_KEY_FILE=/etc/warp-gateway/secret.key

[Install]
WantedBy=multi-user.target
EOF

    # Install the CLI shell service for serial console
    cat > /etc/systemd/system/warp-cli@.service << EOF
[Unit]
Description=WARP Gateway CLI on %I
After=warp-gateway.service
Requires=warp-gateway.service

[Service]
Type=simple
ExecStart=${SCRIPT_DIR}/venv/bin/python ${SCRIPT_DIR}/cli_entry.py
StandardInput=tty
StandardOutput=tty
TTYPath=/dev/%I
TTYReset=yes
TTYVHangup=yes
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

    # Enable the gateway service
    systemctl daemon-reload
    systemctl enable warp-gateway.service
    echo "  Systemd service installed and enabled."

    # Enable CLI on serial console (useful for Pi headless access)
    systemctl enable warp-cli@ttyS0.service 2>/dev/null || true
    # For Raspberry Pi serial (ttyAMA0)
    systemctl enable warp-cli@ttyAMA0.service 2>/dev/null || true
else
    echo "  Skipped (--skip-service flag)."
fi

# ── Pre-provisioned mode (optional) ─────────────────────────────────────────

echo "[9/9] Configuring management mode..."

if [ -n "$PROVISION_TOKEN" ]; then
    # Set up pre-provisioned mode
    GW_NAME="${GATEWAY_NAME:-$(hostname)}"

    PYTHONPATH="$SCRIPT_DIR" ./venv/bin/python3 -c "
import os
os.environ.setdefault('SECRET_KEY', 'setup')
os.environ.setdefault('DATABASE_URL', 'sqlite:////var/lib/warp-gateway/gateway.db')
from gateway import create_app
from database import db
from models_new import GatewayConfig
app = create_app()
with app.app_context():
    config = GatewayConfig.get_instance()
    config.management_mode = 'pre_provisioned'
    config.pre_provision_token = '${PROVISION_TOKEN}'
    config.pre_provision_url = '${PLATFORM_URL}'
    config.hostname = '${GW_NAME}'
    db.session.commit()
    print('  Pre-provisioned mode configured.')
    print('  Gateway will auto-register with Platform Core on first start.')
    print('  Platform URL: ${PLATFORM_URL}')
    print('  Gateway name: ${GW_NAME}')
"
else
    echo "  Standalone mode (no provisioning token provided)."
    echo "  First-boot wizard will run on initial startup."
fi

# ── Done ─────────────────────────────────────────────────────────────────────

echo ""
echo "============================================"
echo "  WARP Gateway — Setup Complete"
echo "============================================"
echo ""
echo "  Admin Credentials:"
echo "  ──────────────────"
echo "  Username: admin"
echo "  Password: ${ADMIN_PASSWORD}"
echo ""
echo "  SAVE THESE CREDENTIALS — they will not be shown again."
echo ""

if [ "$SKIP_SERVICE" = false ]; then
    echo "  The gateway is installed as a systemd service."
    echo ""
    echo "  Start now:"
    echo "    sudo systemctl start warp-gateway"
    echo ""
    echo "  Or start manually:"
    echo "    cd ${SCRIPT_DIR}"
    echo "    source venv/bin/activate"
    echo "    python gateway.py"
    echo ""
    echo "  View logs:"
    echo "    journalctl -u warp-gateway -f"
else
    echo "  To start the gateway:"
    echo "    cd ${SCRIPT_DIR}"
    echo "    source venv/bin/activate"
    echo "    python gateway.py"
fi

echo ""

if [ -n "$PROVISION_TOKEN" ]; then
    echo "  Management: PRE-PROVISIONED"
    echo "  The gateway will auto-register with Platform Core"
    echo "  when the service starts."
else
    echo "  Management: STANDALONE"
    echo "  Run the first-boot wizard or register later via CLI:"
    echo "    configure terminal"
    echo "    nexus register <token> <platform-url>"
fi

echo ""
echo "============================================"

# ── Auto-start if pre-provisioned ────────────────────────────────────────────

if [ -n "$PROVISION_TOKEN" ] && [ "$SKIP_SERVICE" = false ]; then
    echo ""
    echo "  Starting gateway service..."
    systemctl start warp-gateway
    sleep 2
    if systemctl is-active --quiet warp-gateway; then
        echo "  Gateway is running."
        echo "  Web UI: http://$(hostname -I | awk '{print $1}'):5000"
    else
        echo "  WARNING: Gateway failed to start. Check logs:"
        echo "    journalctl -u warp-gateway --no-pager -n 20"
    fi
fi
