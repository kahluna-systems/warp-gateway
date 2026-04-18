#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────────
# WARP Gateway — Setup Script
# Installs system dependencies, creates Python venv, initializes the database,
# and creates the initial admin user.
# ──────────────────────────────────────────────────────────────────────────────

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

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

# ── Install system dependencies ──────────────────────────────────────────────
echo "[1/7] Installing system dependencies..."
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
    > /dev/null 2>&1

echo "  System packages installed."

# ── Disable system dnsmasq (gateway manages it) ─────────────────────────────
echo "[2/7] Configuring dnsmasq..."
systemctl stop dnsmasq 2>/dev/null || true
systemctl disable dnsmasq 2>/dev/null || true
# We'll start it ourselves when DHCP is configured
echo "  dnsmasq disabled (gateway will manage it)."

# ── Enable IP forwarding persistently ────────────────────────────────────────
echo "[3/7] Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 > /dev/null
mkdir -p /etc/sysctl.d
cat > /etc/sysctl.d/99-warp-gateway.conf << 'EOF'
# KahLuna WARP Gateway
net.ipv4.ip_forward=1
EOF
echo "  IP forwarding enabled and persisted."

# ── Create Python virtual environment ────────────────────────────────────────
echo "[4/7] Setting up Python environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
echo "  Python venv created and packages installed."

# ── Create .env if not exists ────────────────────────────────────────────────
echo "[5/7] Creating configuration..."
if [ ! -f ".env" ]; then
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    cat > .env << EOF
SECRET_KEY=${SECRET_KEY}
DATABASE_URL=sqlite:///warp_gateway.db
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
FLASK_DEBUG=false
EOF
    echo "  .env file created."
else
    echo "  .env file already exists, skipping."
fi

# ── Initialize database ─────────────────────────────────────────────────────
echo "[6/7] Initializing database..."
./venv/bin/python3 -c "
import os
os.environ.setdefault('SECRET_KEY', 'setup')
os.environ.setdefault('DATABASE_URL', 'sqlite:///warp_gateway.db')
from gateway import create_app
app = create_app()
with app.app_context():
    from database import db
    db.create_all()
    print('  Database tables created.')
"

# ── Create initial admin user ────────────────────────────────────────────────
echo "[7/7] Creating admin user..."
ADMIN_PASSWORD=$(./venv/bin/python3 -c "import secrets, string; print(''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16)))")

./venv/bin/python3 -c "
import os
os.environ.setdefault('SECRET_KEY', 'setup')
os.environ.setdefault('DATABASE_URL', 'sqlite:///warp_gateway.db')
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

# ── Create WireGuard config directory ────────────────────────────────────────
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

# ── Create dnsmasq config directory ──────────────────────────────────────────
mkdir -p /etc/dnsmasq.d

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
echo "  To start the gateway:"
echo "    cd ${SCRIPT_DIR}"
echo "    source venv/bin/activate"
echo "    python gateway.py"
echo ""
echo "  Or with gunicorn:"
echo "    gunicorn -w 2 -b 0.0.0.0:5000 'gateway:create_app()'"
echo ""
echo "============================================"
