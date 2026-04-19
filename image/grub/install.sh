#!/bin/bash
# ============================================================================
# KahLuna WARP OS — GRUB Theme Installer
# ============================================================================
set -euo pipefail

THEME_DIR="/boot/grub/themes/kahluna-warp"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Installing KahLuna WARP OS GRUB theme..."

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root (sudo)"
    exit 1
fi

# Create theme directory
mkdir -p "${THEME_DIR}"
cp "${SCRIPT_DIR}/theme.txt" "${THEME_DIR}/"

# Configure GRUB to use the theme
if ! grep -q "GRUB_THEME" /etc/default/grub; then
    echo "GRUB_THEME=\"${THEME_DIR}/theme.txt\"" >> /etc/default/grub
else
    sed -i "s|^GRUB_THEME=.*|GRUB_THEME=\"${THEME_DIR}/theme.txt\"|" /etc/default/grub
fi

# Set GRUB options for clean appearance
sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=5/' /etc/default/grub

# Custom GRUB entries
cat > /etc/grub.d/10_kahluna << 'EOF'
#!/bin/sh
exec tail -n +3 $0

# Serial console support
serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1
terminal_input serial console
terminal_output serial console

menuentry "KahLuna WARP OS" --class kahluna {
    linux /vmlinuz root=UUID=ROOT_UUID ro quiet splash console=tty0 console=ttyS0,115200n8
    initrd /initrd.img
}

menuentry "KahLuna WARP OS (Recovery)" --class kahluna {
    linux /vmlinuz root=UUID=ROOT_UUID ro single console=tty0 console=ttyS0,115200n8
    initrd /initrd.img
}
EOF
chmod +x /etc/grub.d/10_kahluna

# Disable OS prober (don't show other OSes)
echo 'GRUB_DISABLE_OS_PROBER=true' >> /etc/default/grub 2>/dev/null || true

update-grub

echo "GRUB theme installed."
