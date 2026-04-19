#!/bin/bash
# ============================================================================
# KahLuna WARP OS — Plymouth Theme Installer
# Installs the boot splash theme on an Ubuntu-based system.
# ============================================================================
set -euo pipefail

THEME_NAME="kahluna-warp"
THEME_DIR="/usr/share/plymouth/themes/${THEME_NAME}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE_DIR="${SCRIPT_DIR}/${THEME_NAME}"

echo "Installing KahLuna WARP OS boot splash..."

# Check for root
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root (sudo)"
    exit 1
fi

# Install plymouth if not present
if ! command -v plymouth &>/dev/null; then
    echo "Installing Plymouth..."
    apt-get install -y plymouth plymouth-themes
fi

# Convert SVG logo to PNG (Plymouth needs PNG)
if command -v rsvg-convert &>/dev/null; then
    echo "Converting logo SVG to PNG..."
    rsvg-convert -w 120 -h 120 "${SOURCE_DIR}/logo.svg" -o "${SOURCE_DIR}/logo.png"
elif command -v convert &>/dev/null; then
    echo "Converting logo SVG to PNG (ImageMagick)..."
    convert -background none -resize 120x120 "${SOURCE_DIR}/logo.svg" "${SOURCE_DIR}/logo.png"
else
    echo "WARNING: No SVG converter found. Creating placeholder logo..."
    # Create a simple 120x120 PNG placeholder using Python
    python3 -c "
import struct, zlib

width, height = 120, 120
# Create a simple gradient image
raw = b''
for y in range(height):
    raw += b'\x00'  # filter byte
    for x in range(width):
        # Dark navy with cyan center glow
        dx = abs(x - 60) / 60.0
        dy = abs(y - 60) / 60.0
        dist = (dx*dx + dy*dy) ** 0.5
        if dist < 0.5:
            r, g, b = 0, int(209 * (1-dist*2)), int(255 * (1-dist*2))
        else:
            r, g, b = 10, 14, 26
        a = 255
        raw += struct.pack('BBBB', r, g, b, a)

def make_png(w, h, raw_data):
    def chunk(ctype, data):
        c = ctype + data
        return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)
    sig = b'\x89PNG\r\n\x1a\n'
    ihdr = chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 6, 0, 0, 0))
    idat = chunk(b'IDAT', zlib.compress(raw_data))
    iend = chunk(b'IEND', b'')
    return sig + ihdr + idat + iend

with open('${SOURCE_DIR}/logo.png', 'wb') as f:
    f.write(make_png(width, height, raw))
print('Placeholder logo created')
"
fi

# Copy theme files
echo "Installing theme to ${THEME_DIR}..."
mkdir -p "${THEME_DIR}"
cp "${SOURCE_DIR}/kahluna-warp.plymouth" "${THEME_DIR}/"
cp "${SOURCE_DIR}/kahluna-warp.script" "${THEME_DIR}/"
cp "${SOURCE_DIR}/logo.png" "${THEME_DIR}/"

# Set as default theme
echo "Setting as default Plymouth theme..."
update-alternatives --install /usr/share/plymouth/themes/default.plymouth default.plymouth \
    "${THEME_DIR}/kahluna-warp.plymouth" 200
update-alternatives --set default.plymouth "${THEME_DIR}/kahluna-warp.plymouth"

# Update initramfs to include the theme
echo "Updating initramfs..."
update-initramfs -u

# Configure GRUB for splash
echo "Configuring GRUB..."
if ! grep -q "splash" /etc/default/grub 2>/dev/null; then
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 splash"/' /etc/default/grub
fi

# Set GRUB timeout and hide menu
sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=3/' /etc/default/grub
grep -q "GRUB_TIMEOUT_STYLE" /etc/default/grub || echo 'GRUB_TIMEOUT_STYLE=hidden' >> /etc/default/grub

update-grub 2>/dev/null || true

echo ""
echo "KahLuna WARP OS boot splash installed."
echo "Reboot to see the new splash screen."
