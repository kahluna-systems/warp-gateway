#!/bin/bash
# ============================================================================
# Export WARP OS rootfs to a bootable installer ISO
# Usage: to-iso.sh <rootfs-dir> <output.iso>
#
# The ISO boots into a live environment and auto-launches the disk installer.
# ============================================================================
set -euo pipefail

ROOTFS="$1"
OUTPUT="$2"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE_DIR="$(dirname "$SCRIPT_DIR")"
WORK_DIR=$(mktemp -d)

echo "Creating bootable installer ISO: $OUTPUT"

# ── Check dependencies ───────────────────────────────────────────────────────

for tool in mksquashfs xorriso grub-mkrescue; do
    if ! command -v "$tool" &>/dev/null; then
        echo "ERROR: Required tool not found: $tool"
        echo "Install with: sudo apt install squashfs-tools xorriso grub-pc-bin grub-efi-amd64-bin"
        exit 1
    fi
done

# ── Build ISO filesystem ────────────────────────────────────────────────────

ISO_ROOT="$WORK_DIR/iso"
mkdir -p "$ISO_ROOT/live"
mkdir -p "$ISO_ROOT/boot/grub"
mkdir -p "$ISO_ROOT/installer"

# ── Create squashfs of the rootfs ────────────────────────────────────────────

echo "Creating squashfs filesystem (this takes a few minutes)..."
mksquashfs "$ROOTFS" "$ISO_ROOT/live/filesystem.squashfs" \
    -comp xz -Xbcj x86 -b 1M -no-duplicates -quiet

# ── Copy kernel and initrd ───────────────────────────────────────────────────

echo "Copying kernel and initrd..."
VMLINUZ=$(ls "$ROOTFS/boot/vmlinuz-"* 2>/dev/null | sort -V | tail -1)
INITRD=$(ls "$ROOTFS/boot/initrd.img-"* 2>/dev/null | sort -V | tail -1)

if [ -z "$VMLINUZ" ] || [ -z "$INITRD" ]; then
    echo "ERROR: Kernel or initrd not found in rootfs"
    exit 1
fi

cp "$VMLINUZ" "$ISO_ROOT/live/vmlinuz"
cp "$INITRD" "$ISO_ROOT/live/initrd"

# ── Copy the installer script ───────────────────────────────────────────────

cp "$IMAGE_DIR/installer/install.sh" "$ISO_ROOT/installer/"
chmod +x "$ISO_ROOT/installer/install.sh"

# ── Create GRUB config for the ISO ──────────────────────────────────────────

cat > "$ISO_ROOT/boot/grub/grub.cfg" << 'GRUB_EOF'
# Serial console support (for headless appliances)
serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1
terminal_input serial console
terminal_output serial console

set timeout=10
set default=0

# Colors
set color_normal=cyan/black
set color_highlight=white/blue

menuentry "KahLuna WARP OS -- Install to Disk" {
    linux /live/vmlinuz boot=live toram quiet splash console=tty0 console=ttyS0,115200n8
    initrd /live/initrd
}

menuentry "KahLuna WARP OS -- Install to Disk (verbose)" {
    linux /live/vmlinuz boot=live toram console=tty0 console=ttyS0,115200n8
    initrd /live/initrd
}

menuentry "KahLuna WARP OS -- Live Mode (no install)" {
    linux /live/vmlinuz boot=live quiet splash console=tty0 console=ttyS0,115200n8
    initrd /live/initrd
}
GRUB_EOF

# ── Create auto-installer hook ──────────────────────────────────────────────
# This script runs after the live system boots and launches the installer

mkdir -p "$ROOTFS/etc/profile.d"
cat > "$ROOTFS/etc/profile.d/warp-installer.sh" << 'PROFILE_EOF'
#!/bin/bash
# Auto-launch the WARP OS installer on first login in the live environment
if [ -f /run/live/medium/installer/install.sh ] && [ "$(id -u)" -eq 0 ]; then
    echo ""
    echo "KahLuna WARP OS Installer detected."
    echo ""
    read -p "Launch the disk installer? [Y/n]: " answer
    answer="${answer:-y}"
    if [[ "$answer" =~ ^[Yy] ]]; then
        bash /run/live/medium/installer/install.sh
    fi
fi
PROFILE_EOF
chmod +x "$ROOTFS/etc/profile.d/warp-installer.sh"

# Also set up auto-login on tty1 for the live environment
mkdir -p "$ROOTFS/etc/systemd/system/getty@tty1.service.d"
cat > "$ROOTFS/etc/systemd/system/getty@tty1.service.d/live-autologin.conf" << 'GETTY_EOF'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I $TERM
GETTY_EOF

# ── Rebuild squashfs with the installer hooks ────────────────────────────────

echo "Rebuilding squashfs with installer hooks..."
rm "$ISO_ROOT/live/filesystem.squashfs"
mksquashfs "$ROOTFS" "$ISO_ROOT/live/filesystem.squashfs" \
    -comp xz -Xbcj x86 -b 1M -no-duplicates -quiet

# ── Build the ISO ────────────────────────────────────────────────────────────

echo "Building ISO image..."
grub-mkrescue -o "$OUTPUT" "$ISO_ROOT" \
    -- -volid "WARP-OS" 2>/dev/null

# ── Cleanup ──────────────────────────────────────────────────────────────────

rm -rf "$WORK_DIR"

echo ""
echo "Installer ISO created: $OUTPUT"
ls -lh "$OUTPUT"
echo ""
echo "Boot this ISO on the target machine to install WARP OS."
echo "The installer will auto-launch after boot."
