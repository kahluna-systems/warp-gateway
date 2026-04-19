#!/bin/bash
# ============================================================================
# Export WARP OS rootfs to a bootable ISO
# Usage: to-iso.sh <rootfs-dir> <output.iso>
# ============================================================================
set -euo pipefail

ROOTFS="$1"
OUTPUT="$2"
WORK_DIR=$(mktemp -d)

echo "Creating bootable ISO: $OUTPUT"

# Check for genisoimage or xorriso
ISO_TOOL=""
if command -v xorriso &>/dev/null; then
    ISO_TOOL="xorriso"
elif command -v genisoimage &>/dev/null; then
    ISO_TOOL="genisoimage"
else
    echo "ERROR: Neither xorriso nor genisoimage found."
    echo "Install with: sudo apt install xorriso"
    exit 1
fi

# Create ISO filesystem structure
ISO_ROOT="$WORK_DIR/iso"
mkdir -p "$ISO_ROOT/live"
mkdir -p "$ISO_ROOT/boot/grub"

# Create squashfs of the rootfs
echo "Creating squashfs filesystem..."
if ! command -v mksquashfs &>/dev/null; then
    echo "ERROR: mksquashfs not found. Install with: sudo apt install squashfs-tools"
    exit 1
fi

mksquashfs "$ROOTFS" "$ISO_ROOT/live/filesystem.squashfs" \
    -comp xz -Xbcj x86 -b 1M -no-duplicates

# Create GRUB config for ISO boot
cat > "$ISO_ROOT/boot/grub/grub.cfg" << 'EOF'
set timeout=5
set default=0

menuentry "KahLuna WARP OS -- Install" {
    linux /live/vmlinuz boot=live toram quiet
    initrd /live/initrd
}

menuentry "KahLuna WARP OS -- Install (verbose)" {
    linux /live/vmlinuz boot=live toram
    initrd /live/initrd
}
EOF

# Copy kernel and initrd from rootfs
cp "$ROOTFS/boot/vmlinuz-"* "$ISO_ROOT/live/vmlinuz" 2>/dev/null || true
cp "$ROOTFS/boot/initrd.img-"* "$ISO_ROOT/live/initrd" 2>/dev/null || true

# Build ISO
echo "Building ISO..."
if [ "$ISO_TOOL" = "xorriso" ]; then
    xorriso -as mkisofs \
        -o "$OUTPUT" \
        -isohybrid-mbr /usr/lib/ISOLINUX/isohdpfx.bin 2>/dev/null || true \
        -c boot/boot.cat \
        -b boot/grub/grub.cfg \
        -no-emul-boot \
        -boot-load-size 4 \
        -boot-info-table \
        "$ISO_ROOT" 2>/dev/null || \
    grub-mkrescue -o "$OUTPUT" "$ISO_ROOT" 2>/dev/null || \
    echo "WARNING: ISO creation may require additional GRUB packages"
else
    genisoimage -o "$OUTPUT" \
        -b boot/grub/grub.cfg \
        -no-emul-boot \
        -boot-load-size 4 \
        -boot-info-table \
        -J -R -V "WARP-OS" \
        "$ISO_ROOT"
fi

rm -rf "$WORK_DIR"
echo "ISO created: $OUTPUT"
ls -lh "$OUTPUT"
