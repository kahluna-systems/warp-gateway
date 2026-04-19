#!/bin/bash
# ============================================================================
# Export WARP OS rootfs to a raw disk image
# Usage: to-raw.sh <rootfs-dir> <output.img>
# Suitable for: bare metal (dd), Proxmox (qm importdisk)
# ============================================================================
set -euo pipefail

ROOTFS="$1"
OUTPUT="$2"
IMAGE_SIZE="${IMAGE_SIZE:-4G}"

echo "Creating raw disk image: $OUTPUT ($IMAGE_SIZE)"

# Create sparse image file
truncate -s "$IMAGE_SIZE" "$OUTPUT"

# Create partition table and filesystem
LOOP=$(losetup --find --show "$OUTPUT")
trap "losetup -d $LOOP" EXIT

# Create a single partition
parted -s "$LOOP" mklabel msdos
parted -s "$LOOP" mkpart primary ext4 1MiB 100%
parted -s "$LOOP" set 1 boot on

# Set up loop device with partitions
losetup -d "$LOOP"
LOOP=$(losetup --find --show --partscan "$OUTPUT")
trap "losetup -d $LOOP" EXIT

PART="${LOOP}p1"

# Wait for partition device
sleep 1

# Format
mkfs.ext4 -L warp-os "$PART"

# Mount and copy rootfs
MOUNT_DIR=$(mktemp -d)
mount "$PART" "$MOUNT_DIR"

echo "Copying rootfs..."
rsync -aHAX "$ROOTFS/" "$MOUNT_DIR/"

# Install GRUB
echo "Installing GRUB bootloader..."
mount --bind /dev "$MOUNT_DIR/dev"
mount --bind /dev/pts "$MOUNT_DIR/dev/pts"
mount -t proc proc "$MOUNT_DIR/proc"
mount -t sysfs sysfs "$MOUNT_DIR/sys"

chroot "$MOUNT_DIR" grub-install --target=i386-pc "$LOOP" 2>/dev/null || true
chroot "$MOUNT_DIR" update-grub 2>/dev/null || true

umount "$MOUNT_DIR/sys" || true
umount "$MOUNT_DIR/proc" || true
umount "$MOUNT_DIR/dev/pts" || true
umount "$MOUNT_DIR/dev" || true
umount "$MOUNT_DIR"
rmdir "$MOUNT_DIR"

echo "Raw image created: $OUTPUT"
ls -lh "$OUTPUT"
