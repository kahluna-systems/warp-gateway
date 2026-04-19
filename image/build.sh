#!/bin/bash
# ============================================================================
# KahLuna WARP OS — Image Builder
# Produces a minimal Ubuntu-based appliance image using debootstrap.
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
WORK_DIR="${WORK_DIR:-/tmp/warp-os-build}"
ROOTFS="$WORK_DIR/rootfs"
UBUNTU_RELEASE="${UBUNTU_RELEASE:-jammy}"  # jammy=22.04, noble=24.04
ARCH="${ARCH:-amd64}"
IMAGE_NAME="${IMAGE_NAME:-warp-os}"
IMAGE_VERSION="${IMAGE_VERSION:-0.1.0}"

echo "============================================"
echo "  KahLuna WARP OS Image Builder"
echo "  Release: $UBUNTU_RELEASE ($ARCH)"
echo "  Version: $IMAGE_VERSION"
echo "============================================"
echo

# ── Pre-flight checks ───────────────────────────────────────────────────────

check_deps() {
    local missing=()
    for cmd in debootstrap chroot mount umount losetup mkfs.ext4 grub-install; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        echo "ERROR: Missing build dependencies: ${missing[*]}"
        echo "Install with: sudo apt install debootstrap grub-pc-bin grub-efi-amd64-bin dosfstools"
        exit 1
    fi
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "ERROR: This script must be run as root (sudo)"
        exit 1
    fi
}

check_disk_space() {
    local available_mb
    available_mb=$(df -m /tmp | awk 'NR==2 {print $4}')
    if [ "$available_mb" -lt 4096 ]; then
        echo "ERROR: Need at least 4 GB free in /tmp (have ${available_mb} MB)"
        exit 1
    fi
}

check_root
check_deps
check_disk_space

# ── Step 1: Create work directory ────────────────────────────────────────────

echo "[1/6] Creating work directory..."
rm -rf "$WORK_DIR"
mkdir -p "$ROOTFS"

# ── Step 2: Bootstrap minimal Ubuntu ─────────────────────────────────────────

echo "[2/6] Running debootstrap ($UBUNTU_RELEASE)..."
debootstrap --variant=minbase --arch="$ARCH" "$UBUNTU_RELEASE" "$ROOTFS" http://archive.ubuntu.com/ubuntu

# ── Step 3: Customize (install packages, copy app, create users) ─────────────

echo "[3/6] Customizing image..."
mount --bind /dev "$ROOTFS/dev"
mount --bind /dev/pts "$ROOTFS/dev/pts"
mount -t proc proc "$ROOTFS/proc"
mount -t sysfs sysfs "$ROOTFS/sys"

# Copy scripts and config into chroot
cp "$SCRIPT_DIR/scripts/customize.sh" "$ROOTFS/tmp/"
cp "$SCRIPT_DIR/scripts/harden.sh" "$ROOTFS/tmp/"
cp "$SCRIPT_DIR/scripts/finalize.sh" "$ROOTFS/tmp/"
cp -r "$SCRIPT_DIR/config" "$ROOTFS/tmp/warp-config"

# Copy the gateway application
mkdir -p "$ROOTFS/opt/warp-gateway"
rsync -a --exclude='venv' --exclude='__pycache__' --exclude='.git' \
    --exclude='*.pyc' --exclude='image' --exclude='tests' \
    "$PROJECT_DIR/" "$ROOTFS/opt/warp-gateway/"

chroot "$ROOTFS" bash /tmp/customize.sh

# ── Step 4: Security hardening ───────────────────────────────────────────────

echo "[4/6] Applying security hardening..."
chroot "$ROOTFS" bash /tmp/harden.sh

# ── Step 5: Finalize (clean up, minimize) ────────────────────────────────────

echo "[5/6] Finalizing image..."
chroot "$ROOTFS" bash /tmp/finalize.sh

# Unmount
umount "$ROOTFS/sys" || true
umount "$ROOTFS/proc" || true
umount "$ROOTFS/dev/pts" || true
umount "$ROOTFS/dev" || true

# ── Step 6: Export ───────────────────────────────────────────────────────────

echo "[6/6] Exporting images..."
mkdir -p "$WORK_DIR/output"

# Raw disk image
bash "$SCRIPT_DIR/export/to-raw.sh" "$ROOTFS" "$WORK_DIR/output/${IMAGE_NAME}-${IMAGE_VERSION}.img"

# OVA (VMware)
bash "$SCRIPT_DIR/export/to-ova.sh" "$WORK_DIR/output/${IMAGE_NAME}-${IMAGE_VERSION}.img" "$WORK_DIR/output/${IMAGE_NAME}-${IMAGE_VERSION}.ova"

# ISO
bash "$SCRIPT_DIR/export/to-iso.sh" "$ROOTFS" "$WORK_DIR/output/${IMAGE_NAME}-${IMAGE_VERSION}.iso"

echo
echo "============================================"
echo "  Build complete!"
echo "  Output: $WORK_DIR/output/"
echo "============================================"
ls -lh "$WORK_DIR/output/"
