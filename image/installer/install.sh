#!/bin/bash
# ============================================================================
# KahLuna WARP OS — Disk Installer
# Runs from the live ISO environment. Writes the OS to a target disk,
# installs the bootloader, and prepares for first boot.
# ============================================================================
set -euo pipefail

# ── Colors (ANSI) ────────────────────────────────────────────────────────────
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m'

# ── Helpers ──────────────────────────────────────────────────────────────────

banner() {
    clear
    echo ""
    echo -e "${CYAN}============================================================${NC}"
    echo -e "${BOLD}       KahLuna WARP OS -- Disk Installer${NC}"
    echo -e "${CYAN}============================================================${NC}"
    echo ""
}

info()    { echo -e "  ${CYAN}>>>${NC} $1"; }
success() { echo -e "  ${GREEN}[OK]${NC} $1"; }
warn()    { echo -e "  ${YELLOW}[!!]${NC} $1"; }
fail()    { echo -e "  ${RED}[FAIL]${NC} $1"; }

confirm() {
    local msg="$1"
    local default="${2:-n}"
    local prompt
    if [ "$default" = "y" ]; then
        prompt="[Y/n]"
    else
        prompt="[y/N]"
    fi
    echo -ne "  ${msg} ${prompt}: "
    read -r answer
    answer="${answer:-$default}"
    [[ "$answer" =~ ^[Yy] ]]
}

# ── Pre-flight ───────────────────────────────────────────────────────────────

banner

# Must be root
if [ "$(id -u)" -ne 0 ]; then
    fail "This installer must be run as root."
    echo "  Run: sudo bash install.sh"
    exit 1
fi

# Check for required tools
for tool in parted mkfs.ext4 mount rsync grub-install; do
    if ! command -v "$tool" &>/dev/null; then
        fail "Required tool not found: $tool"
        exit 1
    fi
done

# ── Detect Disks ─────────────────────────────────────────────────────────────

info "Detecting available disks..."
echo ""

# Find block devices that are disks (not partitions, not loop, not rom)
mapfile -t DISKS < <(lsblk -dpno NAME,SIZE,TYPE,MODEL | grep ' disk ' | grep -v 'loop\|sr\|rom')

if [ ${#DISKS[@]} -eq 0 ]; then
    fail "No suitable disks found."
    exit 1
fi

echo -e "  ${BOLD}Available disks:${NC}"
echo ""
echo -e "  ${DIM}#   Device          Size        Model${NC}"
echo -e "  ${DIM}--- --------------- ----------- --------------------------------${NC}"

idx=1
declare -a DISK_DEVICES
for disk_line in "${DISKS[@]}"; do
    dev=$(echo "$disk_line" | awk '{print $1}')
    size=$(echo "$disk_line" | awk '{print $2}')
    model=$(echo "$disk_line" | awk '{$1=$2=$3=""; print $0}' | sed 's/^ *//')
    echo -e "  ${idx})  ${dev}          ${size}       ${model}"
    DISK_DEVICES+=("$dev")
    ((idx++))
done

echo ""

# ── Select Target Disk ───────────────────────────────────────────────────────

if [ ${#DISK_DEVICES[@]} -eq 1 ]; then
    TARGET="${DISK_DEVICES[0]}"
    info "Only one disk found: ${TARGET}"
else
    while true; do
        echo -ne "  Select target disk [1-${#DISK_DEVICES[@]}]: "
        read -r choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#DISK_DEVICES[@]} ]; then
            TARGET="${DISK_DEVICES[$((choice-1))]}"
            break
        fi
        warn "Invalid selection."
    done
fi

echo ""
echo -e "  ${RED}${BOLD}WARNING: ALL DATA ON ${TARGET} WILL BE DESTROYED.${NC}"
echo ""

if ! confirm "Proceed with installation to ${TARGET}?" "n"; then
    info "Installation cancelled."
    exit 0
fi

# ── Partition the Disk ───────────────────────────────────────────────────────

banner
info "Partitioning ${TARGET}..."

# Unmount any existing partitions
umount "${TARGET}"* 2>/dev/null || true

# Detect if system uses UEFI or BIOS
BOOT_MODE="bios"
if [ -d /sys/firmware/efi ]; then
    BOOT_MODE="uefi"
fi

info "Boot mode: ${BOOT_MODE}"

if [ "$BOOT_MODE" = "uefi" ]; then
    # GPT + EFI System Partition + Root
    parted -s "$TARGET" mklabel gpt
    parted -s "$TARGET" mkpart ESP fat32 1MiB 512MiB
    parted -s "$TARGET" set 1 esp on
    parted -s "$TARGET" mkpart root ext4 512MiB 100%

    sleep 1  # Wait for kernel to register partitions

    # Determine partition naming (sda1 vs nvme0n1p1)
    if [[ "$TARGET" == *nvme* ]] || [[ "$TARGET" == *mmcblk* ]]; then
        EFI_PART="${TARGET}p1"
        ROOT_PART="${TARGET}p2"
    else
        EFI_PART="${TARGET}1"
        ROOT_PART="${TARGET}2"
    fi

    info "Formatting EFI partition (${EFI_PART})..."
    mkfs.fat -F32 "$EFI_PART"

    info "Formatting root partition (${ROOT_PART})..."
    mkfs.ext4 -L warp-os -q "$ROOT_PART"
else
    # MBR + single root partition
    parted -s "$TARGET" mklabel msdos
    parted -s "$TARGET" mkpart primary ext4 1MiB 100%
    parted -s "$TARGET" set 1 boot on

    sleep 1

    if [[ "$TARGET" == *nvme* ]] || [[ "$TARGET" == *mmcblk* ]]; then
        ROOT_PART="${TARGET}p1"
    else
        ROOT_PART="${TARGET}1"
    fi

    info "Formatting root partition (${ROOT_PART})..."
    mkfs.ext4 -L warp-os -q "$ROOT_PART"
fi

success "Disk partitioned and formatted."

# ── Mount and Copy ───────────────────────────────────────────────────────────

info "Mounting target filesystem..."
MOUNT_DIR=$(mktemp -d)
mount "$ROOT_PART" "$MOUNT_DIR"

if [ "$BOOT_MODE" = "uefi" ]; then
    mkdir -p "${MOUNT_DIR}/boot/efi"
    mount "$EFI_PART" "${MOUNT_DIR}/boot/efi"
fi

info "Copying WARP OS to disk (this may take a few minutes)..."

# Determine the source -- either the live squashfs or the running rootfs
if [ -f /run/live/medium/live/filesystem.squashfs ]; then
    # Live ISO boot -- unsquash and copy
    SQUASH_MNT=$(mktemp -d)
    mount -t squashfs /run/live/medium/live/filesystem.squashfs "$SQUASH_MNT" -o ro
    rsync -aHAX --info=progress2 "${SQUASH_MNT}/" "${MOUNT_DIR}/"
    umount "$SQUASH_MNT"
    rmdir "$SQUASH_MNT"
elif [ -d /opt/warp-gateway ]; then
    # Running from an existing installation -- copy the live rootfs
    rsync -aHAX --info=progress2 \
        --exclude='/proc/*' \
        --exclude='/sys/*' \
        --exclude='/dev/*' \
        --exclude='/run/*' \
        --exclude='/tmp/*' \
        --exclude='/mnt/*' \
        --exclude='/media/*' \
        --exclude='/lost+found' \
        / "${MOUNT_DIR}/"
else
    fail "Cannot determine source filesystem."
    umount "$MOUNT_DIR"
    exit 1
fi

success "Filesystem copied."

# ── Configure the Installed System ───────────────────────────────────────────

info "Configuring installed system..."

# Generate fstab
ROOT_UUID=$(blkid -s UUID -o value "$ROOT_PART")
echo "# WARP OS fstab" > "${MOUNT_DIR}/etc/fstab"
echo "UUID=${ROOT_UUID}  /  ext4  errors=remount-ro  0  1" >> "${MOUNT_DIR}/etc/fstab"

if [ "$BOOT_MODE" = "uefi" ]; then
    EFI_UUID=$(blkid -s UUID -o value "$EFI_PART")
    echo "UUID=${EFI_UUID}  /boot/efi  vfat  umask=0077  0  1" >> "${MOUNT_DIR}/etc/fstab"
fi

# Ensure data directory exists
mkdir -p "${MOUNT_DIR}/var/lib/warp-gateway"
mkdir -p "${MOUNT_DIR}/etc/warp-gateway"

# Remove any existing startup-config (triggers first-boot wizard)
rm -f "${MOUNT_DIR}/etc/warp-gateway/startup-config"
rm -f "${MOUNT_DIR}/opt/warp-gateway/startup-config"

# Remove any existing database (clean first boot)
rm -f "${MOUNT_DIR}/var/lib/warp-gateway/gateway.db"

success "System configured."

# ── Install Bootloader ───────────────────────────────────────────────────────

info "Installing bootloader..."

# Bind mount system directories for chroot
mount --bind /dev "${MOUNT_DIR}/dev"
mount --bind /dev/pts "${MOUNT_DIR}/dev/pts"
mount -t proc proc "${MOUNT_DIR}/proc"
mount -t sysfs sysfs "${MOUNT_DIR}/sys"

if [ "$BOOT_MODE" = "uefi" ]; then
    mount --bind /sys/firmware/efi/efivars "${MOUNT_DIR}/sys/firmware/efi/efivars" 2>/dev/null || true
    chroot "$MOUNT_DIR" grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=WARP-OS --recheck
else
    chroot "$MOUNT_DIR" grub-install --target=i386-pc --recheck "$TARGET"
fi

# Update GRUB config with correct root UUID
chroot "$MOUNT_DIR" update-grub

success "Bootloader installed."

# ── Cleanup ──────────────────────────────────────────────────────────────────

info "Cleaning up..."

umount "${MOUNT_DIR}/sys/firmware/efi/efivars" 2>/dev/null || true
umount "${MOUNT_DIR}/sys" 2>/dev/null || true
umount "${MOUNT_DIR}/proc" 2>/dev/null || true
umount "${MOUNT_DIR}/dev/pts" 2>/dev/null || true
umount "${MOUNT_DIR}/dev" 2>/dev/null || true

if [ "$BOOT_MODE" = "uefi" ]; then
    umount "${MOUNT_DIR}/boot/efi" 2>/dev/null || true
fi

umount "$MOUNT_DIR"
rmdir "$MOUNT_DIR"

sync

# ── Done ─────────────────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${BOLD}       Installation Complete${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo -e "  WARP OS has been installed to ${BOLD}${TARGET}${NC}"
echo ""
echo -e "  On first boot, the setup wizard will guide you through"
echo -e "  network configuration, admin credentials, and management"
echo -e "  mode selection."
echo ""
echo -e "  ${DIM}Remove the installation media and reboot.${NC}"
echo ""

if confirm "Reboot now?" "y"; then
    reboot
fi
