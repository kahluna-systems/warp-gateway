# KahLuna WARP OS -- Deployment Guide

This guide covers every deployment method for the WARP Gateway appliance, from virtual machines to pre-installed hardware. Choose the method that fits your use case.

---

## Deployment Methods at a Glance

| Method | Best For | Image Format | Setup Interface |
|--------|----------|-------------|-----------------|
| ISO Installer | New bare metal or VM installs | `.iso` | VGA/serial console |
| Raw Disk Image | Proxmox, dd to disk, factory flash | `.img` | Serial console or LAN |
| OVA | VMware ESXi, Workstation, Fusion | `.ova` | VM console or LAN |
| Pre-provisioned | MSP/enterprise mass deployment | `.img` with baked token | Automatic (no touch) |

---

## 1. ISO Installer

Use this when you have a bare metal machine or VM and want a guided installation experience.

### When to Use

- First-time installs on physical hardware
- VM deployments where you want to choose the target disk
- Lab and testing environments
- Any situation where you want to inspect the hardware before committing

### What You Need

- A USB drive (2 GB minimum) or virtual CD-ROM
- The `warp-os-<version>.iso` file
- A machine with at least 2 GB RAM, 8 GB disk, and 2 network interfaces

### Steps

**1. Write the ISO to USB (physical hardware):**

```bash
# Linux/macOS
sudo dd if=warp-os-0.1.0.iso of=/dev/sdX bs=4M status=progress

# Windows -- use Rufus (rufus.ie) or balenaEtcher
```

**2. Boot from the USB.**

The GRUB menu appears with three options:

- **Install to Disk** -- boots into RAM, launches the disk installer (default)
- **Install to Disk (verbose)** -- same, with full kernel boot messages
- **Live Mode** -- runs from RAM without installing (for testing)

The menu auto-selects "Install to Disk" after 10 seconds.

**3. The disk installer launches automatically.**

```
============================================================
       KahLuna WARP OS -- Disk Installer
============================================================

  >>> Detecting available disks...

  Available disks:

  #   Device          Size        Model
  --- --------------- ----------- --------------------------------
  1)  /dev/sda        32G         INTEL SSDSC2BB08

  Select target disk [1-1 or name]: 1

  WARNING: ALL DATA ON /dev/sda WILL BE DESTROYED.

  Proceed with installation to /dev/sda? [y/N]: y
```

The installer:
- Auto-detects UEFI vs BIOS boot mode
- Partitions the disk (EFI + root, or MBR + root)
- Copies the OS from the live environment
- Installs the GRUB bootloader
- Prepares the system for first boot

**4. Remove the USB and reboot.**

The system boots from the internal disk. The Plymouth boot splash displays the KahLuna boot sequence, then the first-boot wizard launches.

**5. Complete the first-boot wizard** (see "First-Boot Setup" below).

### Serial Console (Headless Hardware)

If the machine has no display output (typical for network appliances), connect via serial console:

```bash
# Linux
screen /dev/ttyUSB0 115200

# macOS
screen /dev/tty.usbserial-* 115200

# Windows -- use PuTTY with COM port at 115200 baud
```

The GRUB menu and installer both output to serial (ttyS0 at 115200,8N1). The entire install and setup process works over serial.

---

## 2. Raw Disk Image (Proxmox / Bare Metal)

Use this when you want to write the OS directly to a disk without an interactive installer.

### When to Use

- Proxmox VM deployments
- Factory pre-installation onto eMMC or SSD
- Automated provisioning pipelines
- Cloning to multiple identical machines

### Proxmox Deployment

**1. Upload the image to your Proxmox host:**

```bash
scp warp-os-0.1.0.img root@proxmox-host:/var/lib/vz/images/
```

**2. Create a VM:**

```bash
# Create VM with 2 cores, 2 GB RAM, 2 NICs
qm create 200 --name warp-gw --cores 2 --memory 2048 \
    --net0 virtio,bridge=vmbr0 \
    --net1 virtio,bridge=vmbr1 \
    --scsihw virtio-scsi-single

# Import the disk image
qm importdisk 200 /var/lib/vz/images/warp-os-0.1.0.img local-lvm

# Attach the disk
qm set 200 --scsi0 local-lvm:vm-200-disk-0

# Set boot order
qm set 200 --boot order=scsi0

# Enable serial console (optional, for headless management)
qm set 200 --serial0 socket
```

**3. Start the VM:**

```bash
qm start 200
```

**4. Connect to the console** (Proxmox web UI or serial) and complete the first-boot wizard.

### Bare Metal (dd)

Write the image directly to a disk:

```bash
sudo dd if=warp-os-0.1.0.img of=/dev/sdX bs=4M status=progress
sync
```

Then install the disk in the target machine and boot.

### Factory Pre-installation

For manufacturing, the raw image is the right format. Flash it to the target storage (eMMC, M.2 SSD, or SATA SSD) using a flashing station or a simple dd from a Linux workstation. The image includes:

- Complete OS with all packages
- WARP Gateway application and Python venv
- Systemd services (auto-start on boot)
- Empty database (triggers first-boot wizard)
- No startup-config (triggers first-boot wizard)

---

## 3. OVA (VMware)

Use this for VMware ESXi, Workstation, or Fusion deployments.

### When to Use

- VMware-based lab environments
- Enterprise VMware infrastructure
- Quick evaluation and testing

### Steps

**1. Import the OVA:**

- **ESXi**: vSphere Client -> Deploy OVF Template -> select `warp-os-0.1.0.ova`
- **Workstation**: File -> Open -> select the OVA
- **Fusion**: File -> Import -> select the OVA

The OVA is pre-configured with:
- 2 vCPUs, 2 GB RAM
- 2 network adapters (WAN + LAN) using VmxNet3
- Ubuntu 64-bit guest OS type

**2. Configure networking:**

Before powering on, verify the network adapter assignments:
- **Network adapter 1** (WAN) -- connect to your upstream/internet network
- **Network adapter 2** (LAN) -- connect to your internal/lab network

**3. Power on and complete the first-boot wizard.**

---

## 4. Pre-provisioned Deployment

Use this for managed deployments where the gateway should auto-register with KahLuna Platform Core without operator intervention.

### When to Use

- MSP deploying gateways to customer sites
- Enterprise branch office rollouts
- Hardware shipped directly to end customers
- Any scenario where you want zero-touch provisioning

### How It Works

1. The MSP generates a provisioning token in Mission Control
2. The token and Platform Core URL are embedded in the gateway image at build time
3. The gateway is shipped to the customer site
4. The customer plugs in power and WAN ethernet
5. The gateway boots, gets a WAN IP via DHCP, and auto-registers with Platform Core
6. The MSP sees the gateway appear in Mission Control and can configure it remotely
7. The customer connects to the LAN port and gets network access

### Building a Pre-provisioned Image

Modify the `GatewayConfig` in the image before flashing:

```bash
# After building the base image, mount it and embed the token
sudo losetup --find --show --partscan warp-os-0.1.0.img
sudo mount /dev/loop0p2 /mnt  # or p1 for MBR

# Create the pre-provision config
sudo mkdir -p /mnt/etc/warp-gateway
cat << EOF | sudo tee /mnt/etc/warp-gateway/pre-provision.json
{
    "token": "YOUR_PROVISIONING_TOKEN",
    "platform_url": "https://api.kahluna.com",
    "management_mode": "pre_provisioned"
}
EOF

sudo umount /mnt
sudo losetup -d /dev/loop0
```

On first boot, the gateway reads the pre-provision config, skips the management mode prompt in the wizard, and auto-registers after WAN connectivity is established.

### Setup Mode (LAN Access)

Even with pre-provisioned gateways, the LAN port is immediately accessible:

- **Default LAN IP**: 10.246.247.1
- **DHCP range**: 10.246.247.10 - 10.246.247.199
- **Web UI**: http://10.246.247.1:5000

The customer can plug a laptop into the LAN port, get an IP via DHCP, and access the web UI to verify the gateway status or complete local configuration.

---

## First-Boot Setup

Regardless of deployment method, the first-boot wizard runs when the gateway starts with no existing configuration.

### Console Wizard

The wizard walks through:

1. **Interface detection** -- discovers all physical NICs, shows MAC addresses, link status, and DHCP detection
2. **WAN assignment** -- select which interface connects to the internet/upstream
3. **LAN assignment** -- select which interface serves the local network
4. **WAN configuration** -- static IP or DHCP
5. **LAN configuration** -- gateway IP, subnet, DHCP server settings
6. **Admin credentials** -- username and password for CLI and web UI
7. **Enable password** -- separate password for privileged CLI mode
8. **Hostname** -- gateway identity
9. **Management mode** -- standalone (local only) or managed (register with KahLuna Nexus)

### Web UI Setup

If the wizard is skipped (Ctrl+C) or the gateway boots in setup mode, the web UI is accessible at:

```
http://10.246.247.1:5000
```

Connect a laptop to the LAN port, obtain an IP via DHCP, and open the URL in a browser. Default credentials after a skipped wizard: `admin` / `admin` (change immediately).

### Post-Setup

After the wizard completes:

- The CLI shell is available on the console and via SSH
- The web UI is available on port 5000
- The startup configuration is saved and persists across reboots
- All services (DHCP, DNS, firewall, VPN) are active based on the configuration

---

## Building the Images

All images are built from the same source using the image builder scripts.

### Prerequisites

A Linux build host (Ubuntu 22.04 or 24.04) with:

```bash
sudo apt install debootstrap grub-pc-bin grub-efi-amd64-bin \
    squashfs-tools xorriso qemu-utils parted dosfstools rsync
```

At least 4 GB free disk space in `/tmp`.

### Build All Formats

```bash
cd /path/to/warp-gateway
sudo bash image/build.sh
```

This produces three files in `/tmp/warp-os-build/output/`:

| File | Format | Size (approx) | Use |
|------|--------|---------------|-----|
| `warp-os-0.1.0.img` | Raw disk image | 2-4 GB | Proxmox, dd, factory flash |
| `warp-os-0.1.0.ova` | VMware OVA | 1-2 GB | VMware ESXi/Workstation |
| `warp-os-0.1.0.iso` | Bootable ISO | 1-2 GB | USB installer |

### Build Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WORK_DIR` | `/tmp/warp-os-build` | Build working directory |
| `UBUNTU_RELEASE` | `jammy` | Ubuntu release (jammy=22.04, noble=24.04) |
| `ARCH` | `amd64` | Target architecture |
| `IMAGE_NAME` | `warp-os` | Output filename prefix |
| `IMAGE_VERSION` | `0.1.0` | Version string |
| `IMAGE_SIZE` | `4G` | Raw image disk size |

Example with custom settings:

```bash
UBUNTU_RELEASE=noble IMAGE_VERSION=1.0.0 IMAGE_SIZE=8G sudo -E bash image/build.sh
```

---

## Hardware Requirements

### Minimum

- CPU: x86_64, 1 GHz dual-core
- RAM: 1 GB
- Storage: 4 GB
- NICs: 1 (WAN only) or 2 (WAN + LAN)

### Recommended

- CPU: x86_64, 2 GHz quad-core (Intel Celeron N5105 or better)
- RAM: 2-4 GB
- Storage: 16-32 GB SSD
- NICs: 2-6 (Intel i226-V recommended for appliance hardware)

### Tested Hardware

| Device | CPU | NICs | Notes |
|--------|-----|------|-------|
| Generic x86 VM | Any | 2+ virtio | VMware, Proxmox, VirtualBox |
| Fanless Mini PC (N3710) | Intel Pentium N3710 | 6x i226 | Primary appliance target |
| Intel NUC | Various | 1-2 | Development and testing |

---

## Network Topology

### Typical Deployment

```
Internet
    |
[ISP Router/Modem]
    |
    | WAN (ens33 / eth0)
+---+---+
| WARP  |
| GW    |
+---+---+
    | LAN (ens38 / eth1)
    |
[Switch]
    |
+---+---+---+
|   |   |   |
PC  PC  AP  Server
```

### Multi-Site with Central Management

```
                    KahLuna Cloud
                   +-------------+
                   | Platform    |
                   | Core API    |
                   | Mission     |
                   | Control UI  |
                   +------+------+
                          |
            +-------------+-------------+
            |             |             |
      Site A (HQ)   Site B (Branch) Site C (Remote)
      +--------+    +--------+     +--------+
      | WARP   |    | WARP   |     | WARP   |
      | GW-01  |    | GW-02  |     | GW-03  |
      +--------+    +--------+     +--------+
      | LAN    |    | LAN    |     | LAN    |
      | Users  |    | Users  |     | Users  |
      +--------+    +--------+     +--------+
```

---

## Troubleshooting

### Cannot reach the web UI after first boot

1. Connect a laptop to the LAN port
2. Check if you received a DHCP address in the 10.246.247.x range
3. Try `http://10.246.247.1:5000`
4. If no DHCP, set a static IP: `10.246.247.100/24`, gateway `10.246.247.1`

### Serial console shows no output

- Verify cable connection and baud rate (115200, 8N1)
- Try both COM1 (ttyS0) and COM2 (ttyS1)
- Some hardware requires BIOS configuration to enable serial console output

### Installer doesn't detect any disks

- Verify the target disk is connected and recognized by the BIOS
- Check `lsblk` from the live environment (choose "Live Mode" from GRUB)
- NVMe drives require kernel support (included in the default image)

### Gateway can't reach the internet after setup

- Verify the WAN interface has an IP: `show interfaces` in the CLI
- Check the default route: `show ip route`
- Test DNS: `nslookup google.com`
- If WAN is DHCP, verify the upstream DHCP server is reachable

### Forgot the admin password

From the serial console or physical console, boot into recovery mode (GRUB menu option 2), then:

```bash
cd /opt/warp-gateway
source venv/bin/activate
python3 -c "
from gateway import create_app
from database import db
from models_new import User
app = create_app()
with app.app_context():
    user = User.query.filter_by(username='admin').first()
    user.set_password('newpassword')
    db.session.commit()
    print('Password reset.')
"
```
