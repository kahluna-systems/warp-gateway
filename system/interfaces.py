"""
Network interface detection and management.
Detects physical NICs, their status, and provides IP configuration.
"""
import re
import logging
from dataclasses import dataclass
from typing import Optional
from system.commander import run, run_pipe

logger = logging.getLogger("warp.system.interfaces")


@dataclass
class InterfaceInfo:
    """Information about a network interface."""
    name: str
    mac: str = ""
    ip: Optional[str] = None
    netmask: Optional[str] = None
    broadcast: Optional[str] = None
    link_up: bool = False
    speed: Optional[str] = None
    driver: Optional[str] = None
    is_physical: bool = False
    is_wireless: bool = False
    mtu: int = 1500

    def to_dict(self):
        return {
            "name": self.name,
            "mac": self.mac,
            "ip": self.ip,
            "netmask": self.netmask,
            "link_up": self.link_up,
            "speed": self.speed,
            "driver": self.driver,
            "is_physical": self.is_physical,
            "is_wireless": self.is_wireless,
            "mtu": self.mtu,
        }


@dataclass
class ArpEntry:
    """An entry from the ARP table."""
    ip: str
    mac: str
    interface: str
    state: str = ""

    def to_dict(self):
        return {"ip": self.ip, "mac": self.mac, "interface": self.interface, "state": self.state}


def detect_all() -> list:
    """Detect all network interfaces with their details."""
    interfaces = []

    # Get interface list from ip link
    result = run(["ip", "-j", "link", "show"])
    if not result.success:
        # Fallback to non-JSON parsing
        return _detect_all_fallback()

    import json
    try:
        links = json.loads(result.stdout)
    except json.JSONDecodeError:
        return _detect_all_fallback()

    for link in links:
        name = link.get("ifname", "")

        # Skip loopback and virtual interfaces
        if name == "lo" or name.startswith("veth") or name.startswith("docker") or name.startswith("br-"):
            continue

        info = InterfaceInfo(
            name=name,
            mac=link.get("address", ""),
            link_up="UP" in link.get("flags", []),
            mtu=link.get("mtu", 1500),
        )

        # Check if physical (has a driver in /sys/class/net)
        driver_result = run(["readlink", "-f", f"/sys/class/net/{name}/device/driver"])
        if driver_result.success and driver_result.stdout:
            info.is_physical = True
            info.driver = driver_result.stdout.split("/")[-1]

        # Check if wireless (suppress warning -- expected to fail on wired NICs)
        import subprocess
        try:
            wireless_result = subprocess.run(
                ["test", "-d", f"/sys/class/net/{name}/wireless"],
                capture_output=True, timeout=5,
            )
            info.is_wireless = wireless_result.returncode == 0
        except Exception:
            info.is_wireless = False

        # Get speed (suppress warning -- not all interfaces report speed)
        try:
            speed_result = subprocess.run(
                ["cat", f"/sys/class/net/{name}/speed"],
                capture_output=True, text=True, timeout=5,
            )
            if speed_result.returncode == 0 and speed_result.stdout.strip().lstrip('-').isdigit():
                speed_val = int(speed_result.stdout.strip())
                if speed_val > 0:
                    info.speed = f"{speed_val} Mbps"
        except Exception:
            pass

        # Get IP address
        addr_result = run(["ip", "-j", "addr", "show", name])
        if addr_result.success:
            try:
                addrs = json.loads(addr_result.stdout)
                for addr in addrs:
                    for ai in addr.get("addr_info", []):
                        if ai.get("family") == "inet":
                            info.ip = ai.get("local")
                            prefix = ai.get("prefixlen")
                            if prefix:
                                info.netmask = _prefix_to_netmask(int(prefix))
                            info.broadcast = ai.get("broadcast")
                            break
            except json.JSONDecodeError:
                pass

        interfaces.append(info)

    return interfaces


def _detect_all_fallback() -> list:
    """Fallback interface detection without JSON support."""
    interfaces = []
    result = run(["ip", "link", "show"])
    if not result.success:
        return interfaces

    current = None
    for line in result.stdout.split("\n"):
        match = re.match(r"^\d+:\s+(\S+):", line)
        if match:
            name = match.group(1).rstrip("@")
            if name != "lo" and not name.startswith("veth"):
                current = InterfaceInfo(name=name)
                current.link_up = "UP" in line
                interfaces.append(current)
        elif current and "link/ether" in line:
            mac_match = re.search(r"link/ether\s+(\S+)", line)
            if mac_match:
                current.mac = mac_match.group(1)

    return interfaces


def get_status(name: str) -> Optional[InterfaceInfo]:
    """Get detailed status for a specific interface."""
    for iface in detect_all():
        if iface.name == name:
            return iface
    return None


def set_ip(name: str, ip: str, netmask: str) -> 'CommandResult':
    """Set a static IP on an interface."""
    prefix = _netmask_to_prefix(netmask)
    # Flush existing IPs
    run(["ip", "addr", "flush", "dev", name], sudo=True)
    # Set new IP
    return run(["ip", "addr", "add", f"{ip}/{prefix}", "dev", name], sudo=True)


def bring_up(name: str) -> 'CommandResult':
    """Bring an interface up."""
    return run(["ip", "link", "set", name, "up"], sudo=True)


def bring_down(name: str) -> 'CommandResult':
    """Bring an interface down."""
    return run(["ip", "link", "set", name, "down"], sudo=True)


def get_arp_table() -> list:
    """Get the ARP table — shows all devices seen on the network."""
    entries = []
    result = run(["ip", "neigh", "show"])
    if not result.success:
        return entries

    for line in result.stdout.split("\n"):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 5 and "lladdr" in parts:
            ip = parts[0]
            dev_idx = parts.index("dev") + 1 if "dev" in parts else None
            lladdr_idx = parts.index("lladdr") + 1 if "lladdr" in parts else None
            interface = parts[dev_idx] if dev_idx else ""
            mac = parts[lladdr_idx] if lladdr_idx else ""
            state = parts[-1] if parts[-1] in ("REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "PERMANENT") else ""
            entries.append(ArpEntry(ip=ip, mac=mac, interface=interface, state=state))

    return entries


def detect_default_interface() -> Optional[str]:
    """Detect the default outbound interface (WAN)."""
    result = run(["ip", "route", "show", "default"])
    if result.success:
        match = re.search(r"dev\s+(\S+)", result.stdout)
        if match:
            return match.group(1)
    return None


def get_public_ip() -> Optional[str]:
    """Detect the public IP address."""
    import urllib.request
    try:
        return urllib.request.urlopen("https://ipv4.icanhazip.com", timeout=5).read().decode().strip()
    except Exception:
        return None


def _prefix_to_netmask(prefix: int) -> str:
    """Convert CIDR prefix to dotted netmask."""
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return f"{(mask >> 24) & 0xFF}.{(mask >> 16) & 0xFF}.{(mask >> 8) & 0xFF}.{mask & 0xFF}"


def _netmask_to_prefix(netmask: str) -> int:
    """Convert dotted netmask to CIDR prefix."""
    return sum(bin(int(x)).count("1") for x in netmask.split("."))
