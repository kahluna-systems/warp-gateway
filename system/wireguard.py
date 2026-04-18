"""
WireGuard interface lifecycle management.
Creates, destroys, and manages WireGuard interfaces and peers.
All operations go through commander.py for safe execution.
"""
import os
import re
import logging
from dataclasses import dataclass, field
from typing import Optional
from system.commander import run, which

logger = logging.getLogger("warp.system.wireguard")

WG_CONFIG_DIR = "/etc/wireguard"


@dataclass
class PeerStatus:
    """Status of a WireGuard peer from wg show."""
    public_key: str
    endpoint: Optional[str] = None
    allowed_ips: str = ""
    latest_handshake: Optional[int] = None  # unix timestamp
    transfer_rx: int = 0  # bytes
    transfer_tx: int = 0  # bytes
    persistent_keepalive: Optional[int] = None

    def to_dict(self):
        return {
            "public_key": self.public_key,
            "endpoint": self.endpoint,
            "allowed_ips": self.allowed_ips,
            "latest_handshake": self.latest_handshake,
            "transfer_rx": self.transfer_rx,
            "transfer_tx": self.transfer_tx,
            "persistent_keepalive": self.persistent_keepalive,
            "connected": self.latest_handshake is not None and self.latest_handshake > 0,
        }


@dataclass
class InterfaceStatus:
    """Status of a WireGuard interface from wg show."""
    name: str
    public_key: str = ""
    private_key: str = "(hidden)"
    listening_port: int = 0
    peers: list = field(default_factory=list)

    def to_dict(self):
        return {
            "name": self.name,
            "public_key": self.public_key,
            "listening_port": self.listening_port,
            "peer_count": len(self.peers),
            "connected_peers": sum(1 for p in self.peers if p.latest_handshake and p.latest_handshake > 0),
            "peers": [p.to_dict() for p in self.peers],
        }


def is_installed() -> bool:
    """Check if WireGuard tools are installed."""
    return which("wg") is not None and which("wg-quick") is not None


def generate_keypair() -> tuple:
    """Generate a WireGuard private/public key pair."""
    priv = run(["wg", "genkey"])
    if not priv.success:
        return None, None
    pub = run(["wg", "pubkey"], input_data=priv.stdout)
    if not pub.success:
        return None, None
    return priv.stdout, pub.stdout


def generate_preshared_key() -> Optional[str]:
    """Generate a WireGuard preshared key."""
    result = run(["wg", "genpsk"])
    return result.stdout if result.success else None


def write_config(name: str, config_content: str) -> bool:
    """Write a WireGuard config file to /etc/wireguard/."""
    config_path = os.path.join(WG_CONFIG_DIR, f"{name}.conf")
    try:
        # Ensure directory exists
        run(["mkdir", "-p", WG_CONFIG_DIR], sudo=True)
        # Write config via tee (needs sudo for /etc/wireguard)
        result = run(["tee", config_path], sudo=True, input_data=config_content)
        if result.success:
            # Restrict permissions
            run(["chmod", "600", config_path], sudo=True)
            logger.info(f"Wrote WireGuard config: {config_path}")
            return True
        return False
    except Exception as e:
        logger.error(f"Failed to write config {config_path}: {e}")
        return False


def create_interface(name: str, config_content: str) -> 'CommandResult':
    """Create and bring up a WireGuard interface."""
    if not is_installed():
        from system.commander import CommandResult
        return CommandResult(success=False, error="WireGuard is not installed")

    # Write config
    if not write_config(name, config_content):
        from system.commander import CommandResult
        return CommandResult(success=False, error=f"Failed to write config for {name}")

    # Bring up interface
    result = run(["wg-quick", "up", name], sudo=True, timeout=15)
    if result.success:
        logger.info(f"WireGuard interface {name} is UP")
    else:
        logger.error(f"Failed to bring up {name}: {result.stderr}")
    return result


def destroy_interface(name: str) -> 'CommandResult':
    """Bring down and remove a WireGuard interface."""
    # Bring down
    result = run(["wg-quick", "down", name], sudo=True, timeout=15)

    # Remove config file
    config_path = os.path.join(WG_CONFIG_DIR, f"{name}.conf")
    run(["rm", "-f", config_path], sudo=True)

    if result.success:
        logger.info(f"WireGuard interface {name} destroyed")
    else:
        logger.warning(f"Error destroying {name}: {result.stderr}")
    return result


def add_peer(
    interface: str,
    public_key: str,
    allowed_ips: str,
    endpoint: Optional[str] = None,
    preshared_key: Optional[str] = None,
    persistent_keepalive: Optional[int] = None,
) -> 'CommandResult':
    """Add a peer to a running WireGuard interface."""
    cmd = ["wg", "set", interface, "peer", public_key, "allowed-ips", allowed_ips]

    if endpoint:
        cmd.extend(["endpoint", endpoint])
    if preshared_key:
        cmd.extend(["preshared-key", "/dev/stdin"])
    if persistent_keepalive:
        cmd.extend(["persistent-keepalive", str(persistent_keepalive)])

    result = run(cmd, sudo=True, input_data=preshared_key if preshared_key else None)
    if result.success:
        logger.info(f"Added peer {public_key[:16]}... to {interface}")
    else:
        logger.error(f"Failed to add peer to {interface}: {result.stderr}")
    return result


def remove_peer(interface: str, public_key: str) -> 'CommandResult':
    """Remove a peer from a running WireGuard interface."""
    result = run(["wg", "set", interface, "peer", public_key, "remove"], sudo=True)
    if result.success:
        logger.info(f"Removed peer {public_key[:16]}... from {interface}")
    return result


def get_status(interface: str) -> Optional[InterfaceStatus]:
    """Get the status of a WireGuard interface by parsing wg show output."""
    result = run(["wg", "show", interface], sudo=True)
    if not result.success:
        return None
    return _parse_wg_show(interface, result.stdout)


def get_all_interfaces() -> list:
    """List all WireGuard interfaces."""
    result = run(["wg", "show", "interfaces"], sudo=True)
    if not result.success or not result.stdout:
        return []
    return result.stdout.split()


def _parse_wg_show(name: str, output: str) -> InterfaceStatus:
    """Parse the output of wg show <interface> into structured data."""
    status = InterfaceStatus(name=name)
    current_peer = None

    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue

        if line.startswith("public key:"):
            status.public_key = line.split(":", 1)[1].strip()
        elif line.startswith("listening port:"):
            try:
                status.listening_port = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif line.startswith("peer:"):
            if current_peer:
                status.peers.append(current_peer)
            current_peer = PeerStatus(public_key=line.split(":", 1)[1].strip())
        elif current_peer:
            if line.startswith("endpoint:"):
                current_peer.endpoint = line.split(":", 1)[1].strip()
            elif line.startswith("allowed ips:"):
                current_peer.allowed_ips = line.split(":", 1)[1].strip()
            elif line.startswith("latest handshake:"):
                hs = line.split(":", 1)[1].strip()
                if "second" in hs or "minute" in hs or "hour" in hs:
                    current_peer.latest_handshake = _parse_handshake_time(hs)
            elif line.startswith("transfer:"):
                tx_rx = line.split(":", 1)[1].strip()
                rx_match = re.search(r"([\d.]+)\s+(\w+)\s+received", tx_rx)
                tx_match = re.search(r"([\d.]+)\s+(\w+)\s+sent", tx_rx)
                if rx_match:
                    current_peer.transfer_rx = _parse_bytes(float(rx_match.group(1)), rx_match.group(2))
                if tx_match:
                    current_peer.transfer_tx = _parse_bytes(float(tx_match.group(1)), tx_match.group(2))
            elif line.startswith("persistent keepalive:"):
                ka = line.split(":", 1)[1].strip()
                if ka != "off":
                    try:
                        current_peer.persistent_keepalive = int(ka.split()[0])
                    except ValueError:
                        pass

    if current_peer:
        status.peers.append(current_peer)

    return status


def _parse_handshake_time(text: str) -> int:
    """Parse handshake time like '1 minute, 23 seconds ago' into seconds ago."""
    import time
    total_seconds = 0
    for match in re.finditer(r"(\d+)\s+(second|minute|hour|day)", text):
        val = int(match.group(1))
        unit = match.group(2)
        if unit == "second":
            total_seconds += val
        elif unit == "minute":
            total_seconds += val * 60
        elif unit == "hour":
            total_seconds += val * 3600
        elif unit == "day":
            total_seconds += val * 86400
    return int(time.time()) - total_seconds


def _parse_bytes(value: float, unit: str) -> int:
    """Convert value + unit (KiB, MiB, GiB) to bytes."""
    multipliers = {"B": 1, "KiB": 1024, "MiB": 1048576, "GiB": 1073741824, "TiB": 1099511627776}
    return int(value * multipliers.get(unit, 1))
