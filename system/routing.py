"""
IP forwarding, NAT, and static route management.
"""
import logging
from typing import Optional
from system.commander import run

logger = logging.getLogger("warp.system.routing")


def enable_ip_forwarding() -> 'CommandResult':
    """Enable IPv4 forwarding immediately and persist across reboots."""
    # Apply immediately
    result = run(["sysctl", "-w", "net.ipv4.ip_forward=1"], sudo=True)
    if not result.success:
        logger.error(f"Failed to enable IP forwarding: {result.stderr}")
        return result

    # Persist
    persist = run(
        ["tee", "/etc/sysctl.d/99-warp-gateway.conf"],
        sudo=True,
        input_data="# KahLuna WARP Gateway\nnet.ipv4.ip_forward=1\n",
    )
    if persist.success:
        logger.info("IP forwarding enabled and persisted")
    else:
        logger.warning("IP forwarding enabled but failed to persist")

    return result


def get_forwarding_status() -> bool:
    """Check if IPv4 forwarding is enabled."""
    result = run(["sysctl", "-n", "net.ipv4.ip_forward"])
    return result.success and result.stdout.strip() == "1"


def detect_default_interface() -> Optional[str]:
    """Detect the default outbound interface."""
    import re
    result = run(["ip", "route", "show", "default"])
    if result.success:
        match = re.search(r"dev\s+(\S+)", result.stdout)
        if match:
            return match.group(1)
    return None


def get_default_gateway() -> Optional[str]:
    """Get the default gateway IP."""
    import re
    result = run(["ip", "route", "show", "default"])
    if result.success:
        match = re.search(r"via\s+(\S+)", result.stdout)
        if match:
            return match.group(1)
    return None


def add_static_route(destination: str, gateway: str, interface: Optional[str] = None) -> 'CommandResult':
    """Add a static route."""
    cmd = ["ip", "route", "add", destination, "via", gateway]
    if interface:
        cmd.extend(["dev", interface])
    return run(cmd, sudo=True)


def remove_static_route(destination: str) -> 'CommandResult':
    """Remove a static route."""
    return run(["ip", "route", "del", destination], sudo=True)


def add_default_gateway(gateway: str, interface: Optional[str] = None) -> 'CommandResult':
    """Set the default gateway. Replaces any existing default route."""
    # Remove existing default route first (best effort)
    run(["ip", "route", "del", "default"], sudo=True)

    cmd = ["ip", "route", "add", "default", "via", gateway]
    if interface:
        cmd.extend(["dev", interface])
    result = run(cmd, sudo=True)
    if result.success:
        logger.info(f"Default gateway set to {gateway}" + (f" via {interface}" if interface else ""))
    else:
        logger.error(f"Failed to set default gateway: {result.stderr}")
    return result


def get_routing_table() -> list:
    """Get the current routing table."""
    result = run(["ip", "route", "show"])
    if not result.success:
        return []
    routes = []
    for line in result.stdout.split("\n"):
        if line.strip():
            routes.append(line.strip())
    return routes
