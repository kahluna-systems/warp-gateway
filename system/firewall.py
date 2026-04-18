"""
iptables firewall rule management.
Handles NAT, port forwarding, default policies, and custom rules.
"""
import logging
from typing import Optional
from system.commander import run

logger = logging.getLogger("warp.system.firewall")


def set_default_policy(wan_interface: str, lan_interface: str) -> bool:
    """
    Set the default firewall policy:
    - Allow all outbound from LAN
    - Allow established/related inbound
    - Drop unsolicited inbound on WAN
    - Allow loopback
    """
    commands = [
        # Flush existing rules
        ["iptables", "-F"],
        ["iptables", "-t", "nat", "-F"],
        ["iptables", "-X"],

        # Default policies
        ["iptables", "-P", "INPUT", "DROP"],
        ["iptables", "-P", "FORWARD", "DROP"],
        ["iptables", "-P", "OUTPUT", "ACCEPT"],

        # Allow loopback
        ["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],

        # Allow established/related
        ["iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ["iptables", "-A", "FORWARD", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],

        # Allow all from LAN
        ["iptables", "-A", "INPUT", "-i", lan_interface, "-j", "ACCEPT"],
        ["iptables", "-A", "FORWARD", "-i", lan_interface, "-o", wan_interface, "-j", "ACCEPT"],

        # Allow DHCP on LAN
        ["iptables", "-A", "INPUT", "-i", lan_interface, "-p", "udp", "--dport", "67:68", "-j", "ACCEPT"],

        # Allow DNS on LAN
        ["iptables", "-A", "INPUT", "-i", lan_interface, "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
        ["iptables", "-A", "INPUT", "-i", lan_interface, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"],

        # Allow web UI (port 5000)
        ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "5000", "-j", "ACCEPT"],

        # Allow SSH
        ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"],

        # Allow WireGuard (51820-51829)
        ["iptables", "-A", "INPUT", "-p", "udp", "--dport", "51820:51829", "-j", "ACCEPT"],

        # Allow ICMP (ping)
        ["iptables", "-A", "INPUT", "-p", "icmp", "-j", "ACCEPT"],
    ]

    success = True
    for cmd in commands:
        result = run(cmd, sudo=True)
        if not result.success:
            logger.error(f"Firewall rule failed: {' '.join(cmd)} — {result.stderr}")
            success = False

    if success:
        logger.info(f"Default firewall policy applied (WAN={wan_interface}, LAN={lan_interface})")
    return success


def add_nat_masquerade(source_subnet: str, out_interface: str) -> 'CommandResult':
    """Add NAT masquerade rule for a subnet going out an interface."""
    # Check if rule already exists
    check = run(["iptables", "-t", "nat", "-C", "POSTROUTING", "-s", source_subnet, "-o", out_interface, "-j", "MASQUERADE"], sudo=True)
    if check.success:
        logger.debug(f"NAT masquerade already exists for {source_subnet} → {out_interface}")
        from system.commander import CommandResult
        return CommandResult(success=True, command="(already exists)")

    result = run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", source_subnet, "-o", out_interface, "-j", "MASQUERADE"], sudo=True)
    if result.success:
        logger.info(f"NAT masquerade added: {source_subnet} → {out_interface}")
    return result


def remove_nat_masquerade(source_subnet: str, out_interface: str) -> 'CommandResult':
    """Remove NAT masquerade rule."""
    result = run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", source_subnet, "-o", out_interface, "-j", "MASQUERADE"], sudo=True)
    if result.success:
        logger.info(f"NAT masquerade removed: {source_subnet} → {out_interface}")
    return result


def add_forward_rule(in_interface: str, out_interface: str) -> 'CommandResult':
    """Allow forwarding between two interfaces."""
    check = run(["iptables", "-C", "FORWARD", "-i", in_interface, "-o", out_interface, "-j", "ACCEPT"], sudo=True)
    if check.success:
        from system.commander import CommandResult
        return CommandResult(success=True, command="(already exists)")

    return run(["iptables", "-A", "FORWARD", "-i", in_interface, "-o", out_interface, "-j", "ACCEPT"], sudo=True)


def add_port_forward(wan_port: int, lan_ip: str, lan_port: int, protocol: str = "tcp") -> 'CommandResult':
    """Add a port forwarding rule (DNAT)."""
    result = run([
        "iptables", "-t", "nat", "-A", "PREROUTING",
        "-p", protocol, "--dport", str(wan_port),
        "-j", "DNAT", "--to-destination", f"{lan_ip}:{lan_port}"
    ], sudo=True)
    if result.success:
        logger.info(f"Port forward added: WAN:{wan_port}/{protocol} → {lan_ip}:{lan_port}")
    return result


def remove_port_forward(wan_port: int, lan_ip: str, lan_port: int, protocol: str = "tcp") -> 'CommandResult':
    """Remove a port forwarding rule."""
    return run([
        "iptables", "-t", "nat", "-D", "PREROUTING",
        "-p", protocol, "--dport", str(wan_port),
        "-j", "DNAT", "--to-destination", f"{lan_ip}:{lan_port}"
    ], sudo=True)


def block_peer_to_peer(interface: str) -> 'CommandResult':
    """Block peer-to-peer traffic on an interface (network isolation)."""
    return run(["iptables", "-I", "FORWARD", "-i", interface, "-o", interface, "-j", "DROP"], sudo=True)


def allow_peer_to_peer(interface: str) -> 'CommandResult':
    """Remove peer-to-peer block on an interface."""
    return run(["iptables", "-D", "FORWARD", "-i", interface, "-o", interface, "-j", "DROP"], sudo=True)


def add_custom_rule(chain: str, source: str = None, dest: str = None,
                    port: int = None, protocol: str = None,
                    action: str = "ACCEPT", interface: str = None) -> 'CommandResult':
    """Add a custom firewall rule."""
    cmd = ["iptables", "-A", chain]
    if interface:
        cmd.extend(["-i", interface])
    if protocol:
        cmd.extend(["-p", protocol])
    if source:
        cmd.extend(["-s", source])
    if dest:
        cmd.extend(["-d", dest])
    if port and protocol:
        cmd.extend(["--dport", str(port)])
    cmd.extend(["-j", action])
    return run(cmd, sudo=True)


def list_rules(table: str = "filter", chain: str = None) -> list:
    """List current iptables rules."""
    cmd = ["iptables", "-t", table, "-L", "-n", "-v", "--line-numbers"]
    if chain:
        cmd.insert(4, chain)
    result = run(cmd, sudo=True)
    if not result.success:
        return []
    return result.stdout.split("\n")


def save_rules() -> 'CommandResult':
    """Save current iptables rules to persist across reboots."""
    result = run(["sh", "-c", "iptables-save > /etc/iptables/rules.v4"], sudo=True)
    if not result.success:
        # Try alternative path
        result = run(["sh", "-c", "iptables-save > /etc/iptables.rules"], sudo=True)
    if result.success:
        logger.info("Firewall rules saved")
    return result


def restore_rules() -> 'CommandResult':
    """Restore saved iptables rules."""
    import os
    if os.path.exists("/etc/iptables/rules.v4"):
        return run(["iptables-restore", "/etc/iptables/rules.v4"], sudo=True)
    elif os.path.exists("/etc/iptables.rules"):
        return run(["iptables-restore", "/etc/iptables.rules"], sudo=True)
    from system.commander import CommandResult
    return CommandResult(success=False, error="No saved rules found")
