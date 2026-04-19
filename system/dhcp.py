"""
DHCP server management via dnsmasq.
Handles DHCP configuration, static leases, and lease monitoring.
"""
import os
import logging
from typing import Optional
from dataclasses import dataclass
from system.commander import run

logger = logging.getLogger("warp.system.dhcp")

DNSMASQ_CONFIG_DIR = "/etc/dnsmasq.d"
DNSMASQ_WARP_CONF = os.path.join(DNSMASQ_CONFIG_DIR, "warp-gateway.conf")
DNSMASQ_LEASE_FILE = "/var/lib/misc/dnsmasq.leases"


@dataclass
class DhcpLease:
    """A DHCP lease entry."""
    expiry: str
    mac: str
    ip: str
    hostname: str
    client_id: str = ""

    def to_dict(self):
        return {
            "expiry": self.expiry,
            "mac": self.mac,
            "ip": self.ip,
            "hostname": self.hostname,
            "client_id": self.client_id,
        }


def configure(
    interface: str,
    range_start: str,
    range_end: str,
    netmask: str = "255.255.255.0",
    gateway: Optional[str] = None,
    dns_servers: str = "1.1.1.1,8.8.8.8",
    lease_time: str = "12h",
    domain: str = "local",
    reservations: list = None,
) -> 'CommandResult':
    """
    Write dnsmasq DHCP configuration and restart the service.
    """
    config_lines = [
        "# KahLuna WARP Gateway — DHCP Configuration",
        "# Auto-generated — do not edit manually",
        "",
        f"interface={interface}",
        f"dhcp-range={range_start},{range_end},{netmask},{lease_time}",
        f"domain={domain}",
        "",
        "# DNS servers for clients",
    ]

    for dns in dns_servers.split(","):
        config_lines.append(f"dhcp-option=6,{dns.strip()}")

    if gateway:
        config_lines.append(f"dhcp-option=3,{gateway}")

    config_lines.extend([
        "",
        "# Logging",
        "log-dhcp",
        "",
        "# Don't use /etc/resolv.conf",
        "no-resolv",
        "",
        f"# Upstream DNS",
    ])

    for dns in dns_servers.split(","):
        config_lines.append(f"server={dns.strip()}")

    # Static reservations
    if reservations:
        config_lines.append("")
        config_lines.append("# Static DHCP reservations")
        for res in reservations:
            mac = res.get("mac", "")
            ip = res.get("ip", "")
            hostname = res.get("hostname", "")
            if mac and ip:
                if hostname:
                    config_lines.append(f"dhcp-host={mac},{ip},{hostname}")
                else:
                    config_lines.append(f"dhcp-host={mac},{ip}")

    config_content = "\n".join(config_lines) + "\n"

    # Ensure config directory exists
    run(["mkdir", "-p", DNSMASQ_CONFIG_DIR], sudo=True)

    # Write config
    result = run(["tee", DNSMASQ_WARP_CONF], sudo=True, input_data=config_content)
    if not result.success:
        logger.error(f"Failed to write DHCP config: {result.stderr}")
        return result

    logger.info(f"DHCP configured on {interface}: {range_start}-{range_end}")
    return restart()


def add_reservation(mac: str, ip: str, hostname: str = "") -> bool:
    """Add a static DHCP reservation by appending to the config."""
    line = f"dhcp-host={mac},{ip}"
    if hostname:
        line += f",{hostname}"
    line += "\n"

    result = run(["tee", "-a", DNSMASQ_WARP_CONF], sudo=True, input_data=line)
    if result.success:
        restart()
        logger.info(f"DHCP reservation added: {mac} → {ip}")
    return result.success


def remove_reservation(mac: str) -> bool:
    """Remove a static DHCP reservation from the config."""
    result = run(["sed", "-i", f"/{mac}/d", DNSMASQ_WARP_CONF], sudo=True)
    if result.success:
        restart()
        logger.info(f"DHCP reservation removed: {mac}")
    return result.success


def get_leases() -> list:
    """Parse the dnsmasq lease file to get active DHCP leases."""
    leases = []
    try:
        # Try standard lease file locations
        for path in [DNSMASQ_LEASE_FILE, "/tmp/dnsmasq.leases", "/var/lib/dnsmasq/dnsmasq.leases"]:
            if os.path.exists(path):
                with open(path) as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            leases.append(DhcpLease(
                                expiry=parts[0],
                                mac=parts[1],
                                ip=parts[2],
                                hostname=parts[3] if parts[3] != "*" else "",
                                client_id=parts[4] if len(parts) > 4 else "",
                            ))
                break
    except Exception as e:
        logger.error(f"Failed to read DHCP leases: {e}")
    return leases


def restart() -> 'CommandResult':
    """Restart the dnsmasq service."""
    result = run(["systemctl", "restart", "dnsmasq"], sudo=True)
    if result.success:
        logger.info("dnsmasq restarted")
    else:
        logger.error(f"Failed to restart dnsmasq: {result.stderr}")
    return result


def stop() -> 'CommandResult':
    """Stop the dnsmasq service."""
    return run(["systemctl", "stop", "dnsmasq"], sudo=True)


def status() -> dict:
    """Get dnsmasq service status."""
    result = run(["systemctl", "is-active", "dnsmasq"])
    leases = get_leases()
    return {
        "running": result.success and result.stdout.strip() == "active",
        "lease_count": len(leases),
        "leases": [l.to_dict() for l in leases],
    }
