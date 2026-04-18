"""
System dependency checker.
Validates that all required tools are installed and reports their status.
Run on every gateway startup.
"""
import logging
from dataclasses import dataclass, field
from typing import Optional
from system.commander import which, version, run

logger = logging.getLogger("warp.system.checker")


@dataclass
class DependencyStatus:
    """Status of a single system dependency."""
    name: str
    description: str
    required: bool
    installed: bool
    path: Optional[str] = None
    version: Optional[str] = None
    install_hint: str = ""

    def to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "required": self.required,
            "installed": self.installed,
            "path": self.path,
            "version": self.version,
            "install_hint": self.install_hint,
        }


@dataclass
class SystemHealth:
    """Overall system health report."""
    ready: bool = False
    dependencies: list = field(default_factory=list)
    ip_forwarding: bool = False
    warnings: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    def to_dict(self):
        return {
            "ready": self.ready,
            "ip_forwarding": self.ip_forwarding,
            "dependencies": [d.to_dict() for d in self.dependencies],
            "warnings": self.warnings,
            "errors": self.errors,
            "installed_count": sum(1 for d in self.dependencies if d.installed),
            "total_count": len(self.dependencies),
            "missing_required": [
                d.name for d in self.dependencies if d.required and not d.installed
            ],
        }


# Define all dependencies
DEPENDENCIES = [
    {
        "name": "wg",
        "description": "WireGuard CLI tool",
        "required": True,
        "version_flag": "--version",
        "install_hint": "sudo apt install -y wireguard-tools",
    },
    {
        "name": "wg-quick",
        "description": "WireGuard interface manager",
        "required": True,
        "version_flag": None,
        "install_hint": "sudo apt install -y wireguard-tools",
    },
    {
        "name": "dnsmasq",
        "description": "DHCP and DNS server",
        "required": True,
        "version_flag": "--version",
        "install_hint": "sudo apt install -y dnsmasq",
    },
    {
        "name": "iptables",
        "description": "Firewall rule management",
        "required": True,
        "version_flag": "--version",
        "install_hint": "sudo apt install -y iptables",
    },
    {
        "name": "tc",
        "description": "Traffic control / bandwidth shaping",
        "required": False,
        "version_flag": "-V",
        "install_hint": "sudo apt install -y iproute2",
    },
    {
        "name": "ip",
        "description": "Network interface management",
        "required": True,
        "version_flag": "-V",
        "install_hint": "sudo apt install -y iproute2",
    },
    {
        "name": "sysctl",
        "description": "Kernel parameter management",
        "required": True,
        "version_flag": "--version",
        "install_hint": "sudo apt install -y procps",
    },
    {
        "name": "tcpdump",
        "description": "Packet capture",
        "required": False,
        "version_flag": "--version",
        "install_hint": "sudo apt install -y tcpdump",
    },
    {
        "name": "iperf3",
        "description": "Bandwidth testing",
        "required": False,
        "version_flag": "--version",
        "install_hint": "sudo apt install -y iperf3",
    },
    {
        "name": "mtr",
        "description": "Network path analysis",
        "required": False,
        "version_flag": "--version",
        "install_hint": "sudo apt install -y mtr-tiny",
    },
    {
        "name": "traceroute",
        "description": "Route tracing",
        "required": False,
        "version_flag": "--version",
        "install_hint": "sudo apt install -y traceroute",
    },
    {
        "name": "dig",
        "description": "DNS lookup tool",
        "required": False,
        "version_flag": "-v",
        "install_hint": "sudo apt install -y dnsutils",
    },
]


def check_dependency(dep: dict) -> DependencyStatus:
    """Check a single dependency."""
    path = which(dep["name"])
    ver = None

    if path and dep.get("version_flag"):
        ver = version(dep["name"], dep["version_flag"])

    return DependencyStatus(
        name=dep["name"],
        description=dep["description"],
        required=dep["required"],
        installed=path is not None,
        path=path,
        version=ver,
        install_hint=dep["install_hint"],
    )


def check_ip_forwarding() -> bool:
    """Check if IPv4 forwarding is enabled."""
    result = run(["sysctl", "-n", "net.ipv4.ip_forward"])
    return result.success and result.stdout.strip() == "1"


def run_full_check() -> SystemHealth:
    """Run a complete system health check."""
    health = SystemHealth()

    # Check all dependencies
    for dep in DEPENDENCIES:
        status = check_dependency(dep)
        health.dependencies.append(status)

        if not status.installed:
            msg = f"{status.name} ({status.description}) is not installed. Fix: {status.install_hint}"
            if status.required:
                health.errors.append(msg)
                logger.error(f"Missing required dependency: {status.name}")
            else:
                health.warnings.append(msg)
                logger.warning(f"Missing optional dependency: {status.name}")

    # Check IP forwarding
    health.ip_forwarding = check_ip_forwarding()
    if not health.ip_forwarding:
        health.warnings.append("IP forwarding is disabled. Run: sudo sysctl -w net.ipv4.ip_forward=1")

    # Determine overall readiness
    missing_required = [d for d in health.dependencies if d.required and not d.installed]
    health.ready = len(missing_required) == 0

    if health.ready:
        logger.info("System dependency check passed — all required tools installed")
    else:
        logger.error(
            f"System dependency check FAILED — missing: {', '.join(d.name for d in missing_required)}"
        )

    return health


# Cache the last check result
_last_check: Optional[SystemHealth] = None


def get_cached_health() -> Optional[SystemHealth]:
    """Get the last cached health check result."""
    return _last_check


def refresh_health() -> SystemHealth:
    """Run a fresh health check and cache the result."""
    global _last_check
    _last_check = run_full_check()
    return _last_check
