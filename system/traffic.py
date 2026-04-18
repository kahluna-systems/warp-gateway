"""
Traffic shaping via tc (traffic control).
Uses HTB (Hierarchical Token Bucket) for per-IP bandwidth limiting.
"""
import logging
from typing import Optional
from system.commander import run, which

logger = logging.getLogger("warp.system.traffic")


def is_available() -> bool:
    """Check if tc is available."""
    return which("tc") is not None


def apply_limit(
    interface: str,
    peer_ip: str,
    download_kbps: int,
    upload_kbps: int,
    burst_kbps: Optional[int] = None,
) -> bool:
    """
    Apply bandwidth limit to a specific IP on an interface.
    Uses tc htb with u32 filters.
    """
    if not is_available():
        logger.warning("tc not available — rate limiting disabled")
        return False

    if not burst_kbps:
        burst_kbps = max(download_kbps // 10, 100)  # 10% burst or 100kbps minimum

    # Generate a unique class ID from the IP
    class_id = _ip_to_class_id(peer_ip)

    # Ensure root qdisc exists
    _ensure_root_qdisc(interface)

    # Add class for this peer
    result = run([
        "tc", "class", "add", "dev", interface,
        "parent", "1:0", "classid", f"1:{class_id}",
        "htb", "rate", f"{download_kbps}kbit",
        "burst", f"{burst_kbps}kbit",
        "ceil", f"{download_kbps}kbit",
    ], sudo=True)

    if not result.success:
        # Try replace instead of add (in case it exists)
        result = run([
            "tc", "class", "replace", "dev", interface,
            "parent", "1:0", "classid", f"1:{class_id}",
            "htb", "rate", f"{download_kbps}kbit",
            "burst", f"{burst_kbps}kbit",
            "ceil", f"{download_kbps}kbit",
        ], sudo=True)

    if not result.success:
        logger.error(f"Failed to apply rate limit class for {peer_ip}: {result.stderr}")
        return False

    # Add filter to match this IP to the class
    run([
        "tc", "filter", "add", "dev", interface,
        "parent", "1:0", "protocol", "ip",
        "u32", "match", "ip", "dst", f"{peer_ip}/32",
        "flowid", f"1:{class_id}",
    ], sudo=True)

    logger.info(f"Rate limit applied: {peer_ip} on {interface} — {download_kbps}kbps down")
    return True


def remove_limit(interface: str, peer_ip: str) -> bool:
    """Remove bandwidth limit for a specific IP."""
    class_id = _ip_to_class_id(peer_ip)

    result = run([
        "tc", "class", "del", "dev", interface,
        "classid", f"1:{class_id}",
    ], sudo=True)

    if result.success:
        logger.info(f"Rate limit removed: {peer_ip} on {interface}")
    return result.success


def clear_all(interface: str) -> bool:
    """Remove all traffic shaping from an interface."""
    result = run(["tc", "qdisc", "del", "dev", interface, "root"], sudo=True)
    if result.success:
        logger.info(f"All rate limits cleared on {interface}")
    return result.success


def get_stats(interface: str) -> dict:
    """Get traffic shaping statistics for an interface."""
    result = run(["tc", "-s", "class", "show", "dev", interface], sudo=True)
    if not result.success:
        return {"active": False, "classes": []}
    return {"active": True, "raw": result.stdout}


def _ensure_root_qdisc(interface: str):
    """Ensure the root HTB qdisc exists on the interface."""
    # Check if it exists
    check = run(["tc", "qdisc", "show", "dev", interface], sudo=True)
    if check.success and "htb" in check.stdout:
        return

    # Add root qdisc
    run(["tc", "qdisc", "add", "dev", interface, "root", "handle", "1:", "htb", "default", "99"], sudo=True)

    # Add default class (unlimited)
    run([
        "tc", "class", "add", "dev", interface,
        "parent", "1:0", "classid", "1:99",
        "htb", "rate", "1000mbit",
    ], sudo=True)


def _ip_to_class_id(ip: str) -> str:
    """Convert an IP address to a tc class ID (hex)."""
    parts = ip.split(".")
    if len(parts) == 4:
        # Use last two octets as hex class ID
        return f"{int(parts[2]):x}{int(parts[3]):02x}"
    return "10"
