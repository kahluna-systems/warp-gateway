"""
Rate limiting orchestration — calls system/traffic.py.
"""
import logging
from system import traffic as sys_traffic
from models_new import Endpoint, VPNNetwork

logger = logging.getLogger('warp.services.shaping')


def apply_endpoint_limit(endpoint):
    """Apply rate limit to a single endpoint based on its effective config."""
    rl = endpoint.get_effective_rate_limit()
    if not rl['enabled']:
        return False

    network = endpoint.vpn_network
    iface_name = network.get_interface_name()

    download_kbps = int(rl['download_mbps'] * 1000) if rl['download_mbps'] else 0
    upload_kbps = int(rl['upload_mbps'] * 1000) if rl['upload_mbps'] else 0
    burst_factor = rl.get('burst_factor', 1.5)
    burst_kbps = int(download_kbps * burst_factor) if download_kbps else None

    if download_kbps > 0:
        return sys_traffic.apply_limit(
            interface=iface_name,
            peer_ip=endpoint.ip_address,
            download_kbps=download_kbps,
            upload_kbps=upload_kbps,
            burst_kbps=burst_kbps,
        )
    return False


def remove_endpoint_limit(endpoint):
    """Remove rate limit from an endpoint."""
    network = endpoint.vpn_network
    iface_name = network.get_interface_name()
    return sys_traffic.remove_limit(iface_name, endpoint.ip_address)


def apply_all_limits():
    """Apply rate limits for all active endpoints. Called on startup."""
    from database import db
    endpoints = Endpoint.query.filter_by(is_active=True).all()
    count = 0
    for ep in endpoints:
        rl = ep.get_effective_rate_limit()
        if rl['enabled']:
            if apply_endpoint_limit(ep):
                count += 1
    logger.info(f'Applied rate limits to {count} endpoints')


def clear_interface_limits(interface_name):
    """Clear all rate limits on an interface."""
    return sys_traffic.clear_all(interface_name)


def get_interface_stats(interface_name):
    """Get traffic shaping stats for an interface."""
    return sys_traffic.get_stats(interface_name)
