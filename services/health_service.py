"""
System health aggregation — CPU, memory, disk, interface stats, WireGuard stats.
"""
import logging
import platform
from datetime import datetime

logger = logging.getLogger('warp.services.health')


def get_system_health():
    """Get comprehensive system health information."""
    health = {
        'hostname': platform.node(),
        'platform': platform.platform(),
        'python': platform.python_version(),
        'timestamp': datetime.utcnow().isoformat(),
    }

    try:
        import psutil
        health['cpu_percent'] = psutil.cpu_percent(interval=0.5)
        health['cpu_count'] = psutil.cpu_count()

        mem = psutil.virtual_memory()
        health['memory'] = {
            'total_mb': round(mem.total / 1048576),
            'used_mb': round(mem.used / 1048576),
            'available_mb': round(mem.available / 1048576),
            'percent': mem.percent,
        }

        disk = psutil.disk_usage('/')
        health['disk'] = {
            'total_gb': round(disk.total / 1073741824, 1),
            'used_gb': round(disk.used / 1073741824, 1),
            'free_gb': round(disk.free / 1073741824, 1),
            'percent': disk.percent,
        }

        boot = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot
        health['uptime_seconds'] = int(uptime.total_seconds())
        health['uptime_human'] = _format_uptime(uptime.total_seconds())

    except ImportError:
        health['cpu_percent'] = 0
        health['memory'] = {'total_mb': 0, 'used_mb': 0, 'available_mb': 0, 'percent': 0}
        health['disk'] = {'total_gb': 0, 'used_gb': 0, 'free_gb': 0, 'percent': 0}
        health['uptime_human'] = 'unknown'

    return health


def get_interface_stats():
    """Get per-interface traffic counters."""
    stats = {}
    try:
        import psutil
        counters = psutil.net_io_counters(pernic=True)
        for name, c in counters.items():
            stats[name] = {
                'bytes_sent': c.bytes_sent,
                'bytes_recv': c.bytes_recv,
                'packets_sent': c.packets_sent,
                'packets_recv': c.packets_recv,
                'errors_in': c.errin,
                'errors_out': c.errout,
            }
    except ImportError:
        pass
    return stats


def get_vpn_stats():
    """Get WireGuard stats for all active networks."""
    from models_new import VPNNetwork
    from system import wireguard as sys_wg

    stats = []
    networks = VPNNetwork.query.filter_by(is_active=True).all()
    for net in networks:
        iface_name = net.get_interface_name()
        wg_status = sys_wg.get_status(iface_name)
        stats.append({
            'network': net.name,
            'interface': iface_name,
            'status': wg_status.to_dict() if wg_status else None,
        })
    return stats


def get_firewall_stats():
    """Get firewall rule counts."""
    from models_new import FirewallRule, PortForward
    return {
        'custom_rules': FirewallRule.query.filter_by(is_active=True).count(),
        'port_forwards': PortForward.query.filter_by(is_active=True).count(),
    }


def get_dhcp_stats():
    """Get DHCP statistics."""
    from system import dhcp as sys_dhcp
    from models_new import DhcpConfig, DhcpReservation
    status = sys_dhcp.status()
    return {
        'running': status.get('running', False),
        'lease_count': status.get('lease_count', 0),
        'reservation_count': DhcpReservation.query.count(),
        'configured_interfaces': DhcpConfig.query.filter_by(is_active=True).count(),
    }


def get_dependency_status():
    """Get system dependency check results."""
    from system.checker import refresh_health
    return refresh_health().to_dict()


def get_full_health():
    """Aggregate all health data into a single report."""
    return {
        'system': get_system_health(),
        'interfaces': get_interface_stats(),
        'vpn': get_vpn_stats(),
        'firewall': get_firewall_stats(),
        'dhcp': get_dhcp_stats(),
        'dependencies': get_dependency_status(),
    }


def _format_uptime(seconds):
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    parts = []
    if days:
        parts.append(f'{days}d')
    if hours:
        parts.append(f'{hours}h')
    parts.append(f'{minutes}m')
    return ' '.join(parts)
