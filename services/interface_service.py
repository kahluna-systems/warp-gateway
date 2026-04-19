"""
Interface role assignment and IP configuration.
Bridges the database (InterfaceConfig) with system/interfaces.py.
"""
import logging
from database import db
from models_new import InterfaceConfig, AuditLog
from system import interfaces as sys_iface
from system import routing as sys_routing
from system import firewall as sys_fw

logger = logging.getLogger('warp.services.interface')


def get_all_interfaces():
    """Return all detected NICs merged with saved role assignments."""
    detected = sys_iface.detect_all()
    saved = {c.name: c for c in InterfaceConfig.query.all()}

    result = []
    for iface in detected:
        cfg = saved.get(iface.name)
        result.append({
            'name': iface.name,
            'mac': iface.mac,
            'ip': iface.ip,
            'netmask': iface.netmask,
            'link_up': iface.link_up,
            'speed': iface.speed,
            'driver': iface.driver,
            'is_physical': iface.is_physical,
            'role': cfg.role if cfg else 'UNASSIGNED',
            'mode': cfg.mode if cfg else 'static',
            'configured_ip': cfg.ip_address if cfg else None,
            'configured_netmask': cfg.netmask if cfg else None,
            'configured_gateway': cfg.gateway if cfg else None,
            'config_id': cfg.id if cfg else None,
        })
    return result


def get_wan_interface():
    """Return the interface assigned as WAN, or None."""
    cfg = InterfaceConfig.query.filter_by(role='WAN').first()
    return cfg


def get_lan_interface():
    """Return the interface assigned as LAN, or None."""
    cfg = InterfaceConfig.query.filter_by(role='LAN').first()
    return cfg


def assign_role(interface_name, role, mode='static', ip=None, netmask=None, gateway=None, dns=None):
    """
    Assign a role (WAN/LAN/OPT/DISABLED) to a physical interface.
    Saves to DB and applies system configuration.
    """
    try:
        # If assigning WAN or LAN, clear any existing assignment for that role
        if role in ('WAN', 'LAN'):
            existing = InterfaceConfig.query.filter_by(role=role).first()
            if existing and existing.name != interface_name:
                existing.role = 'DISABLED'

        cfg = InterfaceConfig.query.filter_by(name=interface_name).first()
        if not cfg:
            cfg = InterfaceConfig(name=interface_name)
            db.session.add(cfg)

        cfg.role = role
        cfg.mode = mode
        cfg.ip_address = ip
        cfg.netmask = netmask
        cfg.gateway = gateway
        cfg.dns_servers = dns

        # Apply to system
        if role == 'DISABLED':
            sys_iface.bring_down(interface_name)
        else:
            sys_iface.bring_up(interface_name)
            if mode == 'dhcp':
                # Run DHCP client to obtain an address
                from system.commander import run as sys_run
                sys_run(['dhclient', '-1', interface_name], sudo=True, timeout=30)
            elif mode == 'static' and ip and netmask:
                sys_iface.set_ip(interface_name, ip, netmask)
            # Apply default gateway if specified (typically on WAN)
            if gateway:
                sys_routing.add_default_gateway(gateway, interface_name)

        db.session.commit()
        AuditLog.log('interface_assign', f'{interface_name} assigned as {role}')
        db.session.commit()
        logger.info(f'Interface {interface_name} assigned as {role}')
        return {'success': True, 'message': f'{interface_name} configured as {role}'}

    except Exception as e:
        db.session.rollback()
        logger.error(f'Failed to assign role to {interface_name}: {e}')
        return {'success': False, 'message': str(e)}


def apply_saved_configs():
    """Apply all saved interface configurations from the database. Called on startup."""
    configs = InterfaceConfig.query.filter(InterfaceConfig.role != 'DISABLED').all()
    for cfg in configs:
        try:
            sys_iface.bring_up(cfg.name)
            if cfg.mode == 'dhcp':
                from system.commander import run as sys_run
                sys_run(['dhclient', '-1', cfg.name], sudo=True, timeout=30)
            elif cfg.mode == 'static' and cfg.ip_address and cfg.netmask:
                sys_iface.set_ip(cfg.name, cfg.ip_address, cfg.netmask)
            # Apply default gateway if configured (typically WAN)
            if cfg.gateway:
                sys_routing.add_default_gateway(cfg.gateway, cfg.name)
            logger.info(f'Applied saved config for {cfg.name} ({cfg.role})')
        except Exception as e:
            logger.error(f'Failed to apply config for {cfg.name}: {e}')


def setup_lan_nat():
    """Set up NAT masquerade from LAN to WAN. Called after interfaces are configured."""
    wan = get_wan_interface()
    lan = get_lan_interface()
    if wan and lan and lan.ip_address and lan.netmask:
        import ipaddress
        network = ipaddress.ip_network(f'{lan.ip_address}/{lan.netmask}', strict=False)
        sys_fw.add_nat_masquerade(str(network), wan.name)
        logger.info(f'NAT masquerade: {network} -> {wan.name}')
