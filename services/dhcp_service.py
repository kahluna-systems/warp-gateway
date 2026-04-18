"""
DHCP configuration — orchestrates database + dnsmasq.
"""
import logging
from database import db
from models_new import DhcpConfig, DhcpReservation, AuditLog
from system import dhcp as sys_dhcp
from system import interfaces as sys_iface

logger = logging.getLogger('warp.services.dhcp')


def get_config(interface=None):
    """Get DHCP configuration, optionally for a specific interface."""
    if interface:
        return DhcpConfig.query.filter_by(interface=interface).first()
    return DhcpConfig.query.first()


def setup_dhcp(interface, range_start, range_end, netmask='255.255.255.0',
               gateway=None, dns_servers='1.1.1.1,8.8.8.8', lease_time='12h'):
    """
    Configure DHCP on an interface:
    1. Save config to DB
    2. Write dnsmasq config
    3. Restart dnsmasq
    """
    try:
        cfg = DhcpConfig.query.filter_by(interface=interface).first()
        if not cfg:
            cfg = DhcpConfig(interface=interface)
            db.session.add(cfg)

        cfg.range_start = range_start
        cfg.range_end = range_end
        cfg.netmask = netmask
        cfg.gateway = gateway
        cfg.dns_servers = dns_servers
        cfg.lease_time = lease_time
        cfg.is_active = True

        # Get reservations for this interface
        reservations = [
            {'mac': r.mac, 'ip': r.ip, 'hostname': r.hostname}
            for r in DhcpReservation.query.all()
        ]

        # Write config and restart dnsmasq
        result = sys_dhcp.configure(
            interface=interface,
            range_start=range_start,
            range_end=range_end,
            netmask=netmask,
            gateway=gateway,
            dns_servers=dns_servers,
            lease_time=lease_time,
            reservations=reservations,
        )

        if not result.success:
            db.session.rollback()
            return {'success': False, 'message': f'dnsmasq error: {result.stderr or result.error}'}

        db.session.commit()
        AuditLog.log('dhcp_configure', f'DHCP configured on {interface}: {range_start}-{range_end}')
        db.session.commit()

        logger.info(f'DHCP configured on {interface}')
        return {'success': True, 'config': cfg}

    except Exception as e:
        db.session.rollback()
        logger.error(f'Failed to configure DHCP: {e}')
        return {'success': False, 'message': str(e)}


def add_reservation(mac, ip, hostname=''):
    """Add a static DHCP reservation."""
    try:
        existing = DhcpReservation.query.filter_by(mac=mac).first()
        if existing:
            return {'success': False, 'message': f'Reservation for MAC {mac} already exists'}

        res = DhcpReservation(mac=mac, ip=ip, hostname=hostname)
        db.session.add(res)

        sys_dhcp.add_reservation(mac, ip, hostname)

        db.session.commit()
        AuditLog.log('dhcp_reservation_add', f'DHCP reservation: {mac} -> {ip} ({hostname})')
        db.session.commit()

        return {'success': True, 'reservation': res}

    except Exception as e:
        db.session.rollback()
        return {'success': False, 'message': str(e)}


def remove_reservation(reservation_id):
    """Remove a static DHCP reservation."""
    try:
        res = DhcpReservation.query.get(reservation_id)
        if not res:
            return {'success': False, 'message': 'Reservation not found'}

        sys_dhcp.remove_reservation(res.mac)

        db.session.delete(res)
        db.session.commit()

        AuditLog.log('dhcp_reservation_remove', f'Removed DHCP reservation: {res.mac}')
        db.session.commit()

        return {'success': True, 'message': 'Reservation removed'}

    except Exception as e:
        db.session.rollback()
        return {'success': False, 'message': str(e)}


def get_reservations():
    """Get all static DHCP reservations."""
    return DhcpReservation.query.all()


def get_leases():
    """Get current DHCP leases from dnsmasq."""
    return sys_dhcp.get_leases()


def get_connected_clients():
    """Merge DHCP leases with ARP table for a complete client picture."""
    leases = sys_dhcp.get_leases()
    arp = sys_iface.get_arp_table()

    # Index leases by MAC
    lease_map = {l.mac.lower(): l for l in leases}

    clients = []
    seen_macs = set()

    # Start with DHCP leases
    for lease in leases:
        mac = lease.mac.lower()
        seen_macs.add(mac)
        clients.append({
            'ip': lease.ip,
            'mac': lease.mac,
            'hostname': lease.hostname,
            'source': 'DHCP',
            'expiry': lease.expiry,
            'state': 'active',
        })

    # Add ARP entries not in DHCP
    for entry in arp:
        mac = entry.mac.lower()
        if mac not in seen_macs and mac != '00:00:00:00:00:00':
            seen_macs.add(mac)
            clients.append({
                'ip': entry.ip,
                'mac': entry.mac,
                'hostname': '',
                'source': 'ARP',
                'expiry': '',
                'state': entry.state,
            })

    return clients


def start_dhcp_on_lan():
    """Start DHCP on all configured LAN interfaces. Called on startup."""
    configs = DhcpConfig.query.filter_by(is_active=True).all()
    for cfg in configs:
        reservations = [
            {'mac': r.mac, 'ip': r.ip, 'hostname': r.hostname}
            for r in DhcpReservation.query.all()
        ]
        result = sys_dhcp.configure(
            interface=cfg.interface,
            range_start=cfg.range_start,
            range_end=cfg.range_end,
            netmask=cfg.netmask,
            gateway=cfg.gateway,
            dns_servers=cfg.dns_servers,
            lease_time=cfg.lease_time,
            reservations=reservations,
        )
        if result.success:
            logger.info(f'DHCP started on {cfg.interface}')
        else:
            logger.error(f'Failed to start DHCP on {cfg.interface}: {result.stderr}')


def get_dhcp_status():
    """Get dnsmasq service status."""
    return sys_dhcp.status()
