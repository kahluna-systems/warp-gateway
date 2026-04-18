"""
DNS configuration — manages upstream servers and local overrides.
"""
import logging
from database import db
from models_new import DnsOverride, AuditLog
from system import dns as sys_dns

logger = logging.getLogger('warp.services.dns')


def get_overrides():
    """Get all DNS overrides from the database."""
    return DnsOverride.query.order_by(DnsOverride.hostname).all()


def add_override(hostname, ip):
    """Add a local DNS override."""
    try:
        existing = DnsOverride.query.filter_by(hostname=hostname).first()
        if existing:
            existing.ip = ip
        else:
            override = DnsOverride(hostname=hostname, ip=ip)
            db.session.add(override)

        result = sys_dns.add_override(hostname, ip)
        if not result:
            db.session.rollback()
            return {'success': False, 'message': 'Failed to apply DNS override'}

        db.session.commit()
        AuditLog.log('dns_override_add', f'DNS override: {hostname} -> {ip}')
        db.session.commit()

        return {'success': True, 'message': f'DNS override added: {hostname} -> {ip}'}

    except Exception as e:
        db.session.rollback()
        return {'success': False, 'message': str(e)}


def remove_override(override_id):
    """Remove a DNS override."""
    try:
        override = DnsOverride.query.get(override_id)
        if not override:
            return {'success': False, 'message': 'Override not found'}

        hostname = override.hostname
        sys_dns.remove_override(hostname)

        db.session.delete(override)
        db.session.commit()

        AuditLog.log('dns_override_remove', f'Removed DNS override: {hostname}')
        db.session.commit()

        return {'success': True, 'message': f'DNS override for {hostname} removed'}

    except Exception as e:
        db.session.rollback()
        return {'success': False, 'message': str(e)}


def get_upstream_servers():
    """Get the configured upstream DNS servers from the DHCP config."""
    from models_new import DhcpConfig
    cfg = DhcpConfig.query.first()
    if cfg and cfg.dns_servers:
        return [s.strip() for s in cfg.dns_servers.split(',')]
    return ['1.1.1.1', '8.8.8.8']


def set_upstream_servers(servers):
    """Update upstream DNS servers."""
    sys_dns.set_upstream_servers(servers)
    logger.info(f'Upstream DNS servers set to: {", ".join(servers)}')
    return {'success': True}


def sync_overrides():
    """Sync all DB overrides to the system DNS config. Called on startup."""
    overrides = DnsOverride.query.all()
    for o in overrides:
        sys_dns.add_override(o.hostname, o.ip)
    logger.info(f'Synced {len(overrides)} DNS overrides')
