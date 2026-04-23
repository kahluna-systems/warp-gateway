"""
Security zone service layer.
Manages security zones, zone-based firewall policies, and inter-VLAN routing defaults.
"""
import logging
from database import db
from models_new import SecurityZone, ZonePolicy, InterfaceConfig, AuditLog
from system import firewall as sys_fw

logger = logging.getLogger('warp.services.zone')

DEFAULT_ZONES = [
    {'name': 'WAN', 'description': 'Untrusted (internet-facing)', 'is_default': True},
    {'name': 'LAN', 'description': 'Trusted (internal network)', 'is_default': True},
    {'name': 'DMZ', 'description': 'Semi-trusted (servers)', 'is_default': True},
    {'name': 'GUEST', 'description': 'Isolated (guest network)', 'is_default': True},
]


# ── Zone CRUD ────────────────────────────────────────────────────────────────

def create_zone(name: str, description: str = '') -> dict:
    """Create a security zone."""
    existing = SecurityZone.query.filter_by(name=name).first()
    if existing:
        return {'success': False, 'message': f'Zone "{name}" already exists'}

    zone = SecurityZone(name=name, description=description)
    db.session.add(zone)
    db.session.commit()

    AuditLog.log('zone_create', f'Security zone "{name}" created')
    db.session.commit()

    logger.info(f'Security zone "{name}" created')
    return {'success': True, 'zone': zone}


def delete_zone(name: str) -> dict:
    """Delete a zone. Rejects if interfaces are still assigned."""
    zone = SecurityZone.query.filter_by(name=name).first()
    if not zone:
        return {'success': False, 'message': f'Zone "{name}" not found'}

    if zone.interfaces:
        iface_names = ', '.join(i.name for i in zone.interfaces)
        return {'success': False,
                'message': f'Cannot delete zone "{name}": interfaces still assigned ({iface_names})'}

    db.session.delete(zone)
    db.session.commit()

    AuditLog.log('zone_delete', f'Security zone "{name}" deleted')
    db.session.commit()

    logger.info(f'Security zone "{name}" deleted')
    return {'success': True, 'message': f'Zone "{name}" deleted'}


def list_zones():
    return SecurityZone.query.order_by(SecurityZone.name).all()


def get_zone(name: str):
    return SecurityZone.query.filter_by(name=name).first()


# ── Zone Assignment ──────────────────────────────────────────────────────────

def assign_interface_to_zone(interface_name: str, zone_name: str) -> dict:
    """Assign an interface to a zone. Removes from previous zone."""
    zone = SecurityZone.query.filter_by(name=zone_name).first()
    if not zone:
        return {'success': False, 'message': f'Zone "{zone_name}" not found'}

    cfg = InterfaceConfig.query.filter_by(name=interface_name).first()
    if not cfg:
        return {'success': False, 'message': f'Interface "{interface_name}" not found'}

    cfg.zone_id = zone.id
    db.session.commit()

    # Regenerate zone-based firewall rules
    apply_zone_policies()

    logger.info(f'Interface {interface_name} assigned to zone {zone_name}')
    return {'success': True, 'message': f'{interface_name} assigned to zone {zone_name}'}


def remove_interface_from_zone(interface_name: str) -> dict:
    """Remove an interface from its current zone."""
    cfg = InterfaceConfig.query.filter_by(name=interface_name).first()
    if not cfg:
        return {'success': False, 'message': f'Interface "{interface_name}" not found'}

    cfg.zone_id = None
    db.session.commit()

    apply_zone_policies()

    return {'success': True, 'message': f'{interface_name} removed from zone'}


def get_zone_interfaces(zone_name: str) -> list:
    """Get all interfaces in a zone."""
    zone = SecurityZone.query.filter_by(name=zone_name).first()
    if not zone:
        return []
    return zone.interfaces


# ── Zone Policies ────────────────────────────────────────────────────────────

def create_zone_policy(source_zone: str, dest_zone: str, action: str,
                       protocol: str = None, port: int = None,
                       priority: int = 100, description: str = '') -> dict:
    """Create a zone-based firewall policy."""
    src = SecurityZone.query.filter_by(name=source_zone).first()
    dst = SecurityZone.query.filter_by(name=dest_zone).first()

    if not src:
        return {'success': False, 'message': f'Source zone "{source_zone}" not found'}
    if not dst:
        return {'success': False, 'message': f'Destination zone "{dest_zone}" not found'}

    policy = ZonePolicy(
        source_zone_id=src.id,
        dest_zone_id=dst.id,
        action=action.upper(),
        protocol=protocol,
        port=port,
        priority=priority,
        description=description,
    )
    db.session.add(policy)
    db.session.commit()

    AuditLog.log('zone_policy_create',
                 f'Zone policy: {source_zone} -> {dest_zone} {action}')
    db.session.commit()

    apply_zone_policies()

    logger.info(f'Zone policy created: {source_zone} -> {dest_zone} {action}')
    return {'success': True, 'policy': policy}


def delete_zone_policy(policy_id: int) -> dict:
    """Delete a zone policy."""
    policy = ZonePolicy.query.get(policy_id)
    if not policy:
        return {'success': False, 'message': 'Policy not found'}

    db.session.delete(policy)
    db.session.commit()

    apply_zone_policies()

    return {'success': True, 'message': 'Policy deleted'}


def list_zone_policies():
    return ZonePolicy.query.order_by(ZonePolicy.priority, ZonePolicy.id).all()


# ── Zone Policy Application ─────────────────────────────────────────────────

def apply_zone_policies() -> bool:
    """Translate all zone policies into iptables rules."""
    try:
        # Create the WARP-ZONES chain if it doesn't exist
        sys_fw.run(['iptables', '-N', 'WARP-ZONES'], sudo=True)
        # Flush existing zone rules
        sys_fw.run(['iptables', '-F', 'WARP-ZONES'], sudo=True)

        # Ensure the chain is referenced from FORWARD
        sys_fw.run(['iptables', '-C', 'FORWARD', '-j', 'WARP-ZONES'], sudo=True)
        # If -C fails, add it
    except Exception:
        pass

    try:
        from system.commander import run
        # Ensure chain exists and is in FORWARD
        run(['iptables', '-N', 'WARP-ZONES'], sudo=True)
        run(['iptables', '-F', 'WARP-ZONES'], sudo=True)

        # Check if jump to WARP-ZONES exists in FORWARD
        check = run(['iptables', '-C', 'FORWARD', '-j', 'WARP-ZONES'], sudo=True)
        if not check.success:
            run(['iptables', '-I', 'FORWARD', '1', '-j', 'WARP-ZONES'], sudo=True)

        # Add intra-zone allow rules
        zones = SecurityZone.query.all()
        for zone in zones:
            ifaces = [i.name for i in zone.interfaces if i.is_active]
            for i, src_iface in enumerate(ifaces):
                for dst_iface in ifaces[i + 1:]:
                    run(['iptables', '-A', 'WARP-ZONES',
                         '-i', src_iface, '-o', dst_iface, '-j', 'ACCEPT'], sudo=True)
                    run(['iptables', '-A', 'WARP-ZONES',
                         '-i', dst_iface, '-o', src_iface, '-j', 'ACCEPT'], sudo=True)

        # Add explicit zone policies
        policies = ZonePolicy.query.filter_by(is_active=True).order_by(ZonePolicy.priority).all()
        for policy in policies:
            src_zone = SecurityZone.query.get(policy.source_zone_id)
            dst_zone = SecurityZone.query.get(policy.dest_zone_id)
            if not src_zone or not dst_zone:
                continue

            src_ifaces = [i.name for i in src_zone.interfaces if i.is_active]
            dst_ifaces = [i.name for i in dst_zone.interfaces if i.is_active]

            for src_iface in src_ifaces:
                for dst_iface in dst_ifaces:
                    cmd = ['iptables', '-A', 'WARP-ZONES',
                           '-i', src_iface, '-o', dst_iface]
                    if policy.protocol:
                        cmd.extend(['-p', policy.protocol])
                    if policy.port and policy.protocol:
                        cmd.extend(['--dport', str(policy.port)])
                    cmd.extend(['-j', policy.action])
                    run(cmd, sudo=True)

        logger.info('Zone policies applied to iptables')
        return True

    except Exception as e:
        logger.error(f'Failed to apply zone policies: {e}')
        return False


# ── Default Zones ────────────────────────────────────────────────────────────

def ensure_default_zones():
    """Create the four default zones if they don't exist."""
    for zone_def in DEFAULT_ZONES:
        existing = SecurityZone.query.filter_by(name=zone_def['name']).first()
        if not existing:
            zone = SecurityZone(**zone_def)
            db.session.add(zone)
    db.session.commit()
    logger.info('Default security zones ensured')


# ── Startup Sync ─────────────────────────────────────────────────────────────

def sync_zones_on_boot():
    """Restore zone assignments and regenerate iptables rules on startup."""
    ensure_default_zones()
    apply_zone_policies()
    logger.info('Security zones synced on boot')
