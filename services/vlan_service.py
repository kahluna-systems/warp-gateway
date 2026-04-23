"""
VLAN service layer -- orchestrates VLAN CRUD between database and kernel.
Manages VLAN records, sub-interfaces, switchport modes, trunk/access config, and QinQ.
"""
import logging
from database import db
from models_new import Vlan, VlanSubInterface, InterfaceConfig, AuditLog
from system import vlan as sys_vlan

logger = logging.getLogger('warp.services.vlan')


# ── VLAN CRUD ────────────────────────────────────────────────────────────────

def create_vlan(vlan_id: int, name: str = None) -> dict:
    """Create a VLAN record."""
    if not Vlan.validate_vlan_id(vlan_id):
        return {'success': False, 'message': 'VLAN ID must be between 1 and 4094'}

    existing = Vlan.query.filter_by(vlan_id=vlan_id).first()
    if existing:
        return {'success': False, 'message': f'VLAN {vlan_id} already exists'}

    vlan_name = name or f'VLAN{vlan_id}'
    vlan = Vlan(vlan_id=vlan_id, name=vlan_name)
    db.session.add(vlan)
    db.session.commit()

    AuditLog.log('vlan_create', f'VLAN {vlan_id} ({vlan_name}) created')
    db.session.commit()

    logger.info(f'VLAN {vlan_id} ({vlan_name}) created')
    return {'success': True, 'vlan': vlan}


def delete_vlan(vlan_id: int) -> dict:
    """Delete a VLAN and all associated sub-interfaces."""
    vlan = Vlan.query.filter_by(vlan_id=vlan_id).first()
    if not vlan:
        return {'success': False, 'message': f'VLAN {vlan_id} not found'}

    # Delete all sub-interfaces first
    for sub in vlan.sub_interfaces:
        sys_vlan.delete_sub_interface(sub.parent_interface, vlan_id)
        # Remove the InterfaceConfig for the sub-interface
        iface_cfg = InterfaceConfig.query.filter_by(name=sub.sub_interface_name).first()
        if iface_cfg:
            db.session.delete(iface_cfg)

    db.session.delete(vlan)
    db.session.commit()

    AuditLog.log('vlan_delete', f'VLAN {vlan_id} deleted')
    db.session.commit()

    logger.info(f'VLAN {vlan_id} deleted')
    return {'success': True, 'message': f'VLAN {vlan_id} deleted'}


def get_vlan(vlan_id: int):
    return Vlan.query.filter_by(vlan_id=vlan_id).first()


def list_vlans():
    return Vlan.query.order_by(Vlan.vlan_id).all()


# ── Sub-Interface Lifecycle ──────────────────────────────────────────────────

def create_sub_interface(parent: str, vlan_id: int) -> dict:
    """Create a VLAN sub-interface: DB record + kernel creation + InterfaceConfig."""
    vlan = Vlan.query.filter_by(vlan_id=vlan_id).first()
    if not vlan:
        return {'success': False, 'message': f'VLAN {vlan_id} does not exist. Create it first.'}

    sub_name = sys_vlan.get_sub_interface_name(parent, vlan_id)

    # Check if already exists
    existing = VlanSubInterface.query.filter_by(sub_interface_name=sub_name).first()
    if existing:
        return {'success': True, 'message': f'Sub-interface {sub_name} already exists'}

    # Create in kernel
    if not sys_vlan.sub_interface_exists(parent, vlan_id):
        result = sys_vlan.create_sub_interface(parent, vlan_id)
        if not result.success:
            return {'success': False, 'message': f'Kernel error: {result.stderr or result.error}'}

    # Create DB records
    sub = VlanSubInterface(
        vlan_id_ref=vlan.id,
        parent_interface=parent,
        sub_interface_name=sub_name,
    )
    db.session.add(sub)

    # Create InterfaceConfig for the sub-interface (first-class interface)
    iface_cfg = InterfaceConfig.query.filter_by(name=sub_name).first()
    if not iface_cfg:
        iface_cfg = InterfaceConfig(
            name=sub_name,
            role='DISABLED',
            is_sub_interface=True,
            parent_interface=parent,
        )
        db.session.add(iface_cfg)

    db.session.commit()
    logger.info(f'Sub-interface {sub_name} created')
    return {'success': True, 'sub_interface': sub}


def delete_sub_interface(parent: str, vlan_id: int) -> dict:
    """Delete a VLAN sub-interface: kernel removal + DB cleanup."""
    sub_name = sys_vlan.get_sub_interface_name(parent, vlan_id)

    sys_vlan.delete_sub_interface(parent, vlan_id)

    sub = VlanSubInterface.query.filter_by(sub_interface_name=sub_name).first()
    if sub:
        db.session.delete(sub)

    iface_cfg = InterfaceConfig.query.filter_by(name=sub_name).first()
    if iface_cfg:
        db.session.delete(iface_cfg)

    db.session.commit()
    logger.info(f'Sub-interface {sub_name} deleted')
    return {'success': True, 'message': f'Sub-interface {sub_name} deleted'}


# ── Switchport Mode ──────────────────────────────────────────────────────────

def set_switchport_mode(interface_name: str, mode: str, vlan_id: int = None) -> dict:
    """Set trunk/access/routed mode on a physical interface."""
    if mode not in ('routed', 'trunk', 'access'):
        return {'success': False, 'message': 'Mode must be routed, trunk, or access'}

    cfg = InterfaceConfig.query.filter_by(name=interface_name).first()
    if not cfg:
        return {'success': False, 'message': f'Interface {interface_name} not found'}

    old_mode = cfg.switchport_mode or 'routed'

    # Transition from trunk/access to routed: remove all sub-interfaces
    if mode == 'routed' and old_mode in ('trunk', 'access'):
        subs = VlanSubInterface.query.filter_by(parent_interface=interface_name).all()
        for sub in subs:
            delete_sub_interface(interface_name, sub.vlan.vlan_id)

    cfg.switchport_mode = mode

    if mode == 'access' and vlan_id:
        cfg.access_vlan_id = vlan_id

    if mode == 'trunk':
        cfg.allowed_vlans = cfg.allowed_vlans or 'all'
        # Create sub-interfaces for allowed VLANs
        _sync_trunk_sub_interfaces(interface_name, cfg.allowed_vlans)

    db.session.commit()
    logger.info(f'Interface {interface_name} switchport mode set to {mode}')
    return {'success': True, 'message': f'{interface_name} set to {mode} mode'}


def set_trunk_allowed_vlans(interface_name: str, vlan_ids: list, operation: str = 'set') -> dict:
    """Manage allowed VLAN list on a trunk port."""
    cfg = InterfaceConfig.query.filter_by(name=interface_name).first()
    if not cfg or cfg.switchport_mode != 'trunk':
        return {'success': False, 'message': f'{interface_name} is not a trunk port'}

    # Validate all VLAN IDs exist
    for vid in vlan_ids:
        if not Vlan.query.filter_by(vlan_id=vid).first():
            return {'success': False, 'message': f'VLAN {vid} does not exist'}

    current = _parse_vlan_list(cfg.allowed_vlans)

    if operation == 'set':
        new_set = set(vlan_ids)
    elif operation == 'add':
        new_set = current | set(vlan_ids)
    elif operation == 'remove':
        new_set = current - set(vlan_ids)
    else:
        return {'success': False, 'message': f'Invalid operation: {operation}'}

    cfg.allowed_vlans = ','.join(str(v) for v in sorted(new_set))
    db.session.commit()

    _sync_trunk_sub_interfaces(interface_name, cfg.allowed_vlans)

    logger.info(f'Trunk {interface_name} allowed VLANs updated: {cfg.allowed_vlans}')
    return {'success': True, 'message': f'Allowed VLANs updated'}


def set_trunk_native_vlan(interface_name: str, vlan_id: int) -> dict:
    """Set the native VLAN on a trunk port."""
    if not Vlan.query.filter_by(vlan_id=vlan_id).first():
        return {'success': False, 'message': f'VLAN {vlan_id} does not exist'}

    cfg = InterfaceConfig.query.filter_by(name=interface_name).first()
    if not cfg or cfg.switchport_mode != 'trunk':
        return {'success': False, 'message': f'{interface_name} is not a trunk port'}

    cfg.native_vlan_id = vlan_id
    db.session.commit()
    return {'success': True, 'message': f'Native VLAN set to {vlan_id}'}


def set_access_vlan(interface_name: str, vlan_id: int) -> dict:
    """Set the access VLAN on an access port."""
    if not Vlan.query.filter_by(vlan_id=vlan_id).first():
        return {'success': False, 'message': f'VLAN {vlan_id} does not exist'}

    cfg = InterfaceConfig.query.filter_by(name=interface_name).first()
    if not cfg or cfg.switchport_mode != 'access':
        return {'success': False, 'message': f'{interface_name} is not an access port'}

    cfg.access_vlan_id = vlan_id
    db.session.commit()
    return {'success': True, 'message': f'Access VLAN set to {vlan_id}'}


# ── QinQ ─────────────────────────────────────────────────────────────────────

def create_qinq_interface(parent: str, s_vlan_id: int, c_vlan_id: int = None) -> dict:
    """Create QinQ S-VLAN (and optionally C-VLAN) interface."""
    result = sys_vlan.create_qinq_outer(parent, s_vlan_id)
    if not result.success:
        return {'success': False, 'message': f'Failed to create S-VLAN: {result.stderr}'}

    if c_vlan_id:
        result = sys_vlan.create_qinq_inner(parent, s_vlan_id, c_vlan_id)
        if not result.success:
            return {'success': False, 'message': f'Failed to create C-VLAN: {result.stderr}'}

    # Persist
    vlan = Vlan.query.filter_by(vlan_id=s_vlan_id).first()
    if vlan:
        sub_name = f'{parent}.{s_vlan_id}'
        if c_vlan_id:
            sub_name = f'{parent}.{s_vlan_id}.{c_vlan_id}'
        sub = VlanSubInterface(
            vlan_id_ref=vlan.id,
            parent_interface=parent,
            sub_interface_name=sub_name,
            is_qinq=True,
            s_vlan_id=s_vlan_id,
            c_vlan_id=c_vlan_id,
        )
        db.session.add(sub)
        db.session.commit()

    return {'success': True, 'message': f'QinQ interface created'}


def delete_qinq_interface(parent: str, s_vlan_id: int, c_vlan_id: int = None) -> dict:
    """Delete QinQ interface."""
    sys_vlan.delete_qinq(parent, s_vlan_id, c_vlan_id)

    sub_name = f'{parent}.{s_vlan_id}'
    if c_vlan_id:
        sub_name = f'{parent}.{s_vlan_id}.{c_vlan_id}'

    sub = VlanSubInterface.query.filter_by(sub_interface_name=sub_name).first()
    if sub:
        db.session.delete(sub)
        db.session.commit()

    return {'success': True, 'message': f'QinQ interface deleted'}


# ── Startup Sync ─────────────────────────────────────────────────────────────

def sync_switchport_modes_on_boot():
    """Apply trunk/access modes to physical interfaces on startup."""
    configs = InterfaceConfig.query.filter(
        InterfaceConfig.switchport_mode.in_(['trunk', 'access'])
    ).all()
    for cfg in configs:
        logger.info(f'Restoring switchport mode {cfg.switchport_mode} on {cfg.name}')


def sync_vlans_on_boot():
    """Recreate all persisted VLAN sub-interfaces on startup."""
    subs = VlanSubInterface.query.filter_by(is_active=True).all()
    for sub in subs:
        if sys_vlan.sub_interface_exists(sub.parent_interface, sub.vlan.vlan_id):
            logger.info(f'Sub-interface {sub.sub_interface_name} already exists')
            continue

        if sub.is_qinq:
            sys_vlan.create_qinq_outer(sub.parent_interface, sub.s_vlan_id)
            if sub.c_vlan_id:
                sys_vlan.create_qinq_inner(sub.parent_interface, sub.s_vlan_id, sub.c_vlan_id)
        else:
            result = sys_vlan.create_sub_interface(sub.parent_interface, sub.vlan.vlan_id)
            if result.success:
                logger.info(f'Recreated sub-interface {sub.sub_interface_name}')
            else:
                logger.warning(f'Failed to recreate {sub.sub_interface_name}: {result.stderr}')


# ── Helpers ──────────────────────────────────────────────────────────────────

def _parse_vlan_list(vlan_str: str) -> set:
    """Parse a comma-separated VLAN list or 'all' into a set of integers."""
    if not vlan_str or vlan_str.lower() == 'all':
        return {v.vlan_id for v in Vlan.query.all()}
    result = set()
    for part in vlan_str.split(','):
        part = part.strip()
        if part.isdigit():
            result.add(int(part))
    return result


def _sync_trunk_sub_interfaces(interface_name: str, allowed_vlans_str: str):
    """Create/remove sub-interfaces to match the allowed VLAN list."""
    desired = _parse_vlan_list(allowed_vlans_str)
    existing_subs = VlanSubInterface.query.filter_by(parent_interface=interface_name).all()
    existing_vids = {sub.vlan.vlan_id for sub in existing_subs}

    # Create missing
    for vid in desired - existing_vids:
        create_sub_interface(interface_name, vid)

    # Remove extra
    for vid in existing_vids - desired:
        delete_sub_interface(interface_name, vid)
