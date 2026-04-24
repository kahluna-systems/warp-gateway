"""
Interface sub-mode command handlers.
Handles role assignment, IP configuration, and interface enable/disable.
"""


def set_role(shell, args):
    """role [WAN|LAN|OPT|DISABLED]"""
    if not args:
        shell.formatter.print('% Usage: role <WAN|LAN|OPT|DISABLED>')
        return

    role = args[0].upper()
    if role not in ('WAN', 'LAN', 'OPT', 'DISABLED'):
        shell.formatter.print(f'% Invalid role "{role}". Must be WAN, LAN, OPT, or DISABLED')
        return

    iface_name = shell.mode_stack.context.get('interface')
    if not iface_name:
        shell.formatter.print('% No interface selected')
        return

    from services.interface_service import assign_role
    result = assign_role(iface_name, role)
    if result['success']:
        shell.formatter.print(f'Interface {iface_name} assigned as {role}')
    else:
        shell.formatter.print(f'% Error: {result["message"]}')


def set_ip_address(shell, args):
    """ip address [addr] [mask] | ip address dhcp"""
    if not args:
        shell.formatter.print('% Usage: ip address <address> <netmask> | ip address dhcp')
        return

    iface_name = shell.mode_stack.context.get('interface')
    if not iface_name:
        shell.formatter.print('% No interface selected')
        return

    if args[0].lower() == 'dhcp':
        from services.interface_service import assign_role
        # Get current role
        from models_new import InterfaceConfig
        cfg = InterfaceConfig.query.filter_by(name=iface_name).first()
        role = cfg.role if cfg else 'WAN'
        result = assign_role(iface_name, role, mode='dhcp')
        if result['success']:
            shell.formatter.print(f'Interface {iface_name} configured for DHCP')
        else:
            shell.formatter.print(f'% Error: {result["message"]}')
        return

    if len(args) < 2:
        shell.formatter.print('% Usage: ip address <address> <netmask>')
        return

    address = args[0]
    netmask = args[1]

    from services.interface_service import assign_role
    from models_new import InterfaceConfig
    cfg = InterfaceConfig.query.filter_by(name=iface_name).first()
    role = cfg.role if cfg else 'LAN'
    result = assign_role(iface_name, role, mode='static', ip=address, netmask=netmask)
    if result['success']:
        shell.formatter.print(f'Interface {iface_name} configured with {address} {netmask}')
    else:
        shell.formatter.print(f'% Error: {result["message"]}')


def set_gateway(shell, args):
    """gateway [address]"""
    if not args:
        shell.formatter.print('% Usage: gateway <address>')
        return

    iface_name = shell.mode_stack.context.get('interface')
    if not iface_name:
        shell.formatter.print('% No interface selected')
        return

    gateway = args[0]
    from models_new import InterfaceConfig
    from database import db

    cfg = InterfaceConfig.query.filter_by(name=iface_name).first()
    if not cfg:
        shell.formatter.print(f'% Interface {iface_name} not configured. Assign a role first.')
        return

    cfg.gateway = gateway
    db.session.commit()
    shell.formatter.print(f'Gateway set to {gateway} on {iface_name}')


def shutdown(shell, args):
    """shutdown -- disable the interface"""
    iface_name = shell.mode_stack.context.get('interface')
    if not iface_name:
        shell.formatter.print('% No interface selected')
        return

    from services.interface_service import assign_role
    result = assign_role(iface_name, 'DISABLED')
    if result['success']:
        shell.formatter.print(f'Interface {iface_name} disabled')
    else:
        shell.formatter.print(f'% Error: {result["message"]}')


def no_shutdown(shell, args):
    """no shutdown -- enable the interface"""
    iface_name = shell.mode_stack.context.get('interface')
    if not iface_name:
        shell.formatter.print('% No interface selected')
        return

    from models_new import InterfaceConfig
    cfg = InterfaceConfig.query.filter_by(name=iface_name).first()
    if not cfg:
        shell.formatter.print(f'% Interface {iface_name} not configured. Assign a role first.')
        return

    from services.interface_service import assign_role
    role = cfg.role if cfg.role != 'DISABLED' else 'OPT'
    result = assign_role(iface_name, role)
    if result['success']:
        shell.formatter.print(f'Interface {iface_name} enabled as {role}')
    else:
        shell.formatter.print(f'% Error: {result["message"]}')


# ── Switchport Commands ──────────────────────────────────────────────────────

def set_switchport_mode(shell, args):
    """switchport mode [trunk|access|routed]"""
    if not args:
        shell.formatter.print('% Usage: switchport mode <trunk|access|routed>')
        return

    mode = args[0].lower()
    iface_name = shell.mode_stack.context.get('interface')
    if not iface_name:
        shell.formatter.print('% No interface selected')
        return

    from services.vlan_service import set_switchport_mode as svc_set
    result = svc_set(iface_name, mode)
    if result['success']:
        shell.formatter.print(result['message'])
    else:
        shell.formatter.print(f'% Error: {result["message"]}')


def set_switchport_trunk_allowed(shell, args):
    """switchport trunk allowed vlan <list> | add <list> | remove <list>"""
    if not args:
        shell.formatter.print('% Usage: switchport trunk allowed vlan <id,id,...>')
        return

    iface_name = shell.mode_stack.context.get('interface')
    if not iface_name:
        shell.formatter.print('% No interface selected')
        return

    # Parse operation and VLAN list
    operation = 'set'
    vlan_str = args[0]
    if args[0].lower() in ('add', 'remove'):
        operation = args[0].lower()
        vlan_str = args[1] if len(args) > 1 else ''

    vlan_ids = [int(v.strip()) for v in vlan_str.split(',') if v.strip().isdigit()]
    if not vlan_ids:
        shell.formatter.print('% No valid VLAN IDs provided')
        return

    from services.vlan_service import set_trunk_allowed_vlans
    result = set_trunk_allowed_vlans(iface_name, vlan_ids, operation)
    if result['success']:
        shell.formatter.print(result['message'])
    else:
        shell.formatter.print(f'% Error: {result["message"]}')


def set_switchport_trunk_native(shell, args):
    """switchport trunk native vlan <id>"""
    if not args or not args[0].isdigit():
        shell.formatter.print('% Usage: switchport trunk native vlan <id>')
        return

    iface_name = shell.mode_stack.context.get('interface')
    if not iface_name:
        shell.formatter.print('% No interface selected')
        return

    from services.vlan_service import set_trunk_native_vlan
    result = set_trunk_native_vlan(iface_name, int(args[0]))
    if result['success']:
        shell.formatter.print(result['message'])
    else:
        shell.formatter.print(f'% Error: {result["message"]}')


def set_switchport_access_vlan(shell, args):
    """switchport access vlan <id>"""
    if not args or not args[0].isdigit():
        shell.formatter.print('% Usage: switchport access vlan <id>')
        return

    iface_name = shell.mode_stack.context.get('interface')
    if not iface_name:
        shell.formatter.print('% No interface selected')
        return

    from services.vlan_service import set_access_vlan
    result = set_access_vlan(iface_name, int(args[0]))
    if result['success']:
        shell.formatter.print(result['message'])
    else:
        shell.formatter.print(f'% Error: {result["message"]}')


def set_interface_zone(shell, args):
    """zone <name> -- assign interface to a security zone"""
    if not args:
        shell.formatter.print('% Usage: zone <zone-name>')
        return

    iface_name = shell.mode_stack.context.get('interface')
    if not iface_name:
        shell.formatter.print('% No interface selected')
        return

    from services.zone_service import assign_interface_to_zone
    result = assign_interface_to_zone(iface_name, args[0])
    if result['success']:
        shell.formatter.print(result['message'])
    else:
        shell.formatter.print(f'% Error: {result["message"]}')


def set_description(shell, args):
    """description <text> -- set interface description"""
    if not args:
        shell.formatter.print('% Usage: description <text>')
        return

    iface_name = shell.mode_stack.context.get('interface')
    if not iface_name:
        shell.formatter.print('% No interface selected')
        return

    description = ' '.join(args)
    from models_new import InterfaceConfig
    from database import db

    cfg = InterfaceConfig.query.filter_by(name=iface_name).first()
    if not cfg:
        shell.formatter.print(f'% Interface {iface_name} not configured')
        return

    cfg.description = description
    db.session.commit()
    shell.formatter.print(f'Description set on {iface_name}')
