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
