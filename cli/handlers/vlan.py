"""
VLAN sub-mode command handlers.
Handles VLAN name configuration within config-vlan mode.
"""


def set_vlan_name(shell, args):
    """name <string> -- set VLAN name"""
    if not args:
        shell.formatter.print('% Usage: name <vlan-name>')
        return

    vlan_id = shell.mode_stack.context.get('vlan_id')
    if not vlan_id:
        shell.formatter.print('% No VLAN selected')
        return

    name = ' '.join(args)
    from models_new import Vlan
    from database import db

    vlan = Vlan.query.filter_by(vlan_id=vlan_id).first()
    if not vlan:
        shell.formatter.print(f'% VLAN {vlan_id} not found')
        return

    vlan.name = name
    db.session.commit()
    shell.formatter.print(f'VLAN {vlan_id} name set to "{name}"')


def no_vlan_name(shell, args):
    """no name -- reset VLAN name to default"""
    vlan_id = shell.mode_stack.context.get('vlan_id')
    if not vlan_id:
        shell.formatter.print('% No VLAN selected')
        return

    from models_new import Vlan
    from database import db

    vlan = Vlan.query.filter_by(vlan_id=vlan_id).first()
    if not vlan:
        shell.formatter.print(f'% VLAN {vlan_id} not found')
        return

    vlan.name = f'VLAN{vlan_id}'
    db.session.commit()
    shell.formatter.print(f'VLAN {vlan_id} name reset to default')
