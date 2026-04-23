"""
Zone sub-mode command handlers.
Handles zone description and zone policy management within config-zone mode.
"""


def set_zone_description(shell, args):
    """description <text> -- set zone description"""
    if not args:
        shell.formatter.print('% Usage: description <text>')
        return

    zone_name = shell.mode_stack.context.get('zone_name')
    if not zone_name:
        shell.formatter.print('% No zone selected')
        return

    description = ' '.join(args)
    from models_new import SecurityZone
    from database import db

    zone = SecurityZone.query.filter_by(name=zone_name).first()
    if not zone:
        shell.formatter.print(f'% Zone "{zone_name}" not found')
        return

    zone.description = description
    db.session.commit()
    shell.formatter.print(f'Zone "{zone_name}" description set')


def add_zone_policy(shell, args):
    """policy <src-zone> <dst-zone> <action> [protocol] [port]"""
    if len(args) < 3:
        shell.formatter.print('% Usage: policy <source-zone> <dest-zone> <ACCEPT|DROP|REJECT> [protocol] [port]')
        return

    src_zone = args[0]
    dst_zone = args[1]
    action = args[2].upper()
    protocol = args[3] if len(args) > 3 else None
    port = int(args[4]) if len(args) > 4 and args[4].isdigit() else None

    from services.zone_service import create_zone_policy
    result = create_zone_policy(src_zone, dst_zone, action, protocol=protocol, port=port)
    if result['success']:
        shell.formatter.print(f'Zone policy added: {src_zone} -> {dst_zone} {action}')
    else:
        shell.formatter.print(f'% Error: {result["message"]}')


def remove_zone_policy(shell, args):
    """no policy <id> -- remove a zone policy"""
    if not args or not args[0].isdigit():
        shell.formatter.print('% Usage: no policy <policy-id>')
        return

    from services.zone_service import delete_zone_policy
    result = delete_zone_policy(int(args[0]))
    if result['success']:
        shell.formatter.print('Zone policy removed')
    else:
        shell.formatter.print(f'% Error: {result["message"]}')
