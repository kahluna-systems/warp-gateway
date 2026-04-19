"""
Firewall sub-mode command handlers.
Handles firewall rules and port forwarding.
"""


def add_rule(shell, args):
    """rule [chain] [action] [protocol] [source] [destination] [port]"""
    if len(args) < 5:
        shell.formatter.print('% Usage: rule <chain> <action> <protocol> <source> <destination> [port]')
        shell.formatter.print('% Example: rule INPUT ACCEPT tcp any any 80')
        return

    chain = args[0].upper()
    action = args[1].upper()
    protocol = args[2].lower()
    source = args[3] if args[3].lower() != 'any' else None
    destination = args[4] if args[4].lower() != 'any' else None
    port = int(args[5]) if len(args) > 5 and args[5].isdigit() else None

    if chain not in ('INPUT', 'FORWARD', 'OUTPUT'):
        shell.formatter.print(f'% Invalid chain "{chain}". Must be INPUT, FORWARD, or OUTPUT')
        return

    if action not in ('ACCEPT', 'DROP', 'REJECT'):
        shell.formatter.print(f'% Invalid action "{action}". Must be ACCEPT, DROP, or REJECT')
        return

    if protocol == 'any':
        protocol = None

    from services.firewall_service import add_custom_rule
    desc = f'{chain} {action} {args[2]} {args[3]} {args[4]}'
    if port:
        desc += f' port {port}'

    result = add_custom_rule(
        chain=chain,
        source=source,
        destination=destination,
        port=port,
        protocol=protocol,
        action=action,
        description=desc,
    )
    if result['success']:
        shell.formatter.print(f'Firewall rule added: {desc}')
    else:
        shell.formatter.print(f'% Error: {result["message"]}')


def remove_rule(shell, args):
    """no rule [rule-id]"""
    if not args or not args[0].isdigit():
        shell.formatter.print('% Usage: no rule <rule-id>')
        return

    rule_id = int(args[0])
    from services.firewall_service import remove_custom_rule
    result = remove_custom_rule(rule_id)
    if result['success']:
        shell.formatter.print(f'Firewall rule {rule_id} removed')
    else:
        shell.formatter.print(f'% Error: {result["message"]}')


def add_port_forward(shell, args):
    """port-forward [wan-port] [lan-ip] [lan-port] [protocol]"""
    if len(args) < 3:
        shell.formatter.print('% Usage: port-forward <wan-port> <lan-ip> <lan-port> [protocol]')
        return

    if not args[0].isdigit() or not args[2].isdigit():
        shell.formatter.print('% Ports must be numeric')
        return

    wan_port = int(args[0])
    lan_ip = args[1]
    lan_port = int(args[2])
    protocol = args[3].lower() if len(args) > 3 else 'tcp'

    from services.firewall_service import add_port_forward as svc_add_pf
    result = svc_add_pf(wan_port, lan_ip, lan_port, protocol)
    if result['success']:
        shell.formatter.print(f'Port forward added: WAN:{wan_port} -> {lan_ip}:{lan_port}/{protocol}')
    else:
        shell.formatter.print(f'% Error: {result["message"]}')


def remove_port_forward(shell, args):
    """no port-forward [id]"""
    if not args or not args[0].isdigit():
        shell.formatter.print('% Usage: no port-forward <id>')
        return

    pf_id = int(args[0])
    from services.firewall_service import remove_port_forward as svc_rm_pf
    result = svc_rm_pf(pf_id)
    if result['success']:
        shell.formatter.print(f'Port forward {pf_id} removed')
    else:
        shell.formatter.print(f'% Error: {result["message"]}')
