"""
DHCP sub-mode command handlers.
Handles DHCP pool configuration and static reservations.
"""


def set_pool(shell, args):
    """pool [interface] range [start-ip] [end-ip]"""
    # Expected: pool ens4 range 192.168.1.100 192.168.1.200
    if len(args) < 4:
        shell.formatter.print('% Usage: pool <interface> range <start-ip> <end-ip>')
        return

    interface = args[0]
    # args[1] should be "range"
    if args[1].lower() != 'range':
        shell.formatter.print('% Usage: pool <interface> range <start-ip> <end-ip>')
        return

    range_start = args[2]
    range_end = args[3]

    from services.dhcp_service import setup_dhcp
    result = setup_dhcp(interface, range_start, range_end)
    if result['success']:
        shell.formatter.print(f'DHCP pool configured on {interface}: {range_start} - {range_end}')
    else:
        shell.formatter.print(f'% Error: {result["message"]}')


def add_reservation(shell, args):
    """reservation [mac] [ip] [hostname]"""
    if len(args) < 2:
        shell.formatter.print('% Usage: reservation <mac> <ip> [hostname]')
        return

    mac = args[0]
    ip = args[1]
    hostname = args[2] if len(args) > 2 else ''

    from services.dhcp_service import add_reservation as svc_add_res
    result = svc_add_res(mac, ip, hostname)
    if result['success']:
        shell.formatter.print(f'DHCP reservation added: {mac} -> {ip}')
    else:
        shell.formatter.print(f'% Error: {result["message"]}')


def remove_reservation(shell, args):
    """no reservation [mac]"""
    if not args:
        shell.formatter.print('% Usage: no reservation <mac>')
        return

    mac = args[0]
    from models_new import DhcpReservation
    res = DhcpReservation.query.filter_by(mac=mac).first()
    if not res:
        shell.formatter.print(f'% No reservation found for MAC {mac}')
        return

    from services.dhcp_service import remove_reservation as svc_rm_res
    result = svc_rm_res(res.id)
    if result['success']:
        shell.formatter.print(f'DHCP reservation for {mac} removed')
    else:
        shell.formatter.print(f'% Error: {result["message"]}')
