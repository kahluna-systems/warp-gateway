"""
Diagnostic command handlers.
Handles ping, traceroute, mtr, nslookup/dig, packet capture, and iperf.
"""


def do_ping(shell, args):
    """ping [target]"""
    if not args:
        shell.formatter.print('% Usage: ping <hostname-or-ip>')
        return

    target = args[0]
    count = 4
    if len(args) > 1 and args[1].isdigit():
        count = int(args[1])

    shell.formatter.print(f'Pinging {target} with {count} packets...')
    from services.diagnostics_service import ping
    result = ping(target, count=count)
    print(result.get('output', ''))


def do_traceroute(shell, args):
    """traceroute [target]"""
    if not args:
        shell.formatter.print('% Usage: traceroute <hostname-or-ip>')
        return

    target = args[0]
    shell.formatter.print(f'Tracing route to {target}...')
    from services.diagnostics_service import traceroute
    result = traceroute(target)
    print(result.get('output', ''))


def do_mtr(shell, args):
    """mtr [target]"""
    if not args:
        shell.formatter.print('% Usage: mtr <hostname-or-ip>')
        return

    target = args[0]
    count = 10
    if len(args) > 1 and args[1].isdigit():
        count = int(args[1])

    shell.formatter.print(f'Running MTR to {target} ({count} cycles)...')
    from services.diagnostics_service import mtr
    result = mtr(target, count=count)
    print(result.get('output', ''))


def do_nslookup(shell, args):
    """nslookup [hostname]"""
    if not args:
        shell.formatter.print('% Usage: nslookup <hostname>')
        return

    hostname = args[0]
    record_type = args[1] if len(args) > 1 else 'A'

    from services.diagnostics_service import dns_lookup
    result = dns_lookup(hostname, record_type=record_type)
    if result['success']:
        print(f'{hostname} ({record_type}):')
        print(result.get('output', ''))
    else:
        shell.formatter.print(f'% DNS lookup failed: {result.get("output", "")}')


def do_dig(shell, args):
    """dig [hostname] -- alias for nslookup with more detail"""
    if not args:
        shell.formatter.print('% Usage: dig <hostname> [record-type]')
        return

    hostname = args[0]
    record_type = args[1] if len(args) > 1 else 'A'

    from services.diagnostics_service import dns_lookup
    result = dns_lookup(hostname, record_type=record_type)
    print(result.get('output', ''))


def do_capture(shell, args):
    """capture [interface] [filter] [count]"""
    if not args:
        shell.formatter.print('% Usage: capture <interface> [filter] [count]')
        return

    interface = args[0]
    filter_expr = ''
    count = 50

    if len(args) > 1:
        # Check if last arg is a number (count)
        if args[-1].isdigit():
            count = int(args[-1])
            filter_expr = ' '.join(args[1:-1])
        else:
            filter_expr = ' '.join(args[1:])

    shell.formatter.print(f'Capturing {count} packets on {interface}...')
    if filter_expr:
        shell.formatter.print(f'Filter: {filter_expr}')

    from services.diagnostics_service import packet_capture
    result = packet_capture(interface, filter_expr=filter_expr, count=count)
    print(result.get('output', ''))


def do_iperf(shell, args):
    """iperf [server]"""
    if not args:
        shell.formatter.print('% Usage: iperf <server-address>')
        return

    server = args[0]
    shell.formatter.print(f'Running iperf3 to {server}...')

    from system.commander import run
    result = run(['iperf3', '-c', server, '-t', '10'], timeout=30)
    if result.success:
        print(result.stdout)
    else:
        shell.formatter.print(f'% iperf3 failed: {result.stderr or result.error}')
