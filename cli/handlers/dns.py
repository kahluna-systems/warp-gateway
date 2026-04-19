"""
DNS sub-mode command handlers.
Handles DNS overrides and upstream server configuration.
"""


def add_override(shell, args):
    """override [hostname] [ip]"""
    if len(args) < 2:
        shell.formatter.print('% Usage: override <hostname> <ip>')
        return

    hostname = args[0]
    ip = args[1]

    from services.dns_service import add_override as svc_add
    result = svc_add(hostname, ip)
    if result['success']:
        shell.formatter.print(f'DNS override added: {hostname} -> {ip}')
    else:
        shell.formatter.print(f'% Error: {result["message"]}')


def remove_override(shell, args):
    """no override [hostname]"""
    if not args:
        shell.formatter.print('% Usage: no override <hostname>')
        return

    hostname = args[0]
    from models_new import DnsOverride
    override = DnsOverride.query.filter_by(hostname=hostname).first()
    if not override:
        shell.formatter.print(f'% No DNS override found for "{hostname}"')
        return

    from services.dns_service import remove_override as svc_rm
    result = svc_rm(override.id)
    if result['success']:
        shell.formatter.print(f'DNS override for "{hostname}" removed')
    else:
        shell.formatter.print(f'% Error: {result["message"]}')


def set_upstream(shell, args):
    """upstream [ip1] [ip2]"""
    if not args:
        shell.formatter.print('% Usage: upstream <ip1> [ip2]')
        return

    servers = list(args)
    from services.dns_service import set_upstream_servers
    result = set_upstream_servers(servers)
    if result.get('success'):
        shell.formatter.print(f'Upstream DNS servers set to: {", ".join(servers)}')
    else:
        shell.formatter.print(f'% Error: {result.get("message", "Unknown error")}')
