"""
VPN sub-mode command handlers.
Handles VPN network configuration and peer management.
"""


def set_type(shell, args):
    """type [secure_internet|remote_resource_gw|l3vpn_gateway]"""
    if not args:
        shell.formatter.print('% Usage: type <secure_internet|remote_resource_gw|l3vpn_gateway>')
        return

    net_type = args[0].lower()
    valid = ('secure_internet', 'remote_resource_gw', 'l3vpn_gateway')
    if net_type not in valid:
        shell.formatter.print(f'% Invalid type. Must be one of: {", ".join(valid)}')
        return

    net_name = shell.mode_stack.context.get('network')
    if not net_name:
        shell.formatter.print('% No VPN network selected')
        return

    from models_new import VPNNetwork
    from database import db
    network = VPNNetwork.query.filter_by(name=net_name).first()
    if not network:
        shell.formatter.print(f'% Network "{net_name}" not found')
        return

    network.network_type = net_type
    db.session.commit()
    shell.formatter.print(f'VPN network "{net_name}" type set to {net_type}')


def set_subnet(shell, args):
    """subnet [cidr]"""
    if not args:
        shell.formatter.print('% Usage: subnet <cidr>')
        return

    import ipaddress
    try:
        ipaddress.ip_network(args[0], strict=False)
    except ValueError:
        shell.formatter.print(f'% Invalid CIDR notation: {args[0]}')
        return

    net_name = shell.mode_stack.context.get('network')
    if not net_name:
        shell.formatter.print('% No VPN network selected')
        return

    from models_new import VPNNetwork
    from database import db
    network = VPNNetwork.query.filter_by(name=net_name).first()
    if not network:
        shell.formatter.print(f'% Network "{net_name}" not found')
        return

    network.subnet = args[0]
    db.session.commit()
    shell.formatter.print(f'VPN network "{net_name}" subnet set to {args[0]}')


def set_port(shell, args):
    """port [number]"""
    if not args or not args[0].isdigit():
        shell.formatter.print('% Usage: port <number>')
        return

    port = int(args[0])
    if port < 1 or port > 65535:
        shell.formatter.print('% Port must be between 1 and 65535')
        return

    net_name = shell.mode_stack.context.get('network')
    if not net_name:
        shell.formatter.print('% No VPN network selected')
        return

    from models_new import VPNNetwork
    from database import db
    network = VPNNetwork.query.filter_by(name=net_name).first()
    if not network:
        shell.formatter.print(f'% Network "{net_name}" not found')
        return

    network.port = port
    db.session.commit()
    shell.formatter.print(f'VPN network "{net_name}" port set to {port}')


def add_peer(shell, args):
    """peer [name]"""
    if not args:
        shell.formatter.print('% Usage: peer <name>')
        return

    peer_name = args[0]
    net_name = shell.mode_stack.context.get('network')
    if not net_name:
        shell.formatter.print('% No VPN network selected')
        return

    from models_new import VPNNetwork
    network = VPNNetwork.query.filter_by(name=net_name).first()
    if not network:
        shell.formatter.print(f'% Network "{net_name}" not found')
        return

    from services.endpoint_service import add_endpoint, generate_client_config
    result = add_endpoint(network.id, peer_name)
    if result['success']:
        ep = result['endpoint']
        shell.formatter.print(f'Peer "{peer_name}" added to "{net_name}" ({ep.ip_address})')
        print()
        config = generate_client_config(ep.id)
        if config:
            print('Client configuration:')
            print(config)
    else:
        shell.formatter.print(f'% Error: {result["message"]}')


def remove_peer(shell, args):
    """no peer [name]"""
    if not args:
        shell.formatter.print('% Usage: no peer <name>')
        return

    peer_name = args[0]
    net_name = shell.mode_stack.context.get('network')
    if not net_name:
        shell.formatter.print('% No VPN network selected')
        return

    from models_new import VPNNetwork, Endpoint
    network = VPNNetwork.query.filter_by(name=net_name).first()
    if not network:
        shell.formatter.print(f'% Network "{net_name}" not found')
        return

    ep = Endpoint.query.filter_by(vpn_network_id=network.id, name=peer_name).first()
    if not ep:
        shell.formatter.print(f'% Peer "{peer_name}" not found in network "{net_name}"')
        return

    from services.endpoint_service import remove_endpoint
    result = remove_endpoint(ep.id)
    if result['success']:
        shell.formatter.print(f'Peer "{peer_name}" removed from "{net_name}"')
    else:
        shell.formatter.print(f'% Error: {result["message"]}')


def set_rate_limit(shell, args):
    """rate-limit [download] [upload]"""
    if len(args) < 2:
        shell.formatter.print('% Usage: rate-limit <download-mbps> <upload-mbps>')
        return

    try:
        download = float(args[0])
        upload = float(args[1])
    except ValueError:
        shell.formatter.print('% Rate limits must be numeric (Mbps)')
        return

    net_name = shell.mode_stack.context.get('network')
    if not net_name:
        shell.formatter.print('% No VPN network selected')
        return

    from models_new import VPNNetwork
    from database import db
    network = VPNNetwork.query.filter_by(name=net_name).first()
    if not network:
        shell.formatter.print(f'% Network "{net_name}" not found')
        return

    network.rate_limit_enabled = True
    network.rate_limit_download_mbps = download
    network.rate_limit_upload_mbps = upload
    db.session.commit()
    shell.formatter.print(f'Rate limit set: {download} Mbps down / {upload} Mbps up')
