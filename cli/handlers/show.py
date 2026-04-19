"""
Show command handlers.
All "show" commands that display system state.
Each handler receives (shell, args) and prints formatted output.
"""


def show_interfaces(shell, args):
    """show interfaces [name]"""
    from services.interface_service import get_all_interfaces
    from services.health_service import get_interface_stats

    interfaces = get_all_interfaces()
    stats = get_interface_stats()

    if args:
        # Detailed view for a specific interface
        name = args[0]
        iface = next((i for i in interfaces if i['name'] == name), None)
        if not iface:
            shell.formatter.print(f'% Interface "{name}" not found')
            return

        iface_stats = stats.get(name, {})
        data = {
            'Interface': iface['name'],
            'Role': iface['role'],
            'Link': 'UP' if iface['link_up'] else 'DOWN',
            'MAC': iface['mac'] or 'N/A',
            'IP Address': iface['ip'] or 'not configured',
            'Netmask': iface['netmask'] or 'N/A',
            'Speed': iface['speed'] or 'unknown',
            'Driver': iface['driver'] or 'unknown',
            'Mode': iface['mode'],
            'Configured IP': iface['configured_ip'] or 'N/A',
            'Configured Mask': iface['configured_netmask'] or 'N/A',
            'Gateway': iface['configured_gateway'] or 'N/A',
            'Bytes Sent': str(iface_stats.get('bytes_sent', 0)),
            'Bytes Recv': str(iface_stats.get('bytes_recv', 0)),
            'Packets Sent': str(iface_stats.get('packets_sent', 0)),
            'Packets Recv': str(iface_stats.get('packets_recv', 0)),
            'Errors In': str(iface_stats.get('errors_in', 0)),
            'Errors Out': str(iface_stats.get('errors_out', 0)),
        }
        print(shell.formatter.key_value(data))
        return

    # Brief table view
    headers = ['Interface', 'Role', 'IP Address', 'Netmask', 'Link', 'Speed', 'MAC']
    rows = []
    for iface in interfaces:
        if not iface.get('is_physical', True):
            continue
        rows.append([
            iface['name'],
            iface['role'],
            iface['ip'] or 'N/A',
            iface['netmask'] or 'N/A',
            'UP' if iface['link_up'] else 'DOWN',
            iface['speed'] or 'N/A',
            iface['mac'] or 'N/A',
        ])
    print(shell.formatter.table(headers, rows))


def show_ip_route(shell, args):
    """show ip route"""
    from system.routing import get_routing_table

    routes = get_routing_table()
    if not routes:
        shell.formatter.print('No routes found')
        return

    print('Routing Table:')
    for route in routes:
        print(f'  {route}')


def show_firewall_rules(shell, args):
    """show firewall rules"""
    from services.firewall_service import list_rules, list_port_forwards, get_iptables_rules

    # Custom rules from DB
    rules = list_rules()
    if rules:
        headers = ['ID', 'Chain', 'Action', 'Protocol', 'Source', 'Destination', 'Port', 'Active']
        rows = []
        for r in rules:
            rows.append([
                str(r.id),
                r.chain,
                r.action,
                r.protocol or 'any',
                r.source or 'any',
                r.destination or 'any',
                str(r.port) if r.port else 'any',
                'Yes' if r.is_active else 'No',
            ])
        print('Custom Firewall Rules:')
        print(shell.formatter.table(headers, rows))
    else:
        print('No custom firewall rules configured')

    # Port forwards
    forwards = list_port_forwards()
    if forwards:
        print()
        headers = ['ID', 'WAN Port', 'LAN IP', 'LAN Port', 'Protocol', 'Active']
        rows = []
        for pf in forwards:
            rows.append([
                str(pf.id),
                str(pf.wan_port),
                pf.lan_ip,
                str(pf.lan_port),
                pf.protocol or 'tcp',
                'Yes' if pf.is_active else 'No',
            ])
        print('Port Forwarding Rules:')
        print(shell.formatter.table(headers, rows))

    # Live iptables
    print()
    print('Active iptables rules (filter):')
    try:
        iptables = get_iptables_rules()
        for line in iptables.get('filter', []):
            if line.strip():
                print(f'  {line}')
    except Exception as e:
        shell.formatter.print(f'% Could not read iptables: {e}')


def show_vpn_networks(shell, args):
    """show vpn networks"""
    from services.network_service import list_networks

    networks = list_networks()
    if not networks:
        shell.formatter.print('No VPN networks configured')
        return

    headers = ['Name', 'Type', 'Subnet', 'Port', 'Status', 'Peers', 'Rate Limit']
    rows = []
    for net in networks:
        rl = 'N/A'
        if net.rate_limit_enabled:
            rl = f'{net.rate_limit_download_mbps}/{net.rate_limit_upload_mbps} Mbps'
        rows.append([
            net.name,
            net.network_type,
            net.subnet,
            str(net.port),
            net.status,
            str(len(net.endpoints)),
            rl,
        ])
    print(shell.formatter.table(headers, rows))


def show_vpn_peers(shell, args):
    """show vpn peers"""
    from services.endpoint_service import list_endpoints
    from system import wireguard as sys_wg
    from models_new import VPNNetwork

    endpoints = list_endpoints()
    if not endpoints:
        shell.formatter.print('No VPN peers configured')
        return

    # Get live WireGuard status for handshake info
    wg_peers = {}
    networks = VPNNetwork.query.filter_by(is_active=True).all()
    for net in networks:
        iface = net.get_interface_name()
        status = sys_wg.get_status(iface)
        if status:
            for peer in status.peers:
                wg_peers[peer.public_key] = peer

    headers = ['Name', 'Network', 'IP', 'Status', 'Last Handshake', 'RX', 'TX']
    rows = []
    for ep in endpoints:
        peer = wg_peers.get(ep.public_key)
        connected = peer and peer.latest_handshake and peer.latest_handshake > 0
        handshake = 'Never'
        rx = '0 B'
        tx = '0 B'
        if peer:
            if peer.latest_handshake and peer.latest_handshake > 0:
                from datetime import datetime
                hs_time = datetime.fromtimestamp(peer.latest_handshake)
                handshake = hs_time.strftime('%Y-%m-%d %H:%M:%S')
            rx = _format_bytes(peer.transfer_rx)
            tx = _format_bytes(peer.transfer_tx)

        rows.append([
            ep.name,
            ep.vpn_network.name if ep.vpn_network else 'N/A',
            ep.ip_address,
            'Connected' if connected else 'Offline',
            handshake,
            rx,
            tx,
        ])
    print(shell.formatter.table(headers, rows))


def show_vpn_peer_config(shell, args):
    """show vpn peer-config [name]"""
    if not args:
        shell.formatter.print('% Usage: show vpn peer-config <peer-name>')
        return

    from services.endpoint_service import generate_client_config
    from models_new import Endpoint

    name = args[0]
    ep = Endpoint.query.filter_by(name=name).first()
    if not ep:
        shell.formatter.print(f'% Peer "{name}" not found')
        return

    config = generate_client_config(ep.id)
    if config:
        print(config)
    else:
        shell.formatter.print('% Failed to generate peer config')


def show_dhcp_leases(shell, args):
    """show dhcp leases"""
    from services.dhcp_service import get_leases

    leases = get_leases()
    if not leases:
        shell.formatter.print('No active DHCP leases')
        return

    headers = ['IP Address', 'MAC Address', 'Hostname', 'Expiry']
    rows = []
    for lease in leases:
        rows.append([
            lease.ip,
            lease.mac,
            lease.hostname or '',
            lease.expiry or '',
        ])
    print(shell.formatter.table(headers, rows))


def show_dhcp_config(shell, args):
    """show dhcp config"""
    from models_new import DhcpConfig, DhcpReservation

    configs = DhcpConfig.query.all()
    if not configs:
        shell.formatter.print('No DHCP configuration')
        return

    for cfg in configs:
        data = {
            'Interface': cfg.interface,
            'Range Start': cfg.range_start,
            'Range End': cfg.range_end,
            'Netmask': cfg.netmask,
            'Gateway': cfg.gateway or 'N/A',
            'DNS Servers': cfg.dns_servers or 'N/A',
            'Lease Time': cfg.lease_time,
            'Active': 'Yes' if cfg.is_active else 'No',
        }
        print(shell.formatter.key_value(data))
        print()

    reservations = DhcpReservation.query.all()
    if reservations:
        print('Static Reservations:')
        headers = ['MAC', 'IP', 'Hostname']
        rows = [[r.mac, r.ip, r.hostname or ''] for r in reservations]
        print(shell.formatter.table(headers, rows))


def show_dns_overrides(shell, args):
    """show dns overrides"""
    from services.dns_service import get_overrides, get_upstream_servers

    overrides = get_overrides()
    upstream = get_upstream_servers()

    print(f'Upstream DNS: {", ".join(upstream)}')
    print()

    if not overrides:
        shell.formatter.print('No DNS overrides configured')
        return

    headers = ['Hostname', 'IP Address']
    rows = [[o.hostname, o.ip] for o in overrides]
    print(shell.formatter.table(headers, rows))


def show_clients(shell, args):
    """show clients"""
    from services.client_service import get_all_clients

    clients = get_all_clients()
    if not clients:
        shell.formatter.print('No connected clients')
        return

    headers = ['Name', 'IP', 'MAC', 'Type', 'Source', 'Status']
    rows = []
    for c in clients:
        rows.append([
            c['name'] or '(unknown)',
            c['ip'],
            c['mac'] or 'N/A',
            c['type'],
            c['source'],
            c['status'],
        ])
    print(shell.formatter.table(headers, rows))


def show_system_health(shell, args):
    """show system health"""
    from services.health_service import get_system_health, get_dependency_status

    health = get_system_health()
    deps = get_dependency_status()

    data = {
        'Hostname': health.get('hostname', 'unknown'),
        'Platform': health.get('platform', 'unknown'),
        'Uptime': health.get('uptime_human', 'unknown'),
        'CPU Usage': f'{health.get("cpu_percent", 0)}%',
        'CPU Cores': str(health.get('cpu_count', 0)),
    }

    mem = health.get('memory', {})
    data['Memory'] = f'{mem.get("used_mb", 0)} / {mem.get("total_mb", 0)} MB ({mem.get("percent", 0)}%)'

    disk = health.get('disk', {})
    data['Disk'] = f'{disk.get("used_gb", 0)} / {disk.get("total_gb", 0)} GB ({disk.get("percent", 0)}%)'

    print(shell.formatter.key_value(data))

    if deps:
        print()
        print('Dependencies:')
        ready = deps.get('ready', False)
        print(f'  Status: {"All OK" if ready else "MISSING DEPENDENCIES"}')
        missing = deps.get('missing_required', [])
        if missing:
            print(f'  Missing: {", ".join(missing)}')


def show_running_config(shell, args):
    """show running-config"""
    from cli.config_serializer import ConfigSerializer

    serializer = ConfigSerializer()
    config = serializer.serialize_running_config()
    print(config)


def show_startup_config(shell, args):
    """show startup-config"""
    from cli.config_serializer import ConfigSerializer

    serializer = ConfigSerializer()
    config = serializer.load_startup_config()
    if config:
        print(config)
    else:
        shell.formatter.print('% No startup configuration found')


def show_version(shell, args):
    """show version"""
    from models_new import GatewayConfig
    from services.health_service import get_system_health
    import platform

    config = GatewayConfig.get_instance()
    health = get_system_health()

    data = {
        'Software': f'KahLuna WARP Gateway v{config.software_version}',
        'Hostname': config.hostname,
        'Management': config.management_mode,
        'Platform': health.get('platform', platform.platform()),
        'Python': health.get('python', platform.python_version()),
        'Uptime': health.get('uptime_human', 'unknown'),
    }
    print(shell.formatter.key_value(data))


def show_nexus_status(shell, args):
    """show nexus status"""
    from models_new import GatewayConfig

    config = GatewayConfig.get_instance()

    if config.management_mode == 'standalone':
        print('Management mode: standalone -- not registered with KahLuna Nexus')
        print()
        print('To register, enter configure mode and run:')
        print('  nexus register <token> <platform-url>')
        return

    # Managed or pre-provisioned
    try:
        from nexus_client import nexus
        status = nexus.get_status() if hasattr(nexus, 'get_status') else {}
    except Exception:
        status = {}

    data = {
        'Management Mode': config.management_mode,
        'Platform URL': status.get('platform_url', 'N/A'),
        'Service ID': status.get('service_id', 'N/A'),
        'Tenant ID': status.get('tenant_id', 'N/A'),
        'Heartbeat': status.get('heartbeat_state', 'unknown'),
        'Last Heartbeat': status.get('last_heartbeat', 'N/A'),
        'Registered': 'Yes' if status.get('is_registered') else 'No',
    }
    print(shell.formatter.key_value(data))


# ── Helpers ──────────────────────────────────────────────────────────────────

def _format_bytes(b):
    """Format byte count to human-readable string."""
    if b < 1024:
        return f'{b} B'
    elif b < 1048576:
        return f'{b / 1024:.1f} KB'
    elif b < 1073741824:
        return f'{b / 1048576:.1f} MB'
    else:
        return f'{b / 1073741824:.1f} GB'
