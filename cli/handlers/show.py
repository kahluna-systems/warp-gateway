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


def show_arp(shell, args):
    """show arp -- display the full ARP table across all interfaces"""
    from system.interfaces import get_arp_table

    entries = get_arp_table()
    if not entries:
        shell.formatter.print('ARP table is empty')
        return

    headers = ['IP Address', 'MAC Address', 'Interface', 'State']
    rows = []
    for e in entries:
        rows.append([e.ip, e.mac, e.interface, e.state or 'unknown'])
    print(shell.formatter.table(headers, rows))


def show_system_health(shell, args):
    """show system health"""
    from services.health_service import get_system_health, get_dependency_status
    from models_new import GatewayConfig

    health = get_system_health()
    deps = get_dependency_status()
    gw_config = GatewayConfig.get_instance()

    data = {
        'Hostname': gw_config.hostname,
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


def show_log(shell, args):
    """show log [count]"""
    from models_new import AuditLog

    count = 20
    if args and args[0].isdigit():
        count = int(args[0])

    entries = AuditLog.recent(limit=count)
    if not entries:
        shell.formatter.print('No log entries')
        return

    headers = ['Time', 'Action', 'Details', 'User']
    rows = []
    for e in entries:
        time_str = e.created_at.strftime('%Y-%m-%d %H:%M:%S') if e.created_at else 'N/A'
        user = e.user.username if e.user else 'System'
        details = (e.details or '')[:60]
        rows.append([time_str, e.action, details, user])
    print(shell.formatter.table(headers, rows))


def show_uptime(shell, args):
    """show uptime"""
    from services.health_service import get_system_health
    health = get_system_health()
    print(f'Uptime: {health.get("uptime_human", "unknown")}')


def show_history(shell, args):
    """show history -- display commands entered in this session"""
    if not shell._command_history:
        shell.formatter.print('No command history')
        return

    for i, cmd in enumerate(shell._command_history, 1):
        print(f'  {i:4d}  {cmd}')


def show_tech_support(shell, args):
    """show tech-support -- dump full system state for support tickets"""
    print('=' * 60)
    print('KahLuna WARP Gateway -- Technical Support Dump')
    print('=' * 60)

    print()
    print('--- show version ---')
    show_version(shell, [])

    print()
    print('--- show interfaces ---')
    show_interfaces(shell, [])

    print()
    print('--- show ip route ---')
    show_ip_route(shell, [])

    print()
    print('--- show firewall rules ---')
    show_firewall_rules(shell, [])

    print()
    print('--- show vpn networks ---')
    show_vpn_networks(shell, [])

    print()
    print('--- show vpn peers ---')
    show_vpn_peers(shell, [])

    print()
    print('--- show dhcp config ---')
    show_dhcp_config(shell, [])

    print()
    print('--- show dhcp leases ---')
    show_dhcp_leases(shell, [])

    print()
    print('--- show dns overrides ---')
    show_dns_overrides(shell, [])

    print()
    print('--- show clients ---')
    show_clients(shell, [])

    print()
    print('--- show system health ---')
    show_system_health(shell, [])

    print()
    print('--- show nexus status ---')
    show_nexus_status(shell, [])

    print()
    print('--- show running-config ---')
    show_running_config(shell, [])

    print()
    print('--- show log ---')
    show_log(shell, ['50'])

    print()
    print('=' * 60)
    print('End of technical support dump')
    print('=' * 60)


# ── VLAN and Zone Show Commands ──────────────────────────────────────────────

def show_vlan(shell, args):
    """show vlan -- display VLAN table"""
    from services.vlan_service import list_vlans
    from models_new import VlanSubInterface, SecurityZone

    vlans = list_vlans()
    if not vlans:
        shell.formatter.print('No VLANs configured')
        return

    headers = ['ID', 'Name', 'Interfaces', 'Zone', 'Status']
    rows = []
    for v in vlans:
        ifaces = [s.sub_interface_name for s in v.sub_interfaces]
        # Get zone from first sub-interface
        zone_name = 'N/A'
        for s in v.sub_interfaces:
            from models_new import InterfaceConfig
            cfg = InterfaceConfig.query.filter_by(name=s.sub_interface_name).first()
            if cfg and cfg.zone:
                zone_name = cfg.zone.name
                break

        rows.append([
            str(v.vlan_id),
            v.name,
            ', '.join(ifaces) if ifaces else 'none',
            zone_name,
            'Active' if v.is_active else 'Inactive',
        ])
    print(shell.formatter.table(headers, rows))


def show_interfaces_trunk(shell, args):
    """show interfaces trunk -- display trunk port status"""
    from models_new import InterfaceConfig

    trunks = InterfaceConfig.query.filter_by(switchport_mode='trunk').all()
    if not trunks:
        shell.formatter.print('No trunk ports configured')
        return

    headers = ['Interface', 'Allowed VLANs', 'Native VLAN', 'Role']
    rows = []
    for t in trunks:
        rows.append([
            t.name,
            t.allowed_vlans or 'all',
            str(t.native_vlan_id or 1),
            t.role,
        ])
    print(shell.formatter.table(headers, rows))


def show_zone(shell, args):
    """show zone -- display security zone assignments"""
    from services.zone_service import list_zones

    zones = list_zones()
    if not zones:
        shell.formatter.print('No security zones configured')
        return

    headers = ['Zone', 'Description', 'Interfaces', 'Default']
    rows = []
    for z in zones:
        ifaces = [i.name for i in z.interfaces]
        rows.append([
            z.name,
            z.description or '',
            ', '.join(ifaces) if ifaces else 'none',
            'Yes' if z.is_default else 'No',
        ])
    print(shell.formatter.table(headers, rows))


def show_zone_policy(shell, args):
    """show zone-policy -- display zone firewall policies"""
    from services.zone_service import list_zone_policies

    policies = list_zone_policies()
    if not policies:
        shell.formatter.print('No zone policies configured')
        return

    headers = ['ID', 'Source', 'Destination', 'Action', 'Protocol', 'Port', 'Priority']
    rows = []
    for p in policies:
        d = p.to_dict()
        rows.append([
            str(p.id),
            d.get('source_zone', 'N/A'),
            d.get('dest_zone', 'N/A'),
            p.action,
            p.protocol or 'any',
            str(p.port) if p.port else 'any',
            str(p.priority),
        ])
    print(shell.formatter.table(headers, rows))
