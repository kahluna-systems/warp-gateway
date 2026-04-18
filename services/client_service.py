"""
Connected client visibility — merges ARP table + DHCP leases + WireGuard peers.
"""
import logging
from system import interfaces as sys_iface
from system import dhcp as sys_dhcp
from system import wireguard as sys_wg
from models_new import VPNNetwork, Endpoint, DhcpReservation

logger = logging.getLogger('warp.services.client')


def get_all_clients():
    """
    Build a unified client list from three sources:
    1. DHCP leases (LAN clients with hostname)
    2. ARP table (LAN clients without DHCP)
    3. WireGuard peers (VPN clients)
    """
    clients = []
    seen_ips = set()

    # ── DHCP leases ──────────────────────────────────────────────────────
    leases = sys_dhcp.get_leases()
    reservations = {r.mac.lower(): r for r in DhcpReservation.query.all()}

    for lease in leases:
        ip = lease.ip
        seen_ips.add(ip)
        res = reservations.get(lease.mac.lower())
        clients.append({
            'name': res.hostname if res else (lease.hostname or ''),
            'ip': ip,
            'mac': lease.mac,
            'type': 'LAN',
            'source': 'Static' if res else 'DHCP',
            'status': 'Active',
            'interface': '',
            'rx_bytes': 0,
            'tx_bytes': 0,
        })

    # ── ARP table ────────────────────────────────────────────────────────
    arp_entries = sys_iface.get_arp_table()
    for entry in arp_entries:
        if entry.ip not in seen_ips and entry.mac != '00:00:00:00:00:00':
            seen_ips.add(entry.ip)
            clients.append({
                'name': '',
                'ip': entry.ip,
                'mac': entry.mac,
                'type': 'LAN',
                'source': 'ARP',
                'status': entry.state.capitalize() if entry.state else 'Unknown',
                'interface': entry.interface,
                'rx_bytes': 0,
                'tx_bytes': 0,
            })

    # ── WireGuard peers ──────────────────────────────────────────────────
    networks = VPNNetwork.query.filter_by(is_active=True).all()
    for net in networks:
        iface_name = net.get_interface_name()
        wg_status = sys_wg.get_status(iface_name)
        if not wg_status:
            continue

        # Map public keys to endpoint names
        ep_map = {ep.public_key: ep for ep in net.endpoints}

        for peer in wg_status.peers:
            ep = ep_map.get(peer.public_key)
            connected = peer.latest_handshake is not None and peer.latest_handshake > 0
            ip = ep.ip_address if ep else peer.allowed_ips.split('/')[0]

            if ip not in seen_ips:
                seen_ips.add(ip)
                clients.append({
                    'name': ep.name if ep else peer.public_key[:12] + '...',
                    'ip': ip,
                    'mac': '',
                    'type': 'VPN',
                    'source': net.name,
                    'status': 'Connected' if connected else 'Offline',
                    'interface': iface_name,
                    'rx_bytes': peer.transfer_rx,
                    'tx_bytes': peer.transfer_tx,
                })

    return clients


def get_client_counts():
    """Get summary counts for the dashboard."""
    clients = get_all_clients()
    lan_clients = [c for c in clients if c['type'] == 'LAN']
    vpn_clients = [c for c in clients if c['type'] == 'VPN']
    vpn_connected = [c for c in vpn_clients if c['status'] == 'Connected']

    return {
        'total': len(clients),
        'lan': len(lan_clients),
        'vpn_total': len(vpn_clients),
        'vpn_connected': len(vpn_connected),
        'vpn_offline': len(vpn_clients) - len(vpn_connected),
    }
