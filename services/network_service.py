"""
VPN Network CRUD — orchestrates database + WireGuard + firewall.
"""
import ipaddress
import logging
from database import db
from models_new import VPNNetwork, AuditLog
from system import wireguard as sys_wg
from system import firewall as sys_fw
from system import routing as sys_routing
from services.interface_service import get_wan_interface

logger = logging.getLogger('warp.services.network')


def list_networks():
    """Return all VPN networks."""
    return VPNNetwork.query.order_by(VPNNetwork.created_at.desc()).all()


def get_network(network_id):
    """Get a single VPN network by ID."""
    return VPNNetwork.query.get(network_id)


def get_network_by_name(name):
    """Get a VPN network by name."""
    return VPNNetwork.query.filter_by(name=name).first()


def create_network(name, network_type, subnet, port, rate_limit_enabled=False,
                   rate_limit_download_mbps=None, rate_limit_upload_mbps=None):
    """
    Create a new VPN network:
    1. Generate WireGuard keys
    2. Save to database
    3. Write WireGuard config + bring up interface
    4. Add NAT masquerade if secure_internet type
    """
    try:
        # Generate keys
        private_key, public_key = sys_wg.generate_keypair()
        if not private_key or not public_key:
            return {'success': False, 'message': 'Failed to generate WireGuard keys'}

        # Create DB record
        network = VPNNetwork(
            name=name,
            network_type=network_type,
            subnet=subnet,
            port=port,
            private_key=private_key,
            public_key=public_key,
            status='pending',
            is_active=True,
            rate_limit_enabled=rate_limit_enabled,
            rate_limit_download_mbps=rate_limit_download_mbps,
            rate_limit_upload_mbps=rate_limit_upload_mbps,
        )
        db.session.add(network)
        db.session.flush()  # Get the ID

        iface_name = network.get_interface_name()
        gateway_ip = network.get_gateway_ip()
        net = ipaddress.ip_network(subnet, strict=False)

        # Build WireGuard config
        config = f"""[Interface]
Address = {gateway_ip}/{net.prefixlen}
ListenPort = {port}
PrivateKey = {private_key}
"""
        # Add PostUp/PostDown for NAT if secure_internet
        wan = get_wan_interface()
        wan_name = wan.name if wan else 'eth0'
        type_cfg = network.get_network_type_config()

        if type_cfg.get('routing_style') == 'full_tunnel':
            config += f"""
PostUp = iptables -t nat -A POSTROUTING -s {subnet} -o {wan_name} -j MASQUERADE
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PostUp = iptables -A FORWARD -o %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s {subnet} -o {wan_name} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT
PostDown = iptables -D FORWARD -o %i -j ACCEPT
"""
        else:
            config += f"""
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PostUp = iptables -A FORWARD -o %i -j ACCEPT
PostDown = iptables -D FORWARD -i %i -j ACCEPT
PostDown = iptables -D FORWARD -o %i -j ACCEPT
"""

        # Write config and bring up
        result = sys_wg.create_interface(iface_name, config)
        if not result.success:
            db.session.rollback()
            return {'success': False, 'message': f'Failed to create WireGuard interface: {result.stderr or result.error}'}

        network.status = 'active'
        db.session.commit()

        AuditLog.log('network_create', f'Created VPN network "{name}" ({network_type}) on port {port}')
        db.session.commit()

        logger.info(f'VPN network "{name}" created on {iface_name}')
        return {'success': True, 'network': network}

    except Exception as e:
        db.session.rollback()
        logger.error(f'Failed to create network "{name}": {e}')
        return {'success': False, 'message': str(e)}


def delete_network(network_id):
    """
    Delete a VPN network:
    1. wg-quick down
    2. Remove NAT rules
    3. Remove config file
    4. Delete from DB
    """
    try:
        network = VPNNetwork.query.get(network_id)
        if not network:
            return {'success': False, 'message': 'Network not found'}

        iface_name = network.get_interface_name()
        name = network.name

        # Bring down WireGuard interface
        sys_wg.destroy_interface(iface_name)

        # Remove from DB (cascade deletes endpoints)
        db.session.delete(network)
        db.session.commit()

        AuditLog.log('network_delete', f'Deleted VPN network "{name}"')
        db.session.commit()

        logger.info(f'VPN network "{name}" deleted')
        return {'success': True, 'message': f'Network "{name}" deleted'}

    except Exception as e:
        db.session.rollback()
        logger.error(f'Failed to delete network {network_id}: {e}')
        return {'success': False, 'message': str(e)}


def suspend_network(network_id):
    """Suspend a VPN network (bring interface down but keep config)."""
    try:
        network = VPNNetwork.query.get(network_id)
        if not network:
            return {'success': False, 'message': 'Network not found'}

        iface_name = network.get_interface_name()
        from system.commander import run
        run(['ip', 'link', 'set', 'down', 'dev', iface_name], sudo=True)

        network.status = 'suspended'
        network.is_active = False
        db.session.commit()

        AuditLog.log('network_suspend', f'Suspended VPN network "{network.name}"')
        db.session.commit()

        return {'success': True, 'message': f'Network "{network.name}" suspended'}

    except Exception as e:
        db.session.rollback()
        logger.error(f'Failed to suspend network {network_id}: {e}')
        return {'success': False, 'message': str(e)}


def resume_network(network_id):
    """Resume a suspended VPN network."""
    try:
        network = VPNNetwork.query.get(network_id)
        if not network:
            return {'success': False, 'message': 'Network not found'}

        iface_name = network.get_interface_name()
        from system.commander import run
        run(['ip', 'link', 'set', 'up', 'dev', iface_name], sudo=True)

        network.status = 'active'
        network.is_active = True
        db.session.commit()

        AuditLog.log('network_resume', f'Resumed VPN network "{network.name}"')
        db.session.commit()

        return {'success': True, 'message': f'Network "{network.name}" resumed'}

    except Exception as e:
        db.session.rollback()
        logger.error(f'Failed to resume network {network_id}: {e}')
        return {'success': False, 'message': str(e)}


def get_network_status(network_id):
    """Get real-time WireGuard status for a network."""
    network = VPNNetwork.query.get(network_id)
    if not network:
        return None

    iface_name = network.get_interface_name()
    wg_status = sys_wg.get_status(iface_name)

    return {
        'network': network.to_dict(),
        'wireguard': wg_status.to_dict() if wg_status else {'name': iface_name, 'peers': [], 'peer_count': 0},
    }


def bring_up_all():
    """Bring up all active VPN networks. Called on startup."""
    networks = VPNNetwork.query.filter_by(is_active=True).all()
    for network in networks:
        iface_name = network.get_interface_name()
        # Check if already up
        existing = sys_wg.get_status(iface_name)
        if existing:
            logger.info(f'WireGuard interface {iface_name} already up')
            continue

        result = sys_wg.create_interface(iface_name, _build_config(network))
        if result.success:
            network.status = 'active'
            logger.info(f'Brought up WireGuard interface {iface_name}')
        else:
            network.status = 'failed'
            logger.error(f'Failed to bring up {iface_name}: {result.stderr or result.error}')

    db.session.commit()


def _build_config(network):
    """Build a WireGuard config string for a network including all its active peers."""
    net = ipaddress.ip_network(network.subnet, strict=False)
    gateway_ip = network.get_gateway_ip()
    wan = get_wan_interface()
    wan_name = wan.name if wan else 'eth0'
    type_cfg = network.get_network_type_config()

    config = f"""[Interface]
Address = {gateway_ip}/{net.prefixlen}
ListenPort = {network.port}
PrivateKey = {network.private_key}
"""
    if type_cfg.get('routing_style') == 'full_tunnel':
        config += f"""
PostUp = iptables -t nat -A POSTROUTING -s {network.subnet} -o {wan_name} -j MASQUERADE
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PostUp = iptables -A FORWARD -o %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s {network.subnet} -o {wan_name} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT
PostDown = iptables -D FORWARD -o %i -j ACCEPT
"""
    else:
        config += f"""
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PostUp = iptables -A FORWARD -o %i -j ACCEPT
PostDown = iptables -D FORWARD -i %i -j ACCEPT
PostDown = iptables -D FORWARD -o %i -j ACCEPT
"""

    # Add active peers
    for ep in network.endpoints:
        if ep.is_active:
            config += f"""
[Peer]
PublicKey = {ep.public_key}
AllowedIPs = {ep.ip_address}/32
"""
            if ep.preshared_key:
                config += f"PresharedKey = {ep.preshared_key}\n"

    return config
