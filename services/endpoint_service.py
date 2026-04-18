"""
VPN Endpoint (peer) CRUD — orchestrates database + WireGuard + rate limiting.
"""
import io
import logging
from database import db
from models_new import Endpoint, VPNNetwork, AuditLog
from system import wireguard as sys_wg
from services.shaping_service import apply_endpoint_limit, remove_endpoint_limit

logger = logging.getLogger('warp.services.endpoint')


def list_endpoints(network_id=None):
    """List endpoints, optionally filtered by network."""
    q = Endpoint.query
    if network_id:
        q = q.filter_by(vpn_network_id=network_id)
    return q.order_by(Endpoint.created_at.desc()).all()


def get_endpoint(endpoint_id):
    """Get a single endpoint by ID."""
    return Endpoint.query.get(endpoint_id)


def add_endpoint(network_id, name, endpoint_type='mobile', use_psk=True,
                 rate_limit_enabled=False, rate_limit_download_mbps=None,
                 rate_limit_upload_mbps=None):
    """
    Add a new VPN endpoint:
    1. Generate keys
    2. Allocate IP from network subnet
    3. Save to DB
    4. wg set add peer on the running interface
    5. Apply rate limit if configured
    """
    try:
        network = VPNNetwork.query.get(network_id)
        if not network:
            return {'success': False, 'message': 'Network not found'}

        if not network.can_add_endpoint():
            return {'success': False, 'message': 'Network has reached maximum peer count'}

        # Generate keys
        private_key, public_key = sys_wg.generate_keypair()
        if not private_key or not public_key:
            return {'success': False, 'message': 'Failed to generate WireGuard keys'}

        preshared_key = sys_wg.generate_preshared_key() if use_psk else None

        # Allocate IP
        try:
            ip_address = network.get_next_ip()
        except ValueError as e:
            return {'success': False, 'message': str(e)}

        # Create DB record
        endpoint = Endpoint(
            vpn_network_id=network_id,
            name=name,
            endpoint_type=endpoint_type,
            ip_address=ip_address,
            private_key=private_key,
            public_key=public_key,
            preshared_key=preshared_key,
            status='pending',
            is_active=True,
            rate_limit_enabled=rate_limit_enabled,
            rate_limit_download_mbps=rate_limit_download_mbps,
            rate_limit_upload_mbps=rate_limit_upload_mbps,
        )
        db.session.add(endpoint)
        db.session.flush()

        # Add peer to running WireGuard interface
        iface_name = network.get_interface_name()
        result = sys_wg.add_peer(
            interface=iface_name,
            public_key=public_key,
            allowed_ips=f'{ip_address}/32',
            preshared_key=preshared_key,
        )

        if not result.success:
            db.session.rollback()
            return {'success': False, 'message': f'Failed to add peer to WireGuard: {result.stderr or result.error}'}

        db.session.commit()

        # Apply rate limit
        rl = endpoint.get_effective_rate_limit()
        if rl['enabled']:
            apply_endpoint_limit(endpoint)

        AuditLog.log('endpoint_create', f'Added endpoint "{name}" to network "{network.name}" ({ip_address})')
        db.session.commit()

        logger.info(f'Endpoint "{name}" added to {network.name} ({ip_address})')
        return {'success': True, 'endpoint': endpoint}

    except Exception as e:
        db.session.rollback()
        logger.error(f'Failed to add endpoint "{name}": {e}')
        return {'success': False, 'message': str(e)}


def remove_endpoint(endpoint_id):
    """
    Remove a VPN endpoint:
    1. wg set remove peer
    2. Remove rate limit
    3. Delete from DB
    """
    try:
        endpoint = Endpoint.query.get(endpoint_id)
        if not endpoint:
            return {'success': False, 'message': 'Endpoint not found'}

        network = endpoint.vpn_network
        iface_name = network.get_interface_name()
        name = endpoint.name

        # Remove from WireGuard
        sys_wg.remove_peer(iface_name, endpoint.public_key)

        # Remove rate limit
        remove_endpoint_limit(endpoint)

        # Delete from DB
        db.session.delete(endpoint)
        db.session.commit()

        AuditLog.log('endpoint_delete', f'Removed endpoint "{name}" from network "{network.name}"')
        db.session.commit()

        logger.info(f'Endpoint "{name}" removed from {network.name}')
        return {'success': True, 'message': f'Endpoint "{name}" removed'}

    except Exception as e:
        db.session.rollback()
        logger.error(f'Failed to remove endpoint {endpoint_id}: {e}')
        return {'success': False, 'message': str(e)}


def suspend_endpoint(endpoint_id):
    """Suspend an endpoint (remove from WG but keep in DB)."""
    try:
        endpoint = Endpoint.query.get(endpoint_id)
        if not endpoint:
            return {'success': False, 'message': 'Endpoint not found'}

        network = endpoint.vpn_network
        iface_name = network.get_interface_name()
        sys_wg.remove_peer(iface_name, endpoint.public_key)
        remove_endpoint_limit(endpoint)

        endpoint.status = 'suspended'
        endpoint.is_active = False
        db.session.commit()

        AuditLog.log('endpoint_suspend', f'Suspended endpoint "{endpoint.name}"')
        db.session.commit()

        return {'success': True, 'message': f'Endpoint "{endpoint.name}" suspended'}

    except Exception as e:
        db.session.rollback()
        return {'success': False, 'message': str(e)}


def resume_endpoint(endpoint_id):
    """Resume a suspended endpoint."""
    try:
        endpoint = Endpoint.query.get(endpoint_id)
        if not endpoint:
            return {'success': False, 'message': 'Endpoint not found'}

        network = endpoint.vpn_network
        iface_name = network.get_interface_name()

        result = sys_wg.add_peer(
            interface=iface_name,
            public_key=endpoint.public_key,
            allowed_ips=f'{endpoint.ip_address}/32',
            preshared_key=endpoint.preshared_key,
        )

        if result.success:
            endpoint.status = 'active'
            endpoint.is_active = True
            db.session.commit()

            rl = endpoint.get_effective_rate_limit()
            if rl['enabled']:
                apply_endpoint_limit(endpoint)

            AuditLog.log('endpoint_resume', f'Resumed endpoint "{endpoint.name}"')
            db.session.commit()

        return {'success': result.success, 'message': 'Endpoint resumed' if result.success else 'Failed to resume'}

    except Exception as e:
        db.session.rollback()
        return {'success': False, 'message': str(e)}


def get_endpoint_status(endpoint_id):
    """Get real-time status for an endpoint from WireGuard."""
    endpoint = Endpoint.query.get(endpoint_id)
    if not endpoint:
        return None

    network = endpoint.vpn_network
    iface_name = network.get_interface_name()
    wg_status = sys_wg.get_status(iface_name)

    peer_info = None
    if wg_status:
        for peer in wg_status.peers:
            if peer.public_key == endpoint.public_key:
                peer_info = peer.to_dict()
                break

    return {
        'endpoint': endpoint.to_dict(),
        'wireguard_peer': peer_info,
    }


def generate_client_config(endpoint_id):
    """Generate a WireGuard client configuration file for an endpoint."""
    endpoint = Endpoint.query.get(endpoint_id)
    if not endpoint:
        return None

    network = endpoint.vpn_network
    type_cfg = network.get_network_type_config()
    allowed_ips = type_cfg.get('allowed_ips', '0.0.0.0/0')

    # Determine the server endpoint (public IP + port)
    from system.interfaces import get_public_ip
    public_ip = get_public_ip()
    if not public_ip:
        from services.interface_service import get_wan_interface
        wan = get_wan_interface()
        public_ip = wan.ip_address if wan else '0.0.0.0'

    config = f"""[Interface]
PrivateKey = {endpoint.private_key}
Address = {endpoint.ip_address}/{_subnet_prefix(network.subnet)}
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = {network.public_key}
AllowedIPs = {allowed_ips}
Endpoint = {public_ip}:{network.port}
PersistentKeepalive = 25
"""
    if endpoint.preshared_key:
        config = config.replace(
            f'Endpoint = {public_ip}:{network.port}',
            f'PresharedKey = {endpoint.preshared_key}\nEndpoint = {public_ip}:{network.port}'
        )

    return config


def generate_qr_code(endpoint_id):
    """Generate a QR code PNG for the client config."""
    config = generate_client_config(endpoint_id)
    if not config:
        return None

    try:
        import qrcode
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(config)
        qr.make(fit=True)
        img = qr.make_image(fill_color='black', back_color='white')

        buf = io.BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        return buf
    except ImportError:
        logger.warning('qrcode library not installed — QR generation unavailable')
        return None


def _subnet_prefix(subnet):
    import ipaddress
    return ipaddress.ip_network(subnet, strict=False).prefixlen
