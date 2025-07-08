import base64
import secrets
import qrcode
from io import BytesIO
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.backends import default_backend
import ipaddress
import subprocess
import tempfile
import os


def generate_keypair():
    """Generate WireGuard keypair"""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    return (
        base64.b64encode(private_key_bytes).decode('utf-8'),
        base64.b64encode(public_key_bytes).decode('utf-8')
    )


def generate_preshared_key():
    """Generate WireGuard preshared key"""
    key = secrets.token_bytes(32)
    return base64.b64encode(key).decode('utf-8')


def generate_endpoint_config(endpoint):
    """Generate WireGuard config for an endpoint"""
    from models import ServerConfig
    
    # Get server configuration
    server_config = ServerConfig.query.first()
    if not server_config:
        raise ValueError("Server not configured - run server initialization first")
    
    network = endpoint.vpn_network
    allowed_ips = network.get_allowed_ips()
    
    config = f"""[Interface]
PrivateKey = {endpoint.private_key}
Address = {endpoint.ip_address}/32
DNS = 8.8.8.8, 8.8.4.4

[Peer]
PublicKey = {network.public_key}
AllowedIPs = {allowed_ips}
Endpoint = {server_config.public_ip}:{network.port}
"""
    
    if endpoint.preshared_key:
        config += f"PresharedKey = {endpoint.preshared_key}\n"
    
    config += "PersistentKeepalive = 25\n"
    
    return config


def generate_qr_code(config_content):
    """Generate QR code for WireGuard config"""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(config_content)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    img_io = BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    
    return base64.b64encode(img_io.getvalue()).decode('utf-8')


def setup_gre_tunnel(interface_name, local_ip, remote_ip, tunnel_key=None):
    """Set up GRE tunnel - stub implementation (deprecated, use setup_gretap_with_vlan)"""
    cmd = [
        'ip', 'tunnel', 'add', interface_name, 'mode', 'gre',
        'remote', remote_ip, 'local', local_ip
    ]
    
    if tunnel_key:
        cmd.extend(['key', str(tunnel_key)])
    
    # This would execute the command in production
    # subprocess.run(cmd, check=True)
    print(f"Would execute: {' '.join(cmd)}")
    return True


def setup_vxlan_tunnel(interface_name, vni, local_ip, remote_ip):
    """Set up VXLAN tunnel - stub implementation (deprecated, use setup_vxlan_with_vlan)"""
    cmd = [
        'ip', 'link', 'add', interface_name, 'type', 'vxlan',
        'id', str(vni), 'local', local_ip, 'remote', remote_ip
    ]
    
    # This would execute the command in production
    # subprocess.run(cmd, check=True)
    print(f"Would execute: {' '.join(cmd)}")
    return True


def setup_gretap_tunnel(interface_name, local_ip, remote_ip):
    """Set up GRE TAP tunnel for Layer 2 - stub implementation (deprecated, use setup_gretap_with_vlan)"""
    cmd = [
        'ip', 'link', 'add', interface_name, 'type', 'gretap',
        'remote', remote_ip, 'local', local_ip
    ]
    
    # This would execute the command in production
    # subprocess.run(cmd, check=True)
    print(f"Would execute: {' '.join(cmd)}")
    return True


def validate_subnet(subnet):
    """Validate subnet format"""
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        return True
    except ValueError:
        return False


def get_network_size(subnet):
    """Get number of available IPs in subnet"""
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        return network.num_addresses - 2  # Exclude network and broadcast
    except ValueError:
        return 0


# VLAN-Aware Utility Functions

def setup_vlan_bridge(bridge_name, vlan_id=None, enable_vlan_filtering=True):
    """Set up a VLAN-aware bridge with optional VLAN filtering"""
    commands = [
        ['ip', 'link', 'add', bridge_name, 'type', 'bridge'],
        ['ip', 'link', 'set', 'up', 'dev', bridge_name]
    ]
    
    if enable_vlan_filtering:
        commands.append(['ip', 'link', 'set', 'dev', bridge_name, 'type', 'bridge', 'vlan_filtering', '1'])
    
    # This would execute the commands in production
    for cmd in commands:
        print(f"Would execute: {' '.join(cmd)}")
        # subprocess.run(cmd, check=True)
    
    return True


def setup_vxlan_with_vlan(interface_name, vni, local_ip, vlan_id=None, bridge_name=None):
    """Set up VXLAN interface with VLAN support"""
    commands = [
        ['ip', 'link', 'add', interface_name, 'type', 'vxlan', 'id', str(vni), 
         'local', local_ip, 'dstport', '4789'],
        ['ip', 'link', 'set', 'up', 'dev', interface_name]
    ]
    
    if bridge_name:
        # Create bridge if it doesn't exist
        commands.extend([
            ['ip', 'link', 'add', bridge_name, 'type', 'bridge'],
            ['ip', 'link', 'set', 'up', 'dev', bridge_name]
        ])
        
        # Enable VLAN filtering if VLAN ID is specified
        if vlan_id:
            commands.append(['ip', 'link', 'set', 'dev', bridge_name, 'type', 'bridge', 'vlan_filtering', '1'])
        
        # Add interface to bridge
        commands.append(['ip', 'link', 'set', interface_name, 'master', bridge_name])
        
        # Configure VLAN if specified
        if vlan_id:
            commands.append(['bridge', 'vlan', 'add', 'dev', interface_name, 'vid', str(vlan_id)])
    
    # This would execute the commands in production
    for cmd in commands:
        print(f"Would execute: {' '.join(cmd)}")
        # subprocess.run(cmd, check=True)
    
    return True


def setup_gretap_with_vlan(interface_name, local_ip, remote_ip, vlan_id=None, bridge_name=None):
    """Set up GRE TAP interface with VLAN support"""
    commands = [
        ['ip', 'link', 'add', interface_name, 'type', 'gretap', 'remote', remote_ip, 'local', local_ip],
        ['ip', 'link', 'set', 'up', 'dev', interface_name]
    ]
    
    if bridge_name:
        # Create bridge if it doesn't exist
        commands.extend([
            ['ip', 'link', 'add', bridge_name, 'type', 'bridge'],
            ['ip', 'link', 'set', 'up', 'dev', bridge_name]
        ])
        
        # Enable VLAN filtering if VLAN ID is specified
        if vlan_id:
            commands.append(['ip', 'link', 'set', 'dev', bridge_name, 'type', 'bridge', 'vlan_filtering', '1'])
        
        # Add interface to bridge
        commands.append(['ip', 'link', 'set', interface_name, 'master', bridge_name])
        
        # Configure VLAN if specified
        if vlan_id:
            commands.append(['bridge', 'vlan', 'add', 'dev', interface_name, 'vid', str(vlan_id)])
    
    # This would execute the commands in production
    for cmd in commands:
        print(f"Would execute: {' '.join(cmd)}")
        # subprocess.run(cmd, check=True)
    
    return True


def validate_vlan_id(vlan_id):
    """Validate VLAN ID range"""
    if vlan_id is None:
        return True
    
    try:
        vlan_id = int(vlan_id)
        return 1 <= vlan_id <= 4094
    except (ValueError, TypeError):
        return False


def validate_vlan_range(vlan_range):
    """Validate VLAN range format (e.g., '100-110')"""
    if not vlan_range:
        return True
    
    try:
        if '-' in vlan_range:
            start, end = vlan_range.split('-')
            start_id = int(start.strip())
            end_id = int(end.strip())
            
            if start_id > end_id:
                return False
            
            return validate_vlan_id(start_id) and validate_vlan_id(end_id)
        else:
            return validate_vlan_id(int(vlan_range))
    except (ValueError, TypeError):
        return False


def get_vlan_ids_from_range(vlan_range):
    """Get list of VLAN IDs from a range string"""
    if not vlan_range:
        return []
    
    try:
        if '-' in vlan_range:
            start, end = vlan_range.split('-')
            start_id = int(start.strip())
            end_id = int(end.strip())
            return list(range(start_id, end_id + 1))
        else:
            return [int(vlan_range)]
    except (ValueError, TypeError):
        return []


def check_vlan_conflicts(vlan_id, exclude_network_id=None):
    """Check for VLAN ID conflicts with existing networks"""
    if not vlan_id:
        return False
    
    from models import VPNNetwork
    
    query = VPNNetwork.query.filter(VPNNetwork.vlan_id == vlan_id)
    
    if exclude_network_id:
        query = query.filter(VPNNetwork.id != exclude_network_id)
    
    return query.first() is not None


# Port and Subnet Management

def get_available_ports(start_port=51820, end_port=51829, exclude_network_id=None):
    """Get list of available ports in the specified range"""
    from models import VPNNetwork
    
    query = VPNNetwork.query.with_entities(VPNNetwork.port)
    
    if exclude_network_id:
        query = query.filter(VPNNetwork.id != exclude_network_id)
    
    used_ports = {port[0] for port in query.all()}
    available_ports = [port for port in range(start_port, end_port + 1) if port not in used_ports]
    
    return available_ports


def get_next_available_port(start_port=51820, end_port=51829, exclude_network_id=None):
    """Get the next available port in the specified range"""
    available_ports = get_available_ports(start_port, end_port, exclude_network_id)
    return available_ports[0] if available_ports else None


def generate_subnet_pools():
    """Generate default subnet pools for different network types"""
    return {
        'secure_internet': {
            'base_network': '10.100.0.0/16',
            'subnet_size': 31,  # /31 for point-to-point
            'description': 'Secure Internet /31 subnets'
        },
        'remote_resource_gw': {
            'base_network': '10.200.0.0/16',
            'subnet_size': 24,  # /24 for small offices
            'description': 'Remote Resource Gateway subnets'
        },
        'l3vpn_gateway': {
            'base_network': '10.300.0.0/16',
            'subnet_size': 24,  # /24 for site-to-site
            'description': 'L3 VPN Gateway subnets'
        },
        'l2_point_to_point': {
            'base_network': '10.400.0.0/16',
            'subnet_size': 30,  # /30 for point-to-point L2
            'description': 'L2 Point-to-Point subnets'
        },
        'l2_mesh': {
            'base_network': '10.500.0.0/16',
            'subnet_size': 24,  # /24 for mesh networks
            'description': 'L2 Mesh subnets'
        }
    }


def get_next_available_subnet(network_type, exclude_network_id=None):
    """Get the next available subnet for a network type"""
    pools = generate_subnet_pools()
    
    if network_type not in pools:
        return None
    
    pool = pools[network_type]
    base_network = ipaddress.ip_network(pool['base_network'])
    subnet_size = pool['subnet_size']
    
    from models import VPNNetwork
    
    query = VPNNetwork.query.filter(VPNNetwork.network_type == network_type)
    
    if exclude_network_id:
        query = query.filter(VPNNetwork.id != exclude_network_id)
    
    used_subnets = {subnet.subnet for subnet in query.all()}
    
    # Generate subnets of the specified size
    for subnet in base_network.subnets(new_prefix=subnet_size):
        if str(subnet) not in used_subnets:
            return str(subnet)
    
    return None