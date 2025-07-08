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
import random
import math


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
    """Generate WireGuard config for an endpoint with proper topology support"""
    from models import ServerConfig
    
    # Get server configuration
    server_config = ServerConfig.query.first()
    if not server_config:
        raise ValueError("Server not configured - run server initialization first")
    
    network = endpoint.vpn_network
    topology_mode = network.get_topology_mode()
    
    # Generate AllowedIPs based on topology and network type
    allowed_ips = generate_allowed_ips_for_endpoint(endpoint, topology_mode)
    
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
    
    # Add VRF information as comments for troubleshooting
    config += f"\n# VRF Information\n"
    config += f"# VCID: {network.vcid}\n"
    config += f"# Topology: {topology_mode}\n"
    config += f"# Network Type: {network.network_type}\n"
    if network.peer_communication_enabled:
        config += f"# Peer Communication: Enabled\n"
    
    return config


def generate_allowed_ips_for_endpoint(endpoint, topology_mode):
    """Generate AllowedIPs configuration based on topology and network type"""
    network = endpoint.vpn_network
    network_config = network.get_network_type_config()
    
    # Check for custom allowed IPs first
    if network.custom_allowed_ips:
        return network.custom_allowed_ips
    
    # Handle different network types and topologies
    if network.network_type == 'secure_internet':
        if topology_mode == 'mesh':
            # Mesh mode: Full internet access + network subnet for peer communication
            return f"0.0.0.0/0, ::/0"
        else:
            # Hub-and-spoke mode: Only internet traffic via gateway
            return "0.0.0.0/0, ::/0"
    
    elif network.network_type == 'remote_resource_gw':
        # Split tunnel: Only specific corporate subnets
        return network_config.get('allowed_ips', '10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16')
    
    elif network.network_type == 'l3vpn_gateway':
        # L3VPN: Full mesh routing
        return "0.0.0.0/0"
    
    elif network.network_type in ['l2_point_to_point', 'l2_mesh']:
        # Layer 2 networks: Allow all traffic (transparent bridging)
        return "0.0.0.0/0"
    
    # Fallback to network type default
    return network_config.get('allowed_ips', '0.0.0.0/0')


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


# VRF-Related Utility Functions

def generate_vcid():
    """Generate a unique 8-digit Virtual Circuit ID"""
    return random.randint(10000000, 99999999)


def format_vcid(vcid):
    """Format VCID for display with separators
    
    Args:
        vcid (int): 8-digit VCID
        
    Returns:
        str: Formatted VCID (e.g., '1234-5678')
    """
    vcid_str = str(vcid)
    return f"{vcid_str[:4]}-{vcid_str[4:]}"


def parse_vcid(vcid_str):
    """Parse VCID from formatted string
    
    Args:
        vcid_str (str): Formatted VCID string
        
    Returns:
        int: VCID as integer
    """
    # Remove any non-digit characters
    import re
    digits_only = re.sub(r'\D', '', vcid_str)
    return int(digits_only) if digits_only else None


def generate_unique_vcid():
    """Generate a unique 8-digit VCID that doesn't conflict with existing ones"""
    from models import VPNNetwork
    
    max_attempts = 100
    for _ in range(max_attempts):
        vcid = generate_vcid()
        
        # Check if VCID already exists
        existing = VPNNetwork.query.filter(VPNNetwork.vcid == vcid).first()
        if not existing:
            return vcid
    
    raise ValueError("Could not generate unique VCID after maximum attempts")


def calculate_dynamic_subnet_size(expected_users):
    """Calculate appropriate subnet size based on expected users
    
    Args:
        expected_users (int): Expected number of users
        
    Returns:
        int: Prefix length for subnet (e.g., 24 for /24)
    """
    if expected_users <= 0:
        return 30  # /30 for minimal setup
    
    # Need to account for:
    # - Gateway IP (1)
    # - Network/broadcast addresses (2)
    # - Some overhead for growth (20%)
    required_ips = math.ceil(expected_users * 1.2) + 3
    
    # Calculate minimum prefix length needed
    # We need 2^(32-prefix) >= required_ips
    # So prefix <= 32 - log2(required_ips)
    min_prefix = 32 - math.ceil(math.log2(required_ips))
    
    # Dynamic subnet allocation based on user count
    if expected_users <= 2:
        return 30  # /30 (2 hosts)
    elif expected_users <= 6:
        return 29  # /29 (6 hosts)
    elif expected_users <= 14:
        return 28  # /28 (14 hosts)
    elif expected_users <= 30:
        return 27  # /27 (30 hosts)
    elif expected_users <= 62:
        return 26  # /26 (62 hosts)
    elif expected_users <= 126:
        return 25  # /25 (126 hosts)
    elif expected_users <= 254:
        return 24  # /24 (254 hosts)
    else:
        return 23  # /23 (510 hosts) - maximum reasonable size


def get_dynamic_subnet_for_network(network_type, expected_users, exclude_network_id=None):
    """Get dynamically sized subnet for a network based on expected users
    
    Args:
        network_type (str): Type of network
        expected_users (int): Expected number of users
        exclude_network_id (int): Network ID to exclude from conflict checking
        
    Returns:
        str: Subnet string (e.g., '10.100.1.0/24')
    """
    pools = generate_subnet_pools()
    
    if network_type not in pools:
        return None
    
    # For Secure Internet with peer communication enabled, use dynamic sizing
    if network_type == 'secure_internet' and expected_users > 1:
        pool = pools[network_type]
        base_network = ipaddress.ip_network(pool['base_network'])
        subnet_size = calculate_dynamic_subnet_size(expected_users)
        
        from models import VPNNetwork
        
        query = VPNNetwork.query.filter(VPNNetwork.network_type == network_type)
        
        if exclude_network_id:
            query = query.filter(VPNNetwork.id != exclude_network_id)
        
        used_subnets = {subnet.subnet for subnet in query.all()}
        
        # Generate subnets of the calculated size
        for subnet in base_network.subnets(new_prefix=subnet_size):
            if str(subnet) not in used_subnets:
                return str(subnet)
        
        return None
    
    # For other network types, use the default allocation
    return get_next_available_subnet(network_type, exclude_network_id)


def validate_expected_users(expected_users):
    """Validate expected users count
    
    Args:
        expected_users (int): Expected number of users
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        count = int(expected_users)
        return 1 <= count <= 1000  # Reasonable range
    except (ValueError, TypeError):
        return False


def get_subnet_info(subnet_str):
    """Get information about a subnet
    
    Args:
        subnet_str (str): Subnet string (e.g., '10.100.1.0/24')
        
    Returns:
        dict: Information about the subnet
    """
    try:
        network = ipaddress.ip_network(subnet_str, strict=False)
        return {
            'network_address': str(network.network_address),
            'broadcast_address': str(network.broadcast_address),
            'gateway_ip': str(network.network_address + 1),
            'prefix_length': network.prefixlen,
            'total_addresses': network.num_addresses,
            'usable_addresses': network.num_addresses - 2,
            'first_usable': str(network.network_address + 1),
            'last_usable': str(network.broadcast_address - 1)
        }
    except ValueError:
        return None


def generate_vrf_name(network_name):
    """Generate VRF namespace name for a network
    
    Args:
        network_name (str): Network name
        
    Returns:
        str: VRF namespace name
    """
    # Replace non-alphanumeric characters with hyphens
    import re
    clean_name = re.sub(r'[^a-zA-Z0-9]', '-', network_name.lower())
    return f"vrf-{clean_name}"


def generate_routing_table_id(network_id):
    """Generate routing table ID for a network
    
    Args:
        network_id (int): Network ID
        
    Returns:
        int: Routing table ID
    """
    # Start from 1000 to avoid conflicts with system tables
    return 1000 + network_id


def generate_hub_and_spoke_config(endpoint):
    """Generate WireGuard config for hub-and-spoke topology
    
    In hub-and-spoke mode:
    - Endpoints can only communicate with the gateway
    - No peer-to-peer communication
    - Gateway acts as the central hub
    """
    network = endpoint.vpn_network
    
    if network.network_type == 'secure_internet':
        # For secure internet, route all traffic through gateway
        return "0.0.0.0/0, ::/0"
    elif network.network_type == 'remote_resource_gw':
        # For remote resource gateway, only route specific subnets
        return network.get_network_type_config().get('allowed_ips', '10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16')
    else:
        # For other types, use default behavior
        return network.get_allowed_ips()


def generate_mesh_config(endpoint):
    """Generate WireGuard config for mesh topology
    
    In mesh mode:
    - Endpoints can communicate with each other
    - Full peer-to-peer communication
    - Gateway also participates in the mesh
    """
    network = endpoint.vpn_network
    
    if network.network_type == 'secure_internet':
        # For secure internet mesh, allow full internet + peer communication
        return "0.0.0.0/0, ::/0"
    else:
        # For other mesh types, use full routing
        return "0.0.0.0/0"


def validate_network_topology(network):
    """Validate that network topology configuration is consistent
    
    Args:
        network: VPNNetwork instance
        
    Returns:
        list: List of validation errors
    """
    errors = []
    
    # Check peer communication setting consistency
    if network.peer_communication_enabled and network.network_type != 'secure_internet':
        errors.append("Peer communication can only be enabled for Secure Internet networks")
    
    # Check expected users vs subnet size
    subnet_info = get_subnet_info(network.subnet)
    if subnet_info and network.expected_users > subnet_info['usable_addresses']:
        errors.append(f"Expected users ({network.expected_users}) exceeds subnet capacity ({subnet_info['usable_addresses']})")
    
    # Check VLAN configuration for L2 networks
    if network.requires_vlan_support() and not network.vlan_id:
        errors.append(f"VLAN ID is required for {network.network_type} networks")
    
    return errors