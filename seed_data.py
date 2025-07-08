from models import NetworkType, Gateway, WGInterface
from database import db
from utils import generate_keypair


def init_seed_data():
    """Initialize seed data for NetworkTypes and sample Gateway"""
    
    # Check if data already exists
    if NetworkType.query.first():
        return
    
    # Create NetworkTypes
    network_types = [
        {
            'name': 'Secure Internet',
            'description': 'Full tunnel VPN for secure internet access',
            'routing_mode': 'full_tunnel',
            'allowed_ips_template': '0.0.0.0/0',
            'overlay_mode': None,
            'bgp_enabled': False,
            'ospf_enabled': False
        },
        {
            'name': 'Remote Resource Gateway',
            'description': 'Split tunnel for accessing specific remote resources',
            'routing_mode': 'split_tunnel',
            'allowed_ips_template': '10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16',
            'overlay_mode': None,
            'bgp_enabled': False,
            'ospf_enabled': False
        },
        {
            'name': 'L3VPN Gateway',
            'description': 'Peer-to-peer VPN with BGP/OSPF routing support',
            'routing_mode': 'peer_to_peer',
            'allowed_ips_template': '10.0.0.0/8',
            'overlay_mode': None,
            'bgp_enabled': True,
            'ospf_enabled': True
        },
        {
            'name': 'L2 Point to Point',
            'description': 'Direct Layer 2 bridging using GRE/VXLAN',
            'routing_mode': 'l2_bridge',
            'allowed_ips_template': '0.0.0.0/0',
            'overlay_mode': 'gretap',
            'bgp_enabled': False,
            'ospf_enabled': False
        },
        {
            'name': 'L2 Mesh',
            'description': 'Shared Layer 2 broadcast domain for multiple peers',
            'routing_mode': 'l2_bridge',
            'allowed_ips_template': '0.0.0.0/0',
            'overlay_mode': 'vxlan',
            'bgp_enabled': False,
            'ospf_enabled': False
        }
    ]
    
    for nt_data in network_types:
        network_type = NetworkType(**nt_data)
        db.session.add(network_type)
    
    # Create sample Gateway
    gateway = Gateway(
        name='Main Gateway',
        public_ip='203.0.113.1',
        location='New York, US',
        description='Primary WireGuard gateway server'
    )
    db.session.add(gateway)
    
    # Commit to get the gateway ID
    db.session.commit()
    
    # Create sample WGInterface
    private_key, public_key = generate_keypair()
    wg_interface = WGInterface(
        gateway_id=gateway.id,
        name='wg0',
        port=51820,
        subnet='10.0.0.0/24',
        private_key=private_key,
        public_key=public_key
    )
    db.session.add(wg_interface)
    
    db.session.commit()
    print("Seed data initialized successfully!")