from datetime import datetime
import ipaddress
import subprocess
import json
from database import db


# Fixed Network Types - not stored in database
# Updated network type descriptions for business focus
NETWORK_TYPES = {
    'secure_internet': {
        'name': 'Secure Internet',
        'description': 'Route all client traffic (including public internet) through the VPN gateway',
        'routing_style': 'full_tunnel',
        'allowed_ips': '0.0.0.0/0, ::/0',
        'peer_to_peer': False,
        'overlay_required': False,
        'overlay_mode': None,
        'max_peers': None,
        'use_case': 'Remote workers, privacy-focused users, hotspot replacement'
    },
    'remote_resource_gw': {
        'name': 'Remote Resource Gateway',
        'description': 'Secure access to corporate resources and internal services via split tunnel',
        'routing_style': 'split_tunnel',
        'allowed_ips': '10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16',
        'peer_to_peer': False,
        'overlay_required': False,
        'overlay_mode': None,
        'max_peers': None,
        'use_case': 'Corporate remote access, internal file servers, web dashboards, databases'
    },
    'l3vpn_gateway': {
        'name': 'L3VPN Gateway',
        'description': 'Layer 3 mesh between clients and gateway with peer-to-peer communication',
        'routing_style': 'routed_mesh',
        'allowed_ips': '0.0.0.0/0',
        'peer_to_peer': True,
        'overlay_required': False,
        'overlay_mode': None,
        'max_peers': None,
        'use_case': 'Site-to-site VPN, cross-datacenter connectivity, lab environments'
    },
    'l2_point_to_point': {
        'name': 'L2 Point to Point',
        'description': 'Virtual Layer 2 link between exactly two clients',
        'routing_style': 'transparent_l2',
        'allowed_ips': '0.0.0.0/0',
        'peer_to_peer': True,
        'overlay_required': True,
        'overlay_mode': 'gretap',
        'max_peers': 2,
        'use_case': 'Legacy bridging, passthrough of VLANs, transparent client links'
    },
    'l2_mesh': {
        'name': 'L2 Mesh',
        'description': 'Full Layer 2 broadcast domain among many peers',
        'routing_style': 'shared_l2_lan',
        'allowed_ips': '0.0.0.0/0',
        'peer_to_peer': True,
        'overlay_required': True,
        'overlay_mode': 'vxlan',
        'max_peers': None,
        'use_case': 'VPLS emulation, broadcast-heavy services, Layer 2 segmentation'
    }
}


class ServerConfig(db.Model):
    """Single server configuration for this VPN appliance"""
    __tablename__ = 'server_config'
    
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), nullable=False)
    public_ip = db.Column(db.String(45), nullable=False)
    location = db.Column(db.String(100))
    admin_email = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<ServerConfig {self.hostname}>'


class VPNNetwork(db.Model):
    __tablename__ = 'vpn_networks'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    port = db.Column(db.Integer, nullable=False, unique=True)
    subnet = db.Column(db.String(18), nullable=False)
    network_type = db.Column(db.String(50), nullable=False)  # Key from NETWORK_TYPES
    private_key = db.Column(db.Text, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    is_active = db.Column(db.Boolean, default=False)
    custom_allowed_ips = db.Column(db.Text)  # Override default for split tunnels
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # New VLAN-related fields
    vlan_id = db.Column(db.Integer)  # For L2 networks (1-4094)
    vlan_range = db.Column(db.String(50))  # For VLAN ranges like "100-110"
    bridge_name = db.Column(db.String(50))  # Custom bridge name
    vni_pool = db.Column(db.String(100))  # VNI pool for VXLAN
    
    endpoints = db.relationship('Endpoint', backref='vpn_network', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<VPNNetwork {self.name}>'
    
    def get_network_type_config(self):
        """Get the network type configuration"""
        return NETWORK_TYPES.get(self.network_type, {})
    
    def get_allowed_ips(self):
        """Get allowed IPs for this interface (custom or default)"""
        if self.custom_allowed_ips:
            return self.custom_allowed_ips
        return self.get_network_type_config().get('allowed_ips', '0.0.0.0/0')
    
    def get_next_ip(self):
        """Get next available IP in subnet"""
        network = ipaddress.ip_network(self.subnet, strict=False)
        used_ips = {endpoint.ip_address for endpoint in self.endpoints}
        used_ips.add(str(network.network_address + 1))  # Reserve gateway IP
        
        for ip in network.hosts():
            if str(ip) not in used_ips:
                return str(ip)
        
        raise ValueError("No available IPs in subnet")
    
    def can_add_endpoint(self):
        """Check if we can add another endpoint based on network type limits"""
        network_config = self.get_network_type_config()
        max_endpoints = network_config.get('max_peers')  # Keep using max_peers for now
        
        if max_endpoints is None:
            return True
        
        return len(self.endpoints) < max_endpoints
    
    def create_network(self):
        """Create the actual WireGuard network interface on the system"""
        try:
            # Create WireGuard interface
            subprocess.run(['ip', 'link', 'add', 'dev', self.name, 'type', 'wireguard'], check=True)
            
            # Set private key
            subprocess.run(['wg', 'set', self.name, 'private-key', '/dev/stdin'], 
                          input=self.private_key.encode(), check=True)
            
            # Set IP address (gateway gets first usable IP)
            network = ipaddress.ip_network(self.subnet, strict=False)
            gateway_ip = str(network.network_address + 1)
            subprocess.run(['ip', 'addr', 'add', f'{gateway_ip}/{network.prefixlen}', 'dev', self.name], check=True)
            
            # Set listening port
            subprocess.run(['wg', 'set', self.name, 'listen-port', str(self.port)], check=True)
            
            # Bring interface up
            subprocess.run(['ip', 'link', 'set', 'up', 'dev', self.name], check=True)
            
            # Configure routing based on network type
            self._configure_routing()
            
            # Configure overlay if needed
            self._configure_overlay()
            
            self.is_active = True
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"Error creating network {self.name}: {e}")
            return False
    
    def destroy_network(self):
        """Destroy the WireGuard network interface"""
        try:
            subprocess.run(['ip', 'link', 'delete', 'dev', self.name], check=True)
            self.is_active = False
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error destroying network {self.name}: {e}")
            return False
    
    def _configure_routing(self):
        """Configure routing based on network type"""
        network_config = self.get_network_type_config()
        routing_style = network_config.get('routing_style')
        
        if routing_style == 'full_tunnel':
            # Enable IP forwarding and NAT for full tunnel
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], check=True)
            subprocess.run(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', self.subnet, '-o', 'eth0', '-j', 'MASQUERADE'], check=True)
            subprocess.run(['iptables', '-A', 'FORWARD', '-i', self.name, '-j', 'ACCEPT'], check=True)
            subprocess.run(['iptables', '-A', 'FORWARD', '-o', self.name, '-j', 'ACCEPT'], check=True)
            
        elif routing_style == 'split_tunnel':
            # Only forward traffic for specific subnets
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], check=True)
            # Allow forwarding for this interface
            subprocess.run(['iptables', '-A', 'FORWARD', '-i', self.name, '-j', 'ACCEPT'], check=True)
            subprocess.run(['iptables', '-A', 'FORWARD', '-o', self.name, '-j', 'ACCEPT'], check=True)
            
        elif routing_style in ['routed_mesh', 'transparent_l2', 'shared_l2_lan']:
            # Enable forwarding for mesh topologies
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], check=True)
            subprocess.run(['iptables', '-A', 'FORWARD', '-i', self.name, '-j', 'ACCEPT'], check=True)
            subprocess.run(['iptables', '-A', 'FORWARD', '-o', self.name, '-j', 'ACCEPT'], check=True)
    
    def _configure_overlay(self):
        """Configure Layer 2 overlay if required"""
        network_config = self.get_network_type_config()
        
        if not network_config.get('overlay_required'):
            return
        
        overlay_mode = network_config.get('overlay_mode')
        
        if overlay_mode == 'gretap':
            # Create GRE TAP interface for L2 point-to-point with VLAN support
            gre_name = f"{self.name}-gre"
            bridge_name = self.get_bridge_name()
            
            try:
                subprocess.run(['ip', 'link', 'add', gre_name, 'type', 'gretap', 'local', self._get_gateway_ip()], check=True)
                subprocess.run(['ip', 'link', 'set', 'up', 'dev', gre_name], check=True)
                
                # Create VLAN-aware bridge
                subprocess.run(['ip', 'link', 'add', bridge_name, 'type', 'bridge'], check=True)
                subprocess.run(['ip', 'link', 'set', 'up', 'dev', bridge_name], check=True)
                
                # Enable VLAN filtering if VLAN ID is specified
                if self.vlan_id:
                    subprocess.run(['ip', 'link', 'set', 'dev', bridge_name, 'type', 'bridge', 'vlan_filtering', '1'], check=True)
                
                subprocess.run(['ip', 'link', 'set', gre_name, 'master', bridge_name], check=True)
                
                # Configure VLAN if specified
                if self.vlan_id:
                    subprocess.run(['bridge', 'vlan', 'add', 'dev', gre_name, 'vid', str(self.vlan_id)], check=True)
                    
            except subprocess.CalledProcessError as e:
                print(f"Error setting up GRE TAP overlay: {e}")
                
        elif overlay_mode == 'vxlan':
            # Create VXLAN interface for L2 mesh with VLAN support
            vxlan_name = f"{self.name}-vxlan"
            vni = self.get_vni()  # VLAN-aware VNI assignment
            bridge_name = self.get_bridge_name()
            
            try:
                subprocess.run(['ip', 'link', 'add', vxlan_name, 'type', 'vxlan', 'id', str(vni), 
                               'local', self._get_gateway_ip(), 'dstport', '4789'], check=True)
                subprocess.run(['ip', 'link', 'set', 'up', 'dev', vxlan_name], check=True)
                
                # Create VLAN-aware bridge
                subprocess.run(['ip', 'link', 'add', bridge_name, 'type', 'bridge'], check=True)
                subprocess.run(['ip', 'link', 'set', 'up', 'dev', bridge_name], check=True)
                
                # Enable VLAN filtering if VLAN ID is specified
                if self.vlan_id:
                    subprocess.run(['ip', 'link', 'set', 'dev', bridge_name, 'type', 'bridge', 'vlan_filtering', '1'], check=True)
                
                subprocess.run(['ip', 'link', 'set', vxlan_name, 'master', bridge_name], check=True)
                
                # Configure VLAN if specified
                if self.vlan_id:
                    subprocess.run(['bridge', 'vlan', 'add', 'dev', vxlan_name, 'vid', str(self.vlan_id)], check=True)
                    
            except subprocess.CalledProcessError as e:
                print(f"Error setting up VXLAN overlay: {e}")
    
    def _get_gateway_ip(self):
        """Get the gateway IP (first usable IP in subnet)"""
        network = ipaddress.ip_network(self.subnet, strict=False)
        return str(network.network_address + 1)
    
    def validate_vlan_id(self):
        """Validate VLAN ID for this network"""
        if self.vlan_id is None:
            return True
        
        # Check VLAN ID range
        if not (1 <= self.vlan_id <= 4094):
            return False
        
        # Check for conflicts with other networks
        existing = VPNNetwork.query.filter(
            VPNNetwork.vlan_id == self.vlan_id,
            VPNNetwork.id != self.id
        ).first()
        
        return existing is None
    
    def get_vni(self):
        """Get VXLAN VNI for this network (VLAN-aware)"""
        if self.vlan_id:
            # Use VLAN ID as part of VNI calculation
            return 1000 + (self.vlan_id * 100) + self.id
        else:
            # Fallback to original method
            return 1000 + self.id
    
    def get_bridge_name(self):
        """Get bridge name for this network"""
        if self.bridge_name:
            return self.bridge_name
        elif self.vlan_id:
            return f"br-{self.name}-vlan{self.vlan_id}"
        else:
            return f"br-{self.name}"
    
    def requires_vlan_support(self):
        """Check if this network type requires VLAN support"""
        return self.network_type in ['l2_mesh', 'l2_point_to_point']


class Endpoint(db.Model):
    __tablename__ = 'endpoints'
    
    id = db.Column(db.Integer, primary_key=True)
    vpn_network_id = db.Column(db.Integer, db.ForeignKey('vpn_networks.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    private_key = db.Column(db.Text, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    preshared_key = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=False)
    last_handshake = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # New endpoint type field
    endpoint_type = db.Column(db.String(20), default='mobile')  # mobile, cpe, gateway
    
    configs = db.relationship('EndpointConfig', backref='endpoint', lazy=True, cascade='all, delete-orphan')
    
    __table_args__ = (db.UniqueConstraint('vpn_network_id', 'name'),)
    
    def __repr__(self):
        return f'<Endpoint {self.name}>'
    
    def add_to_network(self):
        """Add this endpoint to the VPN network"""
        try:
            network = self.vpn_network
            cmd = ['wg', 'set', network.name, 'peer', self.public_key, 
                   'allowed-ips', self.ip_address + '/32']
            
            if self.preshared_key:
                # Write preshared key to temp file for wg command
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                    f.write(self.preshared_key)
                    psk_file = f.name
                
                cmd.extend(['preshared-key', psk_file])
                
            subprocess.run(cmd, check=True)
            
            # Clean up temp file if used
            if self.preshared_key:
                import os
                os.unlink(psk_file)
            
            # Handle Layer 2 overlay endpoint configuration
            self._configure_overlay_endpoint()
            
            self.is_active = True
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"Error adding endpoint {self.name} to network: {e}")
            return False
    
    def remove_from_network(self):
        """Remove this endpoint from the VPN network"""
        try:
            network = self.vpn_network
            subprocess.run(['wg', 'set', network.name, 'peer', self.public_key, 'remove'], check=True)
            self.is_active = False
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error removing endpoint {self.name} from network: {e}")
            return False
    
    def _configure_overlay_endpoint(self):
        """Configure Layer 2 overlay for this endpoint if needed"""
        network = self.vpn_network
        network_config = network.get_network_type_config()
        
        if not network_config.get('overlay_required'):
            return
        
        overlay_mode = network_config.get('overlay_mode')
        
        if overlay_mode in ['gretap', 'vxlan']:
            # For L2 overlays, we need to configure the bridge to handle this endpoint
            bridge_name = network.get_bridge_name()
            
            try:
                # The bridge was already created when the network was set up
                # Additional endpoint-specific configuration can be added here
                
                # If this is a VLAN-aware network, ensure endpoint can access the VLAN
                if network.vlan_id:
                    # Bridge VLAN configuration is handled at the network level
                    pass
                    
            except subprocess.CalledProcessError as e:
                print(f"Error configuring overlay for endpoint {self.name}: {e}")
    
    def get_config(self):
        """Generate WireGuard config for this endpoint"""
        from utils import generate_endpoint_config
        return generate_endpoint_config(self)


class EndpointConfig(db.Model):
    __tablename__ = 'endpoint_configs'
    
    id = db.Column(db.Integer, primary_key=True)
    endpoint_id = db.Column(db.Integer, db.ForeignKey('endpoints.id'), nullable=False)
    config_content = db.Column(db.Text, nullable=False)
    version = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<EndpointConfig {self.endpoint.name} v{self.version}>'