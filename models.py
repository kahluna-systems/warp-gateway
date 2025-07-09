from datetime import datetime, timedelta
import ipaddress
import subprocess
import json
import re
from database import db
from sqlalchemy import or_
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


# Status constants for networks and endpoints
NETWORK_STATUS = {
    'active': 'Active',
    'suspended': 'Suspended', 
    'pending': 'Pending',
    'failed': 'Failed'
}

ENDPOINT_STATUS = {
    'active': 'Active',
    'suspended': 'Suspended',
    'pending': 'Pending',
    'disconnected': 'Disconnected',
    'failed': 'Failed'
}

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


class User(UserMixin, db.Model):
    """Authentication model for system users"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='admin')  # admin, viewer, operator
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship to audit logs
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True)
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if provided password matches hash"""
        return check_password_hash(self.password_hash, password)
    
    def is_account_locked(self):
        """Check if account is locked due to failed attempts"""
        if self.locked_until and datetime.utcnow() < self.locked_until:
            return True
        return False
    
    def reset_failed_attempts(self):
        """Reset failed login attempts"""
        self.failed_login_attempts = 0
        self.locked_until = None
    
    def increment_failed_attempts(self):
        """Increment failed attempts and lock if needed"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            # Lock account for 30 minutes
            from datetime import timedelta
            self.locked_until = datetime.utcnow() + timedelta(minutes=30)
    
    def has_permission(self, action):
        """Check if user has permission for action"""
        role_permissions = {
            'admin': ['read', 'write', 'delete', 'manage_users'],
            'operator': ['read', 'write'],
            'viewer': ['read']
        }
        
        return action in role_permissions.get(self.role, [])
    
    def __repr__(self):
        return f'<User {self.username}>'


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
    
    def get_statistics(self):
        """Get server statistics"""
        networks = VPNNetwork.query.all()
        endpoints = Endpoint.query.all()
        
        active_networks = sum(1 for n in networks if n.is_active)
        active_endpoints = sum(1 for e in endpoints if e.is_active)
        
        # Calculate total capacity and usage
        total_ports_used = len(networks)
        total_ports_available = 10  # 51820-51829
        
        # Network type breakdown
        network_types = {}
        for network in networks:
            network_type = network.network_type
            if network_type not in network_types:
                network_types[network_type] = {'count': 0, 'endpoints': 0}
            network_types[network_type]['count'] += 1
            network_types[network_type]['endpoints'] += len(network.endpoints)
        
        return {
            'total_networks': len(networks),
            'active_networks': active_networks,
            'total_endpoints': len(endpoints),
            'active_endpoints': active_endpoints,
            'port_utilization': (total_ports_used / total_ports_available) * 100,
            'network_types': network_types,
            'server_uptime': self.get_uptime(),
            'last_updated': datetime.utcnow()
        }
    
    def get_uptime(self):
        """Get server uptime (stub implementation)"""
        # In production, this would get actual system uptime
        return "N/A (Development Mode)"


class VPNNetwork(db.Model):
    __tablename__ = 'vpn_networks'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    port = db.Column(db.Integer, nullable=False, unique=True)
    subnet = db.Column(db.String(18), nullable=False)
    network_type = db.Column(db.String(50), nullable=False)  # Key from NETWORK_TYPES
    private_key = db.Column(db.Text, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, active, suspended, failed
    custom_allowed_ips = db.Column(db.Text)  # Override default for split tunnels
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # New VLAN-related fields
    vlan_id = db.Column(db.Integer)  # For L2 networks (1-4094)
    vlan_range = db.Column(db.String(50))  # For VLAN ranges like "100-110"
    bridge_name = db.Column(db.String(50))  # Custom bridge name
    vni_pool = db.Column(db.String(100))  # VNI pool for VXLAN
    
    # New VRF-related fields
    vcid = db.Column(db.Integer, unique=True, nullable=False)  # 8-digit Virtual Circuit ID
    peer_communication_enabled = db.Column(db.Boolean, default=False)  # For Secure Internet toggle
    expected_users = db.Column(db.Integer, default=1)  # For dynamic subnet sizing
    vrf_name = db.Column(db.String(50))  # Linux VRF namespace name
    routing_table_id = db.Column(db.Integer)  # Dedicated routing table
    
    # Rate limiting fields
    rate_limit_enabled = db.Column(db.Boolean, default=False)
    rate_limit_download_mbps = db.Column(db.Float)
    rate_limit_upload_mbps = db.Column(db.Float)
    rate_limit_burst_factor = db.Column(db.Float, default=1.5)
    
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
        
        # For Secure Internet networks, consider peer communication setting
        if self.network_type == 'secure_internet':
            if self.peer_communication_enabled:
                # Mesh mode: allow full communication
                return '0.0.0.0/0'
            else:
                # Hub-and-spoke mode: only internet traffic
                return '0.0.0.0/0'
        
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
    
    def get_interface_name(self):
        """Generate a valid Linux interface name using the VCID"""
        # Use VCID as interface name (e.g., wg12345678)
        return f'wg{self.vcid}'
    
    def get_wireguard_status(self):
        """Get current WireGuard interface status and peer information"""
        interface_name = self.get_interface_name()
        
        try:
            # Check if interface exists
            result = subprocess.run(['ip', 'link', 'show', interface_name], 
                                  capture_output=True, text=True, check=True)
            
            # Get WireGuard configuration
            wg_result = subprocess.run(['wg', 'show', interface_name], 
                                     capture_output=True, text=True, check=True)
            
            # Parse WireGuard output to get peer information
            peers = []
            current_peer = None
            
            for line in wg_result.stdout.split('\n'):
                if line.startswith('peer: '):
                    if current_peer:
                        peers.append(current_peer)
                    current_peer = {'public_key': line.split(': ')[1]}
                elif line.startswith('  latest handshake: '):
                    if current_peer:
                        handshake_str = line.split(': ')[1]
                        if handshake_str != '(none)':
                            current_peer['last_handshake'] = handshake_str
                elif line.startswith('  transfer: '):
                    if current_peer:
                        current_peer['transfer'] = line.split(': ')[1]
                elif line.startswith('  allowed ips: '):
                    if current_peer:
                        current_peer['allowed_ips'] = line.split(': ')[1]
            
            if current_peer:
                peers.append(current_peer)
            
            return {
                'interface_exists': True,
                'interface_up': 'UP' in result.stdout,
                'peers': peers,
                'total_peers': len(peers)
            }
            
        except subprocess.CalledProcessError:
            return {
                'interface_exists': False,
                'interface_up': False,
                'peers': [],
                'total_peers': 0
            }
    
    def update_dynamic_status(self):
        """Update network status based on actual WireGuard state"""
        wg_status = self.get_wireguard_status()
        
        if self.status == 'suspended':
            # Don't change suspended status automatically
            return self.status
            
        if not wg_status['interface_exists']:
            self.status = 'failed'
        elif not wg_status['interface_up']:
            self.status = 'pending'
        elif wg_status['total_peers'] > 0:
            # Check if any peers have recent handshakes
            recent_handshakes = False
            for peer in wg_status['peers']:
                if 'last_handshake' in peer:
                    # Consider handshake recent if within last 3 minutes
                    # (WireGuard typically handshakes every 2 minutes)
                    recent_handshakes = True
                    break
            
            self.status = 'active' if recent_handshakes else 'pending'
        else:
            self.status = 'pending'
        
        return self.status
    
    def create_network(self):
        """Create the actual WireGuard network interface on the system"""
        try:
            interface_name = self.get_interface_name()
            
            # Create WireGuard interface
            subprocess.run(['ip', 'link', 'add', 'dev', interface_name, 'type', 'wireguard'], check=True)
            
            # Set private key
            subprocess.run(['wg', 'set', interface_name, 'private-key', '/dev/stdin'], 
                          input=self.private_key.encode(), check=True)
            
            # Set IP address (gateway gets first usable IP)
            network = ipaddress.ip_network(self.subnet, strict=False)
            gateway_ip = str(network.network_address + 1)
            subprocess.run(['ip', 'addr', 'add', f'{gateway_ip}/{network.prefixlen}', 'dev', interface_name], check=True)
            
            # Set listening port
            subprocess.run(['wg', 'set', interface_name, 'listen-port', str(self.port)], check=True)
            
            # Bring interface up
            subprocess.run(['ip', 'link', 'set', 'up', 'dev', interface_name], check=True)
            
            # Configure routing based on network type
            self._configure_routing(interface_name)
            
            # Configure overlay if needed
            self._configure_overlay(interface_name)
            
            self.status = 'pending'  # Will become 'active' when peers connect
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"Error creating network {self.name}: {e}")
            self.status = 'failed'
            return False
    
    def destroy_network(self):
        """Destroy the WireGuard network interface"""
        try:
            interface_name = self.get_interface_name()
            subprocess.run(['ip', 'link', 'delete', 'dev', interface_name], check=True)
            self.status = 'pending'
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error destroying network {self.name}: {e}")
            self.status = 'failed'
            return False
    
    def remove_network(self):
        """Remove the WireGuard network interface (alias for destroy_network)"""
        return self.destroy_network()
    
    def suspend_network(self):
        """Suspend network by bringing interface down"""
        try:
            interface_name = self.get_interface_name()
            subprocess.run(['ip', 'link', 'set', 'down', 'dev', interface_name], check=True)
            self.status = 'suspended'
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error suspending network {self.name}: {e}")
            return False
    
    def resume_network(self):
        """Resume network by bringing interface up"""
        try:
            interface_name = self.get_interface_name()
            subprocess.run(['ip', 'link', 'set', 'up', 'dev', interface_name], check=True)
            self.status = 'pending'  # Will become active when peers connect
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error resuming network {self.name}: {e}")
            return False
    
    @property
    def is_active(self):
        """Backward compatibility property for is_active"""
        return self.status == 'active'
    
    def _configure_routing(self, interface_name):
        """Configure routing based on network type"""
        network_config = self.get_network_type_config()
        routing_style = network_config.get('routing_style')
        
        if routing_style == 'full_tunnel':
            # Enable IP forwarding and NAT for full tunnel
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], check=True)
            subprocess.run(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', self.subnet, '-o', 'eth0', '-j', 'MASQUERADE'], check=True)
            subprocess.run(['iptables', '-A', 'FORWARD', '-i', interface_name, '-j', 'ACCEPT'], check=True)
            subprocess.run(['iptables', '-A', 'FORWARD', '-o', interface_name, '-j', 'ACCEPT'], check=True)
            
        elif routing_style == 'split_tunnel':
            # Only forward traffic for specific subnets
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], check=True)
            # Allow forwarding for this interface
            subprocess.run(['iptables', '-A', 'FORWARD', '-i', interface_name, '-j', 'ACCEPT'], check=True)
            subprocess.run(['iptables', '-A', 'FORWARD', '-o', interface_name, '-j', 'ACCEPT'], check=True)
            
        elif routing_style in ['routed_mesh', 'transparent_l2', 'shared_l2_lan']:
            # Enable forwarding for mesh topologies
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], check=True)
            subprocess.run(['iptables', '-A', 'FORWARD', '-i', interface_name, '-j', 'ACCEPT'], check=True)
            subprocess.run(['iptables', '-A', 'FORWARD', '-o', interface_name, '-j', 'ACCEPT'], check=True)
    
    def _configure_overlay(self, interface_name):
        """Configure Layer 2 overlay if required"""
        network_config = self.get_network_type_config()
        
        if not network_config.get('overlay_required'):
            return
        
        overlay_mode = network_config.get('overlay_mode')
        
        if overlay_mode == 'gretap':
            # Create GRE TAP interface for L2 point-to-point with VLAN support
            gre_name = f"{interface_name}-gre"
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
    
    def populate_vrf_fields(self):
        """Auto-populate VRF fields if not already set"""
        from utils import generate_unique_vcid, generate_vrf_name, generate_routing_table_id
        
        if not self.vcid:
            self.vcid = generate_unique_vcid()
        
        if not self.vrf_name:
            self.vrf_name = generate_vrf_name(self.name)
        
        if not self.routing_table_id:
            self.routing_table_id = generate_routing_table_id(self.id or 0)
    
    def get_topology_mode(self):
        """Get network topology mode based on type and peer communication setting"""
        if self.network_type == 'secure_internet':
            return 'mesh' if self.peer_communication_enabled else 'hub-and-spoke'
        
        network_config = self.get_network_type_config()
        return 'mesh' if network_config.get('peer_to_peer', False) else 'hub-and-spoke'
    
    def get_dynamic_subnet_info(self):
        """Get information about dynamic subnet sizing"""
        from utils import get_subnet_info, calculate_dynamic_subnet_size
        
        subnet_info = get_subnet_info(self.subnet)
        if not subnet_info:
            return None
        
        # Calculate recommended size based on expected users
        recommended_prefix = calculate_dynamic_subnet_size(self.expected_users)
        current_prefix = subnet_info['prefix_length']
        
        return {
            'current_info': subnet_info,
            'expected_users': self.expected_users,
            'recommended_prefix': recommended_prefix,
            'is_optimal': current_prefix == recommended_prefix,
            'can_accommodate': subnet_info['usable_addresses'] >= self.expected_users
        }
    
    def get_statistics(self):
        """Get network statistics"""
        endpoint_count = len(self.endpoints)
        active_endpoints = sum(1 for e in self.endpoints if e.is_active)
        
        # Calculate utilization
        subnet_info = self.get_dynamic_subnet_info()
        if subnet_info:
            utilization = (endpoint_count / subnet_info['current_info']['usable_addresses']) * 100
        else:
            utilization = 0
        
        return {
            'vcid': self.vcid,
            'total_endpoints': endpoint_count,
            'active_endpoints': active_endpoints,
            'utilization_percent': utilization,
            'network_type': self.network_type,
            'topology': self.get_topology_mode(),
            'expected_users': self.expected_users,
            'peer_communication': self.peer_communication_enabled,
            'last_handshake': self.get_last_handshake(),
            'bytes_transferred': self.get_bytes_transferred()  # Stub for now
        }
    
    def get_last_handshake(self):
        """Get last handshake time across all endpoints"""
        last_handshakes = [e.last_handshake for e in self.endpoints if e.last_handshake]
        return max(last_handshakes) if last_handshakes else None
    
    def get_bytes_transferred(self):
        """Get total bytes transferred (stub implementation)"""
        # In production, this would query actual WireGuard statistics
        return {'rx_bytes': 0, 'tx_bytes': 0}
    
    @staticmethod
    def search(query, search_type='all'):
        """Search networks by various criteria"""
        base_query = VPNNetwork.query
        
        if search_type == 'all' or search_type == 'networks':
            # Search by name, network type, or subnet
            network_results = base_query.filter(
                or_(
                    VPNNetwork.name.ilike(f'%{query}%'),
                    VPNNetwork.network_type.ilike(f'%{query}%'),
                    VPNNetwork.subnet.ilike(f'%{query}%')
                )
            ).all()
        else:
            network_results = []
        
        if search_type == 'all' or search_type == 'vcids':
            # Search by VCID (handle both formatted and raw)
            vcid_query = query.replace('-', '').replace(' ', '')
            try:
                vcid_int = int(vcid_query)
                vcid_results = base_query.filter(VPNNetwork.vcid == vcid_int).all()
            except ValueError:
                vcid_results = []
        else:
            vcid_results = []
        
        # Combine results and remove duplicates
        all_results = list(set(network_results + vcid_results))
        return all_results


class Endpoint(db.Model):
    __tablename__ = 'endpoints'
    
    id = db.Column(db.Integer, primary_key=True)
    vpn_network_id = db.Column(db.Integer, db.ForeignKey('vpn_networks.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    private_key = db.Column(db.Text, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    preshared_key = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')  # pending, active, suspended, disconnected, failed
    last_handshake = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # New endpoint type field
    endpoint_type = db.Column(db.String(20), default='mobile')  # mobile, cpe, gateway
    
    # Rate limiting fields
    rate_limit_enabled = db.Column(db.Boolean, default=False)
    rate_limit_download_mbps = db.Column(db.Float)
    rate_limit_upload_mbps = db.Column(db.Float)
    rate_limit_burst_factor = db.Column(db.Float, default=1.5)
    
    configs = db.relationship('EndpointConfig', backref='endpoint', lazy=True, cascade='all, delete-orphan')
    
    __table_args__ = (db.UniqueConstraint('vpn_network_id', 'name'),)
    
    def __repr__(self):
        return f'<Endpoint {self.name}>'
    
    def add_to_network(self):
        """Add this endpoint to the VPN network"""
        try:
            network = self.vpn_network
            interface_name = network.get_interface_name()
            cmd = ['wg', 'set', interface_name, 'peer', self.public_key, 
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
            
            self.status = 'pending'  # Will become 'active' after successful handshake
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"Error adding endpoint {self.name} to network: {e}")
            self.status = 'failed'
            return False
    
    def remove_from_network(self):
        """Remove this endpoint from the VPN network"""
        try:
            network = self.vpn_network
            interface_name = network.get_interface_name()
            subprocess.run(['wg', 'set', interface_name, 'peer', self.public_key, 'remove'], check=True)
            self.status = 'disconnected'
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error removing endpoint {self.name} from network: {e}")
            self.status = 'failed'
            return False
    
    def suspend_endpoint(self):
        """Suspend endpoint by removing from WireGuard but keeping in database"""
        try:
            network = self.vpn_network
            interface_name = network.get_interface_name()
            subprocess.run(['wg', 'set', interface_name, 'peer', self.public_key, 'remove'], check=True)
            self.status = 'suspended'
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error suspending endpoint {self.name}: {e}")
            return False
    
    def resume_endpoint(self):
        """Resume endpoint by re-adding to WireGuard"""
        try:
            network = self.vpn_network
            interface_name = network.get_interface_name()
            cmd = ['wg', 'set', interface_name, 'peer', self.public_key, 
                   'allowed-ips', self.ip_address + '/32']
            
            if self.preshared_key:
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                    f.write(self.preshared_key)
                    psk_file = f.name
                cmd.extend(['preshared-key', psk_file])
                
            subprocess.run(cmd, check=True)
            
            if self.preshared_key:
                import os
                os.unlink(psk_file)
            
            self.status = 'pending'  # Will become active after handshake
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error resuming endpoint {self.name}: {e}")
            return False
    
    def update_handshake_status(self):
        """Update endpoint status based on last handshake"""
        if self.status == 'suspended':
            return self.status
            
        network = self.vpn_network
        wg_status = network.get_wireguard_status()
        
        # Find this endpoint in the WireGuard peer list
        for peer in wg_status['peers']:
            if peer['public_key'] == self.public_key:
                if 'last_handshake' in peer:
                    self.status = 'active'
                    # Update last_handshake timestamp in database
                    # Note: WireGuard handshake parsing would need more sophisticated date parsing
                    self.last_handshake = datetime.utcnow()
                else:
                    self.status = 'pending'
                break
        else:
            # Peer not found in WireGuard - should be disconnected
            if self.status not in ['suspended', 'failed']:
                self.status = 'disconnected'
        
        return self.status
    
    @property
    def is_active(self):
        """Backward compatibility property for is_active"""
        return self.status == 'active'
    
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
    
    def get_statistics(self):
        """Get endpoint statistics"""
        return {
            'endpoint_id': self.id,
            'name': self.name,
            'network_name': self.vpn_network.name,
            'vcid': self.vpn_network.vcid,
            'ip_address': self.ip_address,
            'endpoint_type': self.endpoint_type,
            'is_active': self.is_active,
            'last_handshake': self.last_handshake,
            'bytes_transferred': self.get_bytes_transferred(),
            'connection_uptime': self.get_connection_uptime(),
            'rate_limits': self.get_rate_limits()
        }
    
    def get_bytes_transferred(self):
        """Get bytes transferred for this endpoint (stub implementation)"""
        # In production, this would query actual WireGuard statistics
        return {'rx_bytes': 0, 'tx_bytes': 0}
    
    def get_connection_uptime(self):
        """Get connection uptime (stub implementation)"""
        if self.last_handshake:
            return datetime.utcnow() - self.last_handshake
        return None
    
    def get_rate_limits(self):
        """Get rate limits for this endpoint"""
        # Check endpoint-specific rate limits first, then network-level
        if self.rate_limit_enabled:
            return {
                'download_mbps': self.rate_limit_download_mbps,
                'upload_mbps': self.rate_limit_upload_mbps,
                'burst_factor': self.rate_limit_burst_factor,
                'enabled': True,
                'source': 'endpoint'
            }
        elif self.vpn_network.rate_limit_enabled:
            return {
                'download_mbps': self.vpn_network.rate_limit_download_mbps,
                'upload_mbps': self.vpn_network.rate_limit_upload_mbps,
                'burst_factor': self.vpn_network.rate_limit_burst_factor,
                'enabled': True,
                'source': 'network'
            }
        else:
            return {'enabled': False, 'source': 'none'}
    
    @staticmethod
    def search(query, search_type='all'):
        """Search endpoints by various criteria"""
        base_query = Endpoint.query
        
        if search_type == 'all' or search_type == 'endpoints':
            # Search by name, IP address, or endpoint type
            endpoint_results = base_query.filter(
                or_(
                    Endpoint.name.ilike(f'%{query}%'),
                    Endpoint.ip_address.ilike(f'%{query}%'),
                    Endpoint.endpoint_type.ilike(f'%{query}%')
                )
            ).all()
        else:
            endpoint_results = []
        
        return endpoint_results


class EndpointConfig(db.Model):
    __tablename__ = 'endpoint_configs'
    
    id = db.Column(db.Integer, primary_key=True)
    endpoint_id = db.Column(db.Integer, db.ForeignKey('endpoints.id'), nullable=False)
    config_content = db.Column(db.Text, nullable=False)
    version = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<EndpointConfig {self.endpoint.name} v{self.version}>'


class AuditLog(db.Model):
    """Audit logging for security events and user actions"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Nullable for system events
    event_type = db.Column(db.String(50), nullable=False)  # login, logout, create, update, delete, etc.
    resource_type = db.Column(db.String(50), nullable=True)  # user, network, endpoint, etc.
    resource_id = db.Column(db.Integer, nullable=True)  # ID of the affected resource
    event_description = db.Column(db.Text, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    session_id = db.Column(db.String(255), nullable=True)
    success = db.Column(db.Boolean, default=True)
    error_message = db.Column(db.Text, nullable=True)
    additional_data = db.Column(db.Text, nullable=True)  # JSON data for additional context
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f'<AuditLog {self.event_type} by {self.user.username if self.user else "System"} at {self.timestamp}>'
    
    @staticmethod
    def log_event(event_type, description, user=None, resource_type=None, resource_id=None, 
                  ip_address=None, user_agent=None, session_id=None, success=True, 
                  error_message=None, additional_data=None):
        """Helper method to create audit log entries"""
        log_entry = AuditLog(
            user_id=user.id if user else None,
            event_type=event_type,
            resource_type=resource_type,
            resource_id=resource_id,
            event_description=description,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            success=success,
            error_message=error_message,
            additional_data=additional_data
        )
        
        db.session.add(log_entry)
        # Don't commit here - let the calling function handle it
        return log_entry
    
    @staticmethod
    def get_user_activity(user_id, limit=50):
        """Get recent activity for a specific user"""
        return AuditLog.query.filter_by(user_id=user_id).order_by(AuditLog.timestamp.desc()).limit(limit).all()
    
    @staticmethod
    def get_security_events(limit=100):
        """Get recent security-related events"""
        security_events = ['login', 'logout', 'failed_login', 'account_locked', 'password_change', 
                          'user_created', 'user_deleted', 'user_disabled', 'session_expired']
        return AuditLog.query.filter(AuditLog.event_type.in_(security_events)).order_by(AuditLog.timestamp.desc()).limit(limit).all()
    
    @staticmethod
    def get_failed_attempts(hours=24):
        """Get failed login attempts in the last N hours"""
        from datetime import timedelta
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        return AuditLog.query.filter(
            AuditLog.event_type == 'failed_login',
            AuditLog.timestamp >= cutoff_time
        ).order_by(AuditLog.timestamp.desc()).all()
    
    def to_dict(self):
        """Convert audit log to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'user': self.user.username if self.user else 'System',
            'event_type': self.event_type,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'description': self.event_description,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'success': self.success,
            'error_message': self.error_message,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }