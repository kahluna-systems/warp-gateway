"""
WARP Gateway — Database Models
Refactored models for the network appliance architecture.
"""
from datetime import datetime, timedelta
import ipaddress
from database import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


# ── Network type definitions (not stored in DB) ──────────────────────────────

NETWORK_TYPES = {
    'secure_internet': {
        'name': 'Secure Internet',
        'description': 'Route all client traffic through the VPN gateway (full tunnel)',
        'routing_style': 'full_tunnel',
        'allowed_ips': '0.0.0.0/0, ::/0',
        'peer_to_peer': False,
        'max_peers': None,
        'use_case': 'Remote workers, privacy, hotspot replacement',
    },
    'remote_resource_gw': {
        'name': 'Remote Resource Gateway',
        'description': 'Split-tunnel access to internal resources only',
        'routing_style': 'split_tunnel',
        'allowed_ips': '10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16',
        'peer_to_peer': False,
        'max_peers': None,
        'use_case': 'Corporate remote access, internal services',
    },
    'l3vpn_gateway': {
        'name': 'L3VPN Gateway',
        'description': 'Layer 3 routed mesh with peer-to-peer communication',
        'routing_style': 'routed_mesh',
        'allowed_ips': '0.0.0.0/0',
        'peer_to_peer': True,
        'max_peers': None,
        'use_case': 'Site-to-site VPN, cross-datacenter connectivity',
    },
}


# ── User ─────────────────────────────────────────────────────────────────────

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='admin')
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    audit_logs = db.relationship('AuditLog', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_account_locked(self):
        if self.locked_until and datetime.utcnow() < self.locked_until:
            return True
        return False

    def reset_failed_attempts(self):
        self.failed_login_attempts = 0
        self.locked_until = None

    def increment_failed_attempts(self):
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.locked_until = datetime.utcnow() + timedelta(minutes=30)

    def has_permission(self, action):
        perms = {
            'admin': ['read', 'write', 'delete', 'manage_users'],
            'operator': ['read', 'write'],
            'viewer': ['read'],
        }
        return action in perms.get(self.role, [])

    def __repr__(self):
        return f'<User {self.username}>'


# ── Interface Config ─────────────────────────────────────────────────────────

class InterfaceConfig(db.Model):
    __tablename__ = 'interface_configs'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    role = db.Column(db.String(10), nullable=False)  # WAN, LAN, OPT, DISABLED
    mode = db.Column(db.String(10), default='static')  # static, dhcp
    ip_address = db.Column(db.String(45))
    netmask = db.Column(db.String(15))
    gateway = db.Column(db.String(45))
    dns_servers = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)

    # VLAN / L2 awareness
    switchport_mode = db.Column(db.String(10), default='routed')  # routed, trunk, access
    access_vlan_id = db.Column(db.Integer, nullable=True)
    native_vlan_id = db.Column(db.Integer, default=1)
    allowed_vlans = db.Column(db.Text, nullable=True)  # Comma-separated VLAN IDs or "all"
    zone_id = db.Column(db.Integer, db.ForeignKey('security_zones.id'), nullable=True)
    is_sub_interface = db.Column(db.Boolean, default=False)
    parent_interface = db.Column(db.String(50), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'role': self.role,
            'mode': self.mode,
            'ip_address': self.ip_address,
            'netmask': self.netmask,
            'gateway': self.gateway,
            'dns_servers': self.dns_servers,
            'is_active': self.is_active,
            'switchport_mode': self.switchport_mode,
            'access_vlan_id': self.access_vlan_id,
            'native_vlan_id': self.native_vlan_id,
            'allowed_vlans': self.allowed_vlans,
            'zone_id': self.zone_id,
            'is_sub_interface': self.is_sub_interface,
            'parent_interface': self.parent_interface,
        }

    def __repr__(self):
        return f'<InterfaceConfig {self.name} ({self.role})>'


# ── VPN Network ──────────────────────────────────────────────────────────────

class VPNNetwork(db.Model):
    __tablename__ = 'vpn_networks'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    network_type = db.Column(db.String(50), nullable=False)
    subnet = db.Column(db.String(18), nullable=False)
    port = db.Column(db.Integer, nullable=False, unique=True)
    private_key = db.Column(db.Text, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')
    is_active = db.Column(db.Boolean, default=True)

    # Rate limiting
    rate_limit_enabled = db.Column(db.Boolean, default=False)
    rate_limit_download_mbps = db.Column(db.Float)
    rate_limit_upload_mbps = db.Column(db.Float)
    rate_limit_burst_factor = db.Column(db.Float, default=1.5)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    endpoints = db.relationship('Endpoint', backref='vpn_network', lazy=True, cascade='all, delete-orphan')

    def get_network_type_config(self):
        return NETWORK_TYPES.get(self.network_type, {})

    def get_interface_name(self):
        return f'wg{self.port - 51820}' if self.port else f'wg{self.id}'

    def get_gateway_ip(self):
        network = ipaddress.ip_network(self.subnet, strict=False)
        return str(network.network_address + 1)

    def get_next_ip(self):
        network = ipaddress.ip_network(self.subnet, strict=False)
        used_ips = {ep.ip_address for ep in self.endpoints}
        used_ips.add(self.get_gateway_ip())
        for ip in network.hosts():
            if str(ip) not in used_ips:
                return str(ip)
        raise ValueError('No available IPs in subnet')

    def get_allowed_ips(self):
        return self.get_network_type_config().get('allowed_ips', '0.0.0.0/0')

    def can_add_endpoint(self):
        cfg = self.get_network_type_config()
        max_peers = cfg.get('max_peers')
        if max_peers is None:
            return True
        return len(self.endpoints) < max_peers

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'network_type': self.network_type,
            'subnet': self.subnet,
            'port': self.port,
            'public_key': self.public_key,
            'status': self.status,
            'is_active': self.is_active,
            'endpoint_count': len(self.endpoints),
            'rate_limit_enabled': self.rate_limit_enabled,
            'rate_limit_download_mbps': self.rate_limit_download_mbps,
            'rate_limit_upload_mbps': self.rate_limit_upload_mbps,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f'<VPNNetwork {self.name}>'


# ── Endpoint (VPN Peer) ─────────────────────────────────────────────────────

class Endpoint(db.Model):
    __tablename__ = 'endpoints'

    id = db.Column(db.Integer, primary_key=True)
    vpn_network_id = db.Column(db.Integer, db.ForeignKey('vpn_networks.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    endpoint_type = db.Column(db.String(20), default='mobile')  # mobile, cpe, gateway
    ip_address = db.Column(db.String(45), nullable=False)
    private_key = db.Column(db.Text, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    preshared_key = db.Column(db.Text)
    allowed_ips = db.Column(db.String(255))
    status = db.Column(db.String(20), default='pending')
    is_active = db.Column(db.Boolean, default=True)
    last_handshake = db.Column(db.DateTime)

    # Rate limiting (overrides network-level if set)
    rate_limit_enabled = db.Column(db.Boolean, default=False)
    rate_limit_download_mbps = db.Column(db.Float)
    rate_limit_upload_mbps = db.Column(db.Float)
    rate_limit_burst_factor = db.Column(db.Float, default=1.5)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('vpn_network_id', 'name'),)

    def get_effective_rate_limit(self):
        """Get the effective rate limit — endpoint-level overrides network-level."""
        if self.rate_limit_enabled:
            return {
                'enabled': True,
                'download_mbps': self.rate_limit_download_mbps,
                'upload_mbps': self.rate_limit_upload_mbps,
                'burst_factor': self.rate_limit_burst_factor,
                'source': 'endpoint',
            }
        net = self.vpn_network
        if net and net.rate_limit_enabled:
            return {
                'enabled': True,
                'download_mbps': net.rate_limit_download_mbps,
                'upload_mbps': net.rate_limit_upload_mbps,
                'burst_factor': net.rate_limit_burst_factor,
                'source': 'network',
            }
        return {'enabled': False, 'source': 'none'}

    def to_dict(self):
        return {
            'id': self.id,
            'vpn_network_id': self.vpn_network_id,
            'name': self.name,
            'endpoint_type': self.endpoint_type,
            'ip_address': self.ip_address,
            'public_key': self.public_key,
            'status': self.status,
            'is_active': self.is_active,
            'last_handshake': self.last_handshake.isoformat() if self.last_handshake else None,
            'rate_limit': self.get_effective_rate_limit(),
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f'<Endpoint {self.name}>'


# ── Firewall Rule ────────────────────────────────────────────────────────────

class FirewallRule(db.Model):
    __tablename__ = 'firewall_rules'

    id = db.Column(db.Integer, primary_key=True)
    chain = db.Column(db.String(20), nullable=False)  # INPUT, FORWARD, OUTPUT
    source = db.Column(db.String(45))
    destination = db.Column(db.String(45))
    port = db.Column(db.Integer)
    protocol = db.Column(db.String(10))  # tcp, udp, icmp
    action = db.Column(db.String(10), nullable=False, default='ACCEPT')  # ACCEPT, DROP, REJECT
    priority = db.Column(db.Integer, default=100)
    description = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'chain': self.chain,
            'source': self.source,
            'destination': self.destination,
            'port': self.port,
            'protocol': self.protocol,
            'action': self.action,
            'priority': self.priority,
            'description': self.description,
            'is_active': self.is_active,
        }

    def __repr__(self):
        return f'<FirewallRule {self.chain} {self.action}>'


# ── Port Forward ─────────────────────────────────────────────────────────────

class PortForward(db.Model):
    __tablename__ = 'port_forwards'

    id = db.Column(db.Integer, primary_key=True)
    wan_port = db.Column(db.Integer, nullable=False)
    lan_ip = db.Column(db.String(45), nullable=False)
    lan_port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), default='tcp')
    description = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'wan_port': self.wan_port,
            'lan_ip': self.lan_ip,
            'lan_port': self.lan_port,
            'protocol': self.protocol,
            'description': self.description,
            'is_active': self.is_active,
        }

    def __repr__(self):
        return f'<PortForward WAN:{self.wan_port} -> {self.lan_ip}:{self.lan_port}>'


# ── DHCP Config ──────────────────────────────────────────────────────────────

class DhcpConfig(db.Model):
    __tablename__ = 'dhcp_configs'

    id = db.Column(db.Integer, primary_key=True)
    interface = db.Column(db.String(50), nullable=False, unique=True)
    range_start = db.Column(db.String(45), nullable=False)
    range_end = db.Column(db.String(45), nullable=False)
    netmask = db.Column(db.String(15), default='255.255.255.0')
    gateway = db.Column(db.String(45))
    dns_servers = db.Column(db.String(255), default='1.1.1.1,8.8.8.8')
    lease_time = db.Column(db.String(10), default='12h')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'interface': self.interface,
            'range_start': self.range_start,
            'range_end': self.range_end,
            'netmask': self.netmask,
            'gateway': self.gateway,
            'dns_servers': self.dns_servers,
            'lease_time': self.lease_time,
            'is_active': self.is_active,
        }

    def __repr__(self):
        return f'<DhcpConfig {self.interface}>'


# ── DHCP Reservation ─────────────────────────────────────────────────────────

class DhcpReservation(db.Model):
    __tablename__ = 'dhcp_reservations'

    id = db.Column(db.Integer, primary_key=True)
    mac = db.Column(db.String(17), nullable=False, unique=True)
    ip = db.Column(db.String(45), nullable=False)
    hostname = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'mac': self.mac,
            'ip': self.ip,
            'hostname': self.hostname,
        }

    def __repr__(self):
        return f'<DhcpReservation {self.mac} -> {self.ip}>'


# ── DNS Override ─────────────────────────────────────────────────────────────

class DnsOverride(db.Model):
    __tablename__ = 'dns_overrides'

    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), nullable=False, unique=True)
    ip = db.Column(db.String(45), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'hostname': self.hostname,
            'ip': self.ip,
        }

    def __repr__(self):
        return f'<DnsOverride {self.hostname} -> {self.ip}>'


# ── Audit Log ────────────────────────────────────────────────────────────────

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    @staticmethod
    def log(action, details='', user=None, ip_address=None):
        entry = AuditLog(
            user_id=user.id if user else None,
            action=action,
            details=details,
            ip_address=ip_address,
        )
        db.session.add(entry)
        return entry

    @staticmethod
    def recent(limit=50):
        return AuditLog.query.order_by(AuditLog.created_at.desc()).limit(limit).all()

    def to_dict(self):
        return {
            'id': self.id,
            'user': self.user.username if self.user else 'System',
            'action': self.action,
            'details': self.details,
            'ip_address': self.ip_address,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f'<AuditLog {self.action}>'


# ── Gateway Config (Singleton) ──────────────────────────────────────────────

class GatewayConfig(db.Model):
    """
    Singleton gateway-wide configuration.
    Always ID=1. Stores hostname, management mode, enable password, etc.
    """
    __tablename__ = 'gateway_config'

    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(64), default='warp-gw')
    management_mode = db.Column(db.String(20), default='standalone')  # standalone, managed, pre_provisioned
    software_version = db.Column(db.String(20), default='0.1.0')
    enable_password_hash = db.Column(db.String(255))
    idle_timeout = db.Column(db.Integer, default=600)  # CLI idle timeout in seconds
    pre_provision_token = db.Column(db.String(255))  # Embedded provisioning token
    pre_provision_url = db.Column(db.String(255))    # Platform URL for pre-provisioned mode
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def set_enable_password(self, password):
        self.enable_password_hash = generate_password_hash(password)

    def check_enable_password(self, password):
        if not self.enable_password_hash:
            return False
        return check_password_hash(self.enable_password_hash, password)

    @staticmethod
    def get_instance():
        """Get or create the singleton config instance."""
        config = GatewayConfig.query.get(1)
        if not config:
            config = GatewayConfig(id=1)
            db.session.add(config)
            db.session.commit()
        return config

    def to_dict(self):
        return {
            'hostname': self.hostname,
            'management_mode': self.management_mode,
            'software_version': self.software_version,
            'idle_timeout': self.idle_timeout,
            'has_enable_password': self.enable_password_hash is not None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self):
        return f'<GatewayConfig {self.hostname} ({self.management_mode})>'


# ── VLAN ─────────────────────────────────────────────────────────────────────

class Vlan(db.Model):
    """VLAN definition -- the VLAN database."""
    __tablename__ = 'vlans'

    id = db.Column(db.Integer, primary_key=True)
    vlan_id = db.Column(db.Integer, unique=True, nullable=False)  # 1-4094
    name = db.Column(db.String(64), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    sub_interfaces = db.relationship('VlanSubInterface', backref='vlan', lazy=True,
                                     cascade='all, delete-orphan')

    @staticmethod
    def validate_vlan_id(vlan_id: int) -> bool:
        return isinstance(vlan_id, int) and 1 <= vlan_id <= 4094

    def to_dict(self):
        return {
            'id': self.id,
            'vlan_id': self.vlan_id,
            'name': self.name,
            'is_active': self.is_active,
            'sub_interface_count': len(self.sub_interfaces),
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f'<Vlan {self.vlan_id} ({self.name})>'


class VlanSubInterface(db.Model):
    """Association between a VLAN and a parent physical interface."""
    __tablename__ = 'vlan_sub_interfaces'

    id = db.Column(db.Integer, primary_key=True)
    vlan_id_ref = db.Column(db.Integer, db.ForeignKey('vlans.id'), nullable=False)
    parent_interface = db.Column(db.String(50), nullable=False)
    sub_interface_name = db.Column(db.String(64), unique=True, nullable=False)  # e.g., "ens38.100"
    is_qinq = db.Column(db.Boolean, default=False)
    s_vlan_id = db.Column(db.Integer, nullable=True)
    c_vlan_id = db.Column(db.Integer, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('parent_interface', 'vlan_id_ref', name='uq_parent_vlan'),
    )

    @property
    def vlan_number(self) -> int:
        return self.vlan.vlan_id

    def to_dict(self):
        return {
            'id': self.id,
            'vlan_id': self.vlan.vlan_id if self.vlan else None,
            'parent_interface': self.parent_interface,
            'sub_interface_name': self.sub_interface_name,
            'is_qinq': self.is_qinq,
            's_vlan_id': self.s_vlan_id,
            'c_vlan_id': self.c_vlan_id,
            'is_active': self.is_active,
        }

    def __repr__(self):
        return f'<VlanSubInterface {self.sub_interface_name}>'


# ── Security Zone ────────────────────────────────────────────────────────────

class SecurityZone(db.Model):
    """Named security zone for firewall policy grouping."""
    __tablename__ = 'security_zones'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), unique=True, nullable=False)
    description = db.Column(db.String(255), default='')
    is_default = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    interfaces = db.relationship('InterfaceConfig', backref='zone', lazy=True)
    source_policies = db.relationship('ZonePolicy', foreign_keys='ZonePolicy.source_zone_id',
                                      backref='source_zone_rel', lazy=True)
    dest_policies = db.relationship('ZonePolicy', foreign_keys='ZonePolicy.dest_zone_id',
                                    backref='dest_zone_rel', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'is_default': self.is_default,
            'interface_count': len(self.interfaces),
        }

    def __repr__(self):
        return f'<SecurityZone {self.name}>'


class ZonePolicy(db.Model):
    """Firewall policy between two security zones."""
    __tablename__ = 'zone_policies'

    id = db.Column(db.Integer, primary_key=True)
    source_zone_id = db.Column(db.Integer, db.ForeignKey('security_zones.id'), nullable=False)
    dest_zone_id = db.Column(db.Integer, db.ForeignKey('security_zones.id'), nullable=False)
    action = db.Column(db.String(10), nullable=False)  # ACCEPT, DROP, REJECT
    protocol = db.Column(db.String(10), nullable=True)
    port = db.Column(db.Integer, nullable=True)
    priority = db.Column(db.Integer, default=100)
    description = db.Column(db.String(255), default='')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.Index('ix_zone_policy_priority', 'priority'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'source_zone': self.source_zone_rel.name if self.source_zone_rel else None,
            'dest_zone': self.dest_zone_rel.name if self.dest_zone_rel else None,
            'action': self.action,
            'protocol': self.protocol,
            'port': self.port,
            'priority': self.priority,
            'description': self.description,
            'is_active': self.is_active,
        }

    def __repr__(self):
        return f'<ZonePolicy {self.source_zone_id}->{self.dest_zone_id} {self.action}>'
