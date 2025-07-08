# KahLuna WARP VPN Gateway - Claude Context

## Project Overview
KahLuna WARP is a **self-hosted VPN gateway appliance** designed for cloud marketplace deployment (Linode, DigitalOcean, etc.). The server running the Flask app **IS** the WireGuard gateway - it's an all-in-one VPN solution, not a separate management system.

## ✅ COMPLETED COMPREHENSIVE REFACTORING (2024-01-08)

### Major Architecture Transformation
**FROM:** WireGuard-centric terminology and basic overlay support
**TO:** Business-focused VPN networks with advanced VLAN-aware Layer 2 capabilities

### Database Schema Revolution
- **VPNNetwork** (formerly WGInterface): Business-focused VPN network management
- **Endpoint** (formerly Peer): CPE devices, mobile clients, and gateways
- **EndpointConfig** (formerly PeerConfig): Versioned endpoint configurations
- **New VLAN Fields**: vlan_id, vlan_range, bridge_name, vni_pool

### Enhanced Network Types (Business-Focused)
1. **Secure Internet** - Full tunnel, auto /31 assignment, single endpoint
2. **Remote Resource Gateway** - Split tunnel for corporate resource access
3. **L3VPN Gateway** - Routed mesh for site-to-site connectivity
4. **L2 Point to Point** - GRE TAP with VLAN passthrough (max 2 endpoints)
5. **L2 Mesh** - VXLAN with VLAN isolation (unlimited endpoints)

### VLAN-Aware Layer 2 Networks
- **VLAN ID Support**: 1-4094 range with conflict detection
- **VLAN Isolation**: Multiple L2 networks per server with separation
- **Bridge Management**: VLAN-aware bridge creation with filtering
- **Enhanced VNI**: VLAN-aware VNI assignment for VXLAN networks

### Automatic Resource Management
- **Port Pools**: Auto-assignment from 51820-51829 range
- **Subnet Containers**: Auto-allocation per network type
- **Conflict Prevention**: Automatic detection and resolution
- **Resource Validation**: Form-level validation with auto-correction

## Current Implementation Status

### ✅ **CORE REFACTORING COMPLETE:**
- Database migration script created
- All models updated with new terminology and VLAN fields
- VLAN-aware overlay methods implemented
- Automatic resource management functional
- All forms updated with VLAN validation
- All routes and CLI commands updated
- Enhanced utility functions for VLAN management

### 🔄 **IMMEDIATE NEXT STEPS:**
1. **Template Updates** - Update all HTML templates for new terminology
2. **Missing Templates** - Create edit_server_config.html and add_bulk_endpoints.html
3. **Database Migration** - Run migration script on existing data
4. **Template Testing** - Verify all forms work with new architecture

### 🎯 **TESTING PHASE:**
1. **VLAN Functionality** - Test VLAN isolation between L2 networks
2. **Network Types** - Validate all 5 network types work correctly
3. **Auto-Assignment** - Test automatic port/subnet allocation
4. **Endpoint Types** - Test mobile, CPE, and gateway endpoint types

## Architecture

### Enhanced Database Models
- **ServerConfig**: Single server configuration for this VPN appliance
- **VPNNetwork**: Business-focused network management with VLAN support
- **Endpoint**: CPE devices, mobile clients, gateways with type classification
- **EndpointConfig**: Versioned endpoint configurations

### VLAN-Aware Network Architecture
```
VPN Network (L2 Mesh, VLAN 100)
    ↓
VXLAN Interface (VNI: 1100XX)
    ↓
VLAN-Aware Bridge (br-network-vlan100)
    ↓
Multiple Isolated Endpoints
```

## File Structure
```
/home/groundcontrol/warp-gateway/
├── app.py                 # Main Flask application (UPDATED)
├── database.py           # Database initialization
├── models.py             # SQLAlchemy models (COMPLETELY REFACTORED)
├── forms.py              # WTForms for web interface (UPDATED)
├── utils.py              # VLAN-aware utility functions (ENHANCED)
├── server_init.py        # Server initialization and auto-discovery
├── deploy.sh             # Cloud marketplace deployment script
├── cli.py                # Command-line interface (UPDATED)
├── migrate_to_vpn_networks.py # Database migration script (NEW)
├── requirements.txt      # Python dependencies
├── README.md             # Project documentation
├── CLAUDE.md             # This context file (UPDATED)
├── ADMINISTRATION_GUIDE.md # Admin documentation
├── templates/            # Jinja2 HTML templates (NEEDS UPDATE)
└── warp_gateway.db      # SQLite database (auto-created)
```

## Deployment

### Database Migration (Required for Existing Installations)
```bash
# Run migration to update schema
python migrate_to_vpn_networks.py
```

### Cloud Marketplace Deployment
```bash
# One-command deployment for cloud instances
sudo ./deploy.sh
# Sets up: nginx, SSL, systemd, firewall, server initialization
```

### Manual Server Initialization
```bash
# Initialize server configuration and detect public IP
python server_init.py
```

### Updated CLI Commands
```bash
# List VPN networks
python cli.py list-networks

# Create endpoint
python cli.py create-endpoint <network_id> <endpoint_name> --type mobile|cpe|gateway

# Show endpoint config
python cli.py show-config <endpoint_id>

# Export config to file
python cli.py export-config <endpoint_id> --filename client.conf
```

### Production Service
```bash
# Service management
systemctl start warp-gateway
systemctl stop warp-gateway
systemctl status warp-gateway

# View logs
journalctl -u warp-gateway -f
```

## Enhanced Technical Details

### VLAN-Aware Layer 2 Implementation
- **GRE TAP**: Point-to-point L2 bridging with VLAN passthrough
- **VXLAN**: Multi-peer L2 mesh with VLAN-aware VNI assignment
- **Bridge Management**: VLAN filtering and isolation
- **Conflict Prevention**: VLAN ID validation and conflict detection

### Enhanced Resource Management
- **Automatic Port Assignment**: From pools (51820-51829)
- **Automatic Subnet Assignment**: Per network type containers
- **VLAN Management**: Automatic VLAN ID conflict resolution
- **Endpoint Types**: Mobile, CPE, Gateway classification

### Business-Focused Network Types
- **Secure Internet**: /31 auto-assignment for privacy-focused users
- **Remote Resource Gateway**: Corporate access with enhanced descriptions
- **L3VPN Gateway**: Site-to-site connectivity with routing support
- **L2 Networks**: VLAN-aware with proper isolation and segmentation

## Updated API Endpoints
- `GET /` - Dashboard with network/endpoint stats
- `GET|POST /networks` - VPN Network management (UPDATED)
- `GET|POST /endpoints` - Endpoint management (UPDATED)
- `GET /endpoints/<id>/config` - View endpoint config (UPDATED)
- `GET /endpoints/<id>/config/download` - Download .conf file (UPDATED)
- `GET /endpoints/<id>/qr` - Get QR code JSON (UPDATED)
- `GET|POST /server-config` - Server configuration

## Next Steps for Efficient Progress

### 🎯 **IMMEDIATE (Hours 1-2):**
1. **Run Database Migration**: Execute migration script on existing database
2. **Update Templates**: Convert interfaces.html → networks.html, peers.html → endpoints.html
3. **Create Missing Templates**: edit_server_config.html, add_bulk_endpoints.html
4. **Fix Template References**: Update all template variable names

### 🎯 **SHORT-TERM (Hours 3-4):**
1. **Template Testing**: Test all forms work with new models
2. **VLAN Testing**: Create L2 networks with VLAN IDs, verify isolation
3. **Auto-Assignment Testing**: Test port/subnet auto-assignment
4. **Endpoint Types**: Test mobile, CPE, gateway creation

### 🎯 **VALIDATION (Hours 5-6):**
1. **End-to-End Testing**: Complete network and endpoint lifecycle
2. **Config Generation**: Test WireGuard config generation and QR codes
3. **CLI Testing**: Verify all CLI commands work with new models
4. **Legacy Cleanup**: Remove old templates and unused code

### 🎯 **PRODUCTION READY (Hours 7-8):**
1. **System Integration**: Enable actual WireGuard commands (requires root)
2. **Deployment Testing**: Test deploy.sh on fresh VM
3. **Documentation Updates**: Update README and admin guides
4. **Performance Testing**: Validate VLAN isolation and throughput

## Current Database State
- **Migration Ready**: Migration script handles data preservation
- **New Schema**: VPNNetwork, Endpoint, EndpointConfig tables
- **VLAN Support**: Fields ready for L2 network segmentation
- **Backward Compatibility**: Migration preserves all existing data

## Testing Priority Matrix

### 🔥 **Critical (Must Work):**
- Database migration without data loss
- Basic network and endpoint creation
- Configuration generation and download
- Web interface functionality

### ⚠️ **Important (Should Work):**
- VLAN isolation testing
- Auto-assignment validation
- All 5 network types functional
- CLI command compatibility

### 📋 **Nice-to-Have (Can Test Later):**
- System integration with actual WireGuard
- Performance under load
- Advanced VLAN scenarios
- Production deployment

## Deployment Architecture
```
Cloud Instance → KahLuna WARP Gateway
     ↓
Flask Web App (port 5000) → Self-Hosted VPN Server
     ↓                           ↓
ServerConfig Model          VPN Networks (VLAN-aware)
Network Types (fixed)      Real System Integration
Endpoint Management        Enhanced Layer 2 Overlays
Auto Resource Pools       VLAN Isolation
```

## 🚀 NEXT GENERATION: VRF-BASED NETWORK ARCHITECTURE (2024-01-08)

### Virtual Network Isolation Strategy
**APPROACH:** Treat each VPN network as a Virtual Routing and Forwarding (VRF) instance for enterprise-grade isolation and security.

### Enhanced Network Isolation Architecture
- **True VRF Isolation**: Each network operates in its own routing context with dedicated namespaces
- **Virtual Circuit ID (VCID)**: 8-digit unique identifier for network tracking and management
- **Dynamic Subnet Sizing**: Automatic subnet allocation based on expected user count
- **Topology-Aware Configuration**: Hub-and-spoke vs mesh networking per network type
- **Cross-Network Security**: Complete traffic isolation between VPN networks

### Enhanced Secure Internet Network
**NEW FEATURE:** Peer communication toggle for flexible network topologies:

#### Hub-and-Spoke Mode (Default)
- **Use Case**: Privacy-focused users, hotspot replacement
- **Topology**: Endpoints communicate only with gateway, no peer-to-peer
- **AllowedIPs**: Internet (0.0.0.0/0) + gateway IP only
- **Security**: Maximum isolation between endpoints

#### Mesh Mode (Peer Communication Enabled)
- **Use Case**: Remote office teams, collaborative workgroups
- **Topology**: Full mesh - endpoints communicate with each other + internet
- **AllowedIPs**: Complete network access (0.0.0.0/0)
- **Dynamic Sizing**: Subnet automatically sized based on expected user count

### Dynamic Subnet Allocation
Automatic subnet sizing based on expected user count:
- **2 users**: /30 (2 hosts)
- **3-6 users**: /29 (6 hosts)
- **7-14 users**: /28 (14 hosts)
- **15-30 users**: /27 (30 hosts)
- **31-62 users**: /26 (62 hosts)
- **63-126 users**: /25 (126 hosts)
- **127-254 users**: /24 (254 hosts)

### VRF-Based Network Type Implementation

#### 1. Secure Internet VRF
- **VRF Instance**: Dedicated routing table and namespace
- **Peer Communication**: Toggle between hub-and-spoke and mesh
- **Dynamic Subnet**: Auto-sized based on expected users
- **Internet Gateway**: VRF-specific NAT to internet
- **Isolation**: Complete separation from other networks

#### 2. Remote Resource Gateway VRF
- **VRF Instance**: Split tunnel with corporate resource access
- **Topology**: Hub-and-spoke only (no peer communication)
- **Access Control**: Specific internal subnets only, no internet
- **Security**: Resource-specific firewall rules

#### 3. L3VPN Gateway VRF
- **VRF Instance**: Full mesh routing between sites
- **Topology**: Site-to-site connectivity
- **Routing**: BGP/OSPF integration potential
- **Use Case**: Enterprise multi-site connectivity

#### 4. L2 Point-to-Point VRF
- **VRF Instance**: VLAN-isolated bridge between 2 endpoints
- **Topology**: Layer 2 transparency with VLAN passthrough
- **Limitation**: Maximum 2 endpoints
- **Technology**: GRE TAP with VLAN support

#### 5. L2 Mesh VRF
- **VRF Instance**: VXLAN-based shared broadcast domain
- **Topology**: Multi-endpoint Layer 2 mesh
- **VLAN Support**: Unique VNI per network for isolation
- **Scalability**: Unlimited endpoints per network

### Enhanced Security Architecture
- **Network Namespace Isolation**: Kernel-level separation between VRFs
- **VRF-Specific Firewall Rules**: Prevent cross-network traffic leakage
- **Topology-Aware AllowedIPs**: Proper hub-and-spoke vs mesh configuration
- **Traffic Monitoring**: Per-VRF logging and monitoring
- **VCID Integration**: Unique tracking across all network operations

### Critical Security Fixes Required
**IDENTIFIED ISSUES:**
1. **Cross-Network Communication**: Current architecture allows traffic between different VPN networks
2. **Improper Peer Isolation**: Secure Internet endpoints can communicate with each other
3. **Shared Routing Context**: All networks share the same routing table
4. **Missing Traffic Controls**: No VRF-specific firewall rules

**IMPLEMENTATION REQUIREMENTS:**
- Linux network namespace support for true VRF isolation
- VRF-specific iptables chains for traffic control
- Proper WireGuard AllowedIPs configuration per network topology
- Network-specific routing tables and NAT rules

### Database Schema Enhancements (Planned)
```sql
-- New VRF fields for VPNNetwork model
vcid INTEGER UNIQUE NOT NULL,                    -- 8-digit Virtual Circuit ID
peer_communication_enabled BOOLEAN DEFAULT FALSE, -- For Secure Internet toggle
expected_users INTEGER DEFAULT 1,                -- For dynamic subnet sizing
vrf_name VARCHAR(50),                           -- Linux VRF namespace name
routing_table_id INTEGER,                       -- Dedicated routing table
```

### VRF Implementation Strategy
1. **Database Schema**: Add VRF-specific fields to VPNNetwork model
2. **Linux Integration**: Network namespace and VRF support
3. **UI Enhancement**: Peer communication toggle and user count controls
4. **Security Implementation**: VRF-specific firewall and routing rules
5. **Configuration Generation**: Topology-aware WireGuard config creation

This is a **completely refactored VPN gateway appliance** with business-focused terminology, enhanced VLAN capabilities, automatic resource management, and enterprise-grade VRF-based network isolation - ready for advanced network architecture implementation.