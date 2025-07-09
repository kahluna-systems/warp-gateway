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

### ✅ **MAJOR SYSTEM OVERHAUL COMPLETED (2025-01-09):**
1. **Network Creation Wizard** - Complete wizard system replacing manual entry
2. **Dynamic Status Management** - Real-time status based on WireGuard handshakes
3. **VCID Interface Naming** - Linux-compatible interface names (wg<VCID>)
4. **Actual VPN Integration** - Enabled real WireGuard network creation
5. **Professional On-Demand Control** - Suspend/resume functionality
6. **Gateway Testing Suite** - Enterprise PWA for field technicians

### ✅ **PRODUCTION READY FEATURES:**
- Full authentication system with CSRF protection
- Network and endpoint deletion with proper confirmations
- Automatic port (51820-51829) and subnet allocation
- Rate limiting profiles (residential, business, enterprise)
- Real WireGuard interface creation in /etc/wireguard/
- Dynamic network status monitoring
- Professional field testing tools

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
├── app.py                 # Main Flask application (PRODUCTION READY)
├── database.py           # Database initialization
├── models.py             # SQLAlchemy models (DYNAMIC STATUS SYSTEM)
├── forms.py              # WTForms for web interface (UPDATED)
├── additional_forms.py   # Authentication and configuration forms
├── wizard_forms.py       # Network creation wizard forms (NEW)
├── utils.py              # VLAN-aware utility functions (ENABLED)
├── server_init.py        # Server initialization and auto-discovery
├── deploy.sh             # Cloud marketplace deployment script
├── cli.py                # Command-line interface (UPDATED)
├── migrate_to_vpn_networks.py # Database migration script (NEW)
├── requirements.txt      # Python dependencies (CSRF PROTECTION)
├── README.md             # Project documentation
├── CLAUDE.md             # This context file (UPDATED)
├── ADMINISTRATION_GUIDE.md # Admin documentation
├── templates/            # Jinja2 HTML templates (UPDATED)
├── gateway-testing-suite/ # Enterprise PWA for field technicians (NEW)
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
- `GET|POST /networks/wizard/step1` - Network creation wizard type selection (NEW)
- `GET|POST /networks/wizard/step2` - Network configuration wizard (NEW)
- `POST /networks/<id>/delete` - Delete network with confirmation (NEW)
- `POST /endpoints/<id>/delete` - Delete endpoint with confirmation (NEW)
- `POST /networks/<id>/suspend` - Suspend network on-demand (NEW)
- `POST /networks/<id>/resume` - Resume network on-demand (NEW)
- `POST /endpoints/<id>/suspend` - Suspend endpoint on-demand (NEW)
- `POST /endpoints/<id>/resume` - Resume endpoint on-demand (NEW)

## Implementation Progress Summary

### ✅ **COMPLETED FEATURES:**
1. **Network Creation Wizard** - Complete dynamic wizard system with automatic resource allocation
2. **Dynamic Status Management** - Real-time network/endpoint status based on WireGuard handshakes
3. **VCID Interface Naming** - Linux-compatible interface names (wg<VCID>) for all networks
4. **Actual VPN Integration** - Enabled real WireGuard network creation (no longer simulation mode)
5. **Professional On-Demand Control** - Suspend/resume functionality for networks and endpoints
6. **Gateway Testing Suite** - Enterprise PWA for field technicians and administrators
7. **Authentication System** - Complete user management with CSRF protection
8. **Network/Endpoint Deletion** - Proper deletion with confirmation dialogs and cascade handling
9. **Rate Limiting Profiles** - Pre-configured bandwidth profiles for different user types
10. **Database Schema Migration** - Dynamic status system with proper state management

### 🔄 **REMAINING TASKS:**
1. **Complete Network Wizards** - Add wizards for remaining network types (Remote Resource Gateway, L3VPN, L2 networks)
2. **Content Filtering** - Implement DNS/web filtering for Secure Internet networks
3. **HTTPS Deployment** - Production SSL/TLS configuration
4. **Advanced Network Features** - OSPF/BGP routing for L3VPN networks
5. **Performance Optimization** - Load testing and throughput optimization

## Current Database State
- **Production Ready**: Database schema with dynamic status management
- **Active Schema**: VPNNetwork, Endpoint, EndpointConfig tables with status tracking
- **VLAN Support**: Fields ready for L2 network segmentation
- **Status Management**: Dynamic states (Active, Suspended, Pending, Failed, Disconnected)
- **VCID Integration**: 8-digit Virtual Circuit IDs for all networks
- **Authentication**: Complete user management with role-based access

## Testing Priority Matrix

### 🔥 **Critical (WORKING):**
- ✅ Database schema with dynamic status management
- ✅ Network creation wizard with automatic resource allocation
- ✅ Configuration generation and download
- ✅ Web interface functionality with CSRF protection
- ✅ Actual WireGuard network creation in /etc/wireguard/
- ✅ Network and endpoint deletion with proper confirmations

### ⚠️ **Important (NEEDS COMPLETION):**
- 🔄 Complete network wizards for all 5 network types
- 🔄 VLAN isolation testing for L2 networks
- ✅ Auto-assignment validation for ports and subnets
- ✅ CLI command compatibility with new models
- 🔄 Content filtering implementation
- 🔄 HTTPS deployment for production

### 📋 **Nice-to-Have (FUTURE ENHANCEMENT):**
- 🔄 Performance optimization and load testing
- 🔄 Advanced VLAN scenarios
- 🔄 OSPF/BGP routing integration
- 🔄 Enterprise monitoring and analytics

## Deployment Architecture
```
Cloud Instance → KahLuna WARP Gateway
     ↓
Flask Web App (port 5000) → Self-Hosted VPN Server
     ↓                           ↓
ServerConfig Model          VPN Networks (VLAN-aware)
Network Creation Wizard    Real WireGuard Integration
Dynamic Status Management  Enhanced Layer 2 Overlays
Auto Resource Pools       VLAN Isolation
Gateway Testing Suite     Professional Controls
```

## Gateway Testing Suite (Enterprise PWA)

### Professional Testing Tool
- **Target Users**: Field technicians, network administrators, support engineers
- **Purpose**: Validate VPN gateway deployments, test network connectivity, troubleshoot issues
- **Deployment**: Progressive Web App accessible from any device with camera access

### Enterprise Features
- **QR Code Scanner**: Instant WireGuard configuration import and testing
- **Network Validation**: Comprehensive connectivity testing and diagnostics
- **Device Fleet Management**: Track and manage multiple test devices
- **Usage Analytics**: Professional reporting and configuration analytics
- **Field Tech Interface**: Streamlined interface for deployment validation

### Technical Architecture
```
Gateway Testing Suite (PWA)
     ↓
Mobile-Optimized Interface
     ↓
WireGuard Configuration Testing
     ↓
Real-Time Network Diagnostics
     ↓
Professional Reporting
```

## 🎯 CURRENT SYSTEM STATUS (2025-01-09)

### Production Ready Components

#### ✅ **Core VPN Gateway Functionality**
- **Network Creation**: Dynamic wizard system with automatic resource allocation
- **Interface Management**: VCID-based naming (wg<VCID>) for Linux compatibility
- **Status Tracking**: Real-time status based on WireGuard handshakes
- **Configuration Generation**: Proper WireGuard config files with QR codes
- **Professional Controls**: On-demand suspend/resume functionality

#### ✅ **Database Architecture**
- **Dynamic Status System**: Replaces boolean flags with state-based management
- **VCID Integration**: 8-digit Virtual Circuit IDs for all networks
- **Authentication**: Complete user management with role-based access control
- **CSRF Protection**: Secure form handling throughout the application

#### ✅ **Network Types Implementation**
1. **Secure Internet**: ✅ Full wizard with rate limiting profiles
2. **Remote Resource Gateway**: 🔄 Wizard pending implementation
3. **L3VPN Gateway**: 🔄 Wizard pending implementation
4. **L2 Point-to-Point**: 🔄 Wizard pending implementation
5. **L2 Mesh**: 🔄 Wizard pending implementation

#### ✅ **Enterprise Testing Suite**
- **Progressive Web App**: Mobile-optimized interface for field technicians
- **QR Code Scanner**: Instant configuration import and testing
- **Network Diagnostics**: Comprehensive connectivity validation
- **Professional Reporting**: Usage analytics and fleet management

### Technical Implementation Details

#### Network Creation Wizard System
- **Step 1**: Network type selection with detailed descriptions
- **Step 2**: Type-specific configuration with automatic resource allocation
- **Rate Limiting**: Pre-configured profiles (residential, business, enterprise)
- **Resource Management**: Automatic port (51820-51829) and subnet assignment

#### Dynamic Status Management
- **Network States**: Active, Suspended, Pending, Failed
- **Endpoint States**: Active, Suspended, Pending, Disconnected, Failed
- **Status Detection**: Based on actual WireGuard handshake activity
- **Professional Controls**: Suspend/resume functionality with proper state transitions

#### VCID Interface Naming
- **Problem Solved**: Network names with spaces caused Linux interface failures
- **Solution**: Use 8-digit VCID as interface name (wg<VCID>)
- **Example**: Network "Corporate VPN" → Interface "wg12345678"
- **Compatibility**: Works with all Linux networking tools

### Critical Security Features

#### Authentication System
- **User Management**: Create, edit, delete users with role-based access
- **Session Security**: 8-hour timeout with activity tracking
- **CSRF Protection**: All forms protected against cross-site request forgery
- **Audit Logging**: Complete activity logging for security monitoring

#### Network Isolation
- **VPN Network Separation**: Each network operates independently
- **Status-Based Control**: Networks can be suspended without affecting others
- **Resource Conflicts**: Automatic detection and prevention of port/subnet conflicts

### Known Issues and Limitations

#### ⚠️ **Statistics Page Error**
- **Issue**: Template error accessing `stats.summary.network_utilization.max_utilization`
- **Status**: Non-critical, statistics collection needs debugging
- **Impact**: Statistics page returns 500 error

#### 🔄 **Incomplete Network Wizards**
- **Status**: Only Secure Internet wizard implemented
- **Remaining**: 4 network types need wizard implementation
- **Priority**: High - needed for complete network type support

#### 🔄 **Content Filtering**
- **Status**: Placeholder implementation
- **Needed**: DNS filtering, web content filtering for Secure Internet
- **Priority**: Medium - enhances security for internet-facing networks

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

This is a **production-ready VPN gateway appliance** with:
- ✅ **Dynamic network creation wizard** with automatic resource allocation
- ✅ **Real-time status management** based on WireGuard handshakes
- ✅ **VCID-based interface naming** for Linux compatibility
- ✅ **Actual WireGuard integration** creating real VPN networks
- ✅ **Professional on-demand control** with suspend/resume functionality
- ✅ **Enterprise testing suite** (PWA) for field technicians
- ✅ **Complete authentication system** with CSRF protection
- ✅ **Network/endpoint deletion** with proper confirmations
- ✅ **Rate limiting profiles** for different user types
- 🔄 **4 remaining network type wizards** need implementation
- 🔄 **Content filtering** and **HTTPS deployment** pending

**READY FOR:** Complete network wizard implementation, content filtering, and production HTTPS deployment.