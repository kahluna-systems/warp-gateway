# KahLuna WARP VPN Gateway

A **production-ready, self-hosted VPN gateway appliance** designed for cloud marketplace deployment. This is an all-in-one VPN solution with enterprise-grade features, dynamic network creation, and professional testing tools.

## 🚀 Current Status (2025-01-09)

### ✅ **Production Ready Features**
- **Dynamic Network Creation Wizard** with automatic resource allocation
- **Real-time Status Management** based on WireGuard handshakes
- **VCID-based Interface Naming** for Linux compatibility (wg<VCID>)
- **Actual WireGuard Integration** creating real VPN networks in /etc/wireguard/
- **Professional On-Demand Control** with suspend/resume functionality
- **Enterprise Testing Suite** (PWA) for field technicians
- **Complete Authentication System** with CSRF protection
- **Network/Endpoint Deletion** with proper confirmations
- **Rate Limiting Profiles** for different user types

### 🔄 **Remaining Tasks**
- Complete network wizards for 4 remaining network types
- Content filtering implementation
- HTTPS deployment for production security

## Features

### Network Types
1. **Secure Internet** - Full tunnel VPN with rate limiting profiles ✅
2. **Remote Resource Gateway** - Split tunnel for corporate resources 🔄
3. **L3VPN Gateway** - Site-to-site connectivity with routing 🔄
4. **L2 Point to Point** - Direct Layer 2 bridging (max 2 endpoints) 🔄
5. **L2 Mesh** - Shared Layer 2 broadcast domain 🔄

### Core Capabilities
- **Dynamic Network Creation**: Intelligent wizard system with automatic resource allocation
- **VCID Management**: 8-digit Virtual Circuit IDs for all networks
- **Status Tracking**: Real-time network and endpoint status based on WireGuard handshakes
- **Professional Controls**: Suspend/resume networks and endpoints on-demand
- **QR Code Generation**: Mobile-friendly configuration distribution
- **Enterprise Testing**: Progressive Web App for field validation
- **Security**: CSRF protection, user management, audit logging

## Installation

### Quick Cloud Deployment
```bash
# One-command deployment for cloud instances
sudo ./deploy.sh
# Sets up: nginx, SSL, systemd, firewall, server initialization
```

### Manual Installation
1. Clone the repository:
```bash
git clone <repository-url>
cd warp-gateway
```

2. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize the database:
```bash
python cli.py init-db
```

5. Initialize server configuration:
```bash
python server_init.py
```

## Usage

### Web Interface

Start the Flask application:
```bash
python app.py
```

Access the web interface at: http://localhost:5000

### Network Creation Wizard

1. Navigate to Networks → Create Network
2. Select network type (Secure Internet, Remote Resource Gateway, etc.)
3. Configure network-specific settings with automatic resource allocation
4. Network is created with proper WireGuard interface

### CLI Usage

List VPN networks:
```bash
python cli.py list-networks
```

Create endpoint:
```bash
python cli.py create-endpoint <network_id> <endpoint_name> --type mobile|cpe|gateway
```

Show endpoint configuration:
```bash
python cli.py show-config <endpoint_id>
```

Export configuration:
```bash
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

## Database Models

### Current Schema (Dynamic Status System)
- **ServerConfig**: Single server configuration for this VPN appliance
- **VPNNetwork**: Business-focused network management with VCID and status tracking
- **Endpoint**: CPE devices, mobile clients, gateways with type classification
- **EndpointConfig**: Versioned endpoint configurations
- **User**: Authentication with role-based access control
- **AuditLog**: Complete activity logging

### Status Management
- **Network States**: Active, Suspended, Pending, Failed
- **Endpoint States**: Active, Suspended, Pending, Disconnected, Failed
- **Dynamic Detection**: Status based on actual WireGuard handshake activity

## Gateway Testing Suite (Enterprise PWA)

### Professional Testing Tool
- **Target Users**: Field technicians, network administrators, support engineers
- **Location**: `/gateway-testing-suite/pwa/`
- **Features**: QR scanner, network validation, device fleet management, usage analytics

### Access
Navigate to: `http://your-server:5000/gateway-testing-suite/pwa/`

## Configuration

### Environment Variables
- `SECRET_KEY`: Flask secret key (default: dev key)
- `DATABASE_URL`: Database connection string (default: SQLite)
- `SESSION_COOKIE_SECURE`: HTTPS cookie security (default: False)

### Network Configuration
- **Port Range**: 51820-51829 (automatically assigned)
- **Subnet Allocation**: Automatic per network type
- **VCID Format**: 8-digit numbers for interface naming

## Security Features

### Authentication & Authorization
- **User Management**: Create, edit, delete users with role-based access
- **Session Security**: 8-hour timeout with activity tracking
- **CSRF Protection**: All forms protected against cross-site request forgery
- **Audit Logging**: Complete activity logging for security monitoring

### Network Security
- **VPN Network Isolation**: Each network operates independently
- **Status-Based Control**: Networks can be suspended without affecting others
- **Resource Conflict Prevention**: Automatic detection of port/subnet conflicts
- **Secure Configuration**: Automatic keypair generation with preshared keys

## API Endpoints

### Core Management
- `GET /` - Dashboard with network/endpoint stats
- `GET|POST /networks` - VPN Network management
- `GET|POST /endpoints` - Endpoint management
- `GET /endpoints/<id>/config` - View endpoint config
- `GET /endpoints/<id>/config/download` - Download .conf file
- `GET /endpoints/<id>/qr` - Get QR code JSON
- `GET|POST /server-config` - Server configuration

### Network Creation Wizard
- `GET|POST /networks/wizard/step1` - Network type selection
- `GET|POST /networks/wizard/step2` - Network configuration

### Professional Controls
- `POST /networks/<id>/delete` - Delete network with confirmation
- `POST /endpoints/<id>/delete` - Delete endpoint with confirmation
- `POST /networks/<id>/suspend` - Suspend network on-demand
- `POST /networks/<id>/resume` - Resume network on-demand
- `POST /endpoints/<id>/suspend` - Suspend endpoint on-demand
- `POST /endpoints/<id>/resume` - Resume endpoint on-demand

## Development

### Run in Development Mode
```bash
export FLASK_ENV=development
python app.py
```

### Database Migration
```bash
# Update schema to new format
python migrate_to_vpn_networks.py
```

## Architecture

### Deployment Architecture
```
Cloud Instance → KahLuna WARP Gateway
     ↓
Flask Web App (port 5000) → Self-Hosted VPN Server
     ↓                           ↓
Network Creation Wizard    Real WireGuard Integration
Dynamic Status Management  Enhanced Layer 2 Overlays
Auto Resource Pools       VLAN Isolation
Gateway Testing Suite     Professional Controls
```

### VCID Interface Naming
- **Problem**: Network names with spaces can't be used as Linux interface names
- **Solution**: Use 8-digit VCID as interface name (wg<VCID>)
- **Example**: Network "Corporate VPN" → Interface "wg12345678"

## Known Issues

### ⚠️ **Statistics Page Error**
- **Issue**: Template error accessing network utilization statistics
- **Status**: Non-critical, statistics collection needs debugging
- **Workaround**: Avoid /statistics page until fixed

### 🔄 **Incomplete Network Wizards**
- **Status**: Only Secure Internet wizard implemented
- **Remaining**: 4 network types need wizard implementation
- **Priority**: High for complete functionality

## License

This project is licensed under the MIT License.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Support

For issues and questions, please open an issue on the GitHub repository.