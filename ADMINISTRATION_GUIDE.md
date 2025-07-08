# KahLuna WARP VPN Manager - Administration Guide

## Table of Contents
1. [Installation & Setup](#installation--setup)
2. [Web Interface Administration](#web-interface-administration)
3. [Command Line Administration](#command-line-administration)
4. [Client Management](#client-management)
5. [Network Type Configuration](#network-type-configuration)
6. [Gateway Management](#gateway-management)
7. [Security Considerations](#security-considerations)
8. [Troubleshooting](#troubleshooting)
9. [Client-Side Integration](#client-side-integration)

---

## Installation & Setup

### Prerequisites
- Python 3.10+
- Linux/macOS/Windows with WireGuard support
- Network access for gateway servers

### Initial Setup
```bash
# 1. Clone and navigate to project
cd /path/to/warp-gateway

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Initialize database with seed data
python cli.py init-db

# 5. Start web interface
python app.py
```

### Environment Configuration
Create a `.env` file for production settings:
```bash
SECRET_KEY=your-secure-secret-key-here
DATABASE_URL=postgresql://user:pass@localhost/warp_db  # Optional: Use PostgreSQL
```

---

## Web Interface Administration

### Accessing the Admin Panel
- **URL**: http://localhost:5000 (development) or your server IP
- **Interface**: Responsive Bootstrap-based UI
- **Navigation**: Top navigation bar with all management sections

### Dashboard Overview
The dashboard provides:
- **Statistics Cards**: Gateway, interface, peer, and connection counts
- **Quick Actions**: Direct links to add gateways, interfaces, and peers
- **Recent Activity**: Latest gateways and their details

### Administrative Workflows

#### 1. Setting Up a New Gateway
1. Navigate to **Gateways** → **Add Gateway**
2. Fill in required information:
   - **Name**: Descriptive name (e.g., "NYC-Gateway-01")
   - **Public IP**: External IP address clients will connect to
   - **Location**: Geographic location (optional)
   - **Description**: Purpose or details (optional)
3. Click **Save Gateway**

#### 2. Creating WireGuard Interfaces
1. Navigate to **Interfaces** → **Add Interface**
2. Configure the interface:
   - **Gateway**: Select from existing gateways
   - **Interface Name**: Usually wg0, wg1, etc.
   - **Port**: UDP port (default: 51820)
   - **Subnet**: IP range for peers (e.g., 10.0.0.0/24)
3. Keys are automatically generated
4. Click **Save Interface**

#### 3. Managing Client Peers
1. Navigate to **Peers** → **Add Peer**
2. Peer creation requires:
   - **Interface**: Select target WireGuard interface
   - **Peer Name**: Unique identifier for the client
3. System automatically:
   - Assigns next available IP from subnet
   - Generates WireGuard keypair
   - Creates preshared key
   - Generates initial configuration

#### 4. Client Configuration Distribution
For each peer, administrators can:
- **View Config**: Display full WireGuard configuration
- **Download .conf**: Export configuration file
- **Show QR Code**: Generate QR code for mobile clients
- **Copy to Clipboard**: Quick copy functionality

---

## Command Line Administration

### CLI Overview
The CLI tool (`cli.py`) provides automation capabilities for:
- Bulk peer creation
- Configuration export
- System integration
- Scripting and automation

### Essential CLI Commands

#### Database Management
```bash
# Initialize fresh database
python cli.py init-db
```

#### Interface Management
```bash
# List all available interfaces
python cli.py list-interfaces

# Example output:
# ID: 1, Name: wg0, Gateway: Main Gateway
# Port: 51820, Subnet: 10.0.0.0/24, Peers: 5
```

#### Peer Management
```bash
# Create new peer
python cli.py create-peer <interface_id> <peer_name>

# Example
python cli.py create-peer 1 "laptop-user-john"

# List all peers
python cli.py list-peers

# Show peer configuration
python cli.py show-config <peer_id>

# Export configuration to file
python cli.py export-config <peer_id> --filename john-laptop.conf
```

### Automation Examples

#### Bulk Peer Creation Script
```bash
#!/bin/bash
# Create peers for a team
INTERFACE_ID=1
USERS=("alice" "bob" "charlie" "diana")

for user in "${USERS[@]}"; do
    python cli.py create-peer $INTERFACE_ID "laptop-$user"
    python cli.py export-config $(python cli.py list-peers | grep "laptop-$user" | cut -d: -f2) --filename "${user}-laptop.conf"
done
```

---

## Client Management

### Peer Lifecycle Management

#### 1. Client Onboarding Process
1. **Create Peer**: Use web interface or CLI
2. **Distribute Config**: Via QR code, file download, or secure channel
3. **Client Setup**: User imports config into WireGuard client
4. **Verification**: Test connectivity and functionality

#### 2. Configuration Distribution Methods

##### Method 1: QR Code (Mobile Clients)
- Best for: Mobile devices (iOS/Android)
- Process: Display QR code from web interface
- Client: Scan with WireGuard mobile app

##### Method 2: Configuration File (Desktop Clients)
- Best for: Desktop/laptop clients
- Process: Download .conf file
- Client: Import into WireGuard desktop client

##### Method 3: Manual Configuration
- Best for: Advanced users or custom clients
- Process: Provide configuration text
- Client: Manual entry of parameters

#### 3. Client Configuration Structure
Generated configurations include:
```ini
[Interface]
PrivateKey = <auto-generated>
Address = <auto-assigned-ip>/32
DNS = 8.8.8.8, 8.8.4.4

[Peer]
PublicKey = <server-public-key>
AllowedIPs = <based-on-network-type>
Endpoint = <server-ip>:<port>
PresharedKey = <auto-generated>
PersistentKeepalive = 25
```

---

## Network Type Configuration

### Available Network Types

#### 1. Secure Internet
- **Purpose**: Full tunnel VPN for secure internet access
- **AllowedIPs**: 0.0.0.0/0 (all traffic)
- **Use Case**: Public WiFi protection, general privacy

#### 2. Remote Resource Gateway
- **Purpose**: Split tunnel for specific internal resources
- **AllowedIPs**: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
- **Use Case**: Corporate network access

#### 3. L3VPN Gateway
- **Purpose**: Peer-to-peer with dynamic routing
- **Features**: BGP/OSPF support
- **Use Case**: Site-to-site connections

#### 4. L2 Point to Point
- **Purpose**: Direct Layer 2 bridging
- **Overlay**: GRE TAP
- **Use Case**: LAN extension

#### 5. L2 Mesh
- **Purpose**: Shared broadcast domain
- **Overlay**: VXLAN
- **Use Case**: Multi-site LAN bridging

### Custom Network Types
Administrators can create custom network types:
1. Navigate to **Network Types** → **Add Network Type**
2. Configure parameters:
   - **Routing Mode**: full_tunnel, split_tunnel, peer_to_peer, l2_bridge
   - **Allowed IPs**: Template for client routing
   - **Overlay Mode**: None, GRE, VXLAN, GRE TAP
   - **Routing Protocols**: BGP/OSPF enablement

### Network Instances
Apply network types to specific interfaces:
1. Navigate to **Network Instances** → **Add Network Instance**
2. Link network type to interface
3. Override default settings if needed

---

## Gateway Management

### Gateway Server Requirements
- **Network**: Static public IP address
- **Firewall**: UDP ports open for WireGuard
- **System**: Linux with WireGuard kernel module/userspace tools
- **Performance**: CPU/memory appropriate for peer count

### Gateway Configuration Best Practices

#### 1. Naming Convention
Use descriptive names that include:
- Geographic location
- Purpose/environment
- Sequence number
- Example: "NYC-PROD-GW-01", "LON-DEV-GW-02"

#### 2. Port Management
- Default: 51820
- Multiple interfaces: Use different ports (51821, 51822, etc.)
- Firewall rules: Ensure UDP ports are accessible

#### 3. Subnet Planning
- Avoid overlapping subnets between interfaces
- Plan for growth (use /24 or larger)
- Document IP ranges for troubleshooting

### Gateway Health Monitoring
*Note: Monitoring features are planned for future implementation*

Future monitoring will include:
- Gateway connectivity status
- Peer connection counts
- Bandwidth utilization
- Service health checks

---

## Security Considerations

### Cryptographic Security
- **Key Generation**: Secure random key generation using cryptography library
- **Preshared Keys**: Additional layer of security beyond standard WireGuard
- **Key Storage**: Encrypted storage in database

### Access Control
*Note: Authentication is not yet implemented*

Planned security features:
- Administrator authentication
- Role-based access control
- API token authentication
- Audit logging

### Network Security
- **Endpoint Protection**: Secure gateway server access
- **Firewall Rules**: Restrict administrative access
- **Certificate Management**: Plan for TLS certificates in production

### Configuration Security
- **Environment Variables**: Use for sensitive configuration
- **Database Security**: Encrypt database connections in production
- **Backup Security**: Secure configuration and key backups

---

## Troubleshooting

### Common Issues

#### 1. Peer Cannot Connect
**Symptoms**: Client shows "Handshake failed" or no connectivity
**Diagnosis**:
```bash
# Check gateway firewall
sudo ufw status

# Check WireGuard interface status on gateway
sudo wg show

# Verify peer configuration
python cli.py show-config <peer_id>
```

**Solutions**:
- Verify gateway public IP accessibility
- Check UDP port (default 51820) is open
- Confirm peer configuration matches server

#### 2. IP Address Conflicts
**Symptoms**: "No available IPs" error when creating peers
**Diagnosis**:
```bash
# Check interface subnet utilization
python cli.py list-interfaces
python cli.py list-peers
```

**Solutions**:
- Expand subnet (e.g., /24 to /23)
- Create additional interface with different subnet
- Remove unused peers

#### 3. Configuration Generation Issues
**Symptoms**: Invalid or missing configuration elements
**Diagnosis**:
- Check interface has valid keypair
- Verify gateway has public IP set
- Confirm network type configuration

### Logging and Debugging
- **Flask Logs**: Check terminal output when running `python app.py`
- **Database Issues**: SQLite file permissions and location
- **CLI Debugging**: Add verbose output to CLI commands

---

## Client-Side Integration

### Planning for Client Applications
The current server implementation provides the foundation for client-side applications. Future client development should consider:

#### 1. Configuration Retrieval Methods
**API-Based Retrieval**:
- REST API endpoints for peer configuration
- Secure authentication tokens
- Automatic configuration updates

**QR Code Integration**:
- Mobile app QR scanning
- Automatic profile import
- Configuration validation

**File-Based Distribution**:
- Secure file transfer protocols
- Configuration integrity verification
- Version management

#### 2. Client Platform Considerations

##### Desktop Applications
- **Windows**: Integration with WireGuard Windows client
- **macOS**: Integration with WireGuard macOS client
- **Linux**: Native WireGuard integration

##### Mobile Applications
- **iOS**: WireGuard iOS app integration
- **Android**: WireGuard Android app integration
- **Cross-platform**: React Native or Flutter options

#### 3. Client Features to Implement
**Essential Features**:
- Configuration import/export
- Connection status monitoring
- Server selection (multiple gateways)
- Basic troubleshooting tools

**Advanced Features**:
- Automatic server failover
- Bandwidth monitoring
- Connection logs
- Remote configuration updates

#### 4. Integration Architecture
```
Client App → KahLuna Server → WireGuard Gateway
     ↓            ↓              ↓
Config Mgmt   Peer Mgmt    Connection Handling
Auto-Update   IPAM         Traffic Routing
UI/UX        Analytics     Performance
```

### API Endpoints for Client Integration
Current endpoints suitable for client integration:
- `GET /peers/<id>/config` - Retrieve peer configuration
- `GET /peers/<id>/qr` - Get QR code data
- `POST /peers` - Create new peer (admin)

### Security for Client Integration
- **Authentication**: Implement API tokens or OAuth
- **Encryption**: TLS for all client-server communication
- **Validation**: Client-side configuration validation
- **Updates**: Secure configuration update mechanism

---

## Production Deployment

### Environment Setup
```bash
# Production environment variables
export SECRET_KEY="your-production-secret-key"
export DATABASE_URL="postgresql://user:pass@localhost/warp_prod"
export FLASK_ENV="production"

# Run with Gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

### Database Migration
For PostgreSQL in production:
1. Install PostgreSQL adapter: `pip install psycopg2-binary`
2. Create database: `createdb warp_prod`
3. Update `DATABASE_URL` environment variable
4. Run initialization: `python cli.py init-db`

### Security Hardening
- Use reverse proxy (nginx/Apache)
- Implement SSL/TLS certificates
- Configure firewall rules
- Set up monitoring and logging
- Regular security updates

---

This administration guide provides comprehensive coverage of the KahLuna WARP VPN Manager system. As client-side applications are developed, this guide should be updated to include client-specific administration procedures and integration details.