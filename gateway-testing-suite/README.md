# KahLuna Gateway Testing Suite (GTS)

## Overview

The KahLuna Gateway Testing Suite is a professional Progressive Web App (PWA) designed for field technicians, network administrators, and support engineers. This enterprise-grade diagnostic platform provides comprehensive testing and validation tools for KahLuna WARP VPN Gateway deployments.

**🏢 ENTERPRISE TOOL: Professional diagnostic and validation platform for field deployment**

## 🌟 Features

### 🏢 Enterprise PWA Platform
- **Universal Device Support**: Works on tablets, phones, rugged handhelds, laptops
- **Offline-First**: Full diagnostic capabilities without internet connection
- **Professional Interface**: Optimized for field technician workflows
- **Fleet Management**: Device tracking and usage analytics

### 📷 Professional QR Testing
- **Customer Workflow Validation**: Test end-user QR code experience
- **Deployment Verification**: Validate QR generation and scanning
- **Configuration Analysis**: Parse and validate WireGuard configurations
- **Field Testing**: Test QR workflow in various lighting conditions

### ⚙️ Configuration Management
- **Local Storage**: Save and manage multiple configurations
- **Gateway Integration**: Fetch configs directly from gateway API
- **Format Validation**: Parse and validate WireGuard syntax
- **Export/Import**: Backup and restore configurations

### 🌐 Network Type Explorer
- **Secure Internet**: Full tunnel privacy configurations
- **Remote Resource Gateway**: Split tunnel corporate access
- **L3VPN Gateway**: Site-to-site mesh connectivity
- **L2 Point to Point**: Layer 2 bridging (max 2 endpoints)
- **L2 Mesh**: VXLAN-based Layer 2 mesh with VLAN support

### 🧪 Comprehensive Testing
- **Connectivity Tests**: Basic network reachability
- **Performance Tests**: Bandwidth, latency, packet loss
- **Security Tests**: IP leak detection, DNS leak testing
- **Gateway Integration**: API validation and endpoint testing

### 🔌 Gateway API Integration
- **Authentication**: Secure login with session management
- **Full API Access**: Networks, endpoints, statistics, audit logs
- **Real-time Data**: Live gateway status and monitoring
- **Bulk Operations**: Mass configuration management

## 📁 Project Structure

```
mobile-client/
├── README.md                    # This documentation
├── pwa/                        # Progressive Web App files
│   ├── index.html              # Main application interface
│   ├── manifest.json           # PWA manifest
│   ├── service-worker.js       # Offline functionality
│   ├── css/
│   │   └── mobile.css          # Mobile-optimized styles
│   └── js/
│       ├── gateway-api.js      # Gateway API integration
│       ├── qr-scanner.js       # QR code scanning
│       ├── config-parser.js    # WireGuard config parsing
│       └── network-tester.js   # Network testing suite
└── cli-tools/                 # Command-line testing tools
    └── test-runner.py          # Comprehensive CLI test runner
```

## 🚀 Quick Start

### 1. Development Setup
```bash
# Navigate to the mobile client directory
cd mobile-client/pwa

# Start a local web server (Python 3)
python -m http.server 8080

# Or use Node.js
npx http-server -p 8080

# Access the application
open http://localhost:8080
```

### 2. Gateway Configuration
1. Open the mobile client in your browser
2. Navigate to Dashboard
3. Set Gateway URL (default: `http://localhost:5000`)
4. Test connection to ensure gateway is accessible

### 3. Authentication
1. Go to Gateway API section
2. Enter credentials (default: admin/kahluna123)
3. Click Login to authenticate
4. Verify "Logged In" status appears

### 4. Start Testing
- **QR Scanner**: Scan WireGuard configuration QR codes
- **Configurations**: Manage and test VPN configurations
- **Network Types**: Explore the 5 VPN network architectures
- **Testing**: Run comprehensive connectivity tests
- **Gateway API**: Interact with gateway management functions

## 🔧 CLI Testing Tools

### Python Test Runner
```bash
# Basic connectivity test
./cli-tools/test-runner.py --gateway http://your-gateway:5000

# Authenticated testing
./cli-tools/test-runner.py --gateway http://your-gateway:5000 \
  --username admin --password kahluna123

# Export results
./cli-tools/test-runner.py --gateway http://your-gateway:5000 \
  --username admin --password kahluna123 \
  --export test-results.json

# WireGuard connectivity testing (requires root)
sudo ./cli-tools/test-runner.py --gateway http://your-gateway:5000 \
  --username admin --password kahluna123 \
  --test-wireguard
```

### Test Categories
- **Gateway Connectivity**: Basic reachability and response times
- **API Endpoints**: Validation of all gateway API endpoints
- **Network Types**: Creation and management of all 5 network types
- **Configuration Generation**: WireGuard config creation and validation
- **WireGuard Connectivity**: Actual VPN connection testing (root required)

## 📋 Testing Scenarios

### Network Type Testing
Each of the 5 network types can be thoroughly tested:

1. **Secure Internet**
   - Full tunnel configuration
   - Privacy-focused routing
   - DNS leak protection

2. **Remote Resource Gateway**
   - Split tunnel configuration
   - Corporate resource access
   - Selective routing

3. **L3VPN Gateway**
   - Site-to-site connectivity
   - Mesh network architecture
   - Advanced routing

4. **L2 Point to Point**
   - Layer 2 bridging
   - GRE TAP implementation
   - VLAN passthrough

5. **L2 Mesh**
   - VXLAN-based networking
   - VLAN-aware segmentation
   - Multi-peer connectivity

### Security Testing
- **IP Leak Detection**: Verify VPN IP masking
- **DNS Leak Testing**: Ensure DNS queries route through VPN
- **Traffic Encryption**: Validate HTTPS and encryption
- **Gateway Security**: API authentication and authorization

### Performance Testing
- **Bandwidth Measurement**: Upload/download speed testing
- **Latency Analysis**: Round-trip time measurement
- **Packet Loss Detection**: Network reliability testing
- **Connection Stability**: Long-term connectivity validation

## 🔒 Security Considerations

### Data Protection
- **Local Storage Only**: No sensitive data sent to external servers
- **Client-Side Processing**: All parsing and validation done locally
- **Session Management**: Secure authentication with the gateway
- **Configuration Sanitization**: Private keys masked in displays

### Testing Safety
- **Isolated Testing**: Mobile client operates independently
- **Non-Destructive**: Tests don't modify gateway configuration
- **Permission-Based**: WireGuard tests require explicit root access
- **Audit Trail**: All API interactions logged for security review

## 🌐 Network Integration

### Gateway API Compatibility
- **Authentication**: Flask-Login session management
- **CSRF Protection**: Token-based request validation
- **Rate Limiting**: Respectful API usage patterns
- **Error Handling**: Graceful degradation and retry logic

### Configuration Management
- **Format Support**: Standard WireGuard configuration format
- **Validation**: Comprehensive syntax and semantic checking
- **Metadata Extraction**: Automatic parsing of network details
- **Export/Import**: JSON-based configuration backup/restore

## 📊 Testing Reports

### Real-Time Results
- **Live Status Updates**: Tests update in real-time
- **Progress Tracking**: Visual indicators for test progress
- **Detailed Logging**: Comprehensive error messages and debugging info
- **Performance Metrics**: Latency, bandwidth, and reliability measurements

### Export Capabilities
- **JSON Reports**: Machine-readable test results
- **Configuration Backup**: Export all saved configurations
- **Performance History**: Track testing over time
- **Audit Logs**: Security and access logging

## 🔄 Deployment Strategy

### Development vs Production
- **Git Exclusion**: Mobile client excluded from production deployments via `.gitignore`
- **Development Only**: Testing tools remain in development environment
- **Zero Impact**: No effect on production gateway performance
- **Resource Efficiency**: Minimal footprint for testing infrastructure

### Scalability
- **Multi-Gateway Testing**: Support for testing multiple gateways
- **Concurrent Testing**: Parallel test execution capabilities
- **Cloud Integration**: Compatible with cloud-deployed gateways
- **CI/CD Integration**: Automated testing in deployment pipelines

## 🛠️ Development Guide

### Adding New Tests
1. Extend `NetworkTester` class in `network-tester.js`
2. Add test method following naming convention
3. Update test suites configuration
4. Add UI elements for new test category

### Custom Network Types
1. Add network type to explorer in `index.html`
2. Update configuration templates in `config-parser.js`
3. Add specific testing scenarios in `network-tester.js`
4. Update CLI test runner for new type

### API Integration
1. Extend `GatewayAPI` class methods
2. Add authentication handling if needed
3. Update error handling and retry logic
4. Add corresponding UI interactions

## 📚 Documentation

### Technical References
- **WireGuard Protocol**: [wireguard.com](https://www.wireguard.com/)
- **PWA Standards**: [web.dev/progressive-web-apps](https://web.dev/progressive-web-apps/)
- **Bootstrap 5**: [getbootstrap.com](https://getbootstrap.com/)
- **HTML5 QR Code**: [github.com/mebjas/html5-qrcode](https://github.com/mebjas/html5-qrcode)

### Gateway Documentation
- **KahLuna WARP**: See main project README.md
- **API Reference**: Check gateway `/api/` endpoints
- **Authentication**: Flask-Login integration details
- **Network Types**: VRF-based architecture documentation

## 📧 Support

For issues, feature requests, or questions:
- **GitHub Issues**: Create detailed bug reports
- **Documentation**: Check gateway and mobile client docs
- **Testing**: Use CLI tools for systematic validation
- **Security**: Report security issues through appropriate channels

---

This mobile testing client provides comprehensive validation capabilities for the KahLuna WARP VPN Gateway system while maintaining clean separation between development testing tools and production deployments.