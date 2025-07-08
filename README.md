# KahLuna WARP VPN Manager

A modern, extensible VPN management platform built on WireGuard with support for both Layer 3 and Layer 2 topologies.

## Features

- **Multi-Gateway Support**: Manage multiple WireGuard gateways
- **Dynamic IP Management**: Automatic IP assignment with IPAM
- **Multiple Network Types**: Support for different VPN topologies
- **Overlay Networks**: GRE/VXLAN support for Layer 2 connectivity
- **Config Generation**: Automatic WireGuard config generation
- **QR Code Export**: Generate QR codes for mobile clients
- **Web Interface**: Modern Bootstrap-based admin interface
- **CLI Tools**: Command-line interface for automation

## Network Types

1. **Secure Internet**: Full tunnel VPN for secure internet access
2. **Remote Resource Gateway**: Split tunnel for specific subnets
3. **L3VPN Gateway**: Peer-to-peer with BGP/OSPF routing support
4. **L2 Point to Point**: Direct Layer 2 bridging using GRE/VXLAN
5. **L2 Mesh**: Shared Layer 2 broadcast domain for multiple peers

## Installation

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

## Usage

### Web Interface

Start the Flask application:
```bash
python app.py
```

Access the web interface at: http://localhost:5000

### CLI Usage

List available interfaces:
```bash
python cli.py list-interfaces
```

Create a new peer:
```bash
python cli.py create-peer <interface_id> <peer_name>
```

Show peer configuration:
```bash
python cli.py show-config <peer_id>
```

Export peer configuration:
```bash
python cli.py export-config <peer_id> --filename client.conf
```

## Database Models

- **Gateway**: WireGuard server with public IP and location
- **WGInterface**: WireGuard interface on a gateway with subnet and keys
- **Peer**: Client peer with IP, keys, and config metadata
- **PeerConfig**: Historical versions of peer configurations
- **NetworkType**: Template defining routing/overlay behavior
- **NetworkInstance**: Instantiation of a network type on an interface

## Configuration

Environment variables:
- `SECRET_KEY`: Flask secret key (default: dev key)
- `DATABASE_URL`: Database connection string (default: SQLite)

## Security Features

- Automatic WireGuard keypair generation
- Preshared key support for additional security
- IP address validation and management
- Secure config storage with versioning

## Overlay Networks

Support for Layer 2 overlays:
- **GRE**: Generic Routing Encapsulation
- **VXLAN**: Virtual Extensible LAN
- **GRE TAP**: GRE with TAP for Layer 2 bridging

## Development

Run in development mode:
```bash
export FLASK_ENV=development
python app.py
```

## API Endpoints

- `GET /`: Dashboard
- `GET /gateways`: List gateways
- `POST /gateways/add`: Add gateway
- `GET /interfaces`: List interfaces
- `POST /interfaces/add`: Add interface
- `GET /peers`: List peers
- `POST /peers/add`: Add peer
- `GET /peers/<id>/config`: View peer config
- `GET /peers/<id>/config/download`: Download config file
- `GET /peers/<id>/qr`: Get QR code
- `GET /network_types`: List network types
- `GET /network_instances`: List network instances

## License

This project is licensed under the MIT License.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Support

For issues and questions, please open an issue on the GitHub repository.