#!/usr/bin/env python3
"""
KahLuna WARP CLI - Command line interface for VPN network and endpoint management
"""

import argparse
import sys
from app import app
from database import db
from models import ServerConfig, VPNNetwork, Endpoint, EndpointConfig, NETWORK_TYPES
from utils import generate_keypair, generate_preshared_key, generate_endpoint_config, generate_qr_code


def list_networks():
    """List all available VPN networks"""
    print("Available VPN Networks:")
    print("-" * 60)
    networks = VPNNetwork.query.all()
    
    if not networks:
        print("No networks found. Create a network first.")
        return
    
    for network in networks:
        network_config = network.get_network_type_config()
        print(f"ID: {network.id}")
        print(f"Name: {network.name}")
        print(f"Network Type: {network_config.get('name', 'Unknown')}")
        print(f"Port: {network.port}")
        print(f"Subnet: {network.subnet}")
        if network.vlan_id:
            print(f"VLAN ID: {network.vlan_id}")
        print(f"Endpoints: {len(network.endpoints)}")
        print(f"Active: {'Yes' if network.is_active else 'No'}")
        print("-" * 60)


def create_endpoint(network_id, endpoint_name, endpoint_type='mobile'):
    """Create a new endpoint on the specified network"""
    network = VPNNetwork.query.get(network_id)
    if not network:
        print(f"Network with ID {network_id} not found.")
        return False
    
    # Check if network can accept more endpoints
    if not network.can_add_endpoint():
        print(f"Network has reached maximum endpoint limit.")
        return False
    
    try:
        # Get next available IP
        ip_address = network.get_next_ip()
        
        # Generate keypair
        private_key, public_key = generate_keypair()
        
        # Create endpoint
        endpoint = Endpoint(
            vpn_network_id=network_id,
            name=endpoint_name,
            ip_address=ip_address,
            private_key=private_key,
            public_key=public_key,
            preshared_key=generate_preshared_key(),
            endpoint_type=endpoint_type
        )
        
        db.session.add(endpoint)
        db.session.commit()
        
        # Generate config
        config_content = generate_endpoint_config(endpoint)
        endpoint_config = EndpointConfig(
            endpoint_id=endpoint.id,
            config_content=config_content,
            version=1
        )
        db.session.add(endpoint_config)
        db.session.commit()
        
        print(f"Endpoint '{endpoint_name}' created successfully!")
        print(f"Type: {endpoint_type}")
        print(f"IP Address: {ip_address}")
        print(f"Config saved to database.")
        
        return True
        
    except ValueError as e:
        print(f"Error creating endpoint: {e}")
        return False


def show_endpoint_config(endpoint_id):
    """Show configuration for a specific endpoint"""
    endpoint = Endpoint.query.get(endpoint_id)
    if not endpoint:
        print(f"Endpoint with ID {endpoint_id} not found.")
        return
    
    latest_config = EndpointConfig.query.filter_by(endpoint_id=endpoint_id).order_by(EndpointConfig.version.desc()).first()
    
    if not latest_config:
        config_content = generate_endpoint_config(endpoint)
    else:
        config_content = latest_config.config_content
    
    print(f"Configuration for endpoint '{endpoint.name}':")
    print(f"Type: {endpoint.endpoint_type}")
    print("=" * 50)
    print(config_content)
    print("=" * 50)


def export_endpoint_config(endpoint_id, filename=None):
    """Export endpoint configuration to file"""
    endpoint = Endpoint.query.get(endpoint_id)
    if not endpoint:
        print(f"Endpoint with ID {endpoint_id} not found.")
        return
    
    latest_config = EndpointConfig.query.filter_by(endpoint_id=endpoint_id).order_by(EndpointConfig.version.desc()).first()
    
    if not latest_config:
        config_content = generate_endpoint_config(endpoint)
    else:
        config_content = latest_config.config_content
    
    if not filename:
        filename = f"{endpoint.name}.conf"
    
    with open(filename, 'w') as f:
        f.write(config_content)
    
    print(f"Configuration exported to {filename}")


def list_endpoints():
    """List all endpoints"""
    print("All Endpoints:")
    print("-" * 80)
    endpoints = Endpoint.query.all()
    
    if not endpoints:
        print("No endpoints found.")
        return
    
    for endpoint in endpoints:
        print(f"ID: {endpoint.id}")
        print(f"Name: {endpoint.name}")
        print(f"Type: {endpoint.endpoint_type}")
        print(f"Network: {endpoint.vpn_network.name}")
        print(f"IP Address: {endpoint.ip_address}")
        print(f"Created: {endpoint.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 80)


def main():
    parser = argparse.ArgumentParser(description='KahLuna WARP CLI')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # List networks
    subparsers.add_parser('list-networks', help='List all VPN networks')
    
    # List endpoints
    subparsers.add_parser('list-endpoints', help='List all endpoints')
    
    # Create endpoint
    create_parser = subparsers.add_parser('create-endpoint', help='Create a new endpoint')
    create_parser.add_argument('network_id', type=int, help='Network ID')
    create_parser.add_argument('endpoint_name', help='Endpoint name')
    create_parser.add_argument('--type', choices=['mobile', 'cpe', 'gateway'], default='mobile', help='Endpoint type')
    
    # Show endpoint config
    show_parser = subparsers.add_parser('show-config', help='Show endpoint configuration')
    show_parser.add_argument('endpoint_id', type=int, help='Endpoint ID')
    
    # Export endpoint config
    export_parser = subparsers.add_parser('export-config', help='Export endpoint configuration to file')
    export_parser.add_argument('endpoint_id', type=int, help='Endpoint ID')
    export_parser.add_argument('--filename', help='Output filename (default: endpoint_name.conf)')
    
    # Server status
    subparsers.add_parser('server-status', help='Show server configuration status')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    with app.app_context():
        # Ensure database tables exist
        db.create_all()
        
        if args.command == 'server-status':
            server_config = ServerConfig.query.first()
            if server_config:
                print("Server Configuration:")
                print(f"Hostname: {server_config.hostname}")
                print(f"Public IP: {server_config.public_ip}")
                print(f"Location: {server_config.location or 'Not set'}")
                print(f"Admin Email: {server_config.admin_email or 'Not set'}")
                print(f"Created: {server_config.created_at}")
            else:
                print("Server not initialized. Run 'python server_init.py' first.")
            
        elif args.command == 'list-networks':
            list_networks()
            
        elif args.command == 'list-endpoints':
            list_endpoints()
            
        elif args.command == 'create-endpoint':
            create_endpoint(args.network_id, args.endpoint_name, args.type)
            
        elif args.command == 'show-config':
            show_endpoint_config(args.endpoint_id)
            
        elif args.command == 'export-config':
            export_endpoint_config(args.endpoint_id, args.filename)


if __name__ == '__main__':
    main()