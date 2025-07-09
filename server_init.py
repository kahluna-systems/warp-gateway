#!/usr/bin/env python3
"""
Server initialization for KahLuna WARP VPN Appliance
Detects server configuration and sets up initial state
"""

import subprocess
import socket
import requests
import ipaddress
from database import db
from models import ServerConfig


def get_public_ip():
    """Detect the server's public IP address"""
    try:
        # Try to get public IP from various sources
        sources = [
            'https://ipv4.icanhazip.com',
            'https://api.ipify.org',
            'https://checkip.amazonaws.com',
            'https://ipinfo.io/ip'
        ]
        
        for source in sources:
            try:
                response = requests.get(source, timeout=5)
                if response.status_code == 200:
                    ip = response.text.strip()
                    # Validate it's a valid IP
                    ipaddress.ip_address(ip)
                    return ip
            except:
                continue
                
        # Fallback: try to determine from routing table
        result = subprocess.run(['ip', 'route', 'get', '8.8.8.8'], 
                              capture_output=True, text=True, check=True)
        for line in result.stdout.split('\n'):
            if 'src' in line:
                parts = line.split()
                src_idx = parts.index('src')
                if src_idx + 1 < len(parts):
                    return parts[src_idx + 1]
                    
    except Exception as e:
        print(f"Could not determine public IP: {e}")
        return None


def get_hostname():
    """Get the server hostname"""
    try:
        return socket.gethostname()
    except:
        return "warp-gateway"


def detect_network_interface():
    """Detect the primary network interface"""
    try:
        result = subprocess.run(['ip', 'route', 'show', 'default'], 
                              capture_output=True, text=True, check=True)
        for line in result.stdout.split('\n'):
            if 'default' in line:
                parts = line.split()
                dev_idx = parts.index('dev')
                if dev_idx + 1 < len(parts):
                    return parts[dev_idx + 1]
        
        # Fallback to eth0
        return "eth0"
        
    except Exception:
        return "eth0"


def setup_system_requirements():
    """Set up system requirements for WireGuard and overlays"""
    try:
        # Enable IP forwarding permanently
        with open('/etc/sysctl.conf', 'a') as f:
            f.write('\n# WireGuard VPN forwarding\n')
            f.write('net.ipv4.ip_forward=1\n')
            f.write('net.ipv6.conf.all.forwarding=1\n')
        
        # Apply immediately
        subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], check=True)
        subprocess.run(['sysctl', '-w', 'net.ipv6.conf.all.forwarding=1'], check=True)
        
        # Install required kernel modules
        modules = ['wireguard', 'ip_gre', 'ip6_gre', 'vxlan']
        for module in modules:
            try:
                subprocess.run(['modprobe', module], check=True)
            except subprocess.CalledProcessError:
                print(f"Warning: Could not load module {module}")
        
        # Set up module loading at boot
        with open('/etc/modules-load.d/warp-gateway.conf', 'w') as f:
            f.write('# KahLuna WARP Gateway modules\n')
            for module in modules:
                f.write(f'{module}\n')
        
        print("System requirements configured successfully")
        return True
        
    except Exception as e:
        print(f"Error setting up system requirements: {e}")
        return False


def configure_firewall():
    """Configure basic firewall rules for VPN"""
    try:
        # Allow SSH (port 22)
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'], check=True)
        
        # Allow HTTP/HTTPS for admin interface
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '80', '-j', 'ACCEPT'], check=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '443', '-j', 'ACCEPT'], check=True)
        
        # Allow WireGuard ports (51820-51829)
        for port in range(51820, 51830):
            subprocess.run(['iptables', '-A', 'INPUT', '-p', 'udp', '--dport', str(port), '-j', 'ACCEPT'], check=True)
        
        # Allow established connections
        subprocess.run(['iptables', '-A', 'INPUT', '-m', 'state', '--state', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'], check=True)
        
        # Allow loopback
        subprocess.run(['iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'], check=True)
        
        # Save iptables rules
        try:
            subprocess.run(['iptables-save'], check=True, stdout=open('/etc/iptables/rules.v4', 'w'))
        except FileNotFoundError:
            # Try alternative location
            subprocess.run(['iptables-save'], check=True, stdout=open('/etc/iptables.rules', 'w'))
        
        print("Firewall configured successfully")
        return True
        
    except Exception as e:
        print(f"Error configuring firewall: {e}")
        return False


def initialize_server_config():
    """Initialize server configuration in database"""
    try:
        # Check if already initialized
        existing_config = ServerConfig.query.first()
        if existing_config:
            print(f"Server already configured: {existing_config.hostname}")
            return existing_config
        
        # Create new server configuration
        hostname = get_hostname()
        public_ip = get_public_ip()
        
        if not public_ip:
            print("Warning: Could not detect public IP address")
            public_ip = "0.0.0.0"  # Will need manual configuration
        
        server_config = ServerConfig(
            hostname=hostname,
            public_ip=public_ip,
            location="Auto-detected"
        )
        
        db.session.add(server_config)
        db.session.commit()
        
        print(f"Server initialized: {hostname} ({public_ip})")
        return server_config
        
    except Exception as e:
        print(f"Error initializing server config: {e}")
        return None


def create_systemd_service():
    """Create systemd service for KahLuna WARP"""
    service_content = """[Unit]
Description=KahLuna WARP VPN Gateway
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/warp-gateway
Environment=FLASK_ENV=production
ExecStart=/opt/warp-gateway/venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 app:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""
    
    try:
        with open('/etc/systemd/system/warp-gateway.service', 'w') as f:
            f.write(service_content)
        
        # Reload systemd and enable service
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        subprocess.run(['systemctl', 'enable', 'warp-gateway'], check=True)
        
        print("Systemd service created and enabled")
        return True
        
    except Exception as e:
        print(f"Error creating systemd service: {e}")
        return False


def full_server_initialization():
    """Perform complete server initialization"""
    print("Starting KahLuna WARP VPN Gateway initialization...")
    
    # Initialize database
    db.create_all()
    
    # Initialize server configuration
    server_config = initialize_server_config()
    if not server_config:
        print("Failed to initialize server configuration")
        return False
    
    # Set up system requirements
    if not setup_system_requirements():
        print("Warning: Some system requirements could not be configured")
    
    # Configure firewall
    if not configure_firewall():
        print("Warning: Firewall configuration failed")
    
    # Create systemd service (handled by deploy.sh in production)
    # if not create_systemd_service():
    #     print("Warning: Systemd service creation failed")
    
    print("\n" + "="*60)
    print("KahLuna WARP VPN Gateway initialized successfully!")
    print("="*60)
    print(f"Hostname: {server_config.hostname}")
    print(f"Public IP: {server_config.public_ip}")
    print(f"Admin Interface: http://{server_config.public_ip}")
    print("\nNext steps:")
    print("1. Create WireGuard interfaces")
    print("2. Add client peers")
    print("3. Distribute client configurations")
    print("="*60)
    
    return True


if __name__ == '__main__':
    from app import app
    
    with app.app_context():
        full_server_initialization()