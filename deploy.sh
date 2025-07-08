#!/bin/bash
#
# KahLuna WARP VPN Gateway - Cloud Marketplace Deployment Script
# This script sets up a complete VPN server appliance
#

set -e

# Configuration
INSTALL_DIR="/opt/warp-gateway"
SERVICE_USER="warp"
PYTHON_VERSION="3.10"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        log_error "Cannot detect OS"
        exit 1
    fi
    
    log_info "Detected OS: $OS $VER"
}

# Install system packages
install_packages() {
    log_info "Installing system packages..."
    
    case $OS in
        ubuntu|debian)
            apt-get update
            apt-get install -y \
                python3 python3-pip python3-venv \
                wireguard wireguard-tools \
                iptables iptables-persistent \
                nginx certbot python3-certbot-nginx \
                git curl wget unzip \
                bridge-utils iproute2 \
                build-essential python3-dev
            ;;
        centos|rhel|fedora)
            if command -v dnf &> /dev/null; then
                PKG_MGR="dnf"
            else
                PKG_MGR="yum"
            fi
            
            $PKG_MGR update -y
            $PKG_MGR install -y \
                python3 python3-pip \
                wireguard-tools \
                iptables iptables-services \
                nginx certbot python3-certbot-nginx \
                git curl wget unzip \
                bridge-utils iproute \
                gcc python3-devel
            ;;
        *)
            log_error "Unsupported OS: $OS"
            exit 1
            ;;
    esac
    
    log_success "System packages installed"
}

# Create service user
create_user() {
    log_info "Creating service user..."
    
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd --system --home-dir $INSTALL_DIR --shell /bin/false $SERVICE_USER
        log_success "Created user: $SERVICE_USER"
    else
        log_info "User $SERVICE_USER already exists"
    fi
}

# Install application
install_application() {
    log_info "Installing KahLuna WARP Gateway..."
    
    # Create installation directory
    mkdir -p $INSTALL_DIR
    
    # Copy application files (assumes we're running from the source directory)
    cp -r . $INSTALL_DIR/
    
    # Set up Python virtual environment
    cd $INSTALL_DIR
    python3 -m venv venv
    source venv/bin/activate
    
    # Install Python dependencies
    pip install --upgrade pip
    pip install -r requirements.txt
    
    # Set permissions
    chown -R $SERVICE_USER:$SERVICE_USER $INSTALL_DIR
    chmod +x $INSTALL_DIR/server_init.py
    chmod +x $INSTALL_DIR/cli.py
    
    log_success "Application installed"
}

# Configure nginx
configure_nginx() {
    log_info "Configuring nginx..."
    
    cat > /etc/nginx/sites-available/warp-gateway << 'EOF'
server {
    listen 80;
    server_name _;
    
    # Redirect HTTP to HTTPS (will be enabled after SSL setup)
    # return 301 https://$server_name$request_uri;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support (for future features)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
EOF
    
    # Enable site
    ln -sf /etc/nginx/sites-available/warp-gateway /etc/nginx/sites-enabled/
    
    # Remove default site
    rm -f /etc/nginx/sites-enabled/default
    
    # Test nginx configuration
    nginx -t
    
    log_success "Nginx configured"
}

# Set up systemd service
setup_systemd() {
    log_info "Setting up systemd service..."
    
    cat > /etc/systemd/system/warp-gateway.service << EOF
[Unit]
Description=KahLuna WARP VPN Gateway
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
Environment=FLASK_ENV=production
Environment=DATABASE_URL=sqlite:///$INSTALL_DIR/warp_gateway.db
ExecStart=$INSTALL_DIR/venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 app:app
Restart=always
RestartSec=3
KillMode=mixed
TimeoutStopSec=5

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd
    systemctl daemon-reload
    systemctl enable warp-gateway
    
    log_success "Systemd service configured"
}

# Initialize server
initialize_server() {
    log_info "Initializing server configuration..."
    
    cd $INSTALL_DIR
    source venv/bin/activate
    python server_init.py
    
    log_success "Server initialized"
}

# Start services
start_services() {
    log_info "Starting services..."
    
    systemctl start warp-gateway
    systemctl enable nginx
    systemctl start nginx
    
    log_success "Services started"
}

# Configure firewall
configure_firewall() {
    log_info "Configuring firewall..."
    
    # Allow SSH, HTTP, HTTPS
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    
    # Allow WireGuard ports (51820-51829)
    iptables -A INPUT -p udp --dport 51820:51829 -j ACCEPT
    
    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    
    # Drop other input
    iptables -A INPUT -j DROP
    
    # Save rules
    case $OS in
        ubuntu|debian)
            iptables-save > /etc/iptables/rules.v4
            ;;
        centos|rhel|fedora)
            iptables-save > /etc/sysconfig/iptables
            systemctl enable iptables
            ;;
    esac
    
    log_success "Firewall configured"
}

# Setup SSL certificate
setup_ssl() {
    log_info "Setting up SSL certificate..."
    
    # Get public IP for certificate
    PUBLIC_IP=$(curl -s https://ipv4.icanhazip.com || echo "")
    
    if [[ -n "$PUBLIC_IP" ]]; then
        log_info "Attempting to set up SSL for IP: $PUBLIC_IP"
        
        # Create self-signed certificate for IP-based access
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/ssl/private/warp-gateway.key \
            -out /etc/ssl/certs/warp-gateway.crt \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=$PUBLIC_IP"
        
        # Update nginx configuration for SSL
        cat > /etc/nginx/sites-available/warp-gateway << EOF
server {
    listen 80;
    server_name _;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl;
    server_name _;
    
    ssl_certificate /etc/ssl/certs/warp-gateway.crt;
    ssl_certificate_key /etc/ssl/private/warp-gateway.key;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
EOF
        
        nginx -t && systemctl reload nginx
        log_success "SSL certificate configured"
    else
        log_warning "Could not determine public IP, skipping SSL setup"
    fi
}

# Display completion message
show_completion() {
    PUBLIC_IP=$(curl -s https://ipv4.icanhazip.com || echo "YOUR_SERVER_IP")
    
    echo
    echo "=========================================="
    echo " KahLuna WARP VPN Gateway Deployed!"
    echo "=========================================="
    echo
    echo "Admin Interface: https://$PUBLIC_IP"
    echo "Server Status:   systemctl status warp-gateway"
    echo "Service Logs:    journalctl -u warp-gateway -f"
    echo
    echo "Next Steps:"
    echo "1. Access the admin interface"
    echo "2. Create WireGuard interfaces"
    echo "3. Add client peers"
    echo "4. Download/share client configurations"
    echo
    echo "For help: https://github.com/your-repo/warp-gateway"
    echo "=========================================="
}

# Main deployment function
main() {
    log_info "Starting KahLuna WARP Gateway deployment..."
    
    check_root
    detect_os
    install_packages
    create_user
    install_application
    configure_nginx
    setup_systemd
    initialize_server
    configure_firewall
    setup_ssl
    start_services
    
    log_success "Deployment completed successfully!"
    show_completion
}

# Run main function
main "$@"