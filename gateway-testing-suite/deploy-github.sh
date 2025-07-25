#!/bin/bash
# Deploy mobile client to GitHub Pages for easy iPhone access

echo "🚀 Deploying KahLuna WARP Mobile Client to GitHub Pages"

# Create a temporary directory for GitHub Pages
TEMP_DIR=$(mktemp -d)
echo "Using temporary directory: $TEMP_DIR"

# Copy PWA files
cp -r pwa/* $TEMP_DIR/

# Create a simple index redirect if needed
cat > $TEMP_DIR/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KahLuna WARP Mobile Client</title>
    <link rel="manifest" href="manifest.json">
    <link rel="stylesheet" href="css/mobile.css">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    
    <!-- PWA Meta Tags -->
    <meta name="theme-color" content="#667eea">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <link rel="apple-touch-icon" href="assets/icons/icon-192x192.png">
</head>
<body>
    <!-- Header -->
    <header class="mobile-header">
        <div class="container-fluid">
            <div class="row align-items-center">
                <div class="col-2">
                    <button class="btn btn-link mobile-menu-btn" id="menuToggle">
                        <i class="fas fa-bars"></i>
                    </button>
                </div>
                <div class="col-8 text-center">
                    <h5 class="mb-0">
                        <i class="fas fa-shield-alt text-primary"></i>
                        KahLuna WARP
                    </h5>
                </div>
                <div class="col-2 text-end">
                    <span class="connection-status" id="connectionStatus">
                        <i class="fas fa-circle text-muted"></i>
                    </span>
                </div>
            </div>
        </div>
    </header>

    <!-- Side Navigation -->
    <nav class="mobile-nav" id="mobileNav">
        <div class="nav-header">
            <h6>Mobile Testing Client</h6>
            <button class="btn btn-link" id="navClose">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <ul class="nav-menu">
            <li><a href="#" data-section="dashboard"><i class="fas fa-home"></i> Dashboard</a></li>
            <li><a href="#" data-section="scanner"><i class="fas fa-qrcode"></i> QR Scanner</a></li>
            <li><a href="#" data-section="configs"><i class="fas fa-file-code"></i> Configurations</a></li>
            <li><a href="#" data-section="networks"><i class="fas fa-network-wired"></i> Network Types</a></li>
            <li><a href="#" data-section="testing"><i class="fas fa-vial"></i> Connection Tests</a></li>
            <li><a href="#" data-section="gateway"><i class="fas fa-server"></i> Gateway API</a></li>
        </ul>
    </nav>

    <!-- Main Content -->
    <main class="mobile-main">
        <!-- Dashboard Section -->
        <section id="dashboard" class="content-section active">
            <div class="container-fluid">
                <div class="row">
                    <div class="col-12">
                        <div class="welcome-card">
                            <h4>Welcome to KahLuna WARP</h4>
                            <p class="text-muted">Mobile testing client for VPN gateway validation</p>
                            <div class="alert alert-info mt-3">
                                <i class="fas fa-info-circle"></i>
                                <strong>GitHub Pages Demo:</strong> This is a demo version. Update the Gateway URL below to point to your actual gateway.
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="row">
                    <div class="col-6">
                        <div class="feature-card" data-section="scanner">
                            <i class="fas fa-qrcode"></i>
                            <h6>QR Scanner</h6>
                            <p>Import configs</p>
                        </div>
                    </div>
                    <div class="col-6">
                        <div class="feature-card" data-section="configs">
                            <i class="fas fa-file-code"></i>
                            <h6>Configurations</h6>
                            <p>Manage configs</p>
                        </div>
                    </div>
                </div>
                
                <div class="row">
                    <div class="col-6">
                        <div class="feature-card" data-section="networks">
                            <i class="fas fa-network-wired"></i>
                            <h6>Network Types</h6>
                            <p>Explore VPN types</p>
                        </div>
                    </div>
                    <div class="col-6">
                        <div class="feature-card" data-section="testing">
                            <i class="fas fa-vial"></i>
                            <h6>Connection Tests</h6>
                            <p>Validate connectivity</p>
                        </div>
                    </div>
                </div>
                
                <div class="gateway-status">
                    <h6>Gateway Status</h6>
                    <div class="status-item">
                        <span>Gateway URL:</span>
                        <input type="text" id="gatewayUrl" value="http://your-gateway-ip:5000" class="form-control form-control-sm">
                    </div>
                    <div class="status-item">
                        <span>Connection:</span>
                        <span id="gatewayStatus" class="badge bg-secondary">Unknown</span>
                    </div>
                    <button class="btn btn-primary btn-sm" id="testConnection">Test Connection</button>
                </div>
            </div>
        </section>

        <!-- QR Scanner Section -->
        <section id="scanner" class="content-section">
            <div class="container-fluid">
                <div class="section-header">
                    <h5><i class="fas fa-qrcode"></i> QR Code Scanner</h5>
                    <p class="text-muted">Scan WireGuard configuration QR codes</p>
                </div>
                
                <div class="scanner-container">
                    <div id="qr-reader" class="qr-reader"></div>
                    <div class="scanner-controls">
                        <button class="btn btn-primary" id="startScan">
                            <i class="fas fa-camera"></i> Start Scanning
                        </button>
                        <button class="btn btn-secondary" id="stopScan" style="display: none;">
                            <i class="fas fa-stop"></i> Stop Scanning
                        </button>
                    </div>
                </div>
                
                <div class="file-upload">
                    <h6>Or Upload QR Image</h6>
                    <input type="file" id="qrFile" accept="image/*" class="form-control">
                </div>
                
                <div id="scanResult" class="scan-result" style="display: none;">
                    <h6>Scanned Configuration</h6>
                    <textarea id="scannedConfig" class="form-control" rows="10" readonly></textarea>
                    <button class="btn btn-success mt-2" id="saveConfig">
                        <i class="fas fa-save"></i> Save Configuration
                    </button>
                </div>
            </div>
        </section>

        <!-- Configurations Section -->
        <section id="configs" class="content-section">
            <div class="container-fluid">
                <div class="section-header">
                    <h5><i class="fas fa-file-code"></i> WireGuard Configurations</h5>
                    <p class="text-muted">Manage and test VPN configurations</p>
                </div>
                
                <div class="config-actions">
                    <button class="btn btn-primary" id="fetchConfigs">
                        <i class="fas fa-download"></i> Fetch from Gateway
                    </button>
                    <button class="btn btn-outline-primary" id="addManualConfig">
                        <i class="fas fa-plus"></i> Add Manual
                    </button>
                </div>
                
                <div id="configList" class="config-list">
                    <div class="text-center text-muted mt-4">
                        <i class="fas fa-file-code fa-2x"></i>
                        <p>No configurations loaded</p>
                    </div>
                </div>
            </div>
        </section>

        <!-- Network Types Section -->
        <section id="networks" class="content-section">
            <div class="container-fluid">
                <div class="section-header">
                    <h5><i class="fas fa-network-wired"></i> VPN Network Types</h5>
                    <p class="text-muted">Explore the 5 network architectures</p>
                </div>
                
                <div class="network-types">
                    <div class="network-type-card" data-type="secure_internet">
                        <div class="network-icon">
                            <i class="fas fa-globe-americas"></i>
                        </div>
                        <h6>Secure Internet</h6>
                        <p>Full tunnel routing through gateway</p>
                        <div class="network-details">
                            <span class="badge bg-primary">Full Tunnel</span>
                            <span class="badge bg-info">Privacy Focused</span>
                        </div>
                    </div>
                    
                    <div class="network-type-card" data-type="remote_resource_gw">
                        <div class="network-icon">
                            <i class="fas fa-building"></i>
                        </div>
                        <h6>Remote Resource Gateway</h6>
                        <p>Split tunnel for corporate access</p>
                        <div class="network-details">
                            <span class="badge bg-warning">Split Tunnel</span>
                            <span class="badge bg-success">Corporate</span>
                        </div>
                    </div>
                    
                    <div class="network-type-card" data-type="l3vpn_gateway">
                        <div class="network-icon">
                            <i class="fas fa-project-diagram"></i>
                        </div>
                        <h6>L3VPN Gateway</h6>
                        <p>Site-to-site mesh connectivity</p>
                        <div class="network-details">
                            <span class="badge bg-success">Mesh</span>
                            <span class="badge bg-info">Site-to-Site</span>
                        </div>
                    </div>
                    
                    <div class="network-type-card" data-type="l2_point_to_point">
                        <div class="network-icon">
                            <i class="fas fa-link"></i>
                        </div>
                        <h6>L2 Point to Point</h6>
                        <p>Layer 2 bridging between two points</p>
                        <div class="network-details">
                            <span class="badge bg-secondary">Layer 2</span>
                            <span class="badge bg-warning">Max 2 Peers</span>
                        </div>
                    </div>
                    
                    <div class="network-type-card" data-type="l2_mesh">
                        <div class="network-icon">
                            <i class="fas fa-sitemap"></i>
                        </div>
                        <h6>L2 Mesh</h6>
                        <p>VXLAN-based Layer 2 mesh</p>
                        <div class="network-details">
                            <span class="badge bg-secondary">Layer 2</span>
                            <span class="badge bg-primary">VLAN Aware</span>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!-- Connection Testing Section -->
        <section id="testing" class="content-section">
            <div class="container-fluid">
                <div class="section-header">
                    <h5><i class="fas fa-vial"></i> Connection Testing</h5>
                    <p class="text-muted">Validate VPN connectivity and performance</p>
                </div>
                
                <div class="test-controls">
                    <button class="btn btn-success" id="startTests">
                        <i class="fas fa-play"></i> Run All Tests
                    </button>
                    <button class="btn btn-outline-danger" id="stopTests">
                        <i class="fas fa-stop"></i> Stop Tests
                    </button>
                </div>
                
                <div id="testResults" class="test-results">
                    <div class="text-center text-muted mt-4">
                        <i class="fas fa-vial fa-2x"></i>
                        <p>Ready to run connectivity tests</p>
                    </div>
                </div>
            </div>
        </section>

        <!-- Gateway API Section -->
        <section id="gateway" class="content-section">
            <div class="container-fluid">
                <div class="section-header">
                    <h5><i class="fas fa-server"></i> Gateway API</h5>
                    <p class="text-muted">Interact with the VPN gateway</p>
                </div>
                
                <div class="api-auth">
                    <h6>Authentication</h6>
                    <div class="row">
                        <div class="col-6">
                            <input type="text" id="username" placeholder="Username" class="form-control form-control-sm" value="admin">
                        </div>
                        <div class="col-6">
                            <input type="password" id="password" placeholder="Password" class="form-control form-control-sm" value="kahluna123">
                        </div>
                    </div>
                    <button class="btn btn-primary btn-sm mt-2" id="apiLogin">
                        <i class="fas fa-sign-in-alt"></i> Login
                    </button>
                    <span id="authStatus" class="badge bg-secondary ms-2">Not Logged In</span>
                </div>
                
                <div class="api-actions">
                    <h6>Quick Actions</h6>
                    <div class="action-grid">
                        <button class="btn btn-outline-primary" id="fetchNetworks">
                            <i class="fas fa-network-wired"></i><br>
                            <small>Get Networks</small>
                        </button>
                        <button class="btn btn-outline-primary" id="fetchEndpoints">
                            <i class="fas fa-users"></i><br>
                            <small>Get Endpoints</small>
                        </button>
                        <button class="btn btn-outline-primary" id="fetchStats">
                            <i class="fas fa-chart-line"></i><br>
                            <small>Statistics</small>
                        </button>
                        <button class="btn btn-outline-primary" id="fetchAuditLogs">
                            <i class="fas fa-clipboard-list"></i><br>
                            <small>Audit Logs</small>
                        </button>
                    </div>
                </div>
                
                <div id="apiResults" class="api-results">
                    <div class="text-center text-muted mt-4">
                        <i class="fas fa-server fa-2x"></i>
                        <p>Gateway API responses will appear here</p>
                    </div>
                </div>
            </div>
        </section>
    </main>

    <!-- Scripts -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://unpkg.com/html5-qrcode@2.3.8/html5-qrcode.min.js"></script>
    <script src="js/gateway-api.js"></script>
    <script src="js/config-parser.js"></script>
    <script src="js/qr-scanner.js"></script>
    <script src="js/network-tester.js"></script>
    
    <script>
        // Register service worker
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('service-worker.js');
        }
        
        // Initialize app
        document.addEventListener('DOMContentLoaded', function() {
            initializeApp();
        });
        
        function initializeApp() {
            // Mobile navigation
            setupMobileNavigation();
            
            // Test gateway connection on load
            testGatewayConnection();
            
            // Initialize all modules
            initializeGatewayAPI();
            initializeQRScanner();
            initializeConfigParser();
            initializeNetworkTester();
        }
        
        function setupMobileNavigation() {
            const menuToggle = document.getElementById('menuToggle');
            const navClose = document.getElementById('navClose');
            const mobileNav = document.getElementById('mobileNav');
            const navLinks = document.querySelectorAll('.nav-menu a, .feature-card');
            
            menuToggle.addEventListener('click', () => {
                mobileNav.classList.add('active');
            });
            
            navClose.addEventListener('click', () => {
                mobileNav.classList.remove('active');
            });
            
            navLinks.forEach(link => {
                link.addEventListener('click', (e) => {
                    e.preventDefault();
                    const section = link.dataset.section;
                    if (section) {
                        showSection(section);
                        mobileNav.classList.remove('active');
                    }
                });
            });
        }
        
        function showSection(sectionName) {
            // Hide all sections
            document.querySelectorAll('.content-section').forEach(section => {
                section.classList.remove('active');
            });
            
            // Show target section
            const targetSection = document.getElementById(sectionName);
            if (targetSection) {
                targetSection.classList.add('active');
            }
        }
        
        function testGatewayConnection() {
            const gatewayUrl = document.getElementById('gatewayUrl').value;
            const statusElement = document.getElementById('gatewayStatus');
            const connectionStatus = document.getElementById('connectionStatus');
            
            fetch(gatewayUrl + '/login')
                .then(response => {
                    if (response.ok) {
                        statusElement.textContent = 'Connected';
                        statusElement.className = 'badge bg-success';
                        connectionStatus.innerHTML = '<i class="fas fa-circle text-success"></i>';
                    } else {
                        throw new Error('Not accessible');
                    }
                })
                .catch(() => {
                    statusElement.textContent = 'Disconnected';
                    statusElement.className = 'badge bg-danger';
                    connectionStatus.innerHTML = '<i class="fas fa-circle text-danger"></i>';
                });
        }
        
        // Test connection button
        document.getElementById('testConnection').addEventListener('click', testGatewayConnection);
    </script>
</body>
</html>
EOF

echo "📁 Files prepared in: $TEMP_DIR"
echo ""
echo "📋 Next steps:"
echo "1. Create a new GitHub repository (or use existing)"
echo "2. Copy contents of $TEMP_DIR to your repo"
echo "3. Push to main branch"
echo "4. Enable GitHub Pages in repo Settings -> Pages"
echo "5. Access via: https://YOUR_USERNAME.github.io/YOUR_REPO_NAME"
echo ""
echo "🍏 iPhone access:"
echo "1. Open the GitHub Pages URL in Safari"
echo "2. Tap Share -> Add to Home Screen"
echo "3. Grant camera permissions when prompted"
echo ""
echo "Temporary files location: $TEMP_DIR"