// KahLuna WARP Gateway API Integration

class GatewayAPI {
    constructor() {
        this.baseUrl = 'http://144.129.191.155:5000';
        this.authToken = null;
        this.isAuthenticated = false;
        this.sessionId = null;
    }

    setBaseUrl(url) {
        this.baseUrl = url.replace(/\/$/, ''); // Remove trailing slash
    }

    // Authentication
    async login(username, password) {
        try {
            const response = await fetch(`${this.baseUrl}/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}&csrf_token=`
            });

            if (response.ok) {
                // Check if login was successful by looking for redirect
                const finalUrl = response.url;
                if (finalUrl.includes('/login')) {
                    throw new Error('Invalid credentials');
                }
                
                this.isAuthenticated = true;
                
                // Store session cookie
                const cookies = response.headers.get('set-cookie');
                if (cookies) {
                    this.sessionId = this.extractSessionId(cookies);
                }
                
                return { success: true, message: 'Login successful' };
            } else {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
        } catch (error) {
            console.error('Login error:', error);
            this.isAuthenticated = false;
            return { success: false, message: error.message };
        }
    }

    extractSessionId(cookies) {
        const match = cookies.match(/session=([^;]+)/);
        return match ? match[1] : null;
    }

    // Test gateway connection
    async testConnection() {
        try {
            const response = await fetch(`${this.baseUrl}/login`, {
                method: 'GET',
                mode: 'cors'
            });
            
            return {
                success: response.ok,
                status: response.status,
                message: response.ok ? 'Gateway accessible' : `HTTP ${response.status}`
            };
        } catch (error) {
            return {
                success: false,
                status: 0,
                message: 'Connection failed: ' + error.message
            };
        }
    }

    // Generic API request method
    async apiRequest(endpoint, options = {}) {
        if (!this.isAuthenticated && !endpoint.includes('login')) {
            throw new Error('Not authenticated');
        }

        const url = `${this.baseUrl}${endpoint}`;
        const defaultOptions = {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include'
        };

        const requestOptions = { ...defaultOptions, ...options };

        try {
            const response = await fetch(url, requestOptions);
            
            if (response.status === 401 || response.status === 403) {
                this.isAuthenticated = false;
                throw new Error('Authentication required');
            }
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                return await response.json();
            } else {
                return await response.text();
            }
        } catch (error) {
            console.error(`API request failed for ${endpoint}:`, error);
            throw error;
        }
    }

    // VPN Networks
    async getNetworks() {
        return this.apiRequest('/api/networks');
    }

    async getNetwork(networkId) {
        return this.apiRequest(`/api/networks/${networkId}`);
    }

    async createNetwork(networkData) {
        return this.apiRequest('/networks/add', {
            method: 'POST',
            body: JSON.stringify(networkData)
        });
    }

    // Endpoints
    async getEndpoints() {
        return this.apiRequest('/api/endpoints');
    }

    async getEndpoint(endpointId) {
        return this.apiRequest(`/api/endpoints/${endpointId}`);
    }

    async getEndpointConfig(endpointId) {
        return this.apiRequest(`/endpoints/${endpointId}/config`);
    }

    async getEndpointQR(endpointId) {
        return this.apiRequest(`/endpoints/${endpointId}/qr`);
    }

    async createEndpoint(endpointData) {
        return this.apiRequest('/endpoints/add', {
            method: 'POST',
            body: JSON.stringify(endpointData)
        });
    }

    // Statistics and Monitoring
    async getStatistics() {
        return this.apiRequest('/api/statistics');
    }

    async getAuditLogs(limit = 50) {
        return this.apiRequest(`/api/audit-logs?limit=${limit}`);
    }

    async getCircuits() {
        return this.apiRequest('/api/circuits');
    }

    // Server Configuration
    async getServerConfig() {
        return this.apiRequest('/api/server-config');
    }

    // Network Types
    async getNetworkTypes() {
        return this.apiRequest('/api/network-types');
    }

    // Utility methods for mobile client
    async downloadConfig(endpointId) {
        try {
            const response = await fetch(`${this.baseUrl}/endpoints/${endpointId}/config/download`, {
                credentials: 'include'
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            return await response.text();
        } catch (error) {
            console.error('Config download failed:', error);
            throw error;
        }
    }

    // Bulk operations for testing
    async createTestNetwork(networkType = 'secure_internet') {
        const testNetworkData = {
            name: `Test-${networkType}-${Date.now()}`,
            network_type: networkType,
            expected_users: 5,
            peer_communication_enabled: networkType === 'secure_internet' ? true : false
        };

        return this.createNetwork(testNetworkData);
    }

    async createTestEndpoint(networkId, endpointType = 'mobile') {
        const testEndpointData = {
            vpn_network_id: networkId,
            name: `TestEndpoint-${Date.now()}`,
            endpoint_type: endpointType
        };

        return this.createEndpoint(testEndpointData);
    }

    // Health check and diagnostics
    async healthCheck() {
        try {
            const tests = {
                connection: await this.testConnection(),
                authentication: { success: this.isAuthenticated, message: this.isAuthenticated ? 'Authenticated' : 'Not authenticated' }
            };

            if (this.isAuthenticated) {
                try {
                    tests.api_access = await this.getStatistics().then(() => ({ success: true, message: 'API accessible' }));
                } catch (error) {
                    tests.api_access = { success: false, message: error.message };
                }
            }

            return tests;
        } catch (error) {
            return {
                connection: { success: false, message: error.message },
                authentication: { success: false, message: 'Health check failed' }
            };
        }
    }
}

// Initialize global gateway API instance
const gatewayAPI = new GatewayAPI();

// Initialize gateway API functionality
function initializeGatewayAPI() {
    // Update gateway URL when changed
    document.getElementById('gatewayUrl').addEventListener('change', function() {
        gatewayAPI.setBaseUrl(this.value);
    });

    // Login functionality
    document.getElementById('apiLogin').addEventListener('click', async function() {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const statusElement = document.getElementById('authStatus');
        
        statusElement.textContent = 'Logging in...';
        statusElement.className = 'badge bg-warning ms-2';
        
        const result = await gatewayAPI.login(username, password);
        
        if (result.success) {
            statusElement.textContent = 'Logged In';
            statusElement.className = 'badge bg-success ms-2';
        } else {
            statusElement.textContent = 'Login Failed';
            statusElement.className = 'badge bg-danger ms-2';
            alert('Login failed: ' + result.message);
        }
    });

    // API action buttons
    document.getElementById('fetchNetworks').addEventListener('click', async function() {
        await executeAPIAction('networks', () => gatewayAPI.getNetworks());
    });

    document.getElementById('fetchEndpoints').addEventListener('click', async function() {
        await executeAPIAction('endpoints', () => gatewayAPI.getEndpoints());
    });

    document.getElementById('fetchStats').addEventListener('click', async function() {
        await executeAPIAction('statistics', () => gatewayAPI.getStatistics());
    });

    document.getElementById('fetchAuditLogs').addEventListener('click', async function() {
        await executeAPIAction('audit logs', () => gatewayAPI.getAuditLogs());
    });

    // Fetch configurations for config section
    document.getElementById('fetchConfigs').addEventListener('click', async function() {
        await fetchAndDisplayConfigs();
    });
}

// Execute API action and display results
async function executeAPIAction(actionName, apiCall) {
    const resultsElement = document.getElementById('apiResults');
    
    try {
        resultsElement.innerHTML = `<div class="text-center"><div class="loading-spinner"></div> Fetching ${actionName}...</div>`;
        
        const data = await apiCall();
        
        resultsElement.innerHTML = `
            <div class="api-response-header">
                <h6 class="text-success">
                    <i class="fas fa-check-circle"></i> ${actionName} (${new Date().toLocaleTimeString()})
                </h6>
            </div>
            <div class="api-response">${JSON.stringify(data, null, 2)}</div>
        `;
    } catch (error) {
        resultsElement.innerHTML = `
            <div class="api-response-header">
                <h6 class="text-danger">
                    <i class="fas fa-exclamation-circle"></i> Error fetching ${actionName}
                </h6>
            </div>
            <div class="api-response text-danger">${error.message}</div>
        `;
    }
}

// Fetch and display configurations
async function fetchAndDisplayConfigs() {
    const configListElement = document.getElementById('configList');
    
    try {
        configListElement.innerHTML = '<div class="text-center"><div class="loading-spinner"></div> Loading configurations...</div>';
        
        const endpoints = await gatewayAPI.getEndpoints();
        
        if (!endpoints || endpoints.length === 0) {
            configListElement.innerHTML = `
                <div class="text-center text-muted mt-4">
                    <i class="fas fa-file-code fa-2x"></i>
                    <p>No endpoints found on gateway</p>
                </div>
            `;
            return;
        }

        let configsHTML = '';
        
        for (const endpoint of endpoints) {
            try {
                const config = await gatewayAPI.downloadConfig(endpoint.id);
                configsHTML += createConfigCard(endpoint, config);
            } catch (error) {
                console.error(`Failed to fetch config for endpoint ${endpoint.id}:`, error);
            }
        }
        
        configListElement.innerHTML = configsHTML || `
            <div class="text-center text-muted mt-4">
                <i class="fas fa-exclamation-triangle fa-2x"></i>
                <p>Failed to load configurations</p>
            </div>
        `;
        
    } catch (error) {
        configListElement.innerHTML = `
            <div class="text-center text-danger mt-4">
                <i class="fas fa-exclamation-circle fa-2x"></i>
                <p>Error: ${error.message}</p>
            </div>
        `;
    }
}

// Create configuration card HTML
function createConfigCard(endpoint, config) {
    return `
        <div class="config-item">
            <h6>${endpoint.name}</h6>
            <div class="config-meta">
                <span class="badge bg-primary">${endpoint.endpoint_type}</span>
                <span class="badge bg-info">${endpoint.ip_address}</span>
                <span class="badge bg-secondary">Network: ${endpoint.vpn_network?.name || 'Unknown'}</span>
            </div>
            <div class="config-actions">
                <button class="btn btn-sm btn-outline-primary" onclick="viewConfig('${endpoint.name}', '${btoa(config)}')">
                    <i class="fas fa-eye"></i> View
                </button>
                <button class="btn btn-sm btn-outline-success" onclick="testConfig('${endpoint.id}')">
                    <i class="fas fa-vial"></i> Test
                </button>
                <button class="btn btn-sm btn-outline-info" onclick="generateQR('${endpoint.id}')">
                    <i class="fas fa-qrcode"></i> QR
                </button>
            </div>
        </div>
    `;
}

// Configuration actions
function viewConfig(name, encodedConfig) {
    const config = atob(encodedConfig);
    const modal = document.createElement('div');
    modal.innerHTML = `
        <div class="modal fade" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Configuration: ${name}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <textarea class="form-control" rows="15" readonly>${config}</textarea>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                        <button type="button" class="btn btn-primary" onclick="copyToClipboard('${encodedConfig}')">
                            <i class="fas fa-copy"></i> Copy
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    const bootstrapModal = new bootstrap.Modal(modal.querySelector('.modal'));
    bootstrapModal.show();
    
    modal.addEventListener('hidden.bs.modal', function() {
        document.body.removeChild(modal);
    });
}

function copyToClipboard(encodedConfig) {
    const config = atob(encodedConfig);
    navigator.clipboard.writeText(config).then(() => {
        alert('Configuration copied to clipboard!');
    }).catch(err => {
        console.error('Failed to copy:', err);
        alert('Failed to copy configuration');
    });
}

async function testConfig(endpointId) {
    alert(`Testing endpoint ${endpointId} - This would run connectivity tests`);
    // TODO: Implement actual connectivity testing
}

async function generateQR(endpointId) {
    try {
        const qrData = await gatewayAPI.getEndpointQR(endpointId);
        
        const modal = document.createElement('div');
        modal.innerHTML = `
            <div class="modal fade" tabindex="-1">
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">QR Code</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body text-center">
                            <img src="data:image/png;base64,${qrData.qr_code}" alt="QR Code" class="img-fluid">
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        const bootstrapModal = new bootstrap.Modal(modal.querySelector('.modal'));
        bootstrapModal.show();
        
        modal.addEventListener('hidden.bs.modal', function() {
            document.body.removeChild(modal);
        });
        
    } catch (error) {
        alert('Failed to generate QR code: ' + error.message);
    }
}