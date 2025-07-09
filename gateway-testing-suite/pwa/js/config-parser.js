// WireGuard Configuration Parser for KahLuna WARP

/**
 * Parse WireGuard configuration text into structured object
 * @param {string} configText - Raw WireGuard configuration
 * @returns {Object} Parsed configuration object
 */
function parseWireGuardConfig(configText) {
    if (!configText || typeof configText !== 'string') {
        throw new Error('Invalid configuration text');
    }

    const config = {
        Interface: {},
        Peer: {},
        raw: configText.trim()
    };

    const lines = configText.split('\n').map(line => line.trim());
    let currentSection = null;

    for (const line of lines) {
        // Skip empty lines and comments
        if (!line || line.startsWith('#') || line.startsWith(';')) {
            continue;
        }

        // Check for section headers
        if (line.startsWith('[') && line.endsWith(']')) {
            currentSection = line.slice(1, -1);
            if (!config[currentSection]) {
                config[currentSection] = {};
            }
            continue;
        }

        // Parse key-value pairs
        const equalIndex = line.indexOf('=');
        if (equalIndex > 0 && currentSection) {
            const key = line.slice(0, equalIndex).trim();
            const value = line.slice(equalIndex + 1).trim();
            
            // Handle multi-value fields (like AllowedIPs)
            if (config[currentSection][key]) {
                if (Array.isArray(config[currentSection][key])) {
                    config[currentSection][key].push(value);
                } else {
                    config[currentSection][key] = [config[currentSection][key], value];
                }
            } else {
                config[currentSection][key] = value;
            }
        }
    }

    // Validate required fields
    validateWireGuardConfig(config);

    return config;
}

/**
 * Validate WireGuard configuration structure
 * @param {Object} config - Parsed configuration object
 */
function validateWireGuardConfig(config) {
    const errors = [];

    // Check for required Interface fields
    if (!config.Interface) {
        errors.push('Missing [Interface] section');
    } else {
        if (!config.Interface.PrivateKey) {
            errors.push('Missing PrivateKey in Interface section');
        }
        if (!config.Interface.Address) {
            errors.push('Missing Address in Interface section');
        }
    }

    // Check for required Peer fields
    if (!config.Peer) {
        errors.push('Missing [Peer] section');
    } else {
        if (!config.Peer.PublicKey) {
            errors.push('Missing PublicKey in Peer section');
        }
        if (!config.Peer.Endpoint) {
            errors.push('Missing Endpoint in Peer section');
        }
        if (!config.Peer.AllowedIPs) {
            errors.push('Missing AllowedIPs in Peer section');
        }
    }

    if (errors.length > 0) {
        throw new Error('Configuration validation failed: ' + errors.join(', '));
    }
}

/**
 * Generate WireGuard configuration text from object
 * @param {Object} config - Configuration object
 * @returns {string} WireGuard configuration text
 */
function generateWireGuardConfig(config) {
    let configText = '';

    // Generate Interface section
    if (config.Interface) {
        configText += '[Interface]\n';
        
        // Order interface fields logically
        const interfaceOrder = ['PrivateKey', 'Address', 'DNS', 'MTU', 'Table', 'PreUp', 'PostUp', 'PreDown', 'PostDown'];
        
        for (const key of interfaceOrder) {
            if (config.Interface[key]) {
                const value = Array.isArray(config.Interface[key]) 
                    ? config.Interface[key].join(', ') 
                    : config.Interface[key];
                configText += `${key} = ${value}\n`;
            }
        }
        
        // Add any additional interface fields
        for (const [key, value] of Object.entries(config.Interface)) {
            if (!interfaceOrder.includes(key)) {
                const val = Array.isArray(value) ? value.join(', ') : value;
                configText += `${key} = ${val}\n`;
            }
        }
        
        configText += '\n';
    }

    // Generate Peer section
    if (config.Peer) {
        configText += '[Peer]\n';
        
        // Order peer fields logically
        const peerOrder = ['PublicKey', 'PresharedKey', 'Endpoint', 'AllowedIPs', 'PersistentKeepalive'];
        
        for (const key of peerOrder) {
            if (config.Peer[key]) {
                const value = Array.isArray(config.Peer[key]) 
                    ? config.Peer[key].join(', ') 
                    : config.Peer[key];
                configText += `${key} = ${value}\n`;
            }
        }
        
        // Add any additional peer fields
        for (const [key, value] of Object.entries(config.Peer)) {
            if (!peerOrder.includes(key)) {
                const val = Array.isArray(value) ? value.join(', ') : value;
                configText += `${key} = ${val}\n`;
            }
        }
    }

    return configText.trim();
}

/**
 * Extract configuration metadata for display
 * @param {Object} config - Parsed configuration object
 * @returns {Object} Configuration metadata
 */
function extractConfigMetadata(config) {
    const metadata = {
        isValid: false,
        networkType: 'unknown',
        serverEndpoint: null,
        clientAddress: null,
        allowedIPs: null,
        dnsServers: null,
        keepalive: null,
        mtu: null
    };

    try {
        validateWireGuardConfig(config);
        metadata.isValid = true;
    } catch (error) {
        metadata.validationError = error.message;
        return metadata;
    }

    // Extract basic information
    if (config.Interface) {
        metadata.clientAddress = config.Interface.Address;
        metadata.dnsServers = config.Interface.DNS;
        metadata.mtu = config.Interface.MTU;
    }

    if (config.Peer) {
        metadata.serverEndpoint = config.Peer.Endpoint;
        metadata.allowedIPs = config.Peer.AllowedIPs;
        metadata.keepalive = config.Peer.PersistentKeepalive;
    }

    // Determine network type based on AllowedIPs
    if (metadata.allowedIPs) {
        const allowedIPs = Array.isArray(metadata.allowedIPs) 
            ? metadata.allowedIPs.join(',') 
            : metadata.allowedIPs;
            
        if (allowedIPs.includes('0.0.0.0/0') || allowedIPs.includes('::/0')) {
            metadata.networkType = 'full-tunnel';
        } else {
            metadata.networkType = 'split-tunnel';
        }
    }

    return metadata;
}

/**
 * Compare two WireGuard configurations
 * @param {Object} config1 - First configuration
 * @param {Object} config2 - Second configuration
 * @returns {Object} Comparison result
 */
function compareConfigurations(config1, config2) {
    const comparison = {
        identical: false,
        differences: [],
        summary: {}
    };

    // Compare Interface sections
    if (config1.Interface && config2.Interface) {
        for (const key of new Set([...Object.keys(config1.Interface), ...Object.keys(config2.Interface)])) {
            const val1 = config1.Interface[key];
            const val2 = config2.Interface[key];
            
            if (val1 !== val2) {
                comparison.differences.push({
                    section: 'Interface',
                    key: key,
                    value1: val1,
                    value2: val2
                });
            }
        }
    }

    // Compare Peer sections
    if (config1.Peer && config2.Peer) {
        for (const key of new Set([...Object.keys(config1.Peer), ...Object.keys(config2.Peer)])) {
            const val1 = config1.Peer[key];
            const val2 = config2.Peer[key];
            
            if (val1 !== val2) {
                comparison.differences.push({
                    section: 'Peer',
                    key: key,
                    value1: val1,
                    value2: val2
                });
            }
        }
    }

    comparison.identical = comparison.differences.length === 0;
    comparison.summary = {
        totalDifferences: comparison.differences.length,
        interfaceDifferences: comparison.differences.filter(d => d.section === 'Interface').length,
        peerDifferences: comparison.differences.filter(d => d.section === 'Peer').length
    };

    return comparison;
}

/**
 * Sanitize configuration for safe display (remove sensitive data)
 * @param {Object} config - Configuration object
 * @returns {Object} Sanitized configuration
 */
function sanitizeConfigForDisplay(config) {
    const sanitized = JSON.parse(JSON.stringify(config)); // Deep clone

    // Mask private key
    if (sanitized.Interface && sanitized.Interface.PrivateKey) {
        sanitized.Interface.PrivateKey = '***PRIVATE_KEY***';
    }

    // Optionally mask preshared key
    if (sanitized.Peer && sanitized.Peer.PresharedKey) {
        sanitized.Peer.PresharedKey = '***PRESHARED_KEY***';
    }

    return sanitized;
}

/**
 * Convert configuration to QR code data
 * @param {Object} config - Configuration object
 * @returns {string} QR code data string
 */
function configToQRData(config) {
    return generateWireGuardConfig(config);
}

/**
 * Create a new configuration from template
 * @param {string} networkType - Type of network (secure_internet, etc.)
 * @param {Object} options - Configuration options
 * @returns {Object} Generated configuration
 */
function createConfigFromTemplate(networkType, options = {}) {
    const templates = {
        secure_internet: {
            Interface: {
                Address: options.address || '10.0.0.2/32',
                DNS: options.dns || '1.1.1.1, 8.8.8.8',
                PrivateKey: options.privateKey || 'GENERATE_PRIVATE_KEY'
            },
            Peer: {
                PublicKey: options.serverPublicKey || 'SERVER_PUBLIC_KEY',
                Endpoint: options.endpoint || 'vpn.example.com:51820',
                AllowedIPs: '0.0.0.0/0, ::/0',
                PersistentKeepalive: '25'
            }
        },
        split_tunnel: {
            Interface: {
                Address: options.address || '10.0.0.2/32',
                DNS: options.dns || '10.0.0.1',
                PrivateKey: options.privateKey || 'GENERATE_PRIVATE_KEY'
            },
            Peer: {
                PublicKey: options.serverPublicKey || 'SERVER_PUBLIC_KEY',
                Endpoint: options.endpoint || 'gateway.example.com:51820',
                AllowedIPs: options.allowedIPs || '10.0.0.0/8, 192.168.0.0/16',
                PersistentKeepalive: '25'
            }
        }
    };

    const template = templates[networkType];
    if (!template) {
        throw new Error(`Unknown network type: ${networkType}`);
    }

    return JSON.parse(JSON.stringify(template)); // Deep clone
}

// Configuration storage management
class ConfigurationManager {
    constructor() {
        this.storageKey = 'warp-configurations';
    }

    // Save configuration to local storage
    saveConfiguration(name, config, metadata = {}) {
        const configurations = this.getConfigurations();
        const configData = {
            id: Date.now().toString(),
            name: name,
            config: config,
            metadata: {
                ...metadata,
                created: new Date().toISOString(),
                lastModified: new Date().toISOString()
            }
        };

        configurations.push(configData);
        localStorage.setItem(this.storageKey, JSON.stringify(configurations));
        return configData.id;
    }

    // Get all saved configurations
    getConfigurations() {
        try {
            const data = localStorage.getItem(this.storageKey);
            return data ? JSON.parse(data) : [];
        } catch (error) {
            console.error('Error loading configurations:', error);
            return [];
        }
    }

    // Get specific configuration by ID
    getConfiguration(id) {
        const configurations = this.getConfigurations();
        return configurations.find(config => config.id === id);
    }

    // Update configuration
    updateConfiguration(id, updates) {
        const configurations = this.getConfigurations();
        const index = configurations.findIndex(config => config.id === id);
        
        if (index >= 0) {
            configurations[index] = {
                ...configurations[index],
                ...updates,
                metadata: {
                    ...configurations[index].metadata,
                    lastModified: new Date().toISOString()
                }
            };
            
            localStorage.setItem(this.storageKey, JSON.stringify(configurations));
            return configurations[index];
        }
        
        return null;
    }

    // Delete configuration
    deleteConfiguration(id) {
        const configurations = this.getConfigurations();
        const filtered = configurations.filter(config => config.id !== id);
        localStorage.setItem(this.storageKey, JSON.stringify(filtered));
        return filtered.length < configurations.length;
    }

    // Clear all configurations
    clearAll() {
        localStorage.removeItem(this.storageKey);
    }

    // Export configurations
    exportConfigurations() {
        const configurations = this.getConfigurations();
        const exportData = {
            version: '1.0',
            exported: new Date().toISOString(),
            configurations: configurations
        };
        
        return JSON.stringify(exportData, null, 2);
    }

    // Import configurations
    importConfigurations(exportData) {
        try {
            const data = typeof exportData === 'string' ? JSON.parse(exportData) : exportData;
            
            if (data.configurations && Array.isArray(data.configurations)) {
                const currentConfigs = this.getConfigurations();
                const mergedConfigs = [...currentConfigs, ...data.configurations];
                localStorage.setItem(this.storageKey, JSON.stringify(mergedConfigs));
                return data.configurations.length;
            }
            
            throw new Error('Invalid export data format');
        } catch (error) {
            console.error('Error importing configurations:', error);
            throw error;
        }
    }
}

// Global configuration manager instance
const configManager = new ConfigurationManager();

// Initialize config parser functionality
function initializeConfigParser() {
    // Add manual configuration functionality
    document.getElementById('addManualConfig').addEventListener('click', function() {
        showManualConfigDialog();
    });
    
    console.log('Configuration parser initialized');
}

function showManualConfigDialog() {
    // Create modal for manual configuration entry
    const modal = document.createElement('div');
    modal.innerHTML = `
        <div class="modal fade" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Add Manual Configuration</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label">Configuration Name</label>
                            <input type="text" class="form-control" id="manualConfigName" placeholder="My VPN Config">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">WireGuard Configuration</label>
                            <textarea class="form-control" id="manualConfigText" rows="15" placeholder="[Interface]&#10;PrivateKey = ...&#10;Address = ...&#10;&#10;[Peer]&#10;PublicKey = ...&#10;Endpoint = ..."></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-primary" id="saveManualConfig">Save Configuration</button>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    const bootstrapModal = new bootstrap.Modal(modal.querySelector('.modal'));
    bootstrapModal.show();
    
    // Handle save
    modal.querySelector('#saveManualConfig').addEventListener('click', function() {
        const name = modal.querySelector('#manualConfigName').value.trim();
        const configText = modal.querySelector('#manualConfigText').value.trim();
        
        if (!name) {
            alert('Please enter a configuration name');
            return;
        }
        
        if (!configText) {
            alert('Please enter a configuration');
            return;
        }
        
        try {
            const config = parseWireGuardConfig(configText);
            const metadata = extractConfigMetadata(config);
            
            configManager.saveConfiguration(name, config, {
                source: 'manual',
                ...metadata
            });
            
            bootstrapModal.hide();
            alert('Configuration saved successfully!');
            
            // Refresh config list if visible
            if (document.getElementById('configs').classList.contains('active')) {
                fetchAndDisplayConfigs();
            }
            
        } catch (error) {
            alert('Invalid configuration: ' + error.message);
        }
    });
    
    modal.addEventListener('hidden.bs.modal', function() {
        document.body.removeChild(modal);
    });
}

// Export functions for global use
window.parseWireGuardConfig = parseWireGuardConfig;
window.generateWireGuardConfig = generateWireGuardConfig;
window.extractConfigMetadata = extractConfigMetadata;
window.compareConfigurations = compareConfigurations;
window.sanitizeConfigForDisplay = sanitizeConfigForDisplay;
window.configToQRData = configToQRData;
window.createConfigFromTemplate = createConfigFromTemplate;
window.configManager = configManager;
window.initializeConfigParser = initializeConfigParser;