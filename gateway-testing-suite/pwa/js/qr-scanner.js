// KahLuna WARP QR Scanner Module

class QRScanner {
    constructor() {
        this.html5QrCode = null;
        this.isScanning = false;
        this.cameras = [];
        this.selectedCameraId = null;
    }

    async initialize() {
        try {
            // Get available cameras
            this.cameras = await Html5Qrcode.getCameras();
            
            if (this.cameras && this.cameras.length > 0) {
                // Prefer back camera if available
                const backCamera = this.cameras.find(camera => 
                    camera.label.toLowerCase().includes('back') || 
                    camera.label.toLowerCase().includes('rear')
                );
                this.selectedCameraId = backCamera ? backCamera.id : this.cameras[0].id;
                
                console.log(`Found ${this.cameras.length} cameras. Selected: ${this.selectedCameraId}`);
            } else {
                console.warn('No cameras found');
            }
        } catch (error) {
            console.error('Error initializing QR scanner:', error);
        }
    }

    async startScanning() {
        if (this.isScanning) {
            console.warn('Scanner already running');
            return;
        }

        try {
            if (!this.cameras || this.cameras.length === 0) {
                throw new Error('No cameras available');
            }

            this.html5QrCode = new Html5Qrcode("qr-reader");
            
            const config = {
                fps: 10,
                qrbox: { width: 250, height: 250 },
                aspectRatio: 1.0
            };

            await this.html5QrCode.start(
                this.selectedCameraId,
                config,
                (decodedText, decodedResult) => {
                    this.onScanSuccess(decodedText, decodedResult);
                },
                (errorMessage) => {
                    // Handle scan errors silently unless needed for debugging
                    // console.log('Scan error:', errorMessage);
                }
            );

            this.isScanning = true;
            this.updateScannerUI(true);
            console.log('QR scanner started successfully');

        } catch (error) {
            console.error('Error starting QR scanner:', error);
            this.showScanError('Failed to start camera: ' + error.message);
        }
    }

    async stopScanning() {
        if (!this.isScanning || !this.html5QrCode) {
            return;
        }

        try {
            await this.html5QrCode.stop();
            this.html5QrCode.clear();
            this.html5QrCode = null;
            this.isScanning = false;
            this.updateScannerUI(false);
            console.log('QR scanner stopped');
        } catch (error) {
            console.error('Error stopping QR scanner:', error);
        }
    }

    async scanFromFile(file) {
        try {
            if (!this.html5QrCode) {
                this.html5QrCode = new Html5Qrcode("qr-reader");
            }

            const result = await this.html5QrCode.scanFile(file, true);
            this.onScanSuccess(result, null);
            return result;
        } catch (error) {
            console.error('Error scanning file:', error);
            this.showScanError('Failed to scan QR code from image: ' + error.message);
            throw error;
        }
    }

    onScanSuccess(decodedText, decodedResult) {
        console.log('QR Code scanned:', decodedText);
        
        // Stop scanning after successful scan
        this.stopScanning();
        
        // Check if this looks like a WireGuard configuration
        if (this.isWireGuardConfig(decodedText)) {
            this.displayScannedConfig(decodedText);
        } else {
            this.showScanError('Scanned content does not appear to be a WireGuard configuration');
        }
    }

    isWireGuardConfig(text) {
        // Check for WireGuard configuration markers
        const requiredSections = ['[Interface]', '[Peer]'];
        const requiredFields = ['PrivateKey', 'PublicKey', 'Endpoint'];
        
        let hasRequiredSections = requiredSections.every(section => 
            text.includes(section)
        );
        
        let hasRequiredFields = requiredFields.some(field => 
            text.includes(field)
        );
        
        return hasRequiredSections && hasRequiredFields;
    }

    displayScannedConfig(configText) {
        const scanResult = document.getElementById('scanResult');
        const scannedConfig = document.getElementById('scannedConfig');
        
        scannedConfig.value = configText;
        scanResult.style.display = 'block';
        
        // Scroll to result
        scanResult.scrollIntoView({ behavior: 'smooth' });
        
        // Parse and validate configuration
        try {
            const parsedConfig = parseWireGuardConfig(configText);
            this.showConfigInfo(parsedConfig);
        } catch (error) {
            console.error('Error parsing configuration:', error);
        }
    }

    showConfigInfo(config) {
        let infoHtml = '<div class="config-info mt-2">';
        
        if (config.Interface) {
            infoHtml += `<div class="alert alert-info">
                <h6>Configuration Details:</h6>
                <ul>`;
            
            if (config.Interface.Address) {
                infoHtml += `<li><strong>Address:</strong> ${config.Interface.Address}</li>`;
            }
            if (config.Interface.DNS) {
                infoHtml += `<li><strong>DNS:</strong> ${config.Interface.DNS}</li>`;
            }
            if (config.Peer && config.Peer.Endpoint) {
                infoHtml += `<li><strong>Server:</strong> ${config.Peer.Endpoint}</li>`;
            }
            if (config.Peer && config.Peer.AllowedIPs) {
                infoHtml += `<li><strong>Allowed IPs:</strong> ${config.Peer.AllowedIPs}</li>`;
            }
            
            infoHtml += '</ul></div>';
        }
        
        infoHtml += '</div>';
        
        const scanResult = document.getElementById('scanResult');
        const existingInfo = scanResult.querySelector('.config-info');
        if (existingInfo) {
            existingInfo.remove();
        }
        
        scanResult.insertAdjacentHTML('beforeend', infoHtml);
    }

    showScanError(message) {
        const scanResult = document.getElementById('scanResult');
        const scannedConfig = document.getElementById('scannedConfig');
        
        scannedConfig.value = '';
        scanResult.style.display = 'block';
        
        const errorHtml = `
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-triangle"></i>
                ${message}
            </div>
        `;
        
        scanResult.innerHTML = `
            <h6>Scan Error</h6>
            ${errorHtml}
        `;
        
        scanResult.scrollIntoView({ behavior: 'smooth' });
    }

    updateScannerUI(isScanning) {
        const startBtn = document.getElementById('startScan');
        const stopBtn = document.getElementById('stopScan');
        
        if (isScanning) {
            startBtn.style.display = 'none';
            stopBtn.style.display = 'inline-block';
        } else {
            startBtn.style.display = 'inline-block';
            stopBtn.style.display = 'none';
        }
    }

    saveConfiguration() {
        const configText = document.getElementById('scannedConfig').value;
        
        if (!configText.trim()) {
            alert('No configuration to save');
            return;
        }

        try {
            // Parse configuration to get name/details
            const config = parseWireGuardConfig(configText);
            
            // Generate a name for the configuration
            let configName = 'Scanned Config';
            if (config.Peer && config.Peer.Endpoint) {
                const endpoint = config.Peer.Endpoint.split(':')[0];
                configName = `Config-${endpoint}`;
            }
            
            configName += `-${new Date().toISOString().slice(0, 10)}`;
            
            // Save to localStorage
            const savedConfigs = JSON.parse(localStorage.getItem('warp-configs') || '[]');
            const newConfig = {
                id: Date.now().toString(),
                name: configName,
                config: configText,
                source: 'qr-scan',
                created: new Date().toISOString(),
                parsed: config
            };
            
            savedConfigs.push(newConfig);
            localStorage.setItem('warp-configs', JSON.stringify(savedConfigs));
            
            // Show success message
            const successHtml = `
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i>
                    Configuration saved as "${configName}"
                </div>
            `;
            
            const scanResult = document.getElementById('scanResult');
            const existingAlert = scanResult.querySelector('.alert');
            if (existingAlert) {
                existingAlert.remove();
            }
            
            scanResult.insertAdjacentHTML('afterbegin', successHtml);
            
            console.log('Configuration saved:', newConfig);
            
        } catch (error) {
            console.error('Error saving configuration:', error);
            alert('Failed to save configuration: ' + error.message);
        }
    }
}

// Global QR scanner instance
const qrScanner = new QRScanner();

// Initialize QR scanner functionality
function initializeQRScanner() {
    // Initialize scanner on page load
    qrScanner.initialize();
    
    // Start scan button
    document.getElementById('startScan').addEventListener('click', async function() {
        await qrScanner.startScanning();
    });
    
    // Stop scan button
    document.getElementById('stopScan').addEventListener('click', async function() {
        await qrScanner.stopScanning();
    });
    
    // File upload for QR image
    document.getElementById('qrFile').addEventListener('change', async function(event) {
        const file = event.target.files[0];
        if (file) {
            try {
                await qrScanner.scanFromFile(file);
            } catch (error) {
                console.error('Failed to scan file:', error);
            }
        }
    });
    
    // Save configuration button
    document.getElementById('saveConfig').addEventListener('click', function() {
        qrScanner.saveConfiguration();
    });
    
    // Hide scan result initially
    document.getElementById('scanResult').style.display = 'none';
}

// Camera permission helper
async function requestCameraPermission() {
    try {
        const stream = await navigator.mediaDevices.getUserMedia({ video: true });
        // Stop the stream immediately, we just wanted to request permission
        stream.getTracks().forEach(track => track.stop());
        return true;
    } catch (error) {
        console.error('Camera permission denied:', error);
        return false;
    }
}

// Check if device supports camera
function hasCameraSupport() {
    return !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia);
}

// Export for use in other modules
window.qrScanner = qrScanner;
window.initializeQRScanner = initializeQRScanner;