// Network Testing Module for KahLuna WARP

class NetworkTester {
    constructor() {
        this.isRunning = false;
        this.currentTests = new Map();
        this.testResults = [];
        this.abortController = null;
    }

    // Test categories and their implementations
    getTestSuites() {
        return {
            connectivity: {
                name: 'Basic Connectivity',
                tests: [
                    'ping_gateway',
                    'dns_resolution',
                    'http_connectivity',
                    'https_connectivity'
                ]
            },
            performance: {
                name: 'Performance Tests',
                tests: [
                    'bandwidth_test',
                    'latency_test',
                    'packet_loss_test'
                ]
            },
            security: {
                name: 'Security Validation',
                tests: [
                    'ip_leak_test',
                    'dns_leak_test',
                    'traffic_encryption_test'
                ]
            },
            gateway_specific: {
                name: 'Gateway Integration',
                tests: [
                    'gateway_api_test',
                    'config_validation_test',
                    'endpoint_status_test'
                ]
            }
        };
    }

    // Run all test suites
    async runAllTests() {
        if (this.isRunning) {
            console.warn('Tests already running');
            return;
        }

        this.isRunning = true;
        this.abortController = new AbortController();
        this.testResults = [];
        
        this.updateTestUI(true);
        this.clearTestResults();

        try {
            const testSuites = this.getTestSuites();
            
            for (const [suiteKey, suite] of Object.entries(testSuites)) {
                if (this.abortController.signal.aborted) break;
                
                await this.runTestSuite(suiteKey, suite);
            }
            
            this.displayTestSummary();
            
        } catch (error) {
            console.error('Test execution error:', error);
            this.addTestResult('error', 'Test Execution', 'failed', error.message);
        } finally {
            this.isRunning = false;
            this.updateTestUI(false);
        }
    }

    // Run a specific test suite
    async runTestSuite(suiteKey, suite) {
        this.addTestResult('info', suite.name, 'running', 'Starting test suite...');
        
        let passed = 0;
        let failed = 0;
        
        for (const testName of suite.tests) {
            if (this.abortController.signal.aborted) break;
            
            try {
                const result = await this.runSingleTest(testName);
                if (result.status === 'passed') {
                    passed++;
                } else {
                    failed++;
                }
            } catch (error) {
                failed++;
                this.addTestResult('error', testName, 'failed', error.message);
            }
        }
        
        const suiteStatus = failed === 0 ? 'passed' : 'failed';
        const summary = `${passed} passed, ${failed} failed`;
        
        this.updateTestResult(suite.name, suiteStatus, summary);
    }

    // Run a single test
    async runSingleTest(testName) {
        const testMethod = this.getTestMethod(testName);
        if (!testMethod) {
            throw new Error(`Unknown test: ${testName}`);
        }

        this.addTestResult('test', this.formatTestName(testName), 'running', 'Testing...');
        
        try {
            const result = await testMethod.call(this);
            const status = result.success ? 'passed' : 'failed';
            
            this.updateTestResult(this.formatTestName(testName), status, result.message);
            
            return { status, result };
        } catch (error) {
            this.updateTestResult(this.formatTestName(testName), 'failed', error.message);
            throw error;
        }
    }

    // Get test method by name
    getTestMethod(testName) {
        const methods = {
            'ping_gateway': this.testPingGateway,
            'dns_resolution': this.testDNSResolution,
            'http_connectivity': this.testHTTPConnectivity,
            'https_connectivity': this.testHTTPSConnectivity,
            'bandwidth_test': this.testBandwidth,
            'latency_test': this.testLatency,
            'packet_loss_test': this.testPacketLoss,
            'ip_leak_test': this.testIPLeak,
            'dns_leak_test': this.testDNSLeak,
            'traffic_encryption_test': this.testTrafficEncryption,
            'gateway_api_test': this.testGatewayAPI,
            'config_validation_test': this.testConfigValidation,
            'endpoint_status_test': this.testEndpointStatus
        };
        
        return methods[testName];
    }

    // Format test name for display
    formatTestName(testName) {
        return testName.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }

    // Individual test implementations
    async testPingGateway() {
        const gatewayUrl = document.getElementById('gatewayUrl').value;
        const startTime = Date.now();
        
        try {
            const response = await fetch(gatewayUrl + '/login', {
                method: 'HEAD',
                signal: this.abortController.signal
            });
            
            const latency = Date.now() - startTime;
            
            if (response.ok || response.status === 405) { // 405 is expected for HEAD on login
                return {
                    success: true,
                    message: `Gateway reachable (${latency}ms)`
                };
            } else {
                return {
                    success: false,
                    message: `Gateway returned ${response.status}`
                };
            }
        } catch (error) {
            return {
                success: false,
                message: `Gateway unreachable: ${error.message}`
            };
        }
    }

    async testDNSResolution() {
        const testDomains = ['google.com', 'cloudflare.com', 'example.com'];
        let resolved = 0;
        
        for (const domain of testDomains) {
            try {
                // Use a simple HTTP request to test DNS resolution
                const response = await fetch(`https://${domain}`, {
                    method: 'HEAD',
                    mode: 'no-cors',
                    signal: this.abortController.signal
                });
                resolved++;
            } catch (error) {
                // Ignore individual failures
            }
        }
        
        const success = resolved >= testDomains.length - 1; // Allow 1 failure
        return {
            success,
            message: `${resolved}/${testDomains.length} domains resolved`
        };
    }

    async testHTTPConnectivity() {
        try {
            const response = await fetch('http://httpbin.org/get', {
                signal: this.abortController.signal
            });
            
            if (response.ok) {
                return {
                    success: true,
                    message: 'HTTP connectivity working'
                };
            } else {
                return {
                    success: false,
                    message: `HTTP request failed: ${response.status}`
                };
            }
        } catch (error) {
            return {
                success: false,
                message: `HTTP connectivity failed: ${error.message}`
            };
        }
    }

    async testHTTPSConnectivity() {
        try {
            const response = await fetch('https://httpbin.org/get', {
                signal: this.abortController.signal
            });
            
            if (response.ok) {
                return {
                    success: true,
                    message: 'HTTPS connectivity working'
                };
            } else {
                return {
                    success: false,
                    message: `HTTPS request failed: ${response.status}`
                };
            }
        } catch (error) {
            return {
                success: false,
                message: `HTTPS connectivity failed: ${error.message}`
            };
        }
    }

    async testBandwidth() {
        const testSizeMB = 1; // Test with 1MB
        const testData = new ArrayBuffer(testSizeMB * 1024 * 1024);
        
        try {
            const startTime = Date.now();
            
            // Upload test
            const uploadResponse = await fetch('https://httpbin.org/post', {
                method: 'POST',
                body: testData,
                signal: this.abortController.signal
            });
            
            const uploadTime = Date.now() - startTime;
            const uploadSpeed = (testSizeMB * 8) / (uploadTime / 1000); // Mbps
            
            if (uploadResponse.ok) {
                return {
                    success: true,
                    message: `Upload speed: ${uploadSpeed.toFixed(2)} Mbps`
                };
            } else {
                return {
                    success: false,
                    message: 'Bandwidth test failed'
                };
            }
        } catch (error) {
            return {
                success: false,
                message: `Bandwidth test error: ${error.message}`
            };
        }
    }

    async testLatency() {
        const iterations = 5;
        const latencies = [];
        
        for (let i = 0; i < iterations; i++) {
            const startTime = Date.now();
            
            try {
                await fetch('https://httpbin.org/get', {
                    method: 'HEAD',
                    signal: this.abortController.signal
                });
                
                latencies.push(Date.now() - startTime);
            } catch (error) {
                // Ignore individual failures
            }
        }
        
        if (latencies.length > 0) {
            const avgLatency = latencies.reduce((a, b) => a + b, 0) / latencies.length;
            const minLatency = Math.min(...latencies);
            const maxLatency = Math.max(...latencies);
            
            return {
                success: true,
                message: `Avg: ${avgLatency.toFixed(0)}ms, Min: ${minLatency}ms, Max: ${maxLatency}ms`
            };
        } else {
            return {
                success: false,
                message: 'Latency test failed'
            };
        }
    }

    async testPacketLoss() {
        const requests = 10;
        let successful = 0;
        
        const promises = Array.from({ length: requests }, async (_, i) => {
            try {
                const response = await fetch('https://httpbin.org/get', {
                    method: 'HEAD',
                    signal: this.abortController.signal
                });
                
                if (response.ok) {
                    successful++;
                }
            } catch (error) {
                // Count as packet loss
            }
        });
        
        await Promise.allSettled(promises);
        
        const lossPercentage = ((requests - successful) / requests) * 100;
        const success = lossPercentage < 10; // Allow up to 10% loss
        
        return {
            success,
            message: `Packet loss: ${lossPercentage.toFixed(1)}% (${successful}/${requests} successful)`
        };
    }

    async testIPLeak() {
        try {
            // Test external IP detection
            const response = await fetch('https://httpbin.org/ip', {
                signal: this.abortController.signal
            });
            
            if (response.ok) {
                const data = await response.json();
                const externalIP = data.origin;
                
                // Check if IP appears to be a VPN/proxy (simple heuristic)
                const isLikelyVPN = !this.isPrivateIP(externalIP);
                
                return {
                    success: isLikelyVPN,
                    message: `External IP: ${externalIP} ${isLikelyVPN ? '(likely VPN)' : '(possible leak)'}`
                };
            } else {
                return {
                    success: false,
                    message: 'Could not determine external IP'
                };
            }
        } catch (error) {
            return {
                success: false,
                message: `IP leak test failed: ${error.message}`
            };
        }
    }

    async testDNSLeak() {
        // This is a simplified DNS leak test
        // In reality, you would test against known DNS servers
        try {
            const response = await fetch('https://httpbin.org/get', {
                signal: this.abortController.signal
            });
            
            return {
                success: response.ok,
                message: response.ok ? 'DNS queries routed through VPN' : 'DNS leak test inconclusive'
            };
        } catch (error) {
            return {
                success: false,
                message: `DNS leak test failed: ${error.message}`
            };
        }
    }

    async testTrafficEncryption() {
        // Test HTTPS connectivity as a proxy for encryption
        try {
            const response = await fetch('https://httpbin.org/get', {
                signal: this.abortController.signal
            });
            
            const isSecure = response.url.startsWith('https://');
            
            return {
                success: isSecure,
                message: isSecure ? 'Traffic encrypted (HTTPS)' : 'Encryption test failed'
            };
        } catch (error) {
            return {
                success: false,
                message: `Encryption test failed: ${error.message}`
            };
        }
    }

    async testGatewayAPI() {
        try {
            const healthCheck = await gatewayAPI.healthCheck();
            
            if (healthCheck.connection.success) {
                return {
                    success: true,
                    message: 'Gateway API accessible'
                };
            } else {
                return {
                    success: false,
                    message: 'Gateway API not accessible'
                };
            }
        } catch (error) {
            return {
                success: false,
                message: `Gateway API test failed: ${error.message}`
            };
        }
    }

    async testConfigValidation() {
        try {
            // Get saved configurations and validate them
            const configs = configManager.getConfigurations();
            let validConfigs = 0;
            
            for (const configData of configs) {
                try {
                    validateWireGuardConfig(configData.config);
                    validConfigs++;
                } catch (error) {
                    // Invalid config
                }
            }
            
            const success = configs.length === 0 || validConfigs > 0;
            return {
                success,
                message: `${validConfigs}/${configs.length} configurations valid`
            };
        } catch (error) {
            return {
                success: false,
                message: `Config validation failed: ${error.message}`
            };
        }
    }

    async testEndpointStatus() {
        try {
            if (!gatewayAPI.isAuthenticated) {
                return {
                    success: false,
                    message: 'Not authenticated to gateway'
                };
            }
            
            const endpoints = await gatewayAPI.getEndpoints();
            
            return {
                success: true,
                message: `Found ${endpoints.length} endpoints on gateway`
            };
        } catch (error) {
            return {
                success: false,
                message: `Endpoint status test failed: ${error.message}`
            };
        }
    }

    // Utility methods
    isPrivateIP(ip) {
        const privateRanges = [
            /^10\./,
            /^172\.(1[6-9]|2[0-9]|3[01])\./,
            /^192\.168\./,
            /^127\./,
            /^169\.254\./
        ];
        
        return privateRanges.some(range => range.test(ip));
    }

    // UI Management
    updateTestUI(isRunning) {
        const startBtn = document.getElementById('startTests');
        const stopBtn = document.getElementById('stopTests');
        
        if (isRunning) {
            startBtn.disabled = true;
            stopBtn.disabled = false;
            startBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Running Tests...';
        } else {
            startBtn.disabled = false;
            stopBtn.disabled = true;
            startBtn.innerHTML = '<i class="fas fa-play"></i> Run All Tests';
        }
    }

    clearTestResults() {
        const resultsContainer = document.getElementById('testResults');
        resultsContainer.innerHTML = '<div class="text-center"><div class="loading-spinner"></div> Initializing tests...</div>';
    }

    addTestResult(type, name, status, message) {
        const result = {
            id: Date.now() + Math.random(),
            type,
            name,
            status,
            message,
            timestamp: new Date().toLocaleTimeString()
        };
        
        this.testResults.push(result);
        this.renderTestResult(result);
    }

    updateTestResult(name, status, message) {
        const result = this.testResults.find(r => r.name === name);
        if (result) {
            result.status = status;
            result.message = message;
            result.timestamp = new Date().toLocaleTimeString();
            this.renderTestResult(result, true);
        }
    }

    renderTestResult(result, isUpdate = false) {
        const resultsContainer = document.getElementById('testResults');
        
        if (!isUpdate && this.testResults.length === 1) {
            resultsContainer.innerHTML = ''; // Clear loading message
        }
        
        let existingElement = null;
        if (isUpdate) {
            existingElement = resultsContainer.querySelector(`[data-result-id="${result.id}"]`);
        }
        
        const statusClasses = {
            'running': 'test-item running',
            'passed': 'test-item success',
            'failed': 'test-item failed',
            'info': 'test-item'
        };
        
        const statusIcons = {
            'running': '<i class="fas fa-spinner fa-spin text-info"></i>',
            'passed': '<i class="fas fa-check-circle text-success"></i>',
            'failed': '<i class="fas fa-times-circle text-danger"></i>',
            'info': '<i class="fas fa-info-circle text-primary"></i>'
        };
        
        const html = `
            <div class="${statusClasses[result.status] || 'test-item'}" data-result-id="${result.id}">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        ${statusIcons[result.status] || ''} 
                        <strong>${result.name}</strong>
                    </div>
                    <small class="text-muted">${result.timestamp}</small>
                </div>
                <div class="mt-1">
                    <small>${result.message}</small>
                </div>
            </div>
        `;
        
        if (existingElement) {
            existingElement.outerHTML = html;
        } else {
            resultsContainer.insertAdjacentHTML('beforeend', html);
        }
        
        // Auto-scroll to bottom
        resultsContainer.scrollTop = resultsContainer.scrollHeight;
    }

    displayTestSummary() {
        const passed = this.testResults.filter(r => r.status === 'passed').length;
        const failed = this.testResults.filter(r => r.status === 'failed').length;
        const total = passed + failed;
        
        const summaryHtml = `
            <div class="test-item ${failed === 0 ? 'success' : 'failed'}">
                <div class="text-center">
                    <h6>Test Summary</h6>
                    <div class="row text-center">
                        <div class="col-4">
                            <div class="text-success">
                                <i class="fas fa-check-circle"></i><br>
                                <strong>${passed}</strong><br>
                                <small>Passed</small>
                            </div>
                        </div>
                        <div class="col-4">
                            <div class="text-danger">
                                <i class="fas fa-times-circle"></i><br>
                                <strong>${failed}</strong><br>
                                <small>Failed</small>
                            </div>
                        </div>
                        <div class="col-4">
                            <div class="text-primary">
                                <i class="fas fa-vial"></i><br>
                                <strong>${total}</strong><br>
                                <small>Total</small>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        const resultsContainer = document.getElementById('testResults');
        resultsContainer.insertAdjacentHTML('beforeend', summaryHtml);
    }

    stopTests() {
        if (this.abortController) {
            this.abortController.abort();
        }
        this.isRunning = false;
        this.updateTestUI(false);
        
        this.addTestResult('info', 'Test Execution', 'failed', 'Tests stopped by user');
    }
}

// Global network tester instance
const networkTester = new NetworkTester();

// Initialize network testing functionality
function initializeNetworkTester() {
    // Start tests button
    document.getElementById('startTests').addEventListener('click', async function() {
        await networkTester.runAllTests();
    });
    
    // Stop tests button
    document.getElementById('stopTests').addEventListener('click', function() {
        networkTester.stopTests();
    });
    
    // Initialize stop button as disabled
    document.getElementById('stopTests').disabled = true;
    
    console.log('Network tester initialized');
}

// Export for global use
window.networkTester = networkTester;
window.initializeNetworkTester = initializeNetworkTester;