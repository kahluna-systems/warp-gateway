// Enterprise Features for Gateway Testing Suite
// Field deployment, fleet management, and professional reporting

class EnterpriseFeatures {
    constructor() {
        this.deviceId = this.getOrCreateDeviceId();
        this.installId = this.getOrCreateInstallId();
        this.fieldTechInfo = this.loadFieldTechInfo();
        this.reportingEnabled = true;
    }

    // Device identification for fleet management
    getOrCreateDeviceId() {
        let deviceId = localStorage.getItem('gts-device-id');
        if (!deviceId) {
            deviceId = 'GTS-' + this.generateUUID();
            localStorage.setItem('gts-device-id', deviceId);
        }
        return deviceId;
    }

    getOrCreateInstallId() {
        let installId = localStorage.getItem('gts-install-id');
        if (!installId) {
            installId = 'INSTALL-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
            localStorage.setItem('gts-install-id', installId);
            this.logInstallEvent();
        }
        return installId;
    }

    generateUUID() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = Math.random() * 16 | 0;
            const v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }

    // Field technician information
    loadFieldTechInfo() {
        return JSON.parse(localStorage.getItem('gts-field-tech-info') || '{}');
    }

    saveFieldTechInfo(info) {
        this.fieldTechInfo = info;
        localStorage.setItem('gts-field-tech-info', JSON.stringify(info));
    }

    // Usage analytics and reporting
    logUsageEvent(eventType, details = {}) {
        if (!this.reportingEnabled) return;

        const event = {
            id: this.generateUUID(),
            timestamp: new Date().toISOString(),
            deviceId: this.deviceId,
            installId: this.installId,
            eventType: eventType,
            userAgent: navigator.userAgent,
            details: details,
            fieldTech: this.fieldTechInfo,
            location: {
                url: window.location.href,
                referrer: document.referrer
            }
        };

        // Store locally for later sync
        this.storeEventLocally(event);

        // Try to send immediately if online
        if (navigator.onLine) {
            this.syncEvents();
        }
    }

    storeEventLocally(event) {
        const events = JSON.parse(localStorage.getItem('gts-pending-events') || '[]');
        events.push(event);
        
        // Keep only last 100 events to prevent storage bloat
        if (events.length > 100) {
            events.splice(0, events.length - 100);
        }
        
        localStorage.setItem('gts-pending-events', JSON.stringify(events));
    }

    async syncEvents() {
        const events = JSON.parse(localStorage.getItem('gts-pending-events') || '[]');
        if (events.length === 0) return;

        try {
            // In a real implementation, this would send to your analytics endpoint
            console.log('Syncing events:', events.length);
            
            // For demo purposes, just log the events
            console.table(events.slice(-5)); // Show last 5 events
            
            // Clear synced events
            localStorage.setItem('gts-pending-events', '[]');
            
        } catch (error) {
            console.warn('Failed to sync analytics events:', error);
        }
    }

    logInstallEvent() {
        this.logUsageEvent('app_install', {
            platform: navigator.platform,
            language: navigator.language,
            timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            screen: {
                width: screen.width,
                height: screen.height,
                colorDepth: screen.colorDepth
            }
        });
    }

    // Professional reporting
    generateTestReport(testResults) {
        const report = {
            id: this.generateUUID(),
            timestamp: new Date().toISOString(),
            deviceId: this.deviceId,
            fieldTech: this.fieldTechInfo,
            testResults: testResults,
            systemInfo: this.getSystemInfo(),
            summary: this.generateTestSummary(testResults)
        };

        this.storeReport(report);
        return report;
    }

    storeReport(report) {
        const reports = JSON.parse(localStorage.getItem('gts-test-reports') || '[]');
        reports.push(report);
        
        // Keep only last 50 reports
        if (reports.length > 50) {
            reports.splice(0, reports.length - 50);
        }
        
        localStorage.setItem('gts-test-reports', JSON.stringify(reports));
        
        this.logUsageEvent('test_report_generated', {
            reportId: report.id,
            testCount: report.testResults.length,
            summary: report.summary
        });
    }

    generateTestSummary(testResults) {
        const passed = testResults.filter(r => r.status === 'passed').length;
        const failed = testResults.filter(r => r.status === 'failed').length;
        const skipped = testResults.filter(r => r.status === 'skipped').length;
        const total = testResults.length;

        return {
            total,
            passed,
            failed,
            skipped,
            successRate: total > 0 ? (passed / total * 100).toFixed(1) : 0,
            status: failed === 0 ? 'pass' : 'fail'
        };
    }

    getSystemInfo() {
        return {
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            language: navigator.language,
            cookieEnabled: navigator.cookieEnabled,
            onLine: navigator.onLine,
            screen: {
                width: screen.width,
                height: screen.height,
                colorDepth: screen.colorDepth
            },
            viewport: {
                width: window.innerWidth,
                height: window.innerHeight
            },
            timestamp: new Date().toISOString()
        };
    }

    // Professional UI for field technicians
    showFieldTechSetup() {
        const modal = document.createElement('div');
        modal.innerHTML = `
            <div class="modal fade" tabindex="-1">
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">
                                <i class="fas fa-user-hard-hat"></i> Field Technician Setup
                            </h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <div class="mb-3">
                                <label class="form-label">Technician ID</label>
                                <input type="text" class="form-control" id="techId" 
                                       value="${this.fieldTechInfo.techId || ''}" 
                                       placeholder="TECH-001">
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Full Name</label>
                                <input type="text" class="form-control" id="techName" 
                                       value="${this.fieldTechInfo.name || ''}" 
                                       placeholder="John Doe">
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Department/Team</label>
                                <input type="text" class="form-control" id="techDept" 
                                       value="${this.fieldTechInfo.department || ''}" 
                                       placeholder="Network Operations">
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Contact Email</label>
                                <input type="email" class="form-control" id="techEmail" 
                                       value="${this.fieldTechInfo.email || ''}" 
                                       placeholder="john.doe@company.com">
                            </div>
                            <div class="alert alert-info">
                                <i class="fas fa-info-circle"></i>
                                This information helps with test reporting and device fleet management.
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                            <button type="button" class="btn btn-primary" id="saveFieldTechInfo">Save Information</button>
                        </div>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
        const bootstrapModal = new bootstrap.Modal(modal.querySelector('.modal'));
        bootstrapModal.show();

        modal.querySelector('#saveFieldTechInfo').addEventListener('click', () => {
            const info = {
                techId: modal.querySelector('#techId').value,
                name: modal.querySelector('#techName').value,
                department: modal.querySelector('#techDept').value,
                email: modal.querySelector('#techEmail').value,
                setupDate: new Date().toISOString()
            };

            this.saveFieldTechInfo(info);
            bootstrapModal.hide();
            
            this.logUsageEvent('field_tech_setup', info);
            
            // Update UI to show tech info
            this.updateFieldTechDisplay();
        });

        modal.addEventListener('hidden.bs.modal', function() {
            document.body.removeChild(modal);
        });
    }

    updateFieldTechDisplay() {
        const techDisplay = document.getElementById('fieldTechDisplay');
        if (techDisplay && this.fieldTechInfo.name) {
            techDisplay.innerHTML = `
                <div class="field-tech-info">
                    <i class="fas fa-user-hard-hat"></i>
                    <span>${this.fieldTechInfo.name}</span>
                    <small class="text-muted">${this.fieldTechInfo.techId}</small>
                </div>
            `;
        }
    }

    // Professional test reporting
    exportTestReport(reportId = null) {
        const reports = JSON.parse(localStorage.getItem('gts-test-reports') || '[]');
        const report = reportId ? reports.find(r => r.id === reportId) : reports[reports.length - 1];
        
        if (!report) {
            alert('No test report found to export');
            return;
        }

        const csvContent = this.generateCSVReport(report);
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        
        if (link.download !== undefined) {
            const url = URL.createObjectURL(blob);
            link.setAttribute('href', url);
            link.setAttribute('download', `GTS-Report-${report.timestamp.substring(0, 10)}.csv`);
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        this.logUsageEvent('report_exported', { reportId: report.id, format: 'csv' });
    }

    generateCSVReport(report) {
        const header = [
            'Test Name',
            'Status',
            'Message',
            'Timestamp',
            'Category',
            'Duration (ms)'
        ].join(',');

        const rows = report.testResults.map(result => [
            `"${result.test || result.name}"`,
            result.status,
            `"${result.message}"`,
            result.timestamp || report.timestamp,
            result.category || 'general',
            result.duration || 0
        ].join(','));

        const metadata = [
            '',
            '# Test Report Metadata',
            `Device ID,${report.deviceId}`,
            `Technician,${report.fieldTech.name || 'Unknown'}`,
            `Department,${report.fieldTech.department || 'Unknown'}`,
            `Test Date,${report.timestamp}`,
            `Total Tests,${report.summary.total}`,
            `Passed,${report.summary.passed}`,
            `Failed,${report.summary.failed}`,
            `Success Rate,${report.summary.successRate}%`
        ];

        return [header, ...rows, ...metadata].join('\n');
    }

    // Fleet management features
    getDeviceStatus() {
        return {
            deviceId: this.deviceId,
            installId: this.installId,
            fieldTech: this.fieldTechInfo,
            lastActivity: new Date().toISOString(),
            version: this.getAppVersion(),
            systemInfo: this.getSystemInfo(),
            storageUsage: this.getStorageUsage()
        };
    }

    getAppVersion() {
        // In a real app, this would come from build info
        return '1.0.0';
    }

    getStorageUsage() {
        const events = JSON.parse(localStorage.getItem('gts-pending-events') || '[]');
        const reports = JSON.parse(localStorage.getItem('gts-test-reports') || '[]');
        const configs = JSON.parse(localStorage.getItem('warp-configurations') || '[]');

        return {
            pendingEvents: events.length,
            storedReports: reports.length,
            savedConfigs: configs.length,
            totalStorageUsed: this.estimateStorageSize()
        };
    }

    estimateStorageSize() {
        let total = 0;
        for (let key in localStorage) {
            if (localStorage.hasOwnProperty(key)) {
                total += localStorage[key].length;
            }
        }
        return `${(total / 1024).toFixed(1)} KB`;
    }
}

// Global enterprise features instance
const enterpriseFeatures = new EnterpriseFeatures();

// Initialize enterprise features
function initializeEnterpriseFeatures() {
    // Log app startup
    enterpriseFeatures.logUsageEvent('app_start', {
        version: enterpriseFeatures.getAppVersion(),
        deviceInfo: enterpriseFeatures.getSystemInfo()
    });

    // Set up periodic event sync
    setInterval(() => {
        if (navigator.onLine) {
            enterpriseFeatures.syncEvents();
        }
    }, 30000); // Sync every 30 seconds

    // Add field tech setup button to header if not configured
    if (!enterpriseFeatures.fieldTechInfo.name) {
        addFieldTechSetupButton();
    } else {
        enterpriseFeatures.updateFieldTechDisplay();
    }

    // Add export functionality to test results
    enhanceTestResultsWithExport();
    
    console.log('Enterprise features initialized for device:', enterpriseFeatures.deviceId);
}

function addFieldTechSetupButton() {
    const header = document.querySelector('.mobile-header');
    if (header) {
        const setupButton = document.createElement('div');
        setupButton.innerHTML = `
            <button class="btn btn-outline-primary btn-sm" id="fieldTechSetup" title="Setup Field Technician Info">
                <i class="fas fa-user-hard-hat"></i>
            </button>
        `;
        setupButton.style.position = 'absolute';
        setupButton.style.right = '10px';
        setupButton.style.top = '10px';
        
        header.appendChild(setupButton);
        
        setupButton.addEventListener('click', () => {
            enterpriseFeatures.showFieldTechSetup();
        });
    }
}

function enhanceTestResultsWithExport() {
    // Add export button to test results section
    const testResults = document.getElementById('testResults');
    if (testResults) {
        const exportBtn = document.createElement('button');
        exportBtn.className = 'btn btn-outline-success btn-sm mt-2';
        exportBtn.innerHTML = '<i class="fas fa-download"></i> Export Report';
        exportBtn.style.display = 'none';
        exportBtn.id = 'exportTestReport';
        
        exportBtn.addEventListener('click', () => {
            enterpriseFeatures.exportTestReport();
        });
        
        testResults.appendChild(exportBtn);
    }
}

// Export for global use
window.enterpriseFeatures = enterpriseFeatures;
window.initializeEnterpriseFeatures = initializeEnterpriseFeatures;