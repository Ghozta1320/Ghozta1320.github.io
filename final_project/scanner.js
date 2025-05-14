// Scanner utility functions
const scannerUtils = {
    formatThreatLevel: (level) => {
        switch(level.toLowerCase()) {
            case 'high':
                return { class: 'threat-high', label: 'High Risk' };
            case 'medium':
                return { class: 'threat-medium', label: 'Medium Risk' };
            case 'low':
                return { class: 'threat-low', label: 'Low Risk' };
            default:
                return { class: '', label: 'Unknown Risk' };
        }
    },

    formatTimestamp: (timestamp) => {
        return new Date(timestamp).toLocaleString();
    },

    showLoading: (elementId) => {
        const element = document.getElementById(elementId);
        if (element) {
            element.innerHTML = '<div class="loading"></div> Analyzing...';
        }
    },

    hideLoading: (elementId) => {
        const element = document.getElementById(elementId);
        if (element) {
            element.innerHTML = '';
        }
    },

    displayError: (elementId, message) => {
        const element = document.getElementById(elementId);
        if (element) {
            element.innerHTML = `<div class="scan-result">
                <strong>Error:</strong> ${message}
            </div>`;
        }
    }
};

// API interaction functions
const scannerAPI = {
    baseUrl: 'https://Ghozta1320.github.io/api',

    async performScan(target, scanType) {
        try {
            const response = await fetch(`${this.baseUrl}/scan/${scanType}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ target })
            });

            if (!response.ok) {
                throw new Error('Scan request failed');
            }

            return await response.json();
        } catch (error) {
            console.error('Scan error:', error);
            throw error;
        }
    },

    async deepScan(target, scanTypes) {
        try {
            const response = await fetch(`${this.baseUrl}/deep-scan`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ target, scan_types: scanTypes })
            });

            if (!response.ok) {
                throw new Error('Deep scan request failed');
            }

            return await response.json();
        } catch (error) {
            console.error('Deep scan error:', error);
            throw error;
        }
    }
};

// Result formatting functions
const resultFormatter = {
    formatScanResult: (data) => {
        const threatInfo = scannerUtils.formatThreatLevel(data.threatLevel || 'unknown');
        return `
            <div class="scan-result ${threatInfo.class}">
                <h4>Scan Results</h4>
                <div class="scan-details">
                    <p><strong>Threat Level:</strong> ${threatInfo.label}</p>
                    <p><strong>Confidence:</strong> ${data.confidence || 'N/A'}%</p>
                    ${data.details ? `<p><strong>Details:</strong> ${data.details}</p>` : ''}
                </div>
                <div class="scan-timestamp">
                    Scan completed at ${scannerUtils.formatTimestamp(new Date())}
                </div>
            </div>
        `;
    },

    formatDeepScanResult: (data) => {
        return `
            <div class="scan-result">
                <h4>Deep Scan Results</h4>
                <div class="scan-details">
                    ${data.results.map(result => `
                        <div class="recommendation">
                            <strong>${result.type}:</strong> ${result.finding}
                        </div>
                    `).join('')}
                </div>
                <div class="scan-timestamp">
                    Deep scan completed at ${scannerUtils.formatTimestamp(new Date())}
                </div>
            </div>
        `;
    }
};

// Event handlers
document.addEventListener('DOMContentLoaded', () => {
    console.log('Scanner module initialized');
    
    // Add click handler for Analyze button
    const analyzeButton = document.querySelector('.scan-button');
    if (analyzeButton) {
        analyzeButton.addEventListener('click', async () => {
            const target = document.getElementById('target-input').value;
            if (!target) {
                scannerUtils.displayError('osint-results', 'Please enter a target to analyze');
                return;
            }

            try {
                // Show loading state
                document.getElementById('osint-results').innerHTML = '<h3>OSINT Analysis</h3><div class="loading"></div>';
                document.getElementById('geo-results').innerHTML = '<h3>Geolocation Analysis</h3><div class="loading"></div>';
                document.getElementById('sigint-results').innerHTML = '<h3>SIGINT Analysis</h3><div class="loading"></div>';

                // Perform threat analysis
                const threatData = await scannerAPI.performScan(target, 'threat');
                
                // Perform deep scan
                const deepScanData = await scannerAPI.deepScan(target, ['phone', 'email', 'domain', 'breach', 'threat', 'social']);

                // Update UI with results
                document.getElementById('osint-results').innerHTML = resultFormatter.formatScanResult(threatData);
                document.getElementById('geo-results').innerHTML = resultFormatter.formatDeepScanResult(deepScanData);
                
                // Update summary panel
                document.getElementById('sigint-results').innerHTML = `
                    <h3>Scan Summary</h3>
                    <div class="result-item">
                        <strong>Threat Level:</strong> ${threatData.threatLevel || 'Unknown'}<br>
                        <strong>Risk Score:</strong> ${deepScanData.riskScore || 'N/A'}<br>
                        <strong>Findings:</strong> ${deepScanData.findings ? deepScanData.findings.length : 0} potential issues found
                    </div>
                    ${deepScanData.recommendations ? `
                    <div class="result-item">
                        <strong>Recommendations:</strong>
                        <ul>
                            ${deepScanData.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                        </ul>
                    </div>` : ''}
                `;

                // Add to input history
                const historyDiv = document.getElementById('input-history');
                historyDiv.innerHTML += `
                    <div class="result-item">
                        <strong>Target:</strong> ${target}<br>
                        <strong>Time:</strong> ${new Date().toLocaleTimeString()}
                    </div>
                `;
                historyDiv.scrollTop = historyDiv.scrollHeight;

            } catch (error) {
                console.error('Analysis error:', error);
                document.getElementById('osint-results').innerHTML = `
                    <h3>OSINT Analysis</h3>
                    <div class="scan-result">
                        <strong>Error:</strong> Failed to analyze target. Please try again later.
                    </div>
                `;
                document.getElementById('geo-results').innerHTML = '<h3>Geolocation Analysis</h3><p>Analysis failed</p>';
                document.getElementById('sigint-results').innerHTML = '<h3>SIGINT Analysis</h3><p>Analysis failed</p>';
            }
        });
    }

    // Add Enter key handler for input field
    const inputField = document.getElementById('target-input');
    if (inputField) {
        inputField.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                const analyzeButton = document.querySelector('.scan-button');
                if (analyzeButton) {
                    analyzeButton.click();
                }
            }
        });
    }
});
