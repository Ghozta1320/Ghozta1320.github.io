// Scanner Interface for Scam Detection Website

// Configuration
const config = {
    // API endpoint will be set based on environment
    apiUrl: 'http://localhost:5000/api', // Development
    // apiUrl: 'https://your-production-api.com/api', // Production - Update this when deploying
};

// Initialize scanner
function initScanner() {
    console.log('Scanner module initialized');
    setupEventListeners();
}

// Set up event listeners
function setupEventListeners() {
    const analyzeButton = document.querySelector('.analyze-button');
    if (analyzeButton) {
        analyzeButton.addEventListener('click', handleAnalyze);
    }

    const targetInput = document.querySelector('.target-input');
    if (targetInput) {
        targetInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                handleAnalyze();
            }
        });
    }
}

// Handle analyze button click
async function handleAnalyze() {
    const targetInput = document.querySelector('.target-input');
    const resultsDiv = document.querySelector('.results-container');
    
    if (!targetInput || !targetInput.value) {
        showError('Please enter a target to analyze');
        return;
    }

    const target = targetInput.value;
    showLoading();

    try {
        const result = await performScan(target);
        displayResults(result);
    } catch (error) {
        showError('Error during analysis: ' + error.message);
    }
}

// Perform scan using API
async function performScan(target) {
    try {
        const response = await fetch(`${config.apiUrl}/scan/threat`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
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
}

// Display results in the UI
function displayResults(results) {
    const resultsDiv = document.querySelector('.results-container');
    if (!resultsDiv) return;

    resultsDiv.innerHTML = `
        <div class="scan-results">
            <h3>Scan Results</h3>
            <p>Threat Level: ${results.threatLevel}</p>
            <p>Confidence: ${results.confidence}%</p>
            <p>Details: ${results.details}</p>
            
            <h4>Findings:</h4>
            <ul>
                ${results.findings.map(finding => `
                    <li>${finding.description}</li>
                `).join('')}
            </ul>
            
            <h4>Recommendations:</h4>
            <ul>
                ${results.recommendations.map(rec => `
                    <li>${rec}</li>
                `).join('')}
            </ul>
        </div>
    `;
}

// Show loading state
function showLoading() {
    const resultsDiv = document.querySelector('.results-container');
    if (resultsDiv) {
        resultsDiv.innerHTML = '<p>Analyzing target...</p>';
    }
}

// Show error message
function showError(message) {
    const resultsDiv = document.querySelector('.results-container');
    if (resultsDiv) {
        resultsDiv.innerHTML = `<p class="error">${message}</p>`;
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', initScanner);
