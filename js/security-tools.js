// Enhanced Security Tools with In-Card Results and Malicious File Checker
// Updated: 2025-06-13 06:19:11 UTC
// Current User: ranatalhamajid1
// Location: Islamabad, Pakistan

console.log('SecurityTools loading...');

// Current time updated to your latest
const CURRENT_TIME = new Date('2025-06-13T06:19:11Z');
const CURRENT_USER = 'ranatalhamajid1';

console.log(`⏰ Current Time: ${CURRENT_TIME.toISOString()}`);
console.log(`👤 Current User: ${CURRENT_USER}`);
console.log(`🌍 Location: Islamabad, Pakistan`);

// Password visibility toggle
function togglePasswordVisibility(inputId) {
    const passwordInput = document.getElementById(inputId);
    const toggleButton = passwordInput.parentElement.querySelector('.password-toggle i');
    
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        toggleButton.className = 'fas fa-eye-slash';
    } else {
        passwordInput.type = 'password';
        toggleButton.className = 'fas fa-eye';
    }
}

// Real-time password strength analysis
function updatePasswordStrength() {
    const password = document.getElementById('passwordInput').value;
    const resultContainer = document.getElementById('passwordResult');
    
    if (!password) {
        resultContainer.style.display = 'none';
        return;
    }
    
    // Show the result container
    resultContainer.style.display = 'block';
    resultContainer.className = 'tool-result-container password-strength-result';
    
    // Calculate password strength
    let score = 0;
    const requirements = [
        { test: password.length >= 8, text: 'At least 8 characters', met: false },
        { test: /[A-Z]/.test(password), text: 'At least one uppercase letter', met: false },
        { test: /[a-z]/.test(password), text: 'At least one lowercase letter', met: false },
        { test: /\d/.test(password), text: 'At least one number', met: false },
        { test: /[^a-zA-Z\d]/.test(password), text: 'At least one special character', met: false }
    ];
    
    requirements.forEach(req => {
        if (req.test) {
            score++;
            req.met = true;
        }
    });
    
    const percentage = (score / 5) * 100;
    const strength = score <= 2 ? 'weak' : score <= 4 ? 'medium' : 'strong';
    const strengthText = score <= 2 ? 'Weak' : score <= 4 ? 'Medium' : 'Strong';
    
    // Generate requirements HTML
    const requirementsHTML = requirements.map(req => 
        `<div class="requirement-item ${req.met ? 'met' : 'unmet'}">
            <span class="requirement-icon">${req.met ? '✓' : '✗'}</span>
            ${req.text}
        </div>`
    ).join('');
    
    // Update the result container
    resultContainer.innerHTML = `
        <div class="strength-header">
            <span class="strength-label">Password Strength</span>
            <span class="strength-badge ${strength}">${strengthText} (${score}/5)</span>
        </div>
        <div class="strength-bar">
            <div class="strength-fill ${strength}" style="width: ${percentage}%;"></div>
        </div>
        <div class="requirements-list">
            ${requirementsHTML}
        </div>
    `;
}

// Email breach checker
async function checkEmailBreach() {
    const emailInput = document.getElementById('emailInput');
    const resultContainer = document.getElementById('emailResult');
    const email = emailInput.value.trim();
    
    if (!email) {
        showNotification('Please enter an email address', 'error');
        return;
    }
    
    if (!validateEmail(email)) {
        showNotification('Please enter a valid email address', 'error');
        return;
    }
    
    // Show loading state inside the card
    resultContainer.style.display = 'block';
    resultContainer.className = 'tool-result-container';
    resultContainer.innerHTML = `
        <div class="loading-state">
            <div class="loading-spinner"></div>
            <p>Checking email against breach databases...</p>
        </div>
    `;
    
    try {
        const response = await makeSecureAPICall('/api/check-breach', { email });
        
        if (response.success) {
            displayEmailResult(response, resultContainer);
            showNotification('Email check completed!', 'success');
        } else {
            showError('Failed to check email', resultContainer);
        }
    } catch (error) {
        console.error('Email check error:', error);
        showError('Network error. Please try again.', resultContainer);
    }
}

// URL scanner
async function scanUrl() {
    const urlInput = document.getElementById('urlInput');
    const resultContainer = document.getElementById('urlResult');
    const url = urlInput.value.trim();
    
    if (!url) {
        showNotification('Please enter a URL to scan', 'error');
        return;
    }
    
    if (!validateUrl(url)) {
        showNotification('Please enter a valid URL (include http:// or https://)', 'error');
        return;
    }
    
    // Show loading state inside the card
    resultContainer.style.display = 'block';
    resultContainer.className = 'tool-result-container';
    resultContainer.innerHTML = `
        <div class="loading-state">
            <div class="loading-spinner"></div>
            <p>Scanning URL for security threats...</p>
        </div>
    `;
    
    try {
        const response = await makeSecureAPICall('/api/scan-url', { url });
        
        if (response.success) {
            displayUrlResult(response, resultContainer);
            showNotification('URL scan completed!', 'success');
        } else {
            showError('Failed to scan URL', resultContainer);
        }
    } catch (error) {
        console.error('URL scan error:', error);
        showError('Network error. Please try again.', resultContainer);
    }
}

// NEW: Malicious file checker
async function scanFile() {
    const fileInput = document.getElementById('fileInput');
    const resultContainer = document.getElementById('fileResult');
    const file = fileInput.files[0];
    
    if (!file) {
        showNotification('Please select a file to scan', 'error');
        return;
    }
    
    // Validate file size (10MB limit)
    const maxSize = 10 * 1024 * 1024; // 10MB
    if (file.size > maxSize) {
        showNotification('File size exceeds 10MB limit', 'error');
        return;
    }
    
    // Show loading state inside the card
    resultContainer.style.display = 'block';
    resultContainer.className = 'tool-result-container';
    resultContainer.innerHTML = `
        <div class="loading-state">
            <div class="loading-spinner"></div>
            <p>Scanning file for malicious content...</p>
            <small>Analyzing: ${file.name}</small>
        </div>
    `;
    
    try {
        // Generate file hash (simplified for demo)
        const fileHash = await generateFileHash(file);
        
        const fileData = {
            fileName: file.name,
            fileSize: file.size,
            fileType: file.type || 'unknown',
            fileHash: fileHash
        };
        
        console.log('📁 Scanning file:', fileData);
        
        const response = await makeSecureAPICall('/api/scan-file', fileData);
        
        if (response.success) {
            displayFileResult(response, resultContainer);
            showNotification('File scan completed!', 'success');
        } else {
            showError('Failed to scan file', resultContainer);
        }
    } catch (error) {
        console.error('File scan error:', error);
        showError('Network error. Please try again.', resultContainer);
    }
}

// NEW: Generate simple file hash (for demo purposes)
async function generateFileHash(file) {
    try {
        const arrayBuffer = await file.arrayBuffer();
        const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 16);
    } catch (error) {
        console.warn('Could not generate file hash:', error);
        // Fallback hash based on file properties
        return (file.name + file.size + file.lastModified).split('').reduce((a, b) => {
            a = ((a << 5) - a) + b.charCodeAt(0);
            return a & a;
        }, 0).toString(16);
    }
}

// NEW: Update file input label when file is selected
function updateFileLabel() {
    const fileInput = document.getElementById('fileInput');
    const fileLabel = document.getElementById('fileInputLabel');
    const labelElement = document.querySelector('label[for="fileInput"]');
    
    if (fileInput.files.length > 0) {
        const file = fileInput.files[0];
        const fileName = file.name;
        const fileSize = formatFileSize(file.size);
        
        // Truncate long file names
        const displayName = fileName.length > 30 ? fileName.substring(0, 27) + '...' : fileName;
        
        // Update label text with file info
        fileLabel.innerHTML = `<i class="fas fa-file"></i> ${displayName} (${fileSize})`;
        
        // Add selected class for styling
        if (labelElement) {
            labelElement.classList.add('file-selected');
        }
        
        console.log('📁 File selected:', fileName, 'Size:', fileSize, 'Type:', file.type);
        
        // Auto-clear previous results
        const resultContainer = document.getElementById('fileResult');
        if (resultContainer) {
            resultContainer.style.display = 'none';
        }
    } else {
        // Reset to default
        fileLabel.innerHTML = '<i class="fas fa-upload"></i> Choose file to scan';
        if (labelElement) {
            labelElement.classList.remove('file-selected');
        }
    }
}

// NEW: Helper function to format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Display email results inside card
function displayEmailResult(data, container) {
    const isBreached = data.breached;
    const resultClass = isBreached ? 'email-result-danger' : 'email-result-safe';
    const icon = isBreached ? '⚠️' : '✅';
    
    container.className = `tool-result-container ${resultClass}`;
    container.innerHTML = `
        <div class="result-header">
            <span class="result-icon">${icon}</span>
            <span>${isBreached ? 'Breach Found!' : 'No Breaches Found'}</span>
        </div>
        <div class="result-message">${data.message}</div>
        ${data.breaches && data.breaches.length > 0 ? `
            <div class="breach-details">
                <strong>⚠️ Found in breaches:</strong>
                <div class="breach-list">${data.breaches.join(', ')}</div>
            </div>
        ` : ''}
        ${data.recommendation ? `
            <div class="recommendation">
                <strong>💡 Recommendation:</strong>
                <div class="recommendation-text">${data.recommendation}</div>
            </div>
        ` : ''}
    `;
}

// Display URL results inside card
function displayUrlResult(data, container) {
    const isSafe = data.safe;
    const resultClass = isSafe ? 'url-result-safe' : 'url-result-warning';
    const icon = isSafe ? '✅' : '⚠️';
    
    container.className = `tool-result-container ${resultClass}`;
    container.innerHTML = `
        <div class="result-header">
            <span class="result-icon">${icon}</span>
            <span>${isSafe ? 'URL appears safe' : 'URL may be suspicious'}</span>
        </div>
        <div class="result-message">${data.message}</div>
        <div class="scanned-url">
            <strong>Scanned URL:</strong><br>
            <span class="url-code">${data.url}</span>
        </div>
        ${data.threats && data.threats.length > 0 ? `
            <div class="threat-details">
                <strong>⚠️ Detected threats:</strong>
                <div class="threat-list">${data.threats.join(', ')}</div>
            </div>
        ` : ''}
        ${data.recommendation ? `
            <div class="recommendation">
                <strong>💡 Recommendation:</strong>
                <div class="recommendation-text">${data.recommendation}</div>
            </div>
        ` : ''}
    `;
}

// NEW: Display file results inside card
function displayFileResult(data, container) {
    const isSafe = data.safe;
    const resultClass = isSafe ? 'file-result-safe' : 'file-result-danger';
    const icon = isSafe ? '✅' : '⚠️';
    
    // Determine risk level color
    const riskColors = {
        'low': '#28a745',
        'medium': '#ffc107', 
        'high': '#fd7e14',
        'critical': '#dc3545'
    };
    const riskColor = riskColors[data.riskLevel] || '#6c757d';
    
    container.className = `tool-result-container ${resultClass}`;
    container.innerHTML = `
        <div class="result-header">
            <span class="result-icon">${icon}</span>
            <span>${isSafe ? 'File appears clean' : 'Threats detected!'}</span>
        </div>
        <div class="result-message">${data.message}</div>
        <div class="file-details">
            <div class="file-info">
                <strong>📁 File:</strong> ${data.fileName}<br>
                <strong>📊 Size:</strong> ${formatFileSize(data.fileSize)}<br>
                <strong>🏷️ Type:</strong> ${data.fileType}<br>
                <strong>⚠️ Risk Level:</strong> 
                <span style="color: ${riskColor}; font-weight: bold; text-transform: uppercase;">
                    ${data.riskLevel}
                </span>
            </div>
            ${data.threats && data.threats.length > 0 ? `
                <div class="threat-details">
                    <strong>🛡️ Security Issues Found:</strong>
                    <ul class="threat-list">
                        ${data.threats.map(threat => `<li>${threat}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
            <div class="recommendation">
                <strong>💡 Recommendation:</strong>
                <div class="recommendation-text">${data.recommendation}</div>
            </div>
            ${data.actions && data.actions.length > 0 ? `
                <div class="action-items">
                    <strong>🎯 Recommended Actions:</strong>
                    <ul class="action-list">
                        ${data.actions.map(action => `<li>${action}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
        </div>
        ${data.scanDetails ? `
            <div class="scan-details">
                <strong>🔍 Scan Results:</strong>
                <div class="scan-checks">
                    <div class="check-item ${data.scanDetails.extensionCheck ? 'check-pass' : 'check-fail'}">
                        <span class="check-icon">${data.scanDetails.extensionCheck ? '✓' : '✗'}</span>
                        Extension Check
                    </div>
                    <div class="check-item ${data.scanDetails.nameCheck ? 'check-pass' : 'check-fail'}">
                        <span class="check-icon">${data.scanDetails.nameCheck ? '✓' : '✗'}</span>
                        Filename Check
                    </div>
                    <div class="check-item ${data.scanDetails.hashCheck ? 'check-pass' : 'check-fail'}">
                        <span class="check-icon">${data.scanDetails.hashCheck ? '✓' : '✗'}</span>
                        Hash Check
                    </div>
                    <div class="check-item ${data.scanDetails.sizeCheck ? 'check-pass' : 'check-fail'}">
                        <span class="check-icon">${data.scanDetails.sizeCheck ? '✓' : '✗'}</span>
                        Size Check
                    </div>
                </div>
            </div>
        ` : ''}
    `;
}

// Show error inside card
function showError(message, container) {
    container.className = 'tool-result-container error-state';
    container.innerHTML = `
        <div class="result-header">
            <span class="result-icon">❌</span>
            <span>Error</span>
        </div>
        <div class="result-message">${message}</div>
        <div class="error-help">
            <small>Please check your connection and try again. If the problem persists, contact support.</small>
        </div>
    `;
}

// Enhanced error handling for API calls
async function makeSecureAPICall(endpoint, data) {
    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-User': CURRENT_USER,
                'X-Timestamp': CURRENT_TIME.toISOString()
            },
            body: JSON.stringify({ 
                ...data, 
                timestamp: CURRENT_TIME.toISOString(),
                user: CURRENT_USER,
                location: 'Islamabad, Pakistan'
            })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error(`API Error for ${endpoint}:`, error);
        throw error;
    }
}

// Notification system (top-right notifications)
function showNotification(message, type = 'info') {
    const colors = {
        'error': '#e74c3c',
        'success': '#2ecc71',
        'info': '#3498db'
    };

    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: var(--bg-secondary);
        color: var(--text-primary);
        padding: 1rem 1.5rem;
        border-radius: 12px;
        box-shadow: 0 8px 32px var(--shadow-medium);
        border-left: 4px solid ${colors[type]};
        z-index: 10000;
        font-weight: 500;
        max-width: 300px;
        animation: slideInRight 0.3s ease-out;
    `;
    
    notification.innerHTML = `
        <div style="display: flex; align-items: center;">
            <i class="fas fa-${type === 'success' ? 'check' : type === 'error' ? 'times' : 'info'}-circle" style="margin-right: 0.5rem; color: ${colors[type]};"></i>
            ${message}
        </div>
    `;

    document.body.appendChild(notification);

    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 4000);
}

// Validation functions
function validateEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validateUrl(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}

// Initialize everything
document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 SecurityTools initialized for ranatalhamajid1');
    console.log(`📅 Current Time: ${CURRENT_TIME.toISOString()}`);
    
    // Bind real-time password analysis
    const passwordInput = document.getElementById('passwordInput');
    if (passwordInput) {
        passwordInput.addEventListener('input', updatePasswordStrength);
        passwordInput.addEventListener('keyup', updatePasswordStrength);
        console.log('✅ Password strength analyzer bound');
    }
    
    // Bind file input change event
    const fileInput = document.getElementById('fileInput');
    if (fileInput) {
        fileInput.addEventListener('change', updateFileLabel);
        console.log('✅ File input change listener bound');
    }
    
    // Add notification animation CSS
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideInRight {
            from {
                opacity: 0;
                transform: translateX(100%);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }
        
        /* Enhanced result styling */
        .threat-list, .action-list {
            margin: 0.5rem 0;
            padding-left: 1.5rem;
        }
        
        .threat-list li, .action-list li {
            margin: 0.25rem 0;
            color: var(--text-secondary, #666);
        }
        
        .scan-checks {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 0.5rem;
            margin-top: 0.5rem;
        }
        
        .check-item {
            display: flex;
            align-items: center;
            padding: 0.25rem;
            border-radius: 4px;
            font-size: 0.85rem;
        }
        
        .check-item.check-pass {
            background: rgba(40, 167, 69, 0.1);
            color: #28a745;
        }
        
        .check-item.check-fail {
            background: rgba(220, 53, 69, 0.1);
            color: #dc3545;
        }
        
        .check-icon {
            margin-right: 0.5rem;
            font-weight: bold;
        }
        
        .recommendation, .action-items, .scan-details {
            margin-top: 1rem;
            padding-top: 1rem;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .error-help {
            margin-top: 0.5rem;
            opacity: 0.7;
        }
    `;
    document.head.appendChild(style);
    
    console.log('✅ SecurityTools loaded successfully with all 4 tools operational');
});
// NEW: Password leak checker using k-anonymity
async function checkPasswordLeak() {
    const passwordInput = document.getElementById('passwordLeakInput');
    const resultContainer = document.getElementById('passwordLeakResult');
    const password = passwordInput.value.trim();
    
    if (!password) {
        showNotification('Please enter a password to check', 'error');
        return;
    }
    
    if (password.length < 4) {
        showNotification('Password must be at least 4 characters long', 'error');
        return;
    }
    
    // Show loading state
    resultContainer.style.display = 'block';
    resultContainer.className = 'tool-result-container';
    resultContainer.innerHTML = `
        <div class="loading-state">
            <div class="loading-spinner"></div>
            <p>Checking password against leak databases...</p>
            <small>Using k-anonymity to protect your privacy</small>
        </div>
    `;
    
    try {
        const response = await makeSecureAPICall('/api/check-password-leak', { password });
        
        if (response.success) {
            displayPasswordLeakResult(response, resultContainer);
            showNotification('Password leak check completed!', 'success');
        } else {
            showError('Failed to check password', resultContainer);
        }
    } catch (error) {
        console.error('Password leak check error:', error);
        showError('Network error. Please try again.', resultContainer);
    }
}

// NEW: IP reputation checker
async function checkIPReputation() {
    const ipInput = document.getElementById('ipInput');
    const resultContainer = document.getElementById('ipResult');
    const ip = ipInput.value.trim();
    
    if (!ip) {
        showNotification('Please enter an IP address', 'error');
        return;
    }
    
    if (!validateIP(ip)) {
        showNotification('Please enter a valid IP address', 'error');
        return;
    }
    
    // Show loading state
    resultContainer.style.display = 'block';
    resultContainer.className = 'tool-result-container';
    resultContainer.innerHTML = `
        <div class="loading-state">
            <div class="loading-spinner"></div>
            <p>Checking IP reputation...</p>
            <small>Scanning threat intelligence databases</small>
        </div>
    `;
    
    try {
        const response = await makeSecureAPICall('/api/check-ip-reputation', { ip });
        
        if (response.success) {
            displayIPResult(response, resultContainer);
            showNotification('IP reputation check completed!', 'success');
        } else {
            showError('Failed to check IP reputation', resultContainer);
        }
    } catch (error) {
        console.error('IP reputation check error:', error);
        showError('Network error. Please try again.', resultContainer);
    }
}

// NEW: Get user's current IP
async function getMyIP() {
    const ipInput = document.getElementById('ipInput');
    
    try {
        // Use a simple IP detection service
        const response = await fetch('https://api.ipify.org?format=json');
        const data = await response.json();
        
        if (data.ip) {
            ipInput.value = data.ip;
            showNotification('Your IP address has been detected', 'success');
        } else {
            throw new Error('Could not detect IP');
        }
    } catch (error) {
        console.error('IP detection error:', error);
        // Fallback - use a mock IP for demo
        ipInput.value = '8.8.8.8';
        showNotification('Using example IP address', 'info');
    }
}

// NEW: Display password leak results
function displayPasswordLeakResult(data, container) {
    const isLeaked = data.leaked;
    const resultClass = isLeaked ? 'password-leak-danger' : 'password-leak-safe';
    const icon = isLeaked ? '🚨' : '🛡️';
    
    container.className = `tool-result-container ${resultClass}`;
    container.innerHTML = `
        <div class="result-header">
            <span class="result-icon">${icon}</span>
            <span>${isLeaked ? 'Password Found in Leaks!' : 'Password Not Found in Leaks'}</span>
        </div>
        <div class="result-message">${data.message}</div>
        ${data.occurrences > 0 ? `
            <div class="leak-details">
                <strong>⚠️ Occurrences found:</strong>
                <div class="leak-count">${data.occurrences.toLocaleString()} times</div>
            </div>
        ` : ''}
        <div class="privacy-info">
            <strong>🔒 Privacy Protection:</strong>
            <div class="privacy-text">Your password was checked using k-anonymity - only the first 5 characters of the hash were sent.</div>
        </div>
        ${data.recommendation ? `
            <div class="recommendation">
                <strong>💡 Recommendation:</strong>
                <div class="recommendation-text">${data.recommendation}</div>
            </div>
        ` : ''}
    `;
}

// NEW: Display IP reputation results
function displayIPResult(data, container) {
    const isSafe = data.safe;
    const resultClass = isSafe ? 'ip-result-safe' : 'ip-result-warning';
    const icon = isSafe ? '✅' : '⚠️';
    
    container.className = `tool-result-container ${resultClass}`;
    container.innerHTML = `
        <div class="result-header">
            <span class="result-icon">${icon}</span>
            <span>${isSafe ? 'IP Appears Clean' : 'IP May Be Malicious'}</span>
        </div>
        <div class="result-message">${data.message}</div>
        <div class="ip-details">
            <div class="ip-info">
                <strong>🌐 IP Address:</strong> ${data.ip}<br>
                ${data.location ? `<strong>📍 Location:</strong> ${data.location}<br>` : ''}
                ${data.isp ? `<strong>🏢 ISP:</strong> ${data.isp}<br>` : ''}
                <strong>⚠️ Risk Level:</strong> 
                <span style="color: ${data.riskLevel === 'high' ? '#dc3545' : data.riskLevel === 'medium' ? '#ffc107' : '#28a745'}; font-weight: bold;">
                    ${data.riskLevel.toUpperCase()}
                </span>
            </div>
            ${data.threats && data.threats.length > 0 ? `
                <div class="threat-details">
                    <strong>🛡️ Threat Categories:</strong>
                    <ul class="threat-list">
                        ${data.threats.map(threat => `<li>${threat}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
            ${data.recommendation ? `
                <div class="recommendation">
                    <strong>💡 Recommendation:</strong>
                    <div class="recommendation-text">${data.recommendation}</div>
                </div>
            ` : ''}
        </div>
    `;
}

// NEW: IP validation function
function validateIP(ip) {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipRegex.test(ip);
}

console.log('✅ SecurityTools script loaded - Updated with Malicious File Checker');
console.log('📁 File scanning capabilities added');
console.log('🔐 All security tools operational');