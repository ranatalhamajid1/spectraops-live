// Admin Login JavaScript - FINAL FIX FOR AUTO-REFRESH ISSUE
// Updated: 2025-06-13 04:35:40 UTC
// User: ranatalhamajid1
// Location: Islamabad, Pakistan

console.log('🔐 Admin login script loaded - 2025-06-13 04:35:40 UTC');
console.log('👤 User: ranatalhamajid1');
console.log('📍 Location: Islamabad, Pakistan');

// Global variables
let serverOnline = false;
let redirecting = false; // Prevent multiple redirects
let loginAttempted = false; // Prevent multiple login attempts

// Check server connection ONCE
async function checkServerOnce() {
    try {
        console.log('🔍 Checking server status...');
        const response = await fetch('/api/health');
        const data = await response.json();
        
        if (data.success || data.status === 'healthy') {
            document.getElementById('serverStatus').textContent = 'Online ✅';
            document.getElementById('apiStatus').textContent = 'Ready ✅';
            serverOnline = true;
            console.log('✅ Server is online and ready');
        } else {
            document.getElementById('serverStatus').textContent = 'Error ❌';
            serverOnline = false;
            console.log('❌ Server responded but not healthy');
        }
    } catch (error) {
        console.error('❌ Server check failed:', error);
        document.getElementById('serverStatus').textContent = 'Offline ❌';
        document.getElementById('apiStatus').textContent = 'Failed ❌';
        serverOnline = false;
    }
}

// Show message function
function showMessage(text, type) {
    const messageDiv = document.getElementById('message');
    if (messageDiv) {
        messageDiv.textContent = text;
        messageDiv.className = `message ${type}`;
        messageDiv.style.display = 'block';
        console.log(`📢 Message shown: ${text} (${type})`);
    }
}

// Hide message function
function hideMessage() {
    const messageDiv = document.getElementById('message');
    if (messageDiv) {
        messageDiv.style.display = 'none';
    }
}

// Clear all stored session data
function clearStoredSession() {
    console.log('🗑️ Clearing all stored session data...');
    
    localStorage.removeItem('adminToken');
    localStorage.removeItem('adminUser');
    localStorage.removeItem('adminRole');
    sessionStorage.removeItem('adminToken');
    
    console.log('✅ All session data cleared');
}

// Handle login form submission
async function handleLogin(event) {
    event.preventDefault();
    
    if (redirecting || loginAttempted) {
        console.log('⏸️ Already processing login or redirecting, ignoring attempt');
        return;
    }
    
    loginAttempted = true;
    
    const loginBtn = document.getElementById('loginBtn');
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    
    console.log('🔐 Login attempt initiated...');
    console.log('👤 Username:', username);
    console.log('📅 Time: 2025-06-13 04:35:40 UTC');
    
    // Validation
    if (!username || !password) {
        showMessage('❌ Please enter both username and password', 'error');
        loginAttempted = false;
        return;
    }
    
    if (!serverOnline) {
        showMessage('❌ Server is not available. Please try again later.', 'error');
        loginAttempted = false;
        return;
    }
    
    // Disable button and show loading
    loginBtn.disabled = true;
    loginBtn.textContent = 'Logging in...';
    hideMessage();
    
    try {
        console.log('📤 Sending authentication request...');
        
        const response = await fetch('/api/admin/authenticate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                username: username, 
                password: password,
                timestamp: new Date().toISOString()
            })
        });
        
        console.log('📥 Authentication response status:', response.status);
        
        const data = await response.json();
        console.log('📥 Authentication response data:', data);
        
        if (response.ok && data.success) {
            console.log('✅ Authentication successful!');
            console.log('🔑 Session token received:', data.sessionToken.substring(0, 16) + '...');
            console.log('👤 User:', data.user);
            console.log('🎯 Role:', data.role);
            
            // Clear any existing session data first
            clearStoredSession();
            
            // Store new authentication data
            localStorage.setItem('adminToken', data.sessionToken);
            localStorage.setItem('adminUser', data.user);
            localStorage.setItem('adminRole', data.role);
            
            // Also store in sessionStorage as backup
            sessionStorage.setItem('adminToken', data.sessionToken);
            
            console.log('💾 Session data stored successfully');
            
            showMessage('✅ Login successful! Redirecting to dashboard...', 'success');
            
            // Set redirecting flag
            redirecting = true;
            
            // Redirect after delay
            setTimeout(() => {
                console.log('🔄 Redirecting to admin dashboard...');
                console.log('🔗 Redirect URL: /admin-dashboard.html?token=' + data.sessionToken);
                
                // Redirect with token in URL as backup
                window.location.href = '/admin-dashboard.html?token=' + encodeURIComponent(data.sessionToken);
            }, 1500);
            
        } else {
            console.error('❌ Authentication failed:', data);
            
            // Handle specific error messages
            let errorMessage = 'Login failed';
            
            if (data.error === 'Account Locked') {
                errorMessage = `Account locked: ${data.message}`;
            } else if (data.error === 'Too Many Login Attempts') {
                errorMessage = `Too many attempts: ${data.message}`;
            } else if (data.message) {
                errorMessage = data.message;
            } else if (data.error) {
                errorMessage = data.error;
            }
            
            showMessage(`❌ ${errorMessage}`, 'error');
            loginAttempted = false;
        }
        
    } catch (error) {
        console.error('❌ Login error:', error);
        showMessage(`❌ Login failed: ${error.message}`, 'error');
        loginAttempted = false;
    } finally {
        if (!redirecting) {
            loginBtn.disabled = false;
            loginBtn.textContent = 'Login to Dashboard';
        }
    }
}

// Update current time ONCE without interval
function updateTimeOnce() {
    const now = new Date();
    const timeString = now.toISOString().replace('T', ' ').substring(0, 19);
    const timeElement = document.getElementById('currentTime');
    if (timeElement) {
        timeElement.textContent = timeString;
    }
    console.log('🕐 Time updated once:', timeString);
}

// Initialize when DOM is loaded
function initialize() {
    console.log('🚀 Initializing admin login page...');
    console.log('📅 Time: 2025-06-13 04:35:40 UTC');
    console.log('👤 User: ranatalhamajid1');
    console.log('📍 Location: Islamabad, Pakistan');
    
    // CRITICAL: Clear any existing session data to prevent loops
    console.log('🧹 Clearing existing session data to prevent redirect loops...');
    clearStoredSession();
    
    // Check URL parameters for messages
    const urlParams = new URLSearchParams(window.location.search);
    const message = urlParams.get('message');
    const reason = urlParams.get('reason');
    
    if (message) {
        showMessage(decodeURIComponent(message), 'info');
    } else if (reason) {
        showMessage(`Access denied: ${decodeURIComponent(reason)}`, 'warning');
    }
    
    // Set up event listeners
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
        console.log('✅ Login form event listener attached');
    } else {
        console.error('❌ Login form not found!');
    }
    
    // Add Enter key support for password field
    const passwordField = document.getElementById('password');
    if (passwordField) {
        passwordField.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !redirecting && !loginAttempted) {
                handleLogin(e);
            }
        });
        console.log('✅ Password field Enter key listener attached');
    }
    
    // Add Enter key support for username field
    const usernameField = document.getElementById('username');
    if (usernameField) {
        usernameField.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !redirecting && !loginAttempted) {
                handleLogin(e);
            }
        });
        console.log('✅ Username field Enter key listener attached');
    }
    
    // Check server status ONCE
    checkServerOnce();
    
    // Update time ONCE (NO INTERVAL)
    updateTimeOnce();
    
    console.log('✅ Admin login page initialized successfully');
    console.log('🔄 Auto-redirect COMPLETELY DISABLED');
    console.log('⏰ Auto-refresh COMPLETELY DISABLED');
    console.log('🛑 No setInterval functions running');
}

// Prevent any accidental page refreshes
window.addEventListener('beforeunload', (e) => {
    if (redirecting) {
        console.log('🔄 Allowing redirect to dashboard');
        return;
    }
    
    console.log('⚠️ Page unload detected (not from redirect)');
});

// Only initialize when DOM is fully loaded
document.addEventListener('DOMContentLoaded', () => {
    console.log('📄 DOM Content Loaded');
    initialize();
});

// Additional safety check
window.addEventListener('load', () => {
    console.log('🎯 Window fully loaded');
    console.log('🔍 Checking for any unwanted intervals...');
    
    // Clear any potential intervals that might exist
    for (let i = 1; i < 1000; i++) {
        clearInterval(i);
        clearTimeout(i);
    }
    
    console.log('🧹 Cleared any potential intervals/timeouts');
});

console.log('✅ Admin Login script loaded completely');
console.log('📅 Script timestamp: 2025-06-13 04:35:40 UTC');
console.log('👤 Script user: ranatalhamajid1');
console.log('🚫 NO AUTO-REFRESH FUNCTIONALITY INCLUDED');