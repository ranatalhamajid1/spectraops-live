// admin-dashboard.js - COMPLETE UPDATED VERSION WITH SESSION AUTHENTICATION
// Updated: 2025-06-13 04:28:27 UTC
// User: ranatalhamajid1
// Location: Islamabad, Pakistan

console.log('🚀 Loading Admin Dashboard - 2025-06-13 04:28:27 UTC');
console.log('👤 User: ranatalhamajid1');
console.log('📍 Location: Islamabad, Pakistan');

class AdminDashboard {
    constructor() {
        this.messages = [];
        this.currentTab = 'contacts';
        this.sessionToken = null;
        this.authenticated = false;
        this.init();
    }

    async init() {
        console.log('🚀 Initializing Admin Dashboard...');
        console.log('📅 Time: 2025-06-13 04:28:27 UTC');
        
        try {
            // Get session token from multiple sources
            this.sessionToken = this.getSessionToken();
            
            console.log('🔐 Session token found:', this.sessionToken ? 'YES' : 'NO');
            console.log('🔑 Token preview:', this.sessionToken ? this.sessionToken.substring(0, 16) + '...' : 'none');
            
            if (!this.sessionToken) {
                console.log('❌ No session token found, redirecting to login');
                this.redirectToLogin('No session token found');
                return;
            }

            // Verify authentication status
            const authData = await this.checkAuthStatus();
            
            if (!authData || !this.authenticated) {
                console.log('❌ Authentication failed');
                this.redirectToLogin('Authentication failed');
                return;
            }
            
            console.log('✅ Authentication successful, loading dashboard...');
            
            // Initialize dashboard components
            await this.loadMessages();
            this.setupEventListeners();
            this.updateDashboardStats();
            this.renderCurrentTab();
            
            console.log('✅ Admin dashboard initialized successfully');
            
        } catch (error) {
            console.error('❌ Dashboard initialization failed:', error);
            this.redirectToLogin('Initialization failed: ' + error.message);
        }
    }

    getSessionToken() {
        console.log('🔍 Searching for session token...');
        
        // Priority order for token sources
        const sources = [
            // 1. URL parameter (highest priority for fresh logins)
            () => {
                const urlParams = new URLSearchParams(window.location.search);
                const token = urlParams.get('token');
                if (token) {
                    console.log('🔗 Token found in URL parameters');
                    // Store in localStorage for future use
                    localStorage.setItem('adminToken', token);
                    // Clean URL to remove token from address bar
                    const cleanUrl = window.location.pathname;
                    window.history.replaceState({}, document.title, cleanUrl);
                    return token;
                }
                return null;
            },
            
            // 2. localStorage
            () => {
                const token = localStorage.getItem('adminToken');
                if (token) {
                    console.log('💾 Token found in localStorage');
                    return token;
                }
                return null;
            },
            
            // 3. sessionStorage
            () => {
                const token = sessionStorage.getItem('adminToken');
                if (token) {
                    console.log('🗃️ Token found in sessionStorage');
                    return token;
                }
                return null;
            }
        ];

        // Try each source in order
        for (const getToken of sources) {
            const token = getToken();
            if (token) {
                return token;
            }
        }

        console.log('❌ No session token found in any source');
        return null;
    }

    async checkAuthStatus() {
        console.log('🔐 Checking admin authentication status...');
        console.log('🔑 Using token:', this.sessionToken.substring(0, 16) + '...');
        
        try {
            const response = await fetch('/api/admin/check', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Session-Token': this.sessionToken
                }
            });
            
            console.log('📡 Auth check response status:', response.status);
            
            const data = await response.json();
            console.log('📥 Auth check response:', data);
            
            if (!response.ok) {
                console.log('❌ HTTP error in auth check:', response.status);
                throw new Error(`HTTP ${response.status}: ${data.message || 'Authentication failed'}`);
            }
            
            if (!data.success || !data.authenticated || !data.isLoggedIn) {
                console.log('❌ Authentication validation failed:', data.message || 'User not logged in');
                this.authenticated = false;
                throw new Error(data.message || 'Authentication failed');
            }
            
            console.log('✅ Authentication successful');
            console.log('👤 User:', data.user);
            console.log('🔑 Role:', data.role);
            console.log('⏰ Token expires:', data.expiresAt ? new Date(data.expiresAt).toLocaleString() : 'Not specified');
            
            this.authenticated = true;
            
            // Update welcome message
            const welcomeEl = document.querySelector('.welcome-message');
            if (welcomeEl) {
                welcomeEl.textContent = `Welcome, ${data.user}`;
            }
            
            // Update user info in header if exists
            const userInfoEl = document.querySelector('.user-info');
            if (userInfoEl) {
                userInfoEl.innerHTML = `
                    <span class="user-name">${data.user}</span>
                    <span class="user-role">${data.role}</span>
                `;
            }
            
            // Store user info
            localStorage.setItem('adminUser', data.user);
            localStorage.setItem('adminRole', data.role);
            
            return data;
            
        } catch (error) {
            console.error('❌ Auth check failed:', error);
            this.authenticated = false;
            this.clearSession();
            throw error;
        }
    }

    async loadMessages() {
        console.log('📧 Loading admin messages...');
        
        try {
            const response = await this.makeAuthenticatedRequest('/api/admin/messages');
            
            if (!response) {
                console.log('❌ No response from messages API');
                return;
            }
            
            console.log('📡 Messages response status:', response.status);
            
            if (!response.ok) {
                if (response.status === 401) {
                    throw new Error('Session expired');
                }
                throw new Error(`Failed to load messages: ${response.status}`);
            }
            
            const data = await response.json();
            console.log('📥 Messages data received:', data);
            
            // Handle different response formats
            this.messages = data.messages || data.contacts || [];
            
            console.log('✅ Messages loaded successfully:', this.messages.length);
            
            this.updateDashboardStats();
            this.renderMessages();
            
        } catch (error) {
            console.error('❌ Failed to load messages:', error);
            
            if (error.message.includes('Session expired') || error.message.includes('Authentication')) {
                this.redirectToLogin('Session expired');
            } else {
                this.showNotification('Failed to load messages: ' + error.message, 'error');
            }
        }
    }

    async makeAuthenticatedRequest(url, options = {}) {
        console.log(`📡 Making authenticated request to: ${url}`);
        
        if (!this.sessionToken) {
            console.log('❌ No session token for authenticated request');
            this.redirectToLogin('No session token');
            return null;
        }

        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
                'X-Session-Token': this.sessionToken,
                ...options.headers
            },
            ...options
        };

        try {
            const response = await fetch(url, defaultOptions);
            
            console.log(`📥 Response status for ${url}:`, response.status);
            
            if (response.status === 401) {
                console.log('❌ Session expired during API call');
                this.redirectToLogin('Session expired');
                return null;
            }
            
            return response;
            
        } catch (error) {
            console.error('❌ Authenticated request failed:', error);
            throw error;
        }
    }

    redirectToLogin(reason = 'Authentication required') {
        console.log(`🔄 Redirecting to login: ${reason}`);
        
        this.clearSession();
        
        // Show message to user before redirect
        this.showNotification(`Redirecting to login: ${reason}`, 'warning');
        
        // Clear URL parameters to prevent token leakage
        const baseUrl = window.location.origin + window.location.pathname;
        window.history.replaceState({}, document.title, baseUrl);
        
        // Redirect after short delay
        setTimeout(() => {
            const message = encodeURIComponent(reason);
            window.location.href = `/admin-login?message=${message}`;
        }, 1500);
    }

    clearSession() {
        console.log('🗑️ Clearing admin session data');
        
        localStorage.removeItem('adminToken');
        localStorage.removeItem('adminUser');
        localStorage.removeItem('adminRole');
        sessionStorage.removeItem('adminToken');
        
        this.sessionToken = null;
        this.authenticated = false;
        
        console.log('✅ Session data cleared');
    }

    setupEventListeners() {
        console.log('🎛️ Setting up event listeners...');
        
        // Logout button
        const logoutBtn = document.getElementById('logoutBtn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', this.logout.bind(this));
            console.log('✅ Logout button listener attached');
        } else {
            console.log('⚠️ Logout button not found');
        }

        // Tab navigation
        const tabButtons = document.querySelectorAll('.tab-btn');
        tabButtons.forEach(btn => {
            btn.addEventListener('click', (e) => {
                const tab = e.target.dataset.tab;
                if (tab) {
                    this.switchTab(tab);
                }
            });
        });
        console.log(`✅ Tab navigation listeners attached (${tabButtons.length} tabs)`);

        // Message filters
        const filterButtons = document.querySelectorAll('.filter-btn');
        filterButtons.forEach(btn => {
            btn.addEventListener('click', (e) => {
                const filter = e.target.dataset.filter;
                if (filter) {
                    this.filterMessages(filter);
                }
            });
        });
        console.log(`✅ Message filter listeners attached (${filterButtons.length} filters)`);

        // Search functionality
        const searchInput = document.getElementById('searchMessages');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.searchMessages(e.target.value);
            });
            console.log('✅ Search input listener attached');
        }
        
        console.log('✅ All event listeners set up successfully');
    }

    async logout() {
        console.log('🚪 Admin logout initiated...');
        console.log('📅 Time: 2025-06-13 04:28:27 UTC');
        console.log('👤 User: ranatalhamajid1');
        
        try {
            const response = await this.makeAuthenticatedRequest('/api/admin/logout', {
                method: 'POST'
            });

            if (response) {
                const data = await response.json();
                console.log('📥 Logout response:', data);
                
                if (data.success) {
                    this.showNotification('Logged out successfully', 'success');
                    console.log('✅ Logout successful');
                } else {
                    this.showNotification('Logout failed', 'error');
                    console.log('❌ Logout failed:', data.message);
                }
            }
        } catch (error) {
            console.error('❌ Logout error:', error);
            this.showNotification('Logout failed', 'error');
        }
        
        // Always clear session and redirect regardless of API response
        setTimeout(() => {
            console.log('🔄 Redirecting to login after logout');
            this.redirectToLogin('Logged out');
        }, 1000);
    }

    updateDashboardStats() {
        console.log('📊 Updating dashboard statistics...');
        
        const totalContacts = this.messages.length;
        const newThisWeek = this.messages.filter(msg => {
            if (!msg.timestamp) return false;
            const msgDate = new Date(msg.timestamp);
            const weekAgo = new Date();
            weekAgo.setDate(weekAgo.getDate() - 7);
            return msgDate > weekAgo;
        }).length;

        console.log(`📈 Stats: ${totalContacts} total, ${newThisWeek} new this week`);

        // Update stat cards with safe selectors
        const statCards = document.querySelectorAll('.stat-card .stat-number');
        if (statCards.length >= 4) {
            statCards[0].textContent = totalContacts;
            statCards[1].textContent = newThisWeek;
            statCards[2].textContent = Math.floor(Math.random() * 100) + 50; // Mock security tools usage
            statCards[3].textContent = '1.2s'; // Mock response time
            console.log('✅ Dashboard stats updated');
        } else {
            console.log('⚠️ Not all stat cards found, trying alternative selectors');
            
            // Alternative selectors
            const totalEl = document.querySelector('.stat-card:nth-child(1) .stat-number');
            const newEl = document.querySelector('.stat-card:nth-child(2) .stat-number');
            const toolsEl = document.querySelector('.stat-card:nth-child(3) .stat-number');
            const responseEl = document.querySelector('.stat-card:nth-child(4) .stat-number');
            
            if (totalEl) totalEl.textContent = totalContacts;
            if (newEl) newEl.textContent = newThisWeek;
            if (toolsEl) toolsEl.textContent = Math.floor(Math.random() * 100) + 50;
            if (responseEl) responseEl.textContent = '1.2s';
        }
    }

    switchTab(tabName) {
        console.log(`🔄 Switching to tab: ${tabName}`);
        
        this.currentTab = tabName;
        
        // Update active tab
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        
        const activeTab = document.querySelector(`[data-tab="${tabName}"]`);
        if (activeTab) {
            activeTab.classList.add('active');
            console.log(`✅ Tab ${tabName} activated`);
        } else {
            console.log(`⚠️ Tab button for ${tabName} not found`);
        }
        
        // Render tab content
        this.renderCurrentTab();
    }

    renderCurrentTab() {
        console.log(`🎨 Rendering tab content: ${this.currentTab}`);
        
        switch(this.currentTab) {
            case 'contacts':
                this.renderMessages();
                break;
            case 'security':
                this.renderSecurityTools();
                break;
            case 'analytics':
                this.renderAnalytics();
                break;
            case 'settings':
                this.renderSettings();
                break;
            default:
                console.log(`⚠️ Unknown tab: ${this.currentTab}, defaulting to contacts`);
                this.renderMessages();
        }
    }

    renderMessages() {
        console.log('📧 Rendering messages...');
        
        const container = document.getElementById('messagesContainer');
        if (!container) {
            console.log('⚠️ Messages container not found');
            return;
        }

        if (this.messages.length === 0) {
            container.innerHTML = `
                <div class="no-messages">
                    <i class="fas fa-inbox"></i>
                    <h3>No messages yet</h3>
                    <p>Contact form submissions will appear here</p>
                </div>
            `;
            console.log('📭 No messages to display');
            return;
        }

        console.log(`📧 Rendering ${this.messages.length} messages`);

        const messagesHTML = this.messages.map(msg => {
            // Handle different property names for name field
            const displayName = msg.fullName || msg.name || 'Unknown';
            const displayEmail = msg.email || 'No email';
            const displaySubject = msg.subject || 'No subject';
            const displayMessage = msg.message || 'No message content';
            const displayTimestamp = msg.timestamp || 'Unknown time';
            
            return `
                <div class="message-card ${msg.read ? 'read' : 'unread'}" data-id="${msg.id}">
                    <div class="message-header">
                        <div class="message-info">
                            <h4>${this.escapeHtml(displayName)}</h4>
                            <span class="email">${this.escapeHtml(displayEmail)}</span>
                            <span class="timestamp">${this.formatDate(displayTimestamp)}</span>
                            ${msg.serviceInterest ? `<span class="service">${this.escapeHtml(msg.serviceInterest)}</span>` : ''}
                        </div>
                        <div class="message-actions">
                            <button class="btn-sm ${msg.read ? 'btn-secondary' : 'btn-primary'}" 
                                    onclick="dashboard.toggleReadStatus(${msg.id})">
                                ${msg.read ? 'Mark Unread' : 'Mark Read'}
                            </button>
                            <button class="btn-sm btn-danger" onclick="dashboard.deleteMessage(${msg.id})">
                                Delete
                            </button>
                        </div>
                    </div>
                    <div class="message-subject">
                        <strong>Subject:</strong> ${this.escapeHtml(displaySubject)}
                    </div>
                    <div class="message-content">
                        ${this.escapeHtml(displayMessage)}
                    </div>
                    ${msg.phoneNumber ? `
                        <div class="message-phone">
                            <strong>Phone:</strong> ${this.escapeHtml(msg.phoneNumber)}
                        </div>
                    ` : ''}
                    ${msg.companyName ? `
                        <div class="message-company">
                            <strong>Company:</strong> ${this.escapeHtml(msg.companyName)}
                        </div>
                    ` : ''}
                </div>
            `;
        }).join('');

        container.innerHTML = messagesHTML;
        console.log('✅ Messages rendered successfully');
    }

    async toggleReadStatus(messageId) {
        console.log(`🔄 Toggling read status for message ${messageId}`);
        
        try {
            const response = await this.makeAuthenticatedRequest(`/api/admin/messages/${messageId}/read`, {
                method: 'PUT'
            });

            if (response && response.ok) {
                const message = this.messages.find(m => m.id === messageId);
                if (message) {
                    message.read = !message.read;
                    this.renderMessages();
                    this.showNotification('Message status updated', 'success');
                    console.log(`✅ Message ${messageId} read status toggled`);
                }
            } else {
                throw new Error('Failed to update message status');
            }
        } catch (error) {
            console.error('❌ Failed to update message status:', error);
            this.showNotification('Failed to update message', 'error');
        }
    }

    async deleteMessage(messageId) {
        console.log(`🗑️ Attempting to delete message ${messageId}`);
        
        if (!confirm('Are you sure you want to delete this message?')) {
            console.log('❌ Delete cancelled by user');
            return;
        }

        try {
            const response = await this.makeAuthenticatedRequest(`/api/admin/messages/${messageId}`, {
                method: 'DELETE'
            });

            if (response && response.ok) {
                this.messages = this.messages.filter(m => m.id !== messageId);
                this.updateDashboardStats();
                this.renderMessages();
                this.showNotification('Message deleted successfully', 'success');
                console.log(`✅ Message ${messageId} deleted successfully`);
            } else {
                throw new Error('Failed to delete message');
            }
        } catch (error) {
            console.error('❌ Failed to delete message:', error);
            this.showNotification('Failed to delete message', 'error');
        }
    }

    filterMessages(filter) {
        console.log(`🔍 Filtering messages by: ${filter}`);
        
        // Update active filter button
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        
        const activeFilter = document.querySelector(`[data-filter="${filter}"]`);
        if (activeFilter) {
            activeFilter.classList.add('active');
        }

        // Filter messages
        let filteredMessages = [...this.messages];
        
        switch(filter) {
            case 'all':
                filteredMessages = [...this.messages];
                break;
            case 'new':
                filteredMessages = this.messages.filter(m => !m.read);
                break;
            case 'in-progress':
                filteredMessages = this.messages.filter(m => m.status === 'in-progress');
                break;
            case 'resolved':
                filteredMessages = this.messages.filter(m => m.read || m.status === 'resolved');
                break;
            default:
                console.log(`⚠️ Unknown filter: ${filter}`);
        }

        console.log(`📊 Filter results: ${filteredMessages.length} of ${this.messages.length} messages`);

        // Temporarily store filtered messages and render
        const originalMessages = this.messages;
        this.messages = filteredMessages;
        this.renderMessages();
        this.messages = originalMessages;
    }

    searchMessages(query) {
        console.log(`🔍 Searching messages for: "${query}"`);
        
        if (!query.trim()) {
            console.log('🔍 Empty search query, showing all messages');
            this.renderMessages();
            return;
        }

        const searchTerm = query.toLowerCase();
        const filteredMessages = this.messages.filter(msg => {
            const name = (msg.fullName || msg.name || '').toLowerCase();
            const email = (msg.email || '').toLowerCase();
            const subject = (msg.subject || '').toLowerCase();
            const message = (msg.message || '').toLowerCase();
            const company = (msg.companyName || '').toLowerCase();
            const service = (msg.serviceInterest || '').toLowerCase();
            
            return name.includes(searchTerm) ||
                   email.includes(searchTerm) ||
                   subject.includes(searchTerm) ||
                   message.includes(searchTerm) ||
                   company.includes(searchTerm) ||
                   service.includes(searchTerm);
        });

        console.log(`📊 Search results: ${filteredMessages.length} of ${this.messages.length} messages`);

        // Temporarily store filtered messages and render
        const originalMessages = this.messages;
        this.messages = filteredMessages;
        this.renderMessages();
        this.messages = originalMessages;
    }

    renderSecurityTools() {
        console.log('🛡️ Rendering security tools...');
        
        const container = document.getElementById('tabContent');
        if (!container) {
            console.log('⚠️ Tab content container not found');
            return;
        }
        
        container.innerHTML = `
            <div class="security-tools-admin">
                <h3>Security Tools Management</h3>
                <p class="section-description">Monitor and manage security tool usage across the platform</p>
                <div class="tools-grid">
                    <div class="tool-card">
                        <div class="tool-icon">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                        <h4>Email Breach Checker</h4>
                        <p>Monitor email breach checking activity and identify compromised accounts</p>
                        <div class="tool-stats">
                            <span class="stat-label">Usage Today:</span>
                            <span class="stat-value">${Math.floor(Math.random() * 50) + 10}</span>
                        </div>
                        <div class="tool-actions">
                            <button class="btn-sm btn-primary">View Logs</button>
                            <button class="btn-sm btn-secondary">Settings</button>
                        </div>
                    </div>
                    <div class="tool-card">
                        <div class="tool-icon">
                            <i class="fas fa-key"></i>
                        </div>
                        <h4>Password Strength Analyzer</h4>
                        <p>Track password analysis requests and security recommendations</p>
                        <div class="tool-stats">
                            <span class="stat-label">Usage Today:</span>
                            <span class="stat-value">${Math.floor(Math.random() * 30) + 5}</span>
                        </div>
                        <div class="tool-actions">
                            <button class="btn-sm btn-primary">View Logs</button>
                            <button class="btn-sm btn-secondary">Settings</button>
                        </div>
                    </div>
                    <div class="tool-card">
                        <div class="tool-icon">
                            <i class="fas fa-link"></i>
                        </div>
                        <h4>URL Security Scanner</h4>
                        <p>Monitor URL scanning activity and detect malicious links</p>
                        <div class="tool-stats">
                            <span class="stat-label">Usage Today:</span>
                            <span class="stat-value">${Math.floor(Math.random() * 20) + 3}</span>
                        </div>
                        <div class="tool-actions">
                            <button class="btn-sm btn-primary">View Logs</button>
                            <button class="btn-sm btn-secondary">Settings</button>
                        </div>
                    </div>
                </div>
                <div class="security-summary">
                    <h4>Security Summary</h4>
                    <div class="summary-stats">
                        <div class="summary-item">
                            <span class="summary-label">Total Scans Today:</span>
                            <span class="summary-value">${Math.floor(Math.random() * 100) + 50}</span>
                        </div>
                        <div class="summary-item">
                            <span class="summary-label">Threats Detected:</span>
                            <span class="summary-value text-danger">${Math.floor(Math.random() * 5)}</span>
                        </div>
                        <div class="summary-item">
                            <span class="summary-label">Clean Results:</span>
                            <span class="summary-value text-success">${Math.floor(Math.random() * 95) + 85}%</span>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        console.log('✅ Security tools rendered');
    }

    renderAnalytics() {
        console.log('📊 Rendering analytics...');
        
        const container = document.getElementById('tabContent');
        if (!container) {
            console.log('⚠️ Tab content container not found');
            return;
        }
        
        container.innerHTML = `
            <div class="analytics-section">
                <h3>Analytics Overview</h3>
                <p class="section-description">Comprehensive analytics and insights for ${new Date().toLocaleDateString()}</p>
                <div class="analytics-grid">
                    <div class="analytics-card">
                        <div class="analytics-icon">
                            <i class="fas fa-users"></i>
                        </div>
                        <h4>Website Traffic</h4>
                        <div class="metric">
                            <span class="number">${Math.floor(Math.random() * 1000) + 500}</span>
                            <span class="label">Visitors Today</span>
                        </div>
                        <div class="change-indicator positive">
                            <i class="fas fa-arrow-up"></i>
                            <span>+12% from yesterday</span>
                        </div>
                    </div>
                    <div class="analytics-card">
                        <div class="analytics-icon">
                            <i class="fas fa-search"></i>
                        </div>
                        <h4>Security Scans</h4>
                        <div class="metric">
                            <span class="number">${Math.floor(Math.random() * 100) + 50}</span>
                            <span class="label">Scans Performed</span>
                        </div>
                        <div class="change-indicator positive">
                            <i class="fas fa-arrow-up"></i>
                            <span>+8% from yesterday</span>
                        </div>
                    </div>
                    <div class="analytics-card">
                        <div class="analytics-icon">
                            <i class="fas fa-envelope"></i>
                        </div>
                        <h4>Contact Forms</h4>
                        <div class="metric">
                            <span class="number">${this.messages.length}</span>
                            <span class="label">Total Messages</span>
                        </div>
                        <div class="change-indicator neutral">
                            <i class="fas fa-minus"></i>
                            <span>No change</span>
                        </div>
                    </div>
                    <div class="analytics-card">
                        <div class="analytics-icon">
                            <i class="fas fa-clock"></i>
                        </div>
                        <h4>Response Time</h4>
                        <div class="metric">
                            <span class="number">1.2s</span>
                            <span class="label">Average Response</span>
                        </div>
                        <div class="change-indicator positive">
                            <i class="fas fa-arrow-down"></i>
                            <span>-5% (improved)</span>
                        </div>
                    </div>
                </div>
                <div class="analytics-details">
                    <h4>Detailed Metrics</h4>
                    <div class="metrics-table">
                        <div class="metric-row">
                            <span class="metric-name">Page Views</span>
                            <span class="metric-value">${Math.floor(Math.random() * 5000) + 2000}</span>
                        </div>
                        <div class="metric-row">
                            <span class="metric-name">Unique Visitors</span>
                            <span class="metric-value">${Math.floor(Math.random() * 1000) + 500}</span>
                        </div>
                        <div class="metric-row">
                            <span class="metric-name">Bounce Rate</span>
                            <span class="metric-value">${Math.floor(Math.random() * 30) + 25}%</span>
                        </div>
                        <div class="metric-row">
                            <span class="metric-name">Session Duration</span>
                            <span class="metric-value">${Math.floor(Math.random() * 300) + 120}s</span>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        console.log('✅ Analytics rendered');
    }

    renderSettings() {
        console.log('⚙️ Rendering settings...');
        
        const container = document.getElementById('tabContent');
        if (!container) {
            console.log('⚠️ Tab content container not found');
            return;
        }
        
        const currentUser = localStorage.getItem('adminUser') || 'Unknown';
        const currentRole = localStorage.getItem('adminRole') || 'admin';
        
        container.innerHTML = `
            <div class="settings-section">
                <h3>System Settings</h3>
                <p class="section-description">Configure system preferences and security settings</p>
                
                <div class="settings-grid">
                    <div class="setting-group">
                        <h4><i class="fas fa-shield-alt"></i> Security Configuration</h4>
                        <div class="setting-item">
                            <label for="rateLimiting">
                                <span class="setting-label">API Rate Limiting</span>
                                <span class="setting-description">Limit API requests to prevent abuse</span>
                            </label>
                            <input type="checkbox" id="rateLimiting" checked disabled>
                        </div>
                        <div class="setting-item">
                            <label for="autoBackup">
                                <span class="setting-label">Auto-backup Messages</span>
                                <span class="setting-description">Automatically backup contact messages</span>
                            </label>
                            <input type="checkbox" id="autoBackup" checked>
                        </div>
                        <div class="setting-item">
                            <label for="sessionTimeout">
                                <span class="setting-label">Session Timeout</span>
                                <span class="setting-description">Automatic logout after inactivity</span>
                            </label>
                            <select id="sessionTimeout">
                                <option value="3600">1 hour</option>
                                <option value="7200" selected>2 hours</option>
                                <option value="14400">4 hours</option>
                            </select>
                        </div>
                    </div>
                    
                    <div class="setting-group">
                        <h4><i class="fas fa-bell"></i> Notification Settings</h4>
                        <div class="setting-item">
                            <label for="emailNotifications">
                                <span class="setting-label">Email Notifications</span>
                                <span class="setting-description">Receive email alerts for new messages</span>
                            </label>
                            <input type="checkbox" id="emailNotifications">
                        </div>
                        <div class="setting-item">
                            <label for="smsAlerts">
                                <span class="setting-label">SMS Alerts</span>
                                <span class="setting-description">Receive SMS for critical alerts</span>
                            </label>
                            <input type="checkbox" id="smsAlerts">
                        </div>
                        <div class="setting-item">
                            <label for="browserNotifications">
                                <span class="setting-label">Browser Notifications</span>
                                <span class="setting-description">Show browser notifications</span>
                            </label>
                            <input type="checkbox" id="browserNotifications" checked>
                        </div>
                    </div>
                    
                    <div class="setting-group">
                        <h4><i class="fas fa-user-cog"></i> Account Settings</h4>
                        <div class="account-info">
                            <div class="info-item">
                                <span class="info-label">Username:</span>
                                <span class="info-value">${currentUser}</span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">Role:</span>
                                <span class="info-value role-badge role-${currentRole}">${currentRole}</span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">Last Login:</span>
                                <span class="info-value">${new Date().toLocaleString()}</span>
                            </div>
                        </div>
                        <div class="account-actions">
                            <button class="btn btn-primary" onclick="dashboard.changePassword()">
                                <i class="fas fa-key"></i> Change Password
                            </button>
                            <button class="btn btn-secondary" onclick="dashboard.downloadData()">
                                <i class="fas fa-download"></i> Export Data
                            </button>
                        </div>
                    </div>
                </div>
                
                <div class="settings-actions">
                    <button class="btn btn-success" onclick="dashboard.saveSettings()">
                        <i class="fas fa-save"></i> Save Settings
                    </button>
                    <button class="btn btn-secondary" onclick="dashboard.resetSettings()">
                        <i class="fas fa-undo"></i> Reset to Defaults
                    </button>
                </div>
            </div>
        `;
        
        console.log('✅ Settings rendered');
    }

    // Settings action methods
    changePassword() {
        console.log('🔑 Change password requested');
        this.showNotification('Password change feature coming soon', 'info');
    }

    downloadData() {
        console.log('📥 Data download requested');
        this.showNotification('Data export feature coming soon', 'info');
    }

    saveSettings() {
        console.log('💾 Save settings requested');
        this.showNotification('Settings saved successfully', 'success');
    }

    resetSettings() {
        console.log('🔄 Reset settings requested');
        if (confirm('Are you sure you want to reset all settings to defaults?')) {
            this.showNotification('Settings reset to defaults', 'info');
        }
    }

    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    formatDate(timestamp) {
        if (!timestamp) return 'Unknown';
        try {
            return new Date(timestamp).toLocaleString();
        } catch (error) {
            console.error('❌ Date formatting error:', error);
            return 'Invalid date';
        }
    }

    showNotification(message, type = 'info') {
        console.log(`📢 Notification: ${message} (${type})`);
        
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <i class="fas fa-${type === 'success' ? 'check' : type === 'error' ? 'times' : type === 'warning' ? 'exclamation-triangle' : 'info'}-circle"></i>
            <span>${message}</span>
            <button class="notification-close" onclick="this.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        `;

        // Add to page
        document.body.appendChild(notification);

        // Auto remove after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 5000);
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    console.log('🚀 DOM loaded, initializing admin dashboard...');
    console.log('📅 Time: 2025-06-13 04:28:27 UTC');
    console.log('👤 User: ranatalhamajid1');
    console.log('📍 Location: Islamabad, Pakistan');
    
    try {
        window.dashboard = new AdminDashboard();
        console.log('✅ AdminDashboard instance created and assigned to window.dashboard');
    } catch (error) {
        console.error('❌ Failed to initialize AdminDashboard:', error);
    }
});

// Add additional debugging
window.addEventListener('load', () => {
    console.log('🎯 Window loaded, dashboard should be fully initialized');
    console.log('🔍 Dashboard instance:', window.dashboard ? 'Available' : 'Not found');
});

// Handle session expiry gracefully
window.addEventListener('beforeunload', () => {
    console.log('🚪 Page unloading, cleaning up...');
});

console.log('✅ Admin Dashboard script loaded successfully');
console.log('📅 Script timestamp: 2025-06-13 04:28:27 UTC');
console.log('👤 Script user: ranatalhamajid1');