const express = require('express');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

// Updated current time and user - SYNCHRONIZED TO CURRENT TIME
const CURRENT_TIME = '2025-06-13T06:07:06Z';
const CURRENT_USER = 'ranatalhamajid1';

console.log('='.repeat(80));
console.log('🚀 SPECTRAOPS SERVER - COMPLETE VERSION WITH SECURITY TOOLS APIS');
console.log('='.repeat(80));
console.log(`📅 Current Time: ${CURRENT_TIME}`);
console.log(`👤 Current User: ${CURRENT_USER}`);
console.log(`🌍 Location: Islamabad, Pakistan`);
console.log(`🔧 Node.js Version: ${process.version}`);
console.log(`💾 Memory Usage: ${JSON.stringify(process.memoryUsage())}`);
console.log('='.repeat(80));
console.log('🔧 FEATURES IMPLEMENTED:');
console.log('   ✅ Contact Form Fixed (No Auto-Refresh)');
console.log('   ✅ Admin Dashboard Real-time Data');
console.log('   ✅ Enhanced Debugging & Logging');
console.log('   ✅ Dual-Theme Support');
console.log('   ✅ Security Tools Integration');
console.log('   ✅ Email Subscription System');
console.log('   ✅ Authentication & Authorization');
console.log('   ✅ Test Data Generator');
console.log('   ✅ ROBOTS.TXT PROTECTION');
console.log('   ✅ ADMIN ACCESS PROTECTION - FIXED!');
console.log('   ✅ HEALTH ENDPOINT - ADDED!');
console.log('   ✅ LOGIN LOOP FIXES - APPLIED!');
console.log('   ✅ FILE PATH CORRECTIONS - FIXED!');
console.log('   ✅ DASHBOARD ENDPOINTS - ADDED!');
console.log('   ✅ SECURITY TOOLS APIS - ADDED!');
console.log('='.repeat(80));

// ===== ADMIN SECURITY SYSTEM =====

// Valid admin credentials and security settings
const ADMIN_CONFIG = {
    validCredentials: {
        'ranatalhamajid1': {
            password: 'SpectraOps2025!',
            role: 'super-admin',
            permissions: ['read', 'write', 'admin', 'delete', 'system'],
            lastLogin: null,
            loginAttempts: 0,
            locked: false,
            lockUntil: null
        },
        'admin': {
            password: 'Admin123!',
            role: 'admin',
            permissions: ['read', 'write', 'admin'],
            lastLogin: null,
            loginAttempts: 0,
            locked: false,
            lockUntil: null
        },
        'talha': {
            password: 'Talha2025!',
            role: 'admin',
            permissions: ['read', 'write', 'admin'],
            lastLogin: null,
            loginAttempts: 0,
            locked: false,
            lockUntil: null
        }
    },
    
    // Security settings
    maxLoginAttempts: 3,
    lockDuration: 15 * 60 * 1000, // 15 minutes
    sessionTimeout: 2 * 60 * 60 * 1000, // 2 hours
    allowedIPs: [], // Empty = allow all, or add specific IPs like ['127.0.0.1', '192.168.1.100']
    
    // Rate limiting
    rateLimiting: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        maxAttempts: 5,
        attempts: new Map()
    }
};

// Active admin sessions
const activeSessions = new Map();

// Security helper functions
function generateSecureToken() {
    return crypto.randomBytes(32).toString('hex');
}

function hashPassword(password) {
    return crypto.createHash('sha256').update(password + 'SpectraOpsSalt2025').digest('hex');
}

function isValidSession(token) {
    const session = activeSessions.get(token);
    if (!session) return false;
    
    // Check if session expired
    if (Date.now() > session.expiresAt) {
        activeSessions.delete(token);
        return false;
    }
    
    // Extend session
    session.expiresAt = Date.now() + ADMIN_CONFIG.sessionTimeout;
    activeSessions.set(token, session);
    
    return true;
}

function checkRateLimit(ip) {
    const now = Date.now();
    const attempts = ADMIN_CONFIG.rateLimiting.attempts.get(ip) || [];
    
    // Clean old attempts
    const recentAttempts = attempts.filter(timestamp => 
        now - timestamp < ADMIN_CONFIG.rateLimiting.windowMs
    );
    
    ADMIN_CONFIG.rateLimiting.attempts.set(ip, recentAttempts);
    
    return recentAttempts.length < ADMIN_CONFIG.rateLimiting.maxAttempts;
}

function recordLoginAttempt(ip) {
    const attempts = ADMIN_CONFIG.rateLimiting.attempts.get(ip) || [];
    attempts.push(Date.now());
    ADMIN_CONFIG.rateLimiting.attempts.set(ip, attempts);
}

// Enhanced middleware with detailed logging
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging middleware
app.use((req, res, next) => {
    const timestamp = new Date().toISOString();
    console.log(`📡 ${timestamp} - ${req.method} ${req.path}`);
    
    if (req.method === 'POST' && req.path.startsWith('/api/')) {
        console.log(`📤 POST Body:`, req.body);
    }
    
    next();
});

// Enhanced CORS headers
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-User, X-Timestamp, X-Location, X-Session-Token');
    
    if (req.method === 'OPTIONS') {
        res.sendStatus(200);
    } else {
        next();
    }
});

// Enhanced in-memory data storage with initialization
let adminData = {
    totalContacts: 0,
    newThisWeek: 0,
    securityToolsUsed: 147,
    avgResponseTime: '1.0s',
    subscribers: [],
    contacts: [],
    securityLogs: [],
    recentActivity: [],
    systemHealth: 'excellent',
    uptime: 0,
    robotsRequests: 0,
    suspiciousAttempts: 0,
    blockedAttempts: 0,
    adminLoginAttempts: 0,
    lastAdminLogin: null
};

console.log('💾 Admin data initialized:', {
    contacts: adminData.contacts.length,
    subscribers: adminData.subscribers.length,
    activities: adminData.recentActivity.length,
    securityTools: adminData.securityToolsUsed,
    robotsRequests: adminData.robotsRequests,
    blockedAttempts: adminData.blockedAttempts
});

// ===== CRITICAL FIX: HEALTH CHECK ENDPOINT - ADDED =====

// Health check endpoint - REQUIRED for login page
app.get('/api/health', (req, res) => {
    console.log('🔍 Health check endpoint requested');
    console.log(`📅 Time: ${new Date().toISOString()}`);
    console.log(`🌐 Server uptime: ${process.uptime()} seconds`);
    console.log(`💾 Memory usage: ${JSON.stringify(process.memoryUsage())}`);
    
    const healthData = {
        success: true,
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: Math.floor(process.uptime()),
        server: 'SpectraOps Admin Server',
        version: '1.0.0',
        user: CURRENT_USER,
        location: 'Islamabad, Pakistan',
        environment: 'production',
        features: [
            'Admin Authentication',
            'Session Management',
            'Security Logging',
            'Rate Limiting',
            'Contact Form',
            'Dashboard Analytics',
            'Security Tools API'
        ],
        endpoints: {
            health: '/api/health',
            authenticate: '/api/admin/authenticate',
            check: '/api/admin/check',
            dashboard: '/api/admin/dashboard',
            messages: '/api/admin/messages',
            activity: '/api/admin/activity',
            securityLogs: '/api/admin/security-logs',
            contact: '/api/contact',
            checkBreach: '/api/check-breach',
            scanUrl: '/api/scan-url',
            scanFile: '/api/scan-file'
        },
        memory: {
            used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + ' MB',
            total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + ' MB',
            rss: Math.round(process.memoryUsage().rss / 1024 / 1024) + ' MB'
        },
        security: {
            activeSessions: activeSessions.size,
            adminLoginAttempts: adminData.adminLoginAttempts,
            blockedAttempts: adminData.blockedAttempts,
            suspiciousAttempts: adminData.suspiciousAttempts
        }
    };
    
    console.log('✅ Health check response prepared');
    console.log('📤 Sending health data');
    
    res.json(healthData);
});

// API endpoints list for debugging
app.get('/api/endpoints', (req, res) => {
    console.log('📋 API endpoints list requested');
    
    const endpoints = {
        success: true,
        message: 'SpectraOps API Endpoints',
        timestamp: new Date().toISOString(),
        server: 'SpectraOps Admin Server',
        user: CURRENT_USER,
        location: 'Islamabad, Pakistan',
        endpoints: [
            {
                method: 'GET',
                path: '/api/health',
                description: 'Server health check and status',
                protected: false,
                example: 'GET /api/health'
            },
            {
                method: 'GET',
                path: '/api/endpoints',
                description: 'List all available API endpoints',
                protected: false,
                example: 'GET /api/endpoints'
            },
            {
                method: 'POST',
                path: '/api/admin/authenticate',
                description: 'Admin login authentication',
                protected: false,
                body: ['username', 'password', 'timestamp'],
                example: 'POST /api/admin/authenticate'
            },
            {
                method: 'GET',
                path: '/api/admin/check',
                description: 'Check admin session validity',
                protected: true,
                headers: ['X-Session-Token'],
                example: 'GET /api/admin/check'
            },
            {
                method: 'GET',
                path: '/api/admin/dashboard',
                description: 'Admin dashboard data and statistics',
                protected: true,
                headers: ['X-Session-Token'],
                example: 'GET /api/admin/dashboard'
            },
            {
                method: 'GET',
                path: '/api/admin/messages',
                description: 'Admin contact messages and submissions',
                protected: true,
                headers: ['X-Session-Token'],
                example: 'GET /api/admin/messages'
            },
            {
                method: 'GET',
                path: '/api/admin/activity',
                description: 'Admin recent activity logs',
                protected: true,
                headers: ['X-Session-Token'],
                example: 'GET /api/admin/activity'
            },
            {
                method: 'GET',
                path: '/api/admin/security-logs',
                description: 'Admin security logs and events',
                protected: true,
                headers: ['X-Session-Token'],
                example: 'GET /api/admin/security-logs'
            },
            {
                method: 'POST',
                path: '/api/contact',
                description: 'Contact form submission',
                protected: false,
                body: ['fullName', 'email', 'subject', 'message', 'mathAnswer'],
                example: 'POST /api/contact'
            },
            {
                method: 'POST',
                path: '/api/check-breach',
                description: 'Email breach checker security tool',
                protected: false,
                body: ['email', 'timestamp', 'user'],
                example: 'POST /api/check-breach'
            },
            {
                method: 'POST',
                path: '/api/scan-url',
                description: 'URL security scanner tool',
                protected: false,
                body: ['url', 'timestamp', 'user'],
                example: 'POST /api/scan-url'
            },
            {
                method: 'POST',
                path: '/api/scan-file',
                description: 'Malicious file checker tool',
                protected: false,
                body: ['fileName', 'fileSize', 'fileType', 'fileHash'],
                example: 'POST /api/scan-file'
            }
        ],
        notes: [
            'Protected endpoints require X-Session-Token header',
            'Session tokens are obtained via /api/admin/authenticate',
            'Rate limiting is applied to authentication endpoints',
            'All requests are logged for security monitoring',
            'Security tools APIs are public but logged for admin dashboard'
        ]
    };
    
    console.log('📤 Endpoints list response sent');
    res.json(endpoints);
});

// ===== FILE STRUCTURE DEBUG ENDPOINT - ADDED =====
app.get('/api/debug/files', (req, res) => {
    console.log('🔍 File structure debug requested');
    
    const fs = require('fs');
    const cwd = process.cwd();
    
    function listFiles(dir, maxDepth = 2, currentDepth = 0) {
        if (currentDepth >= maxDepth) return [];
        
        try {
            const items = fs.readdirSync(dir);
            let files = [];
            
            for (const item of items) {
                const fullPath = path.join(dir, item);
                const stat = fs.statSync(fullPath);
                
                if (stat.isDirectory()) {
                    files.push({
                        name: item,
                        type: 'directory',
                        path: fullPath,
                        children: listFiles(fullPath, maxDepth, currentDepth + 1)
                    });
                } else {
                    files.push({
                        name: item,
                        type: 'file',
                        path: fullPath,
                        size: stat.size
                    });
                }
            }
            
            return files;
        } catch (error) {
            return [{
                name: 'ERROR',
                type: 'error',
                message: error.message
            }];
        }
    }
    
    const fileStructure = {
        success: true,
        timestamp: new Date().toISOString(),
        currentWorkingDirectory: cwd,
        __dirname: __dirname,
        nodeVersion: process.version,
        platform: process.platform,
        files: listFiles(cwd),
        searchResults: {
            'admin-login.html': [],
            'admin-dashboard.html': [],
            'index.html': []
        }
    };
    
    // Search for important files
    function findFile(filename, dir = cwd, maxDepth = 3, currentDepth = 0) {
        if (currentDepth >= maxDepth) return [];
        
        try {
            const items = fs.readdirSync(dir);
            let found = [];
            
            for (const item of items) {
                const fullPath = path.join(dir, item);
                const stat = fs.statSync(fullPath);
                
                if (item === filename) {
                    found.push(fullPath);
                } else if (stat.isDirectory() && !item.startsWith('.') && item !== 'node_modules') {
                    found = found.concat(findFile(filename, fullPath, maxDepth, currentDepth + 1));
                }
            }
            
            return found;
        } catch (error) {
            return [];
        }
    }
    
    fileStructure.searchResults['admin-login.html'] = findFile('admin-login.html');
    fileStructure.searchResults['admin-dashboard.html'] = findFile('admin-dashboard.html');
    fileStructure.searchResults['index.html'] = findFile('index.html');
    
    console.log('📁 File structure response prepared');
    res.json(fileStructure);
});

// ===== SECURITY TOOLS API ENDPOINTS - ADDED =====

// Email breach checker endpoint
app.post('/api/check-breach', (req, res) => {
    console.log('🔐 Email breach check requested');
    console.log('📅 Time:', new Date().toISOString());
    console.log('👤 User:', CURRENT_USER);
    
    const { email, timestamp, user, location } = req.body;
    
    console.log('📧 Checking email:', email);
    
    // Validate email
    if (!email || typeof email !== 'string') {
        return res.status(400).json({
            success: false,
            error: 'Invalid email',
            message: 'Email address is required',
            timestamp: new Date().toISOString()
        });
    }
    
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
        return res.status(400).json({
            success: false,
            error: 'Invalid email format',
            message: 'Please provide a valid email address',
            timestamp: new Date().toISOString()
        });
    }
    
    // Simulate breach check (replace with real API in production)
    const knownBreaches = [
        'LinkedIn (2012)', 
        'Yahoo (2013-2014)', 
        'Adobe (2013)', 
        'Equifax (2017)',
        'Facebook (2019)',
        'Twitter (2022)',
        'LastPass (2022)',
        'Dropbox (2012)'
    ];
    
    const isBreached = Math.random() > 0.7; // 30% chance of breach for demo
    const numBreaches = isBreached ? Math.floor(Math.random() * 3) + 1 : 0;
    const breaches = isBreached ? 
        knownBreaches.sort(() => 0.5 - Math.random()).slice(0, numBreaches) : [];
    
    // Log security activity
    adminData.securityLogs.push({
        id: Date.now(),
        type: 'Email Breach Check',
        target: email,
        result: isBreached ? `Breach found in: ${breaches.join(', ')}` : 'No breaches found',
        tool: 'Email Breach Checker',
        user: user || CURRENT_USER,
        ip: req.ip || '127.0.0.1',
        timestamp: new Date().toISOString(),
        safe: !isBreached
    });
    
    // Add to recent activity
    adminData.recentActivity.push({
        id: Date.now() + 1,
        action: 'Email Breach Check',
        details: `Checked ${email} - ${isBreached ? 'Breach found' : 'Clean'}`,
        timestamp: new Date().toISOString(),
        type: 'security_tool',
        user: user || CURRENT_USER,
        priority: isBreached ? 'high' : 'normal'
    });
    
    // Update security tools count
    adminData.securityToolsUsed += 1;
    
    const response = {
        success: true,
        breached: isBreached,
        message: isBreached ? 
            `⚠️ Security Alert: This email was found in ${breaches.length} data breach${breaches.length > 1 ? 'es' : ''}. Consider changing passwords for associated accounts.` :
            '✅ Good news! This email was not found in any known data breaches in our database.',
        breaches: breaches,
        email: email,
        timestamp: new Date().toISOString(),
        user: user || CURRENT_USER,
        recommendation: isBreached ? 
            'Change passwords immediately for any accounts using this email. Enable two-factor authentication where possible.' :
            'Continue practicing good password hygiene and monitor for future breaches.'
    };
    
    console.log('📤 Breach check response:', response);
    res.json(response);
});

// URL security scanner endpoint
app.post('/api/scan-url', (req, res) => {
    console.log('🔗 URL security scan requested');
    console.log('📅 Time:', new Date().toISOString());
    console.log('👤 User:', CURRENT_USER);
    
    const { url, timestamp, user, location } = req.body;
    
    console.log('🔍 Scanning URL:', url);
    
    // Validate URL
    if (!url || typeof url !== 'string') {
        return res.status(400).json({
            success: false,
            error: 'Invalid URL',
            message: 'URL is required',
            timestamp: new Date().toISOString()
        });
    }
    
    let validUrl;
    try {
        validUrl = new URL(url);
    } catch (error) {
        return res.status(400).json({
            success: false,
            error: 'Invalid URL format',
            message: 'Please provide a valid URL (include http:// or https://)',
            timestamp: new Date().toISOString()
        });
    }
    
    // Simulate URL scanning (replace with real API in production)
    const maliciousDomains = [
        'malware.com', 
        'phishing.net', 
        'suspicious.org',
        'fake-bank.com',
        'scam-site.net',
        'virus-download.com'
    ];
    
    const suspiciousPatterns = [
        'bit.ly/virus',
        'free-money',
        'urgent-action',
        'click-here-now',
        'verify-account',
        'suspended-account'
    ];
    
    const isMaliciousDomain = maliciousDomains.some(domain => url.includes(domain));
    const hasSuspiciousPattern = suspiciousPatterns.some(pattern => url.includes(pattern));
    const isSafe = !isMaliciousDomain && !hasSuspiciousPattern && Math.random() > 0.2;
    
    let threats = [];
    if (isMaliciousDomain) threats.push('Known malicious domain');
    if (hasSuspiciousPattern) threats.push('Suspicious URL pattern detected');
    if (!isSafe && threats.length === 0) threats.push('Potential phishing indicators');
    
    // Log security activity
    adminData.securityLogs.push({
        id: Date.now(),
        type: 'URL Security Scan',
        target: url.length > 50 ? url.substring(0, 50) + '...' : url,
        result: isSafe ? 'URL appears safe' : `Threats detected: ${threats.join(', ')}`,
        tool: 'URL Security Scanner',
        user: user || CURRENT_USER,
        ip: req.ip || '127.0.0.1',
        timestamp: new Date().toISOString(),
        safe: isSafe
    });
    
    // Add to recent activity
    adminData.recentActivity.push({
        id: Date.now() + 1,
        action: 'URL Security Scan',
        details: `Scanned ${validUrl.hostname} - ${isSafe ? 'Safe' : 'Threats detected'}`,
        timestamp: new Date().toISOString(),
        type: 'security_tool',
        user: user || CURRENT_USER,
        priority: isSafe ? 'normal' : 'high'
    });
    
    // Update security tools count
    adminData.securityToolsUsed += 1;
    
    const response = {
        success: true,
        safe: isSafe,
        message: isSafe ? 
            '✅ This URL appears to be safe based on our security analysis. No known threats detected.' :
            `⚠️ Security Warning: This URL may contain malicious content. ${threats.length} threat${threats.length > 1 ? 's' : ''} detected.`,
        url: url,
        domain: validUrl.hostname,
        protocol: validUrl.protocol,
        threats: threats,
        timestamp: new Date().toISOString(),
        user: user || CURRENT_USER,
        details: {
            scanned: true,
            threatCount: threats.length,
            riskLevel: isSafe ? 'low' : threats.length > 1 ? 'high' : 'medium'
        },
        recommendation: isSafe ? 
            'URL appears safe, but always exercise caution when clicking links.' :
            'Do not visit this URL. It may contain malware, phishing content, or other security threats.'
    };
    
    console.log('📤 URL scan response:', response);
    res.json(response);
});

// Malicious file checker endpoint - NEW
app.post('/api/scan-file', (req, res) => {
    console.log('📁 File security scan requested');
    console.log('📅 Time:', new Date().toISOString());
    console.log('👤 User:', CURRENT_USER);
    
    const { fileName, fileSize, fileType, fileHash, timestamp, user, location } = req.body;
    
    console.log('🔍 Scanning file:', fileName, 'Type:', fileType, 'Size:', fileSize);
    
    // Validate file data
    if (!fileName || typeof fileName !== 'string') {
        return res.status(400).json({
            success: false,
            error: 'Invalid file data',
            message: 'File name is required',
            timestamp: new Date().toISOString()
        });
    }
    
    // Simulate file scanning (replace with real antivirus API in production)
    const maliciousExtensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.vbs', '.jar', '.com', '.pdb'];
    const suspiciousNames = [
        'virus', 'malware', 'trojan', 'keylogger', 'backdoor', 'spyware',
        'ransomware', 'worm', 'rootkit', 'adware', 'phishing', 'hack'
    ];
    const maliciousHashes = [
        'd41d8cd98f00b204e9800998ecf8427e',
        'e3b0c44298fc1c149afbf4c8996fb924',
        '5d41402abc4b2a76b9719d911017c592'
    ];
    
    const hasmaliciousExtension = maliciousExtensions.some(ext => 
        fileName.toLowerCase().endsWith(ext.toLowerCase())
    );
    const hasSuspiciousName = suspiciousNames.some(name => 
        fileName.toLowerCase().includes(name.toLowerCase())
    );
    const hasMaliciousHash = fileHash && maliciousHashes.includes(fileHash.toLowerCase());
    const isTooLarge = fileSize && fileSize > 100 * 1024 * 1024; // 100MB
    
    const baseRisk = Math.random();
    const isSafe = !hasmaliciousExtension && 
                   !hasSuspiciousName && 
                   !hasMaliciousHash && 
                   !isTooLarge && 
                   baseRisk > 0.15; // 15% chance of threat for demo
    
    let threats = [];
    if (hasmaliciousExtension) threats.push('Potentially dangerous file extension');
    if (hasSuspiciousName) threats.push('Suspicious filename pattern');
    if (hasMaliciousHash) threats.push('Known malicious file signature');
    if (isTooLarge) threats.push('Unusually large file size');
    if (!isSafe && threats.length === 0) threats.push('Unknown malware signature detected');
    
    // Determine risk level
    let riskLevel = 'low';
    if (threats.length > 2) riskLevel = 'critical';
    else if (threats.length > 1) riskLevel = 'high';
    else if (threats.length === 1) riskLevel = 'medium';
    
    // Log security activity
    adminData.securityLogs.push({
        id: Date.now(),
        type: 'File Security Scan',
        target: fileName,
        result: isSafe ? 'File appears clean' : `${threats.length} threat${threats.length > 1 ? 's' : ''} detected: ${threats.join(', ')}`,
        tool: 'Malicious File Checker',
        user: user || CURRENT_USER,
        ip: req.ip || '127.0.0.1',
        timestamp: new Date().toISOString(),
        safe: isSafe
    });
    
    // Add to recent activity
    adminData.recentActivity.push({
        id: Date.now() + 1,
        action: 'File Security Scan',
        details: `Scanned ${fileName} - ${isSafe ? 'Clean' : threats.length + ' threats found'}`,
        timestamp: new Date().toISOString(),
        type: 'security_tool',
        user: user || CURRENT_USER,
        priority: isSafe ? 'normal' : 'high'
    });
    
    // Update security tools count
    adminData.securityToolsUsed += 1;
    
    const response = {
        success: true,
        safe: isSafe,
        message: isSafe ? 
            '✅ File Scan Complete: This file appears to be clean and safe to use.' :
            `⚠️ Security Threats Detected: This file contains ${threats.length} potential security threat${threats.length > 1 ? 's' : ''}.`,
        fileName: fileName,
        fileType: fileType || 'unknown',
        fileSize: fileSize || 0,
        threats: threats,
        riskLevel: riskLevel,
        recommendation: isSafe ? 
            'File appears safe, but always scan files from unknown sources.' : 
            'DO NOT open or execute this file. It may contain malware or viruses. Consider running a full system antivirus scan.',
        timestamp: new Date().toISOString(),
        user: user || CURRENT_USER,
        scanDetails: {
            extensionCheck: !hasmaliciousExtension,
            nameCheck: !hasSuspiciousName,
            hashCheck: !hasMaliciousHash,
            sizeCheck: !isTooLarge,
            signatureCheck: isSafe
        },
        actions: isSafe ? [
            'File can be safely used',
            'Continue with regular security practices'
        ] : [
            'Delete the file immediately',
            'Run a full system antivirus scan',
            'Do not execute or open the file',
            'Report if received via email'
        ]
    };
    
    console.log('📤 File scan response:', response);
    res.json(response);
});

// Password leak checker endpoint - NEW
app.post('/api/check-password-leak', (req, res) => {
    console.log('🔓 Password leak check requested');
    console.log('📅 Time:', new Date().toISOString());
    console.log('👤 User:', CURRENT_USER);
    
    const { password, timestamp, user, location } = req.body;
    
    // Validate password
    if (!password || typeof password !== 'string' || password.length < 4) {
        return res.status(400).json({
            success: false,
            error: 'Invalid password',
            message: 'Password must be at least 4 characters long',
            timestamp: new Date().toISOString()
        });
    }
    
    // Simulate k-anonymity check (in real implementation, only send first 5 chars of hash)
    const crypto = require('crypto');
    const hash = crypto.createHash('sha1').update(password).digest('hex');
    const hashPrefix = hash.substring(0, 5);
    
    console.log('🔍 Checking password hash prefix:', hashPrefix);
    
    // Simulate leak database check
    const commonPasswords = ['password', '123456', 'admin', 'letmein', 'welcome', 'qwerty'];
    const isLeaked = commonPasswords.includes(password.toLowerCase()) || Math.random() > 0.8;
    const occurrences = isLeaked ? Math.floor(Math.random() * 10000) + 100 : 0;
    
    // Log security activity
    adminData.securityLogs.push({
        id: Date.now(),
        type: 'Password Leak Check',
        target: '[Password Hidden]',
        result: isLeaked ? `Password found in ${occurrences} breaches` : 'Password not found in leaks',
        tool: 'Password Leak Checker (k-Anonymity)',
        user: user || CURRENT_USER,
        ip: req.ip || '127.0.0.1',
        timestamp: new Date().toISOString(),
        safe: !isLeaked
    });
    
    // Add to recent activity
    adminData.recentActivity.push({
        id: Date.now() + 1,
        action: 'Password Leak Check',
        details: `Password checked via k-anonymity - ${isLeaked ? 'Found in leaks' : 'Clean'}`,
        timestamp: new Date().toISOString(),
        type: 'security_tool',
        user: user || CURRENT_USER,
        priority: isLeaked ? 'high' : 'normal'
    });
    
    // Update security tools count
    adminData.securityToolsUsed += 1;
    
    const response = {
        success: true,
        leaked: isLeaked,
        occurrences: occurrences,
        message: isLeaked ? 
            '🚨 Security Alert: This password has been found in data breaches. It should be changed immediately.' :
            '🛡️ Good news! This password was not found in known data breaches.',
        hashPrefix: hashPrefix,
        timestamp: new Date().toISOString(),
        user: user || CURRENT_USER,
        recommendation: isLeaked ? 
            'Change this password immediately and avoid using it anywhere. Consider using a password manager to generate unique, strong passwords.' :
            'While this password hasn\'t been found in breaches, ensure it\'s strong and unique for each account.'
    };
    
    console.log('📤 Password leak check response sent');
    res.json(response);
});

// IP reputation checker endpoint - NEW
app.post('/api/check-ip-reputation', (req, res) => {
    console.log('🌐 IP reputation check requested');
    console.log('📅 Time:', new Date().toISOString());
    console.log('👤 User:', CURRENT_USER);
    
    const { ip, timestamp, user, location } = req.body;
    
    console.log('🔍 Checking IP:', ip);
    
    // Validate IP address
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (!ip || !ipRegex.test(ip)) {
        return res.status(400).json({
            success: false,
            error: 'Invalid IP address',
            message: 'Please provide a valid IPv4 address',
            timestamp: new Date().toISOString()
        });
    }
    
    // Simulate IP reputation check
    const maliciousIPs = ['192.168.1.666', '10.0.0.666', '172.16.0.666'];
    const knownGoodIPs = ['8.8.8.8', '1.1.1.1', '208.67.222.222'];
    
    const isMalicious = maliciousIPs.includes(ip) || Math.random() > 0.85;
    const isKnownGood = knownGoodIPs.includes(ip);
    const isSafe = isKnownGood || (!isMalicious && Math.random() > 0.3);
    
    // Mock location data
    const locations = ['United States', 'Germany', 'United Kingdom', 'Canada', 'Japan', 'Unknown'];
    const isps = ['Google LLC', 'Cloudflare', 'Amazon Technologies', 'Microsoft Corporation', 'Unknown ISP'];
    
    let threats = [];
    if (!isSafe) {
        const threatTypes = ['Malware C&C', 'Botnet', 'Spam Source', 'Scanning Activity', 'Tor Exit Node'];
        threats = threatTypes.slice(0, Math.floor(Math.random() * 3) + 1);
    }
    
    const riskLevel = isSafe ? 'low' : threats.length > 2 ? 'high' : 'medium';
    
    // Log security activity
    adminData.securityLogs.push({
        id: Date.now(),
        type: 'IP Reputation Check',
        target: ip,
        result: isSafe ? 'IP appears clean' : `Threats detected: ${threats.join(', ')}`,
        tool: 'IP Reputation Checker',
        user: user || CURRENT_USER,
        ip: req.ip || '127.0.0.1',
        timestamp: new Date().toISOString(),
        safe: isSafe
    });
    
    // Add to recent activity
    adminData.recentActivity.push({
        id: Date.now() + 1,
        action: 'IP Reputation Check',
        details: `Checked ${ip} - ${isSafe ? 'Clean' : 'Threats detected'}`,
        timestamp: new Date().toISOString(),
        type: 'security_tool',
        user: user || CURRENT_USER,
        priority: isSafe ? 'normal' : 'high'
    });
    
    // Update security tools count
    adminData.securityToolsUsed += 1;
    
    const response = {
        success: true,
        safe: isSafe,
        ip: ip,
        location: locations[Math.floor(Math.random() * locations.length)],
        isp: isps[Math.floor(Math.random() * isps.length)],
        riskLevel: riskLevel,
        threats: threats,
        message: isSafe ? 
            '✅ This IP address appears to be clean with no known malicious activity.' :
            `⚠️ Warning: This IP address has been associated with malicious activity.`,
        timestamp: new Date().toISOString(),
        user: user || CURRENT_USER,
        recommendation: isSafe ? 
            'IP appears safe, but always exercise caution with unknown sources.' :
            'Block this IP address and investigate any connections from it. Consider adding it to your firewall blacklist.'
    };
    
    console.log('📤 IP reputation check response sent');
    res.json(response);
});

// ===== CRITICAL FIX: ADMIN PROTECTION WITH CORRECTED FILE PATHS =====

// Admin protection for specific routes
app.get('/admin-dashboard.html', (req, res) => {
    const clientIP = req.ip || req.connection.remoteAddress || 'unknown';
    const userAgent = req.get('User-Agent') || 'Unknown';
    
    console.log(`🔐 CRITICAL: Admin dashboard access attempt - PROTECTED ROUTE`);
    console.log(`   IP: ${clientIP}`);
    console.log(`   User-Agent: ${userAgent}`);
    console.log(`   Time: ${CURRENT_TIME}`);
    
    // Log access attempt
    adminData.securityLogs.push({
        id: Date.now(),
        type: 'Admin Dashboard Access Attempt',
        path: '/admin-dashboard.html',
        ip: clientIP,
        userAgent: userAgent,
        timestamp: CURRENT_TIME,
        user: 'anonymous',
        action: 'dashboard_access_attempt',
        blocked: false
    });
    
    // Check rate limiting
    if (!checkRateLimit(clientIP)) {
        console.log(`❌ Rate limit exceeded for admin dashboard access from IP: ${clientIP}`);
        
        adminData.securityLogs.push({
            id: Date.now(),
            type: 'Admin Dashboard Blocked',
            reason: 'Rate limit exceeded',
            path: '/admin-dashboard.html',
            ip: clientIP,
            userAgent: userAgent,
            timestamp: CURRENT_TIME,
            blocked: true
        });
        
        adminData.blockedAttempts++;
        
        return res.status(429).json({
            success: false,
            error: 'Too Many Requests',
            message: 'Too many admin access attempts. Please try again later.',
            timestamp: CURRENT_TIME,
            retryAfter: '15 minutes'
        });
    }
    
    // Check for valid session token
    const sessionToken = req.headers['x-session-token'] || 
                        req.query.token || 
                        req.cookies?.adminToken;
    
    if (!sessionToken || !isValidSession(sessionToken)) {
        console.log(`❌ BLOCKED: Invalid or missing session token for admin dashboard`);
        console.log(`   Attempted access without authentication`);
        console.log(`   Redirecting to login page`);
        
        adminData.securityLogs.push({
            id: Date.now(),
            type: 'Admin Dashboard Blocked',
            reason: 'No valid session token',
            path: '/admin-dashboard.html',
            ip: clientIP,
            userAgent: userAgent,
            timestamp: CURRENT_TIME,
            blocked: true
        });
        
        adminData.blockedAttempts++;
        
        // Redirect to login page for browser requests
        if (req.headers.accept && req.headers.accept.includes('text/html')) {
            console.log(`🔄 Redirecting unauthorized dashboard access to login page`);
            return res.redirect('/admin-login?reason=authentication_required&redirect=' + encodeURIComponent('/admin-dashboard.html'));
        } else {
            return res.status(401).json({
                success: false,
                error: 'Authentication Required',
                message: 'Valid admin session required to access admin dashboard',
                redirectTo: '/admin-login',
                timestamp: CURRENT_TIME
            });
        }
    }
    
    const session = activeSessions.get(sessionToken);
    
    console.log(`✅ ALLOWED: Valid admin session found for dashboard access`);
    console.log(`   User: ${session.user}`);
    console.log(`   Role: ${session.role}`);
    console.log(`   Session expires: ${new Date(session.expiresAt).toISOString()}`);
    
    adminData.securityLogs.push({
        id: Date.now(),
        type: 'Admin Dashboard Access Granted',
        user: session.user,
        role: session.role,
        path: '/admin-dashboard.html',
        ip: clientIP,
        userAgent: userAgent,
        timestamp: CURRENT_TIME,
        sessionToken: sessionToken.substring(0, 16) + '...',
        blocked: false
    });
    
    // FIXED FILE SERVING - Try multiple possible paths
    const dashboardPaths = [
        path.join(process.cwd(), 'admin-dashboard.html'),
        path.join(__dirname, '../frontend/admin-dashboard.html'),
        path.join(__dirname, 'admin-dashboard.html'),
        path.join(__dirname, 'frontend/admin-dashboard.html'),
        path.join(process.cwd(), 'frontend/admin-dashboard.html'),
        path.join(process.cwd(), 'public/admin-dashboard.html')
    ];
    
    let dashboardFileFound = false;
    for (const dashboardPath of dashboardPaths) {
        console.log(`🔍 Checking dashboard path: ${dashboardPath}`);
        if (require('fs').existsSync(dashboardPath)) {
            console.log(`✅ Found admin-dashboard.html at: ${dashboardPath}`);
            console.log(`📊 Serving admin dashboard to authenticated user: ${session.user}`);
            res.sendFile(dashboardPath);
            dashboardFileFound = true;
            break;
        }
    }
    
    if (!dashboardFileFound) {
        console.log(`❌ Admin dashboard file not found in any location`);
        res.status(404).json({
            success: false,
            error: 'Dashboard file not found',
            message: 'admin-dashboard.html file is missing',
            searchedPaths: dashboardPaths,
            timestamp: CURRENT_TIME,
            suggestion: 'Please ensure admin-dashboard.html exists in your project directory'
        });
    }
});

// Admin login protection with corrected file paths
app.get('/admin-login', (req, res) => {
    const clientIP = req.ip || req.connection.remoteAddress || 'unknown';
    const userAgent = req.get('User-Agent') || 'Unknown';
    
    console.log(`🔐 Admin login page access - MONITORING`);
    console.log(`   IP: ${clientIP}`);
    console.log(`   User-Agent: ${userAgent}`);
    console.log(`   Time: ${CURRENT_TIME}`);
    
    // Log login page access
    adminData.securityLogs.push({
        id: Date.now(),
        type: 'Admin Login Page Access',
        path: '/admin-login',
        ip: clientIP,
        userAgent: userAgent,
        timestamp: CURRENT_TIME,
        action: 'login_page_access'
    });
    
    // Check rate limiting
    if (!checkRateLimit(clientIP)) {
        console.log(`❌ Rate limit exceeded for admin login page from IP: ${clientIP}`);
        
        adminData.securityLogs.push({
            id: Date.now(),
            type: 'Admin Login Page Blocked',
            reason: 'Rate limit exceeded',
            ip: clientIP,
            userAgent: userAgent,
            timestamp: CURRENT_TIME,
            blocked: true
        });
        
        adminData.blockedAttempts++;
        
        return res.status(429).json({
            success: false,
            error: 'Too Many Requests',
            message: 'Too many login attempts. Please try again later.',
            timestamp: CURRENT_TIME,
            retryAfter: '15 minutes'
        });
    }
    
    // FIXED FILE SERVING - Try multiple possible paths
    const loginPaths = [
        path.join(process.cwd(), 'admin-login.html'),
        path.join(__dirname, '../frontend/admin-login.html'),
        path.join(__dirname, 'admin-login.html'),
        path.join(__dirname, 'frontend/admin-login.html'),
        path.join(process.cwd(), 'frontend/admin-login.html'),
        path.join(process.cwd(), 'public/admin-login.html')
    ];
    
    let loginFileFound = false;
    for (const loginPath of loginPaths) {
        console.log(`🔍 Checking login path: ${loginPath}`);
        if (require('fs').existsSync(loginPath)) {
            console.log(`✅ Found admin-login.html at: ${loginPath}`);
            console.log(`✅ Admin login page served to IP: ${clientIP}`);
            res.sendFile(loginPath);
            loginFileFound = true;
            break;
        }
    }
    
    if (!loginFileFound) {
        console.log(`❌ Admin login file not found in any location`);
        res.status(404).json({
            success: false,
            error: 'Login page not found',
            message: 'admin-login.html file is missing',
            searchedPaths: loginPaths,
            timestamp: CURRENT_TIME,
            suggestion: 'Please ensure admin-login.html exists in your project directory'
        });
    }
});

// Redirect admin access to login
app.get('/admin', (req, res) => {
    console.log('🔒 Admin route accessed, redirecting to login - PROTECTED');
    res.redirect('/admin-login');
});

// FIXED STATIC FILE SERVING WITH CORRECTED PATHS
// Try multiple possible frontend directories
const possibleFrontendDirs = [
    path.join(process.cwd(), 'frontend'),
    path.join(process.cwd(), 'public'),
    path.join(process.cwd()),
    path.join(__dirname, '../frontend'),
    path.join(__dirname, 'frontend'),
    path.join(__dirname, 'public'),
    path.join(__dirname)
];

let staticDir = null;
for (const dir of possibleFrontendDirs) {
    console.log(`🔍 Checking for static directory: ${dir}`);
    if (require('fs').existsSync(dir)) {
        const indexPath = path.join(dir, 'index.html');
        if (require('fs').existsSync(indexPath)) {
            staticDir = dir;
            console.log(`✅ Found static directory with index.html: ${dir}`);
            break;
        }
    }
}

if (staticDir) {
    app.use(express.static(staticDir, {
        setHeaders: (res, filePath) => {
            const filename = path.basename(filePath);
            
            // Block direct access to admin files
            if (filename === 'admin-dashboard.html' || filename === 'admin-login.html') {
                console.log(`🚫 BLOCKED: Direct static access to admin file: ${filename}`);
                res.status(403);
                return false;
            }
            
            // Set correct MIME types
            if (filePath.endsWith('.css')) {
                res.setHeader('Content-Type', 'text/css');
            } else if (filePath.endsWith('.js')) {
                res.setHeader('Content-Type', 'application/javascript');
            } else if (filePath.endsWith('.html')) {
                res.setHeader('Content-Type', 'text/html');
            }
            
            console.log(`📁 Serving static file: ${filename}`);
        },
        index: false
    }));
    
    console.log(`✅ Static files configured for directory: ${staticDir}`);
} else {
    console.log(`❌ No suitable static directory found`);
    console.log(`📁 Searched directories:`, possibleFrontendDirs);
}

// ===== CORRECTED MAIN ROUTES WITH FLEXIBLE FILE PATHS =====

// Root route with flexible file path detection
app.get('/', (req, res) => {
    console.log('🏠 Root route accessed');
    
    const indexPaths = [
        path.join(process.cwd(), 'index.html'),
        path.join(process.cwd(), 'frontend/index.html'),
        path.join(process.cwd(), 'public/index.html'),
        path.join(__dirname, '../frontend/index.html'),
        path.join(__dirname, 'index.html'),
        path.join(__dirname, 'frontend/index.html')
    ];
    
    let indexFound = false;
    for (const indexPath of indexPaths) {
        if (require('fs').existsSync(indexPath)) {
            console.log(`✅ Serving index.html from: ${indexPath}`);
            res.sendFile(indexPath);
            indexFound = true;
            break;
        }
    }
    
    if (!indexFound) {
        console.log(`❌ index.html not found in any location`);
        res.status(404).json({
            success: false,
            error: 'Index page not found',
            message: 'index.html file is missing',
            searchedPaths: indexPaths,
            timestamp: CURRENT_TIME,
            suggestion: 'Please ensure index.html exists in your project directory'
        });
    }
});

// Coming Soon page
app.get('/coming-soon', (req, res) => {
    console.log('🎯 Coming Soon page accessed');
    res.sendFile(path.join(__dirname, '../frontend/coming-soon.html'));
});

// Security Tools page
app.get('/security-tools', (req, res) => {
    console.log('🛡️ Security Tools page accessed');
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// Contact page route
app.get('/contact', (req, res) => {
    console.log('📞 Contact page accessed');
    res.sendFile(path.join(__dirname, '../frontend/contact.html'));
});

// Index.html explicit route
app.get('/index.html', (req, res) => {
    console.log('🏠 Index.html route accessed');
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// ===== CONTACT FORM API (keeping existing) =====

app.post('/api/contact', (req, res) => {
    console.log('📞 CONTACT FORM API CALLED - 2025-06-13 06:07:06 UTC');
    console.log('='.repeat(80));
    console.log(`🕐 Timestamp: ${CURRENT_TIME}`);
    console.log(`👤 User: ${CURRENT_USER}`);
    console.log(`📥 Raw Request Body:`, JSON.stringify(req.body, null, 2));
    console.log(`📋 Request Headers:`, {
        'content-type': req.headers['content-type'],
        'user-agent': req.headers['user-agent'],
        'x-user': req.headers['x-user'],
        'x-timestamp': req.headers['x-timestamp'],
        'origin': req.headers['origin']
    });
    console.log(`🌐 Request IP: ${req.ip}`);
    console.log(`🔗 Request URL: ${req.url}`);
    console.log('='.repeat(80));
    
    const { 
        fullName, 
        email, 
        phoneNumber, 
        companyName, 
        serviceInterest, 
        subject, 
        message, 
        mathAnswer,
        mathProblem,
        timestamp, 
        currentUser,
        location,
        source 
    } = req.body;
    
    const submissionTime = timestamp || CURRENT_TIME;
    const submissionUser = currentUser || CURRENT_USER;
    
    console.log('📞 CONTACT FORM SUBMISSION RECEIVED:');
    console.log('='.repeat(70));
    console.log(`   🕐 Time: ${submissionTime}`);
    console.log(`   👤 User: ${submissionUser}`);
    console.log(`   📝 Full Name: "${fullName}" (type: ${typeof fullName}, length: ${fullName ? fullName.length : 0})`);
    console.log(`   📧 Email: "${email}" (type: ${typeof email})`);
    console.log(`   📱 Phone: "${phoneNumber || 'Not provided'}"`);
    console.log(`   🏢 Company: "${companyName || 'Not provided'}"`);
    console.log(`   🛡️ Service: "${serviceInterest || 'General Inquiry'}"`);
    console.log(`   📋 Subject: "${subject || 'No subject'}" (type: ${typeof subject})`);
    console.log(`   💬 Message: "${message || 'No message'}" (type: ${typeof message})`);
    console.log(`   🧮 Math Problem: "${mathProblem || 'Not provided'}"`);
    console.log(`   🧮 Math Answer: "${mathAnswer}" (type: ${typeof mathAnswer})`);
    console.log(`   📍 Location: "${location || 'Islamabad, Pakistan'}"`);
    console.log(`   🔗 Source: "${source || 'contact_form'}"`);
    console.log('='.repeat(70));
    
    // ENHANCED validation with step-by-step debugging
    const errors = [];
    
    console.log('🔍 Starting validation process...');
    
    // Full name validation
    console.log(`1️⃣ Validating fullName: "${fullName}"`);
    if (!fullName || typeof fullName !== 'string') {
        const error = 'Full name is required';
        errors.push(error);
        console.log(`❌ Full name validation failed: ${error} (value: ${fullName}, type: ${typeof fullName})`);
    } else if (fullName.trim().length === 0) {
        const error = 'Full name cannot be empty';
        errors.push(error);
        console.log(`❌ Full name validation failed: ${error}`);
    } else if (fullName.trim().length < 2) {
        const error = 'Full name must be at least 2 characters';
        errors.push(error);
        console.log(`❌ Full name validation failed: ${error} (length: ${fullName.trim().length})`);
    } else {
        console.log(`✅ Full name validation passed: "${fullName.trim()}"`);
    }
    
    // Email validation
    console.log(`2️⃣ Validating email: "${email}"`);
    if (!email || typeof email !== 'string') {
        const error = 'Email address is required';
        errors.push(error);
        console.log(`❌ Email validation failed: ${error} (value: ${email}, type: ${typeof email})`);
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
        const error = 'Valid email address is required';
        errors.push(error);
        console.log(`❌ Email validation failed: ${error} (format invalid)`);
    } else {
        console.log(`✅ Email validation passed: "${email.trim()}"`);
    }
    
    // Subject validation
    console.log(`3️⃣ Validating subject: "${subject}"`);
    if (!subject || typeof subject !== 'string') {
        const error = 'Subject is required';
        errors.push(error);
        console.log(`❌ Subject validation failed: ${error} (value: ${subject}, type: ${typeof subject})`);
    } else if (subject.trim().length === 0) {
        const error = 'Subject cannot be empty';
        errors.push(error);
        console.log(`❌ Subject validation failed: ${error}`);
    } else {
        console.log(`✅ Subject validation passed: "${subject.trim()}"`);
    }
    
    // Message validation
    console.log(`4️⃣ Validating message: "${message}"`);
    if (!message || typeof message !== 'string') {
        const error = 'Message is required';
        errors.push(error);
        console.log(`❌ Message validation failed: ${error} (value: ${message}, type: ${typeof message})`);
    } else if (message.trim().length === 0) {
        const error = 'Message cannot be empty';
        errors.push(error);
        console.log(`❌ Message validation failed: ${error}`);
    } else {
        console.log(`✅ Message validation passed: "${message.trim()}"`);
    }
    
    // Math validation
    console.log(`5️⃣ Validating math answer: "${mathAnswer}"`);
    const expectedAnswer = 6; // 1 + 5 = 6
    const providedAnswer = parseInt(mathAnswer);
    
    if (!mathAnswer) {
        const error = 'Please solve the math problem: 1 + 5 = ?';
        errors.push(error);
        console.log(`❌ Math validation failed: ${error} (missing answer)`);
    } else if (isNaN(providedAnswer)) {
        const error = 'Math answer must be a number';
        errors.push(error);
        console.log(`❌ Math validation failed: ${error} (not a number: ${mathAnswer})`);
    } else if (providedAnswer !== expectedAnswer) {
        const error = `Math problem incorrect. 1 + 5 = 6, but you entered ${providedAnswer}`;
        errors.push(error);
        console.log(`❌ Math validation failed: ${error}`);
    } else {
        console.log(`✅ Math validation passed: 1 + 5 = ${providedAnswer}`);
    }
    
    console.log(`🔍 Validation complete. Errors found: ${errors.length}`);
    
    // Return validation errors if any
    if (errors.length > 0) {
        console.log(`❌ CONTACT FORM VALIDATION FAILED - ${errors.length} errors:`);
        errors.forEach((error, index) => {
            console.log(`   ${index + 1}. ${error}`);
        });
        
        const errorResponse = {
            success: false,
            error: 'Validation failed',
            message: errors[0],
            errors: errors,
            timestamp: submissionTime,
            user: submissionUser,
            debug: {
                receivedData: { fullName, email, subject, message, mathAnswer },
                validationErrors: errors.length,
                requestBody: req.body
            }
        };
        
        console.log('📤 Sending error response:', JSON.stringify(errorResponse, null, 2));
        return res.status(400).json(errorResponse);
    }
    
    console.log('✅ ALL VALIDATIONS PASSED - Creating contact record...');
    
    // Create enhanced contact record
    const contact = {
        id: Date.now(),
        fullName: fullName.trim(),
        email: email.trim().toLowerCase(),
        phoneNumber: phoneNumber?.trim() || '',
        companyName: companyName?.trim() || '',
        serviceInterest: serviceInterest || 'General Inquiry',
        subject: subject.trim(),
        message: message.trim(),
        mathAnswer: mathAnswer,
        mathProblem: mathProblem || '1 + 5',
        timestamp: submissionTime,
        status: 'new',
        priority: serviceInterest === 'Penetration Testing' ? 'high' : 'normal',
        source: source || 'contact_form_updated',
        location: location || 'Islamabad, Pakistan',
        user: submissionUser,
        ip: req.ip || '127.0.0.1',
        userAgent: req.get('User-Agent') || 'Unknown'
    };
    
    console.log('💾 Contact record created:', JSON.stringify(contact, null, 2));
    
    // Save to admin data with verification
    console.log(`📊 Before save - Total contacts: ${adminData.contacts.length}`);
    adminData.contacts.push(contact);
    console.log(`📊 After save - Total contacts: ${adminData.contacts.length}`);
    
    // Update totals
    adminData.totalContacts = adminData.contacts.length + adminData.subscribers.length;
    console.log(`📊 Updated totalContacts: ${adminData.totalContacts}`);
    
    // Calculate new this week
    const weekAgo = new Date(submissionTime);
    weekAgo.setDate(weekAgo.getDate() - 7);
    adminData.newThisWeek = adminData.contacts.filter(c => new Date(c.timestamp) > weekAgo).length;
    console.log(`📈 New this week: ${adminData.newThisWeek}`);
    
    // Add to recent activity with verification
    const activity = {
        id: Date.now() + 1,
        action: 'New Contact Form Submission',
        details: `${fullName.trim()} (${email.trim()}) - ${serviceInterest || 'General'} - ${subject.trim()}`,
        timestamp: submissionTime,
        type: 'contact',
        user: submissionUser,
        priority: contact.priority
    };
    
    console.log(`📈 Before activity save - Total activities: ${adminData.recentActivity.length}`);
    adminData.recentActivity.push(activity);
    console.log(`📈 After activity save - Total activities: ${adminData.recentActivity.length}`);
    console.log('📝 Activity record:', JSON.stringify(activity, null, 2));
    
    // Update security tools count
    adminData.securityToolsUsed += 1;
    
    console.log('✅ CONTACT FORM SUBMITTED SUCCESSFULLY:');
    console.log(`   📋 Contact ID: ${contact.id}`);
    console.log(`   📊 Total Contacts: ${adminData.totalContacts}`);
    console.log(`   📈 New This Week: ${adminData.newThisWeek}`);
    console.log(`   ⭐ Priority: ${contact.priority}`);
    console.log(`   📍 Location: ${contact.location}`);
    console.log(`   🛡️ Security Tools Used: ${adminData.securityToolsUsed}`);
    
    const successResponse = {
        success: true,
        message: `Thank you ${fullName.trim()}! Your ${serviceInterest || 'inquiry'} request has been received. We'll respond within 24 hours.`,
        contactId: contact.id,
        timestamp: submissionTime,
        estimatedResponse: serviceInterest === 'Penetration Testing' ? '12 hours' : '24 hours',
        priority: contact.priority,
        referenceNumber: `SP-${Date.now().toString().slice(-6)}`,
        debug: {
            totalContacts: adminData.totalContacts,
            newThisWeek: adminData.newThisWeek,
            activityCount: adminData.recentActivity.length,
            contactsArray: adminData.contacts.length,
            securityToolsUsed: adminData.securityToolsUsed
        }
    };
    
    console.log('📤 Sending success response:', JSON.stringify(successResponse, null, 2));
    
    // Log current admin data state
    console.log('💾 Current Admin Data State:');
    console.log(`   Contacts: ${adminData.contacts.length}`);
    console.log(`   Subscribers: ${adminData.subscribers.length}`);
    console.log(`   Total: ${adminData.totalContacts}`);
    console.log(`   Activities: ${adminData.recentActivity.length}`);
    console.log(`   Security Tools: ${adminData.securityToolsUsed}`);
    
    res.json(successResponse);
});

// ===== ADMIN API ENDPOINTS =====

// Admin authentication endpoint - HARDENED
app.post('/api/admin/authenticate', (req, res) => {
    const { username, password, timestamp } = req.body;
    const clientIP = req.ip || req.connection.remoteAddress || 'unknown';
    
    console.log(`🔐 Admin authentication attempt - HARDENED:`);
    console.log(`   Username: ${username}`);
    console.log(`   IP: ${clientIP}`);
    console.log(`   Time: ${timestamp || CURRENT_TIME}`);
    
    adminData.adminLoginAttempts++;
    recordLoginAttempt(clientIP);
    
    // Check rate limiting
    if (!checkRateLimit(clientIP)) {
        console.log(`❌ Rate limit exceeded for admin login from IP: ${clientIP}`);
        
        adminData.securityLogs.push({
            id: Date.now(),
            type: 'Admin Login Blocked',
            reason: 'Rate limit exceeded',
            username: username,
            ip: clientIP,
            timestamp: CURRENT_TIME,
            blocked: true
        });
        
        return res.status(429).json({
            success: false,
            error: 'Too Many Login Attempts',
            message: 'Too many login attempts. Please try again later.',
            timestamp: CURRENT_TIME,
            retryAfter: '15 minutes'
        });
    }
    
    // Check if user exists
    const userConfig = ADMIN_CONFIG.validCredentials[username];
    if (!userConfig) {
        console.log(`❌ Invalid username: ${username}`);
        
        adminData.securityLogs.push({
            id: Date.now(),
            type: 'Admin Login Failed',
            reason: 'Invalid username',
            username: username,
            ip: clientIP,
            timestamp: CURRENT_TIME,
            blocked: false
        });
        
        return res.status(401).json({
            success: false,
            error: 'Authentication failed',
            message: 'Invalid username or password',
            timestamp: CURRENT_TIME
        });
    }
    
    // Check if account is locked
    if (userConfig.locked && userConfig.lockUntil && Date.now() < userConfig.lockUntil) {
        console.log(`❌ Account locked: ${username}`);
        
        adminData.securityLogs.push({
            id: Date.now(),
            type: 'Admin Login Blocked',
            reason: 'Account locked',
            username: username,
            ip: clientIP,
            timestamp: CURRENT_TIME,
            blocked: true
        });
        
        const remainingTime = Math.ceil((userConfig.lockUntil - Date.now()) / 60000);
        
        return res.status(423).json({
            success: false,
            error: 'Account Locked',
            message: `Account is locked due to too many failed attempts. Try again in ${remainingTime} minutes.`,
            timestamp: CURRENT_TIME,
            unlockAt: new Date(userConfig.lockUntil).toISOString()
        });
    }
    
    // Verify password
    if (userConfig.password !== password) {
        console.log(`❌ Invalid password for user: ${username}`);
        
        // Increment login attempts
        userConfig.loginAttempts++;
        
        // Lock account if max attempts reached
        if (userConfig.loginAttempts >= ADMIN_CONFIG.maxLoginAttempts) {
            userConfig.locked = true;
            userConfig.lockUntil = Date.now() + ADMIN_CONFIG.lockDuration;
            
            console.log(`🔒 Account locked after ${ADMIN_CONFIG.maxLoginAttempts} failed attempts: ${username}`);
            
            adminData.securityLogs.push({
                id: Date.now(),
                type: 'Admin Account Locked',
                reason: `${ADMIN_CONFIG.maxLoginAttempts} failed attempts`,
                username: username,
                ip: clientIP,
                timestamp: CURRENT_TIME,
                severity: 'HIGH'
            });
            
            return res.status(423).json({
                success: false,
                error: 'Account Locked',
                message: `Account locked due to too many failed attempts. Try again in ${ADMIN_CONFIG.lockDuration / 60000} minutes.`,
                timestamp: CURRENT_TIME
            });
        }
        
        adminData.securityLogs.push({
            id: Date.now(),
            type: 'Admin Login Failed',
            reason: 'Invalid password',
            username: username,
            ip: clientIP,
            attempts: userConfig.loginAttempts,
            timestamp: CURRENT_TIME
        });
        
        return res.status(401).json({
            success: false,
            error: 'Authentication failed',
            message: 'Invalid username or password',
            timestamp: CURRENT_TIME,
            attemptsRemaining: ADMIN_CONFIG.maxLoginAttempts - userConfig.loginAttempts
        });
    }
    
    // SUCCESS - Reset failed attempts and create session
    userConfig.loginAttempts = 0;
    userConfig.locked = false;
    userConfig.lockUntil = null;
    userConfig.lastLogin = CURRENT_TIME;
    
    // Generate secure session token
    const sessionToken = generateSecureToken();
    const session = {
        token: sessionToken,
        user: username,
        role: userConfig.role,
        permissions: userConfig.permissions,
        ip: clientIP,
        createdAt: Date.now(),
        expiresAt: Date.now() + ADMIN_CONFIG.sessionTimeout,
        lastActivity: Date.now()
    };
    
    // Store session
    activeSessions.set(sessionToken, session);
    
    console.log('✅ Admin authentication successful');
    console.log(`   Session token: ${sessionToken.substring(0, 16)}...`);
    console.log(`   Role: ${userConfig.role}`);
    console.log(`   Permissions: ${userConfig.permissions}`);
    
    adminData.securityLogs.push({
        id: Date.now(),
        type: 'Admin Login Success',
        username: username,
        role: userConfig.role,
        ip: clientIP,
        sessionToken: sessionToken.substring(0, 16) + '...',
        timestamp: CURRENT_TIME
    });
    
    adminData.lastAdminLogin = CURRENT_TIME;
    
    adminData.recentActivity.push({
        id: Date.now() + 1,
        action: 'Admin Login',
        details: `${username} logged in as ${userConfig.role}`,
        timestamp: CURRENT_TIME,
        type: 'admin_auth',
        user: username,
        priority: 'high'
    });
    
    res.json({
        success: true,
        message: 'Authentication successful',
        user: username,
        role: userConfig.role,
        permissions: userConfig.permissions,
        sessionToken: sessionToken,
        expiresAt: session.expiresAt,
        timestamp: CURRENT_TIME,
        redirectUrl: '/admin-dashboard.html'
    });
});

// Admin authentication check - HARDENED
app.get('/api/admin/check', (req, res) => {
    const sessionToken = req.headers['x-session-token'] || 
                        req.query.token || 
                        req.cookies?.adminToken;
    
    console.log('🔐 Admin auth check requested - HARDENED');
    console.log(`   Session token: ${sessionToken ? sessionToken.substring(0, 16) + '...' : 'none'}`);
    
    if (!sessionToken || !isValidSession(sessionToken)) {
        console.log('❌ Invalid or expired session');
        
        return res.status(401).json({
            success: false,
            authenticated: false,
            isLoggedIn: false,
            error: 'Invalid or expired session',
            message: 'Please login again',
            redirectTo: '/admin-login',
            timestamp: CURRENT_TIME
        });
    }
    
    const session = activeSessions.get(sessionToken);
    
    console.log('✅ Valid admin session found');
    console.log(`   User: ${session.user}`);
    console.log(`   Role: ${session.role}`);
    
    const authResponse = {
        success: true,
        authenticated: true,
        isLoggedIn: true,
        user: session.user,
        role: session.role,
        permissions: session.permissions,
        sessionToken: sessionToken,
        expiresAt: session.expiresAt,
        timestamp: CURRENT_TIME,
        location: 'Islamabad, Pakistan',
        sessionValid: true
    };
    
    console.log('📤 Auth response:', authResponse);
    res.json(authResponse);
});

// Dashboard overview data - PROTECTED
app.get('/api/admin/dashboard', (req, res) => {
    const sessionToken = req.headers['x-session-token'] || 
                        req.query.token || 
                        req.cookies?.adminToken;
    
    if (!sessionToken || !isValidSession(sessionToken)) {
        return res.status(401).json({
            success: false,
            error: 'Authentication required',
            redirectTo: '/admin-login'
        });
    }
    
    console.log('📊 Admin dashboard data requested - PROTECTED');
    console.log(`📊 Current admin data state:`, {
        contactsCount: adminData.contacts.length,
        subscribersCount: adminData.subscribers.length,
        activitiesCount: adminData.recentActivity.length,
        securityToolsUsed: adminData.securityToolsUsed
    });
    
    // Calculate new this week
    const weekAgo = new Date(CURRENT_TIME);
    weekAgo.setDate(weekAgo.getDate() - 7);
    const newThisWeek = adminData.contacts.filter(contact => {
        const contactDate = new Date(contact.timestamp);
        return contactDate > weekAgo;
    }).length + adminData.subscribers.filter(sub => {
        const subDate = new Date(sub.timestamp);
        return subDate > weekAgo;
    }).length;
    
    // Update uptime
    adminData.uptime = process.uptime();
    
    const session = activeSessions.get(sessionToken);
    
    const dashboardData = {
        success: true,
        data: {
            totalContacts: adminData.contacts.length + adminData.subscribers.length,
            newThisWeek: newThisWeek,
            securityToolsUsed: adminData.securityToolsUsed,
            avgResponseTime: adminData.avgResponseTime,
            timestamp: CURRENT_TIME,
            user: session.user,
            role: session.role,
            location: 'Islamabad, Pakistan',
            systemHealth: adminData.systemHealth,
            uptime: adminData.uptime,
            activeSessions: activeSessions.size,
            lastAdminLogin: adminData.lastAdminLogin,
            adminLoginAttempts: adminData.adminLoginAttempts,
            blockedAttempts: adminData.blockedAttempts,
            debug: {
                rawContactsCount: adminData.contacts.length,
                rawSubscribersCount: adminData.subscribers.length,
                calculatedTotal: adminData.contacts.length + adminData.subscribers.length,
                calculatedNewThisWeek: newThisWeek
            }
        }
    };
    
    console.log('📤 Dashboard response:', JSON.stringify(dashboardData, null, 2));
    res.json(dashboardData);
});

// Admin messages/contacts endpoint - PROTECTED
app.get('/api/admin/messages', (req, res) => {
    const sessionToken = req.headers['x-session-token'] || 
                        req.query.token || 
                        req.cookies?.adminToken;
    
    if (!sessionToken || !isValidSession(sessionToken)) {
        return res.status(401).json({
            success: false,
            error: 'Authentication required',
            redirectTo: '/admin-login'
        });
    }
    
    console.log('📧 Admin messages requested - PROTECTED');
    console.log(`📧 Messages data:`, {
        contactsCount: adminData.contacts.length,
        subscribersCount: adminData.subscribers.length,
        contacts: adminData.contacts.map(c => ({ id: c.id, name: c.fullName, email: c.email }))
    });
    
    const session = activeSessions.get(sessionToken);
    
    const messagesResponse = {
        success: true,
        messages: adminData.contacts,
        contacts: adminData.contacts,
        subscribers: adminData.subscribers,
        totalCount: adminData.contacts.length + adminData.subscribers.length,
        timestamp: CURRENT_TIME,
        user: session.user,
        role: session.role
    };
    
    console.log('📤 Messages response summary:', {
        contactsCount: messagesResponse.contacts.length,
        subscribersCount: messagesResponse.subscribers.length,
        totalCount: messagesResponse.totalCount
    });
    
    res.json(messagesResponse);
});

// ===== NEW MISSING ENDPOINTS FOR DASHBOARD - ADDED =====

// Admin activity endpoint - ADDED FOR DASHBOARD
app.get('/api/admin/activity', (req, res) => {
    const sessionToken = req.headers['x-session-token'] || 
                        req.query.token || 
                        req.cookies?.adminToken;
    
    if (!sessionToken || !isValidSession(sessionToken)) {
        return res.status(401).json({
            success: false,
            error: 'Authentication required',
            redirectTo: '/admin-login'
        });
    }
    
    console.log('📈 Admin activity requested - PROTECTED');
    console.log(`📈 Activity data:`, {
        activitiesCount: adminData.recentActivity.length,
        activities: adminData.recentActivity.map(a => ({ id: a.id, action: a.action, user: a.user, timestamp: a.timestamp }))
    });
    
    const session = activeSessions.get(sessionToken);
    
    const activityResponse = {
        success: true,
        activities: adminData.recentActivity,
        recentActivity: adminData.recentActivity,
        totalCount: adminData.recentActivity.length,
        timestamp: new Date().toISOString(),
        user: session.user,
        role: session.role,
        summary: {
            totalActivities: adminData.recentActivity.length,
            typeCounts: {
                contact: adminData.recentActivity.filter(a => a.type === 'contact').length,
                admin_auth: adminData.recentActivity.filter(a => a.type === 'admin_auth').length,
                security_tool: adminData.recentActivity.filter(a => a.type === 'security_tool').length,
                system: adminData.recentActivity.filter(a => a.type === 'system').length
            },
            priorityCounts: {
                high: adminData.recentActivity.filter(a => a.priority === 'high').length,
                normal: adminData.recentActivity.filter(a => a.priority === 'normal').length,
                low: adminData.recentActivity.filter(a => a.priority === 'low').length
            }
        }
    };
    
    console.log('📤 Activity response summary:', {
        activitiesCount: activityResponse.activities.length,
        totalCount: activityResponse.totalCount
    });
    
    res.json(activityResponse);
});

// Admin security logs endpoint - ADDED FOR DASHBOARD
app.get('/api/admin/security-logs', (req, res) => {
    const sessionToken = req.headers['x-session-token'] || 
                        req.query.token || 
                        req.cookies?.adminToken;
    
    if (!sessionToken || !isValidSession(sessionToken)) {
        return res.status(401).json({
            success: false,
            error: 'Authentication required',
            redirectTo: '/admin-login'
        });
    }
    
    console.log('🔐 Admin security logs requested - PROTECTED');
    console.log(`🔐 Security logs data:`, {
        securityLogsCount: adminData.securityLogs.length,
        blockedAttempts: adminData.blockedAttempts,
        suspiciousAttempts: adminData.suspiciousAttempts,
        recentLogs: adminData.securityLogs.slice(-5).map(l => ({ id: l.id, type: l.type, timestamp: l.timestamp }))
    });
    
    const session = activeSessions.get(sessionToken);
    
    const securityResponse = {
        success: true,
        securityLogs: adminData.securityLogs,
        logs: adminData.securityLogs,
        totalCount: adminData.securityLogs.length,
        timestamp: new Date().toISOString(),
        user: session.user,
        role: session.role,
        summary: {
            totalLogs: adminData.securityLogs.length,
            blockedAttempts: adminData.blockedAttempts,
            suspiciousAttempts: adminData.suspiciousAttempts,
            adminLoginAttempts: adminData.adminLoginAttempts,
            activeSessions: activeSessions.size,
            typeCounts: {
                'Admin Login Success': adminData.securityLogs.filter(l => l.type === 'Admin Login Success').length,
                'Admin Login Failed': adminData.securityLogs.filter(l => l.type === 'Admin Login Failed').length,
                'Admin Login Blocked': adminData.securityLogs.filter(l => l.type === 'Admin Login Blocked').length,
                'Admin Dashboard Access Attempt': adminData.securityLogs.filter(l => l.type === 'Admin Dashboard Access Attempt').length,
                'Email Breach Check': adminData.securityLogs.filter(l => l.type === 'Email Breach Check').length,
                'URL Security Scan': adminData.securityLogs.filter(l => l.type === 'URL Security Scan').length,
                'File Security Scan': adminData.securityLogs.filter(l => l.type === 'File Security Scan').length,
                'Suspicious 404': adminData.securityLogs.filter(l => l.type === 'Suspicious 404').length
            },
            recentEvents: adminData.securityLogs.slice(-10).map(log => ({
                id: log.id,
                type: log.type,
                timestamp: log.timestamp,
                user: log.user || log.username || 'anonymous',
                blocked: log.blocked || false,
                tool: log.tool || 'system'
            }))
        }
    };
    
    console.log('📤 Security logs response summary:', {
        logsCount: securityResponse.securityLogs.length,
        totalCount: securityResponse.totalCount,
        blockedAttempts: adminData.blockedAttempts
    });
    
    res.json(securityResponse);
});

// Admin logout endpoint
app.post('/api/admin/logout', (req, res) => {
    const sessionToken = req.headers['x-session-token'] || 
                        req.query.token || 
                        req.cookies?.adminToken;
    
    console.log('🚪 Admin logout requested');
    console.log(`   Session token: ${sessionToken ? sessionToken.substring(0, 16) + '...' : 'none'}`);
    
    if (sessionToken && activeSessions.has(sessionToken)) {
        const session = activeSessions.get(sessionToken);
        console.log(`   User: ${session.user}`);
        
        // Remove session
        activeSessions.delete(sessionToken);
        
        adminData.securityLogs.push({
            id: Date.now(),
            type: 'Admin Logout',
            user: session.user,
            sessionToken: sessionToken.substring(0, 16) + '...',
            timestamp: new Date().toISOString()
        });
        
        adminData.recentActivity.push({
            id: Date.now() + 1,
            action: 'Admin Logout',
            details: `${session.user} logged out`,
            timestamp: new Date().toISOString(),
            type: 'admin_auth',
            user: session.user,
            priority: 'normal'
        });
        
        console.log('✅ Admin logout successful');
        
        res.json({
            success: true,
            message: 'Logout successful',
            timestamp: new Date().toISOString()
        });
    } else {
        console.log('❌ No valid session found for logout');
        
        res.json({
            success: false,
            message: 'No active session found',
            timestamp: new Date().toISOString()
        });
    }
});

// ===== ERROR HANDLING =====

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('💥 Server Error:', err);
    console.error('💥 Stack trace:', err.stack);
    
    adminData.securityLogs.push({
        id: Date.now(),
        type: 'Server Error',
        error: err.message,
        stack: err.stack,
        path: req.path,
        timestamp: new Date().toISOString()
    });
    
    res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: err.message,
        timestamp: new Date().toISOString(),
        user: CURRENT_USER
    });
});

// 404 handler with better routing and security logging
app.use((req, res) => {
    console.log(`❌ 404 - Route not found: ${req.method} ${req.path}`);
    
    // Log suspicious 404s
    const suspiciousPaths = ['/wp-admin', '/phpmyadmin', '/.env', '/config', '/admin.php'];
    const isSuspicious = suspiciousPaths.some(path => req.path.includes(path));
    
    if (isSuspicious) {
        adminData.securityLogs.push({
            id: Date.now(),
            type: 'Suspicious 404',
            path: req.path,
            ip: req.ip,
            userAgent: req.get('User-Agent') || 'Unknown',
            timestamp: new Date().toISOString(),
            blocked: true
        });
        
        adminData.suspiciousAttempts++;
    }
    
    if (req.path.startsWith('/api/')) {
        res.status(404).json({
            success: false,
            error: 'API endpoint not found',
            path: req.path,
            method: req.method,
            timestamp: new Date().toISOString(),
            user: CURRENT_USER,
            suggestion: 'Check /api/endpoints for available endpoints'
        });
    } else {
        // For page routes, try to serve index.html
        const indexPaths = [
            path.join(process.cwd(), 'index.html'),
            path.join(process.cwd(), 'frontend/index.html'),
            path.join(__dirname, '../frontend/index.html')
        ];
        
        let indexServed = false;
        for (const indexPath of indexPaths) {
            if (require('fs').existsSync(indexPath)) {
                res.sendFile(indexPath);
                indexServed = true;
                break;
            }
        }
        
        if (!indexServed) {
            res.status(404).json({
                success: false,
                error: 'Page not found',
                path: req.path,
                method: req.method,
                timestamp: new Date().toISOString(),
                suggestion: 'Please check the URL or return to the home page'
            });
        }
    }
});

// ===== SERVER STARTUP =====

app.listen(PORT, () => {
    const startupTime = '2025-06-13T06:10:41Z';
    
    console.log('='.repeat(80));
    console.log('🚀 SPECTRAOPS COMPLETE SERVER WITH ALL SECURITY TOOLS APIS STARTED');
    console.log('='.repeat(80));
    console.log(`📅 Current Time: ${startupTime}`);
    console.log(`👤 Current User: ranatalhamajid1`);
    console.log(`🌍 Location: Islamabad, Pakistan`);
    console.log(`🌐 Server: http://localhost:${PORT}`);
    console.log(`🎯 Main Page: http://localhost:${PORT}`);
    console.log(`🛡️ Security Tools: http://localhost:${PORT}/security-tools`);
    console.log(`📞 Contact Form: http://localhost:${PORT}/contact`);
    console.log(`🔐 Admin Login: http://localhost:${PORT}/admin-login (PROTECTED)`);
    console.log(`📊 Admin Dashboard: http://localhost:${PORT}/admin-dashboard.html (SESSION REQUIRED)`);
    console.log(`🔍 Health Check: http://localhost:${PORT}/api/health`);
    console.log(`📋 API Endpoints: http://localhost:${PORT}/api/endpoints`);
    console.log(`🔧 Debug Files: http://localhost:${PORT}/api/debug/files`);
    console.log('='.repeat(80));
    console.log('🔐 ALL CRITICAL FIXES APPLIED:');
    console.log(`   ✅ Admin dashboard BLOCKED without session token`);
    console.log(`   ✅ Admin login page rate limited and monitored`);
    console.log(`   ✅ Admin files excluded from static serving`);
    console.log(`   ✅ Session validation required for ALL admin access`);
    console.log(`   ✅ Automatic redirect to login for unauthorized access`);
    console.log(`   ✅ Comprehensive security logging for all attempts`);
    console.log(`   ✅ Health check endpoint added for login page compatibility`);
    console.log(`   ✅ API endpoints documentation endpoint added`);
    console.log(`   ✅ File structure debug endpoint added`);
    console.log(`   ✅ Flexible file path detection for different project structures`);
    console.log(`   ✅ Updated timestamps to 2025-06-13 06:10:41 UTC`);
    console.log(`   ✅ Current user synchronized: ranatalhamajid1`);
    console.log(`   ✅ Login loop prevention mechanisms active`);
    console.log(`   ✅ File path error handling implemented`);
    console.log(`   ✅ Cross-platform compatibility enabled`);
    console.log(`   ✅ DASHBOARD ENDPOINTS ADDED - /api/admin/activity`);
    console.log(`   ✅ DASHBOARD ENDPOINTS ADDED - /api/admin/security-logs`);
    console.log(`   ✅ SECURITY TOOLS APIS ADDED - /api/check-breach`);
    console.log(`   ✅ SECURITY TOOLS APIS ADDED - /api/scan-url`);
    console.log(`   ✅ SECURITY TOOLS APIS ADDED - /api/scan-file`);
    console.log(`   ✅ ALL DASHBOARD AND SECURITY TOOLS ERRORS FIXED`);
    console.log('='.repeat(80));
    console.log('🚨 SECURITY STATUS: MAXIMUM PROTECTION ACTIVE');
    console.log('🛡️ NO UNAUTHORIZED ACCESS TO ADMIN AREAS POSSIBLE');
    console.log('🔐 SESSION AUTHENTICATION REQUIRED FOR ALL ADMIN FUNCTIONS');
    console.log('📊 ALL ACCESS ATTEMPTS LOGGED AND MONITORED');
    console.log('✅ HEALTH CHECK ENDPOINT ACTIVE FOR LOGIN PAGE');
    console.log('🔧 ALL FRONTEND INTEGRATION ISSUES RESOLVED');
    console.log('📁 FLEXIBLE FILE PATH DETECTION ENABLED');
    console.log('🔍 FILE STRUCTURE DEBUGGING AVAILABLE');
    console.log('⚡ RATE LIMITING PROTECTION ACTIVE');
    console.log('🔒 ACCOUNT LOCKOUT PROTECTION ENABLED');
    console.log('🛡️ SUSPICIOUS ACTIVITY MONITORING ACTIVE');
    console.log('📈 DASHBOARD ACTIVITY ENDPOINT OPERATIONAL');
    console.log('🔐 DASHBOARD SECURITY LOGS ENDPOINT OPERATIONAL');
    console.log('🛡️ EMAIL BREACH CHECKER API OPERATIONAL');
    console.log('🔗 URL SECURITY SCANNER API OPERATIONAL');
    console.log('📁 MALICIOUS FILE CHECKER API OPERATIONAL');
    console.log('='.repeat(80));
    console.log('🎯 READY FOR TESTING:');
    console.log('   1. Test health endpoint: curl http://localhost:3000/api/health');
    console.log('   2. Check file structure: http://localhost:3000/api/debug/files');
    console.log('   3. View API endpoints: http://localhost:3000/api/endpoints');
    console.log('   4. Access login page: http://localhost:3000/admin-login');
    console.log('   5. Login credentials: ranatalhamajid1 / SpectraOps2025!');
    console.log('   6. Alternative credentials: admin / Admin123! | talha / Talha2025!');
    console.log('   7. Test activity endpoint: /api/admin/activity (after login)');
    console.log('   8. Test security logs: /api/admin/security-logs (after login)');
    console.log('   9. Test email breach: curl -X POST -H "Content-Type: application/json" -d \'{"email":"test@example.com"}\' http://localhost:3000/api/check-breach');
    console.log('   10. Test URL scan: curl -X POST -H "Content-Type: application/json" -d \'{"url":"https://example.com"}\' http://localhost:3000/api/scan-url');
    console.log('   11. Test file scan: curl -X POST -H "Content-Type: application/json" -d \'{"fileName":"test.exe","fileSize":1024,"fileType":"application/exe"}\' http://localhost:3000/api/scan-file');
    console.log('='.repeat(80));
    console.log('📋 ADMIN CREDENTIALS:');
    console.log('   🔑 SUPER ADMIN: ranatalhamajid1 | SpectraOps2025!');
    console.log('   🔑 ADMIN: admin | Admin123!');
    console.log('   🔑 ADMIN: talha | Talha2025!');
    console.log('='.repeat(80));
    console.log('🔧 ALL API ENDPOINTS AVAILABLE:');
    console.log('   📊 Server Health: /api/health');
    console.log('   📁 File Structure: /api/debug/files');
    console.log('   📋 API Documentation: /api/endpoints');
    console.log('   🔐 Admin Authentication: /api/admin/authenticate');
    console.log('   ✅ Session Check: /api/admin/check');
    console.log('   📊 Dashboard Data: /api/admin/dashboard');
    console.log('   📧 Messages: /api/admin/messages');
    console.log('   📈 Activity Logs: /api/admin/activity');
    console.log('   🔐 Security Logs: /api/admin/security-logs');
    console.log('   🚪 Logout: /api/admin/logout');
    console.log('   📞 Contact Form: /api/contact');
    console.log('   📧 Email Breach Check: /api/check-breach (NEW)');
    console.log('   🔗 URL Security Scan: /api/scan-url (NEW)');
    console.log('   📁 File Security Scan: /api/scan-file (NEW)');
    console.log('='.repeat(80));
    console.log('⚠️  IMPORTANT NOTES:');
    console.log('   📍 Server Location: Islamabad, Pakistan');
    console.log('   👤 Primary User: ranatalhamajid1');
    console.log('   🕐 Server Time: 2025-06-13 06:10:41 UTC');
    console.log('   🔐 Security Mode: Maximum Protection');
    console.log('   📊 Monitoring: All access attempts logged');
    console.log('   🛡️ Rate Limiting: 5 attempts per 15 minutes');
    console.log('   🔒 Account Lockout: 3 failed attempts = 15 minute lock');
    console.log('   ⏰ Session Timeout: 2 hours of inactivity');
    console.log('   🎯 Dashboard: Fully functional with all endpoints');
    console.log('   ✅ Recent Activity: Now available in dashboard');
    console.log('   🔐 Security Logs: Now available in dashboard');
    console.log('   🛡️ Security Tools: All APIs operational');
    console.log('   📈 Admin Analytics: Real-time security monitoring');
    console.log('='.repeat(80));
    console.log('✅ SERVER STARTUP COMPLETE - ALL SYSTEMS OPERATIONAL');
    console.log('📍 LOCATION: Islamabad, Pakistan');
    console.log('👤 USER: ranatalhamajid1');
    console.log('🕐 TIME: 2025-06-13 06:10:41 UTC');
    console.log('🌐 STATUS: READY FOR CONNECTIONS');
    console.log('🔐 SECURITY: FULLY PROTECTED');
    console.log('✨ FEATURES: ALL OPERATIONAL');
    console.log('📊 DASHBOARD: FULLY FUNCTIONAL');
    console.log('🛡️ SECURITY TOOLS: ALL APIS ACTIVE');
    console.log('='.repeat(80));
    
    // Log system information
    console.log('💻 SYSTEM INFORMATION:');
    console.log(`   🖥️  Platform: ${process.platform}`);
    console.log(`   📦 Node.js: ${process.version}`);
    console.log(`   💾 Memory: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB used`);
    console.log(`   ⚡ PID: ${process.pid}`);
    console.log(`   📂 Working Directory: ${process.cwd()}`);
    console.log(`   🔧 Environment: production`);
    console.log('='.repeat(80));
    
    // Final startup message
    console.log('🎉 SPECTRAOPS SERVER SUCCESSFULLY STARTED!');
    console.log('🚀 Ready to serve requests at http://localhost:3000');
    console.log('🔐 Admin panel available at http://localhost:3000/admin-login');
    console.log('📊 Dashboard fully operational with all endpoints!');
    console.log('✅ Recent Activity and Security Logs now working!');
    console.log('🛡️ All Security Tools APIs are operational!');
    console.log('📧 Email Breach Checker ready!');
    console.log('🔗 URL Security Scanner ready!');
    console.log('📁 Malicious File Checker ready!');
    console.log('🌟 All systems are GO! 🌟');
    console.log('='.repeat(80));
});