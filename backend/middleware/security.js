const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss');
const validator = require('validator');

class SecurityMiddleware {
    constructor() {
        this.blockedIPs = new Set();
        this.suspiciousActivity = new Map();
    }

    // Advanced rate limiting with different tiers
    createRateLimiter(options = {}) {
        const defaults = {
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: 100,
            message: 'Too many requests from this IP',
            standardHeaders: true,
            legacyHeaders: false,
            skip: (req) => this.isWhitelisted(req.ip)
        };

        return rateLimit({ ...defaults, ...options });
    }

    // Slow down responses for potential attackers
    createSlowDown(options = {}) {
        const defaults = {
            windowMs: 15 * 60 * 1000,
            delayAfter: 10,
            delayMs: 500,
            maxDelayMs: 20000
        };

        return slowDown({ ...defaults, ...options });
    }

    // Input sanitization
    sanitizeInput() {
        return (req, res, next) => {
            // Sanitize against NoSQL injection
            mongoSanitize.sanitize(req.body);
            mongoSanitize.sanitize(req.query);
            mongoSanitize.sanitize(req.params);

            // XSS protection
            if (req.body) {
                this.sanitizeObject(req.body);
            }
            if (req.query) {
                this.sanitizeObject(req.query);
            }

            next();
        };
    }

    sanitizeObject(obj) {
        for (const key in obj) {
            if (typeof obj[key] === 'string') {
                obj[key] = xss(obj[key]);
                obj[key] = validator.escape(obj[key]);
            } else if (typeof obj[key] === 'object') {
                this.sanitizeObject(obj[key]);
            }
        }
    }

    // Intrusion detection
    intrusionDetection() {
        return (req, res, next) => {
            const ip = req.ip;
            const suspiciousPatterns = [
                /union.*select/i,
                /script.*alert/i,
                /'.*or.*'.*='.*'/i,
                /\.\.\/.*\.\.\/.*\.\.\//,
                /<script[^>]*>.*<\/script>/i
            ];

            const requestString = JSON.stringify({
                url: req.url,
                body: req.body,
                query: req.query
            });

            for (const pattern of suspiciousPatterns) {
                if (pattern.test(requestString)) {
                    this.logSecurityEvent(ip, 'Suspicious pattern detected', req);
                    this.trackSuspiciousActivity(ip);
                    
                    if (this.shouldBlockIP(ip)) {
                        this.blockedIPs.add(ip);
                        return res.status(403).json({
                            success: false,
                            error: 'Access denied'
                        });
                    }
                    break;
                }
            }

            next();
        };
    }

    // IP blocking middleware
    ipBlocker() {
        return (req, res, next) => {
            const ip = req.ip;
            
            if (this.blockedIPs.has(ip)) {
                this.logSecurityEvent(ip, 'Blocked IP attempted access', req);
                return res.status(403).json({
                    success: false,
                    error: 'Access denied'
                });
            }

            next();
        };
    }

    trackSuspiciousActivity(ip) {
        const current = this.suspiciousActivity.get(ip) || { count: 0, firstSeen: Date.now() };
        current.count++;
        current.lastSeen = Date.now();
        this.suspiciousActivity.set(ip, current);
    }

    shouldBlockIP(ip) {
        const activity = this.suspiciousActivity.get(ip);
        if (!activity) return false;

        // Block if more than 5 suspicious activities in 10 minutes
        const tenMinutes = 10 * 60 * 1000;
        return activity.count > 5 && (Date.now() - activity.firstSeen) < tenMinutes;
    }

    isWhitelisted(ip) {
        const whitelist = process.env.IP_WHITELIST?.split(',') || [];
        return whitelist.includes(ip);
    }

    async logSecurityEvent(ip, event, req) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            ip,
            event,
            url: req.url,
            method: req.method,
            userAgent: req.get('User-Agent'),
            headers: req.headers
        };

        console.warn('🚨 Security Event:', logEntry);
        
        // Store in database
        try {
            const db = require('../config/database');
            await db.run(`
                INSERT INTO security_events (ip_address, event_type, details, created_at)
                VALUES (?, ?, ?, ?)
            `, [ip, event, JSON.stringify(logEntry), new Date().toISOString()]);
        } catch (error) {
            console.error('Failed to log security event:', error);
        }
    }

    // HTTPS enforcement
    httpsEnforcement() {
        return (req, res, next) => {
            if (process.env.NODE_ENV === 'production' && !req.secure && req.get('x-forwarded-proto') !== 'https') {
                return res.redirect(301, `https://${req.get('host')}${req.url}`);
            }
            next();
        };
    }

    // Security headers
    securityHeaders() {
        return (req, res, next) => {
            res.setHeader('X-Content-Type-Options', 'nosniff');
            res.setHeader('X-Frame-Options', 'DENY');
            res.setHeader('X-XSS-Protection', '1; mode=block');
            res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
            res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
            
            if (process.env.NODE_ENV === 'production') {
                res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
            }
            
            next();
        };
    }
}

module.exports = new SecurityMiddleware();