const compression = require('compression');
const helmet = require('helmet');
const express = require('express');

class PerformanceMiddleware {
    constructor() {
        this.cache = new Map();
        this.cacheTimeout = 5 * 60 * 1000; // 5 minutes
    }

    // Response caching middleware
    cacheMiddleware(duration = 300) {
        return (req, res, next) => {
            const key = req.originalUrl;
            const cached = this.cache.get(key);

            if (cached && Date.now() - cached.timestamp < duration * 1000) {
                res.set(cached.headers);
                return res.send(cached.data);
            }

            const originalSend = res.send;
            res.send = (data) => {
                // Cache successful responses
                if (res.statusCode === 200) {
                    this.cache.set(key, {
                        data,
                        headers: res.getHeaders(),
                        timestamp: Date.now()
                    });
                }
                originalSend.call(res, data);
            };

            next();
        };
    }

    // Image optimization middleware
    imageOptimization() {
        return express.static('public/images', {
            maxAge: '1y',
            setHeaders: (res, path) => {
                // Set appropriate headers for different image types
                if (path.endsWith('.webp')) {
                    res.set('Content-Type', 'image/webp');
                } else if (path.endsWith('.avif')) {
                    res.set('Content-Type', 'image/avif');
                }
                
                // Enable browser caching
                res.set('Cache-Control', 'public, max-age=31536000, immutable');
            }
        });
    }

    // Resource bundling and minification
    minificationMiddleware() {
        return (req, res, next) => {
            if (req.path.endsWith('.js') || req.path.endsWith('.css')) {
                res.set({
                    'Cache-Control': 'public, max-age=31536000',
                    'ETag': this.generateETag(req.path)
                });
            }
            next();
        };
    }

    // Database query optimization
    queryOptimization() {
        return (req, res, next) => {
            const startTime = Date.now();
            
            // Monitor slow queries
            const originalQuery = req.db?.query || (() => {});
            if (req.db) {
                req.db.query = (...args) => {
                    const queryStart = Date.now();
                    const result = originalQuery.apply(req.db, args);
                    
                    if (result instanceof Promise) {
                        return result.then(data => {
                            const queryTime = Date.now() - queryStart;
                            if (queryTime > 100) { // Log slow queries
                                console.warn(`Slow query detected: ${queryTime}ms`, args[0]);
                            }
                            return data;
                        });
                    }
                    
                    return result;
                };
            }

            res.on('finish', () => {
                const responseTime = Date.now() - startTime;
                res.set('X-Response-Time', `${responseTime}ms`);
            });

            next();
        };
    }

    generateETag(path) {
        const crypto = require('crypto');
        return crypto.createHash('md5').update(path + Date.now()).digest('hex');
    }

    // Memory usage monitoring
    memoryMonitoring() {
        setInterval(() => {
            const usage = process.memoryUsage();
            if (usage.heapUsed > 100 * 1024 * 1024) { // 100MB
                console.warn('High memory usage detected:', {
                    heapUsed: Math.round(usage.heapUsed / 1024 / 1024) + 'MB',
                    heapTotal: Math.round(usage.heapTotal / 1024 / 1024) + 'MB'
                });
            }

            // Clear cache if memory is high
            if (usage.heapUsed > 200 * 1024 * 1024) { // 200MB
                this.cache.clear();
                console.log('Cache cleared due to high memory usage');
            }
        }, 30000); // Check every 30 seconds
    }

    // Initialize all performance optimizations
    init(app) {
        // Compression
        app.use(compression({
            filter: (req, res) => {
                if (req.headers['x-no-compression']) {
                    return false;
                }
                return compression.filter(req, res);
            },
            threshold: 1024
        }));

        // Security headers
        app.use(helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
                    scriptSrc: ["'self'", "https://cdnjs.cloudflare.com"],
                    imgSrc: ["'self'", "data:", "https:"],
                    fontSrc: ["'self'", "https://fonts.googleapis.com", "https://fonts.gstatic.com"]
                }
            }
        }));

        // Performance monitoring
        this.memoryMonitoring();

        return {
            cache: this.cacheMiddleware.bind(this),
            images: this.imageOptimization.bind(this),
            minification: this.minificationMiddleware.bind(this),
            queryOptimization: this.queryOptimization.bind(this)
        };
    }
}

module.exports = new PerformanceMiddleware();