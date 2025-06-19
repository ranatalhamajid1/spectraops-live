const prometheus = require('prom-client');
const nodemailer = require('nodemailer');

class MonitoringService {
    constructor() {
        this.register = new prometheus.Registry();
        this.setupMetrics();
        this.setupHealthChecks();
        this.setupAlerts();
    }


    setupMetrics() {
        // HTTP request metrics
        this.httpRequestDuration = new prometheus.Histogram({
            name: 'http_request_duration_seconds',
            help: 'Duration of HTTP requests in seconds',
            labelNames: ['method', 'route', 'status_code'],
            buckets: [0.1, 0.5, 1, 2, 5]
        });

        this.httpRequestsTotal = new prometheus.Counter({
            name: 'http_requests_total',
            help: 'Total number of HTTP requests',
            labelNames: ['method', 'route', 'status_code']
        });

        // Database metrics
        this.databaseQueryDuration = new prometheus.Histogram({
            name: 'database_query_duration_seconds',
            help: 'Duration of database queries',
            labelNames: ['query_type'],
            buckets: [0.01, 0.05, 0.1, 0.5, 1, 2]
        });

        this.databaseConnections = new prometheus.Gauge({
            name: 'database_connections_active',
            help: 'Number of active database connections'
        });

        // Security metrics
        this.securityEvents = new prometheus.Counter({
            name: 'security_events_total',
            help: 'Total number of security events',
            labelNames: ['event_type', 'severity']
        });

        this.blockedRequests = new prometheus.Counter({
            name: 'blocked_requests_total',
            help: 'Total number of blocked requests',
            labelNames: ['reason']
        });

        // Application metrics
        this.memoryUsage = new prometheus.Gauge({
            name: 'memory_usage_bytes',
            help: 'Memory usage in bytes',
            labelNames: ['type']
        });

        this.cpuUsage = new prometheus.Gauge({
            name: 'cpu_usage_percent',
            help: 'CPU usage percentage'
        });

        // Business metrics
        this.contactSubmissions = new prometheus.Counter({
            name: 'contact_submissions_total',
            help: 'Total contact form submissions',
            labelNames: ['status']
        });

        this.securityToolUsage = new prometheus.Counter({
            name: 'security_tool_usage_total',
            help: 'Security tool usage count',
            labelNames: ['tool_name', 'success']
        });

        // Register all metrics
        this.register.registerMetric(this.httpRequestDuration);
        this.register.registerMetric(this.httpRequestsTotal);
        this.register.registerMetric(this.databaseQueryDuration);
        this.register.registerMetric(this.databaseConnections);
        this.register.registerMetric(this.securityEvents);
        this.register.registerMetric(this.blockedRequests);
        this.register.registerMetric(this.memoryUsage);
        this.register.registerMetric(this.cpuUsage);
        this.register.registerMetric(this.contactSubmissions);
        this.register.registerMetric(this.securityToolUsage);

        // Collect default metrics
        prometheus.collectDefaultMetrics({ register: this.register });
    }

    setupHealthChecks() {
        this.healthChecks = {
            database: async () => {
                const db = require('../config/database');
                try {
                    await db.get('SELECT 1');
                    return { status: 'healthy', responseTime: Date.now() };
                } catch (error) {
                    return { status: 'unhealthy', error: error.message };
                }
            },
            
            memoryUsage: () => {
                const usage = process.memoryUsage();
                const threshold = 500 * 1024 * 1024; // 500MB
                return {
                    status: usage.heapUsed < threshold ? 'healthy' : 'warning',
                    heapUsed: usage.heapUsed,
                    heapTotal: usage.heapTotal,
                    threshold
                };
            },

            diskSpace: async () => {
                const fs = require('fs').promises;
                try {
                    const stats = await fs.stat('./data');
                    return {
                        status: 'healthy',
                        size: stats.size
                    };
                } catch (error) {
                    return {
                        status: 'unhealthy',
                        error: error.message
                    };
                }
            },

            externalServices: async () => {
                const services = [];
                
                // Check email service
                try {
                    const emailService = require('./emailService');
                    if (emailService.transporter) {
                        await emailService.transporter.verify();
                        services.push({ service: 'email', status: 'healthy' });
                    }
                } catch (error) {
                    services.push({ service: 'email', status: 'unhealthy', error: error.message });
                }

                return { services };
            }
        };
    }

    setupAlerts() {
        this.alertRules = [
            {
                name: 'high_memory_usage',
                condition: () => {
                    const usage = process.memoryUsage();
                    return usage.heapUsed > 400 * 1024 * 1024; // 400MB
                },
                severity: 'warning',
                message: 'High memory usage detected'
            },
            {
                name: 'database_connection_failure',
                condition: async () => {
                    const health = await this.healthChecks.database();
                    return health.status === 'unhealthy';
                },
                severity: 'critical',
                message: 'Database connection failed'
            },
            {
                name: 'high_error_rate',
                condition: () => {
                    // Check error rate in last 5 minutes
                    const errorRate = this.calculateErrorRate();
                    return errorRate > 0.05; // 5%
                },
                severity: 'warning',
                message: 'High error rate detected'
            }
        ];

        // Check alerts every minute
        setInterval(() => {
            this.checkAlerts();
        }, 60000);
    }

    async checkAlerts() {
        for (const rule of this.alertRules) {
            try {
                const triggered = await rule.condition();
                if (triggered) {
                    await this.sendAlert(rule);
                }
            } catch (error) {
                console.error(`Alert check failed for ${rule.name}:`, error);
            }
        }
    }

    async sendAlert(rule) {
        const alertData = {
            name: rule.name,
            severity: rule.severity,
            message: rule.message,
            timestamp: new Date().toISOString(),
            hostname: require('os').hostname()
        };

        console.warn(`🚨 ALERT [${rule.severity.toUpperCase()}]: ${rule.message}`);

        // Send email notification
        if (process.env.ALERT_EMAIL) {
            await this.sendEmailAlert(alertData);
        }

        // Log to database
        try {
            const db = require('../config/database');
            await db.run(`
                INSERT INTO alerts (name, severity, message, triggered_at)
                VALUES (?, ?, ?, ?)
            `, [alertData.name, alertData.severity, alertData.message, alertData.timestamp]);
        } catch (error) {
            console.error('Failed to log alert:', error);
        }
    }

    async sendEmailAlert(alertData) {
        try {
            const transporter = nodemailer.createTransporter({
                host: process.env.SMTP_HOST,
                port: process.env.SMTP_PORT,
                secure: process.env.SMTP_SECURE === 'true',
                auth: {
                    user: process.env.SMTP_USER,
                    pass: process.env.SMTP_PASS
                }
            });

            await transporter.sendMail({
                from: process.env.SMTP_USER,
                to: process.env.ALERT_EMAIL,
                subject: `🚨 SpectraOps Alert: ${alertData.name}`,
                html: `
                    <h2>🚨 System Alert</h2>
                    <p><strong>Alert:</strong> ${alertData.name}</p>
                    <p><strong>Severity:</strong> ${alertData.severity}</p>
                    <p><strong>Message:</strong> ${alertData.message}</p>
                    <p><strong>Time:</strong> ${alertData.timestamp}</p>
                    <p><strong>Server:</strong> ${alertData.hostname}</p>
                `
            });
        } catch (error) {
            console.error('Failed to send email alert:', error);
        }
    }

    calculateErrorRate() {
        // Implementation would calculate actual error rate from metrics
        return 0; // Placeholder
    }

    // Middleware to track HTTP metrics
    trackHTTPMetrics() {
        return (req, res, next) => {
            const start = Date.now();
            
            res.on('finish', () => {
                const duration = (Date.now() - start) / 1000;
                const route = req.route?.path || req.path;
                
                this.httpRequestDuration
                    .labels(req.method, route, res.statusCode)
                    .observe(duration);
                
                this.httpRequestsTotal
                    .labels(req.method, route, res.statusCode)
                    .inc();
            });
            
            next();
        };
    }

    async getMetrics() {
        // Update system metrics
        const usage = process.memoryUsage();
        this.memoryUsage.labels('heap_used').set(usage.heapUsed);
        this.memoryUsage.labels('heap_total').set(usage.heapTotal);
        this.memoryUsage.labels('external').set(usage.external);

        return this.register.metrics();
    }

    async getHealthStatus() {
        const health = {
            status: 'healthy',
            timestamp: new Date().toISOString(),
            checks: {}
        };

        for (const [name, check] of Object.entries(this.healthChecks)) {
            try {
                health.checks[name] = await check();
                if (health.checks[name].status === 'unhealthy') {
                    health.status = 'unhealthy';
                } else if (health.checks[name].status === 'warning' && health.status === 'healthy') {
                    health.status = 'warning';
                }
            } catch (error) {
                health.checks[name] = {
                    status: 'unhealthy',
                    error: error.message
                };
                health.status = 'unhealthy';
            }
        }

        return health;
    }
}

module.exports = new MonitoringService();