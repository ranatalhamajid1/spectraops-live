const AWS = require('aws-sdk');
const cloudflare = require('cloudflare');

class CDNService {
    constructor() {
        this.cloudflare = cloudflare({
            token: process.env.CLOUDFLARE_API_TOKEN
        });
        
        this.aws = new AWS.CloudFront({
            accessKeyId: process.env.AWS_ACCESS_KEY_ID,
            secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
            region: process.env.AWS_REGION || 'us-east-1'
        });
    }

    async setupCloudflare() {
        console.log('☁️ Setting up Cloudflare CDN...');
        
        try {
            const zone = await this.getCloudflareZone();
            
            // Configure caching rules
            await this.setupCachingRules(zone.id);
            
            // Setup security rules
            await this.setupSecurityRules(zone.id);
            
            // Configure SSL settings
            await this.configureSSL(zone.id);
            
            console.log('✅ Cloudflare CDN configured successfully');
            
        } catch (error) {
            console.error('❌ Cloudflare setup failed:', error);
            throw error;
        }
    }

    async getCloudflareZone() {
        const zones = await this.cloudflare.zones.browse();
        const zone = zones.result.find(z => z.name === process.env.DOMAIN);
        
        if (!zone) {
            throw new Error(`Zone not found for domain: ${process.env.DOMAIN}`);
        }
        
        return zone;
    }

    async setupCachingRules(zoneId) {
        const rules = [
            {
                targets: [
                    {
                        target: 'url',
                        constraint: {
                            operator: 'matches',
                            value: '*.css'
                        }
                    }
                ],
                actions: [
                    {
                        id: 'cache_level',
                        value: 'cache_everything'
                    },
                    {
                        id: 'edge_cache_ttl',
                        value: 2592000 // 30 days
                    }
                ]
            },
            {
                targets: [
                    {
                        target: 'url',
                        constraint: {
                            operator: 'matches',
                            value: '*.js'
                        }
                    }
                ],
                actions: [
                    {
                        id: 'cache_level',
                        value: 'cache_everything'
                    },
                    {
                        id: 'edge_cache_ttl',
                        value: 2592000 // 30 days
                    }
                ]
            },
            {
                targets: [
                    {
                        target: 'url',
                        constraint: {
                            operator: 'matches',
                            value: '/api/*'
                        }
                    }
                ],
                actions: [
                    {
                        id: 'cache_level',
                        value: 'bypass'
                    }
                ]
            }
        ];

        for (const rule of rules) {
            await this.cloudflare.pageRules.add(zoneId, rule);
        }

        console.log('📋 Caching rules configured');
    }

    async setupSecurityRules(zoneId) {
        // Enable DDoS protection
        await this.cloudflare.zones.settings.edit(zoneId, 'security_level', {
            value: 'medium'
        });

        // Configure firewall rules
        const firewallRules = [
            {
                filter: {
                    expression: '(http.request.uri.path contains "/admin" and ip.src ne 1.2.3.4)'
                },
                action: 'challenge'
            },
            {
                filter: {
                    expression: '(http.request.uri.path contains "/api/admin" and ip.src ne 1.2.3.4)'
                },
                action: 'block'
            }
        ];

        for (const rule of firewallRules) {
            await this.cloudflare.firewallRules.add(zoneId, [rule]);
        }

        console.log('🔒 Security rules configured');
    }

    async configureSSL(zoneId) {
        // Set SSL mode to Full (strict)
        await this.cloudflare.zones.settings.edit(zoneId, 'ssl', {
            value: 'full'
        });

        // Enable Always Use HTTPS
        await this.cloudflare.zones.settings.edit(zoneId, 'always_use_https', {
            value: 'on'
        });

        // Configure HSTS
        await this.cloudflare.zones.settings.edit(zoneId, 'security_header', {
            value: {
                strict_transport_security: {
                    enabled: true,
                    max_age: 31536000,
                    include_subdomains: true,
                    preload: true
                }
            }
        });

        console.log('🔐 SSL settings configured');
    }

    async purgeCache(urls = []) {
        try {
            const zone = await this.getCloudflareZone();
            
            if (urls.length > 0) {
                await this.cloudflare.zones.purgeCache(zone.id, { files: urls });
                console.log(`🗑️ Purged specific URLs: ${urls.join(', ')}`);
            } else {
                await this.cloudflare.zones.purgeCache(zone.id, { purge_everything: true });
                console.log('🗑️ Purged entire cache');
            }
        } catch (error) {
            console.error('Cache purge failed:', error);
            throw error;
        }
    }

    async getAnalytics(since = '-7d') {
        try {
            const zone = await this.getCloudflareZone();
            
            const analytics = await this.cloudflare.zones.analytics.dashboard(zone.id, {
                since
            });
            
            return {
                requests: analytics.result.totals.requests.all,
                bandwidth: analytics.result.totals.bandwidth.all,
                threats: analytics.result.totals.threats.all,
                pageViews: analytics.result.totals.pageviews.all,
                cacheHitRatio: analytics.result.totals.requests.cached / analytics.result.totals.requests.all
            };
        } catch (error) {
            console.error('Failed to get CDN analytics:', error);
            throw error;
        }
    }
}

module.exports = CDNService;