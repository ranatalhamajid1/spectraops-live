const axios = require('axios');
const crypto = require('crypto');

class IntegrationService {
    constructor() {
        this.integrations = new Map();
        this.setupIntegrations();
    }

    setupIntegrations() {
        // Slack Integration
        if (process.env.SLACK_WEBHOOK_URL) {
            this.integrations.set('slack', {
                enabled: true,
                webhook: process.env.SLACK_WEBHOOK_URL,
                channels: {
                    alerts: process.env.SLACK_ALERTS_CHANNEL || '#alerts',
                    general: process.env.SLACK_GENERAL_CHANNEL || '#general'
                }
            });
        }

        // Microsoft Teams Integration
        if (process.env.TEAMS_WEBHOOK_URL) {
            this.integrations.set('teams', {
                enabled: true,
                webhook: process.env.TEAMS_WEBHOOK_URL
            });
        }

        // Jira Integration
        if (process.env.JIRA_API_TOKEN) {
            this.integrations.set('jira', {
                enabled: true,
                host: process.env.JIRA_HOST,
                email: process.env.JIRA_EMAIL,
                token: process.env.JIRA_API_TOKEN,
                projectKey: process.env.JIRA_PROJECT_KEY || 'SEC'
            });
        }

        // GitHub Integration
        if (process.env.GITHUB_TOKEN) {
            this.integrations.set('github', {
                enabled: true,
                token: process.env.GITHUB_TOKEN,
                owner: process.env.GITHUB_OWNER,
                repo: process.env.GITHUB_REPO
            });
        }

        // Zapier Integration
        if (process.env.ZAPIER_WEBHOOK_URL) {
            this.integrations.set('zapier', {
                enabled: true,
                webhook: process.env.ZAPIER_WEBHOOK_URL
            });
        }
    }

    // Slack Integration Methods
    async sendSlackNotification(message, channel = 'general', severity = 'info') {
        const slack = this.integrations.get('slack');
        if (!slack?.enabled) return false;

        try {
            const color = this.getSeverityColor(severity);
            const payload = {
                channel: slack.channels[channel] || slack.channels.general,
                username: 'SpectraOps Security Bot',
                icon_emoji: ':shield:',
                attachments: [{
                    color,
                    title: '🔒 SpectraOps Security Alert',
                    text: message,
                    footer: 'SpectraOps Ltd.',
                    ts: Math.floor(Date.now() / 1000)
                }]
            };

            await axios.post(slack.webhook, payload);
            console.log('✅ Slack notification sent');
            return true;
        } catch (error) {
            console.error('❌ Slack notification failed:', error.message);
            return false;
        }
    }

    // Microsoft Teams Integration
    async sendTeamsNotification(title, message, severity = 'info') {
        const teams = this.integrations.get('teams');
        if (!teams?.enabled) return false;

        try {
            const color = this.getSeverityColor(severity);
            const payload = {
                '@type': 'MessageCard',
                '@context': 'https://schema.org/extensions',
                summary: title,
                themeColor: color,
                sections: [{
                    activityTitle: '🔒 SpectraOps Security Alert',
                    activitySubtitle: title,
                    text: message,
                    facts: [{
                        name: 'Severity',
                        value: severity.toUpperCase()
                    }, {
                        name: 'Time',
                        value: new Date().toISOString()
                    }]
                }],
                potentialAction: [{
                    '@type': 'OpenUri',
                    name: 'View Dashboard',
                    targets: [{
                        os: 'default',
                        uri: `${process.env.FRONTEND_URL}/admin`
                    }]
                }]
            };

            await axios.post(teams.webhook, payload);
            console.log('✅ Teams notification sent');
            return true;
        } catch (error) {
            console.error('❌ Teams notification failed:', error.message);
            return false;
        }
    }

    // Jira Integration
    async createJiraIssue(summary, description, issueType = 'Bug', priority = 'Medium') {
        const jira = this.integrations.get('jira');
        if (!jira?.enabled) return false;

        try {
            const auth = Buffer.from(`${jira.email}:${jira.token}`).toString('base64');
            
            const payload = {
                fields: {
                    project: { key: jira.projectKey },
                    summary,
                    description: {
                        type: 'doc',
                        version: 1,
                        content: [{
                            type: 'paragraph',
                            content: [{
                                type: 'text',
                                text: description
                            }]
                        }]
                    },
                    issuetype: { name: issueType },
                    priority: { name: priority },
                    labels: ['security', 'automated']
                }
            };

            const response = await axios.post(
                `https://${jira.host}/rest/api/3/issue`,
                payload,
                {
                    headers: {
                        'Authorization': `Basic ${auth}`,
                        'Content-Type': 'application/json'
                    }
                }
            );

            console.log(`✅ Jira issue created: ${response.data.key}`);
            return response.data;
        } catch (error) {
            console.error('❌ Jira issue creation failed:', error.message);
            return false;
        }
    }

    // GitHub Integration
    async createGitHubIssue(title, body, labels = ['security']) {
        const github = this.integrations.get('github');
        if (!github?.enabled) return false;

        try {
            const payload = {
                title,
                body,
                labels
            };

            const response = await axios.post(
                `https://api.github.com/repos/${github.owner}/${github.repo}/issues`,
                payload,
                {
                    headers: {
                        'Authorization': `token ${github.token}`,
                        'Accept': 'application/vnd.github.v3+json'
                    }
                }
            );

            console.log(`✅ GitHub issue created: #${response.data.number}`);
            return response.data;
        } catch (error) {
            console.error('❌ GitHub issue creation failed:', error.message);
            return false;
        }
    }

    // Zapier Integration
    async triggerZapierWebhook(data, zapName = 'security-alert') {
        const zapier = this.integrations.get('zapier');
        if (!zapier?.enabled) return false;

        try {
            const payload = {
                zapName,
                timestamp: new Date().toISOString(),
                source: 'SpectraOps',
                ...data
            };

            await axios.post(zapier.webhook, payload);
            console.log('✅ Zapier webhook triggered');
            return true;
        } catch (error) {
            console.error('❌ Zapier webhook failed:', error.message);
            return false;
        }
    }

    // Unified notification method
    async sendSecurityAlert(alert) {
        const promises = [];

        // Send to all enabled integrations
        if (this.integrations.get('slack')?.enabled) {
            promises.push(this.sendSlackNotification(
                `${alert.title}\n${alert.description}`,
                'alerts',
                alert.severity
            ));
        }

        if (this.integrations.get('teams')?.enabled) {
            promises.push(this.sendTeamsNotification(
                alert.title,
                alert.description,
                alert.severity
            ));
        }

        if (alert.severity === 'high' && this.integrations.get('jira')?.enabled) {
            promises.push(this.createJiraIssue(
                alert.title,
                alert.description,
                'Bug',
                'High'
            ));
        }

        if (this.integrations.get('zapier')?.enabled) {
            promises.push(this.triggerZapierWebhook({
                alert: alert.title,
                description: alert.description,
                severity: alert.severity
            }));
        }

        const results = await Promise.allSettled(promises);
        const successful = results.filter(r => r.status === 'fulfilled').length;
        
        console.log(`📤 Security alert sent to ${successful}/${results.length} integrations`);
        return { successful, total: results.length };
    }

    // SIEM Integration (Splunk, ELK, etc.)
    async sendToSIEM(logData) {
        const siemEndpoint = process.env.SIEM_ENDPOINT;
        const siemToken = process.env.SIEM_TOKEN;

        if (!siemEndpoint || !siemToken) return false;

        try {
            const payload = {
                timestamp: new Date().toISOString(),
                source: 'SpectraOps',
                sourcetype: 'security_log',
                event: logData
            };

            await axios.post(siemEndpoint, payload, {
                headers: {
                    'Authorization': `Splunk ${siemToken}`,
                    'Content-Type': 'application/json'
                }
            });

            console.log('✅ Data sent to SIEM');
            return true;
        } catch (error) {
            console.error('❌ SIEM integration failed:', error.message);
            return false;
        }
    }

    // Third-party security tools integration
    async integrateWithSecurityTools(scanResults) {
        const integrations = [];

        // Nessus Integration
        if (process.env.NESSUS_API_KEY) {
            integrations.push(this.sendToNessus(scanResults));
        }

        // Qualys Integration
        if (process.env.QUALYS_API_KEY) {
            integrations.push(this.sendToQualys(scanResults));
        }

        // OpenVAS Integration
        if (process.env.OPENVAS_ENDPOINT) {
            integrations.push(this.sendToOpenVAS(scanResults));
        }

        const results = await Promise.allSettled(integrations);
        return results;
    }

    getSeverityColor(severity) {
        const colors = {
            low: '#36a64f',     // Green
            medium: '#ff9500',  // Orange
            high: '#ff0000',    // Red
            critical: '#8b0000' // Dark Red
        };
        return colors[severity.toLowerCase()] || colors.medium;
    }

    // Health check for all integrations
    async checkIntegrationsHealth() {
        const health = {};

        for (const [name, config] of this.integrations.entries()) {
            if (!config.enabled) {
                health[name] = { status: 'disabled' };
                continue;
            }

            try {
                await this.testIntegration(name, config);
                health[name] = { status: 'healthy', lastCheck: new Date().toISOString() };
            } catch (error) {
                health[name] = { 
                    status: 'unhealthy', 
                    error: error.message,
                    lastCheck: new Date().toISOString()
                };
            }
        }

        return health;
    }

    async testIntegration(name, config) {
        switch (name) {
            case 'slack':
                // Test with a simple ping
                await axios.post(config.webhook, { text: 'Health check' });
                break;
            case 'teams':
                // Test Teams webhook
                await axios.post(config.webhook, {
                    text: 'Health check from SpectraOps'
                });
                break;
            case 'jira':
                // Test Jira API connection
                const auth = Buffer.from(`${config.email}:${config.token}`).toString('base64');
                await axios.get(`https://${config.host}/rest/api/3/myself`, {
                    headers: { 'Authorization': `Basic ${auth}` }
                });
                break;
            case 'github':
                // Test GitHub API
                await axios.get('https://api.github.com/user', {
                    headers: { 'Authorization': `token ${config.token}` }
                });
                break;
        }
    }
}

module.exports = new IntegrationService();