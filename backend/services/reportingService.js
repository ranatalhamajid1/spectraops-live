const PDFDocument = require('pdfkit');
const fs = require('fs').promises;
const path = require('path');
const db = require('../config/database');

class ReportingService {
    constructor() {
        this.reportsDir = path.join(__dirname, '../reports');
        this.ensureReportsDirectory();
    }

    async ensureReportsDirectory() {
        try {
            await fs.access(this.reportsDir);
        } catch {
            await fs.mkdir(this.reportsDir, { recursive: true });
        }
    }

    async generateSecurityReport(dateRange = '30d') {
        const reportData = await this.collectSecurityData(dateRange);
        const reportPath = path.join(this.reportsDir, `security-report-${Date.now()}.pdf`);
        
        const doc = new PDFDocument();
        const stream = fs.createWriteStream(reportPath);
        doc.pipe(stream);

        // Header
        this.addReportHeader(doc, 'Security Analysis Report');
        
        // Executive Summary
        this.addSection(doc, 'Executive Summary', () => {
            doc.text(`Report Period: Last ${dateRange}`, { indent: 20 });
            doc.text(`Total Security Events: ${reportData.securityEvents.total}`, { indent: 20 });
            doc.text(`Blocked Attacks: ${reportData.blockedAttacks}`, { indent: 20 });
            doc.text(`Tool Usage: ${reportData.toolUsage.total}`, { indent: 20 });
        });

        // Security Events Analysis
        this.addSection(doc, 'Security Events', () => {
            doc.text('Event Types:', { underline: true, indent: 20 });
            reportData.securityEvents.byType.forEach(event => {
                doc.text(`• ${event.type}: ${event.count} events`, { indent: 40 });
            });
        });

        // Tool Usage Statistics
        this.addSection(doc, 'Security Tool Usage', () => {
            reportData.toolUsage.byTool.forEach(tool => {
                doc.text(`${tool.name}:`, { underline: true, indent: 20 });
                doc.text(`  Usage: ${tool.count} times`, { indent: 40 });
                doc.text(`  Success Rate: ${tool.successRate}%`, { indent: 40 });
                doc.text(`  Avg Response Time: ${tool.avgResponseTime}ms`, { indent: 40 });
            });
        });

        // Threat Analysis
        this.addSection(doc, 'Threat Analysis', () => {
            doc.text('Top Threats:', { underline: true, indent: 20 });
            reportData.threats.forEach((threat, index) => {
                doc.text(`${index + 1}. ${threat.type} (${threat.frequency} occurrences)`, { indent: 40 });
            });
        });

        // Recommendations
        this.addSection(doc, 'Recommendations', () => {
            const recommendations = this.generateSecurityRecommendations(reportData);
            recommendations.forEach(rec => {
                doc.text(`• ${rec}`, { indent: 20 });
            });
        });

        doc.end();

        return new Promise((resolve, reject) => {
            stream.on('finish', () => resolve(reportPath));
            stream.on('error', reject);
        });
    }

    async generateBusinessReport(dateRange = '30d') {
        const reportData = await this.collectBusinessData(dateRange);
        const reportPath = path.join(this.reportsDir, `business-report-${Date.now()}.pdf`);
        
        const doc = new PDFDocument();
        const stream = fs.createWriteStream(reportPath);
        doc.pipe(stream);

        this.addReportHeader(doc, 'Business Analytics Report');

        // Key Metrics
        this.addSection(doc, 'Key Performance Indicators', () => {
            doc.text(`Total Visitors: ${reportData.visitors.total.toLocaleString()}`, { indent: 20 });
            doc.text(`Page Views: ${reportData.pageViews.total.toLocaleString()}`, { indent: 20 });
            doc.text(`Contact Submissions: ${reportData.contacts.total}`, { indent: 20 });
            doc.text(`Conversion Rate: ${reportData.conversionRate}%`, { indent: 20 });
        });

        // Traffic Analysis
        this.addSection(doc, 'Traffic Analysis', () => {
            doc.text('Top Pages:', { underline: true, indent: 20 });
            reportData.topPages.forEach((page, index) => {
                doc.text(`${index + 1}. ${page.path} (${page.views} views)`, { indent: 40 });
            });
        });

        // Geographic Distribution
        this.addSection(doc, 'Geographic Distribution', () => {
            reportData.geography.forEach(geo => {
                doc.text(`${geo.country}: ${geo.percentage}%`, { indent: 20 });
            });
        });

        // Contact Analysis
        this.addSection(doc, 'Lead Generation', () => {
            doc.text(`Service Interests:`, { underline: true, indent: 20 });
            reportData.serviceInterests.forEach(interest => {
                doc.text(`• ${interest.service}: ${interest.count} inquiries`, { indent: 40 });
            });
        });

        doc.end();

        return new Promise((resolve, reject) => {
            stream.on('finish', () => resolve(reportPath));
            stream.on('error', reject);
        });
    }

    async collectSecurityData(dateRange) {
        const securityEvents = await db.all(`
            SELECT 
                event_type,
                COUNT(*) as count
            FROM security_events 
            WHERE created_at >= datetime('now', '-${dateRange}')
            GROUP BY event_type
            ORDER BY count DESC
        `);

        const toolUsage = await db.all(`
            SELECT 
                tool_name,
                COUNT(*) as count,
                AVG(processing_time) as avg_response_time,
                (SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) * 100.0 / COUNT(*)) as success_rate
            FROM security_tool_usage 
            WHERE created_at >= datetime('now', '-${dateRange}')
            GROUP BY tool_name
            ORDER BY count DESC
        `);

        const blockedAttacks = await db.get(`
            SELECT COUNT(*) as count
            FROM security_events 
            WHERE event_type = 'blocked_request' 
            AND created_at >= datetime('now', '-${dateRange}')
        `);

        return {
            securityEvents: {
                total: securityEvents.reduce((sum, event) => sum + event.count, 0),
                byType: securityEvents
            },
            toolUsage: {
                total: toolUsage.reduce((sum, tool) => sum + tool.count, 0),
                byTool: toolUsage
            },
            blockedAttacks: blockedAttacks.count,
            threats: this.analyzeThreatPatterns(securityEvents)
        };
    }

    async collectBusinessData(dateRange) {
        const visitors = await db.get(`
            SELECT 
                COUNT(DISTINCT ip_address) as total,
                COUNT(*) as page_views
            FROM page_views 
            WHERE created_at >= datetime('now', '-${dateRange}')
        `);

        const topPages = await db.all(`
            SELECT 
                page_path as path,
                COUNT(*) as views
            FROM page_views 
            WHERE created_at >= datetime('now', '-${dateRange}')
            GROUP BY page_path
            ORDER BY views DESC
            LIMIT 10
        `);

        const contacts = await db.get(`
            SELECT COUNT(*) as total
            FROM contact_submissions 
            WHERE created_at >= datetime('now', '-${dateRange}')
        `);

        const serviceInterests = await db.all(`
            SELECT 
                service_interest as service,
                COUNT(*) as count
            FROM contact_submissions 
            WHERE service_interest IS NOT NULL 
            AND created_at >= datetime('now', '-${dateRange}')
            GROUP BY service_interest
            ORDER BY count DESC
        `);

        const conversionRate = visitors.total > 0 ? 
            ((contacts.total / visitors.total) * 100).toFixed(2) : 0;

        return {
            visitors,
            pageViews: { total: visitors.page_views },
            topPages,
            contacts,
            serviceInterests,
            conversionRate,
            geography: await this.getGeographicData(dateRange)
        };
    }

    async getGeographicData(dateRange) {
        // Simplified geographic data - in production, you'd use IP geolocation
        return [
            { country: 'Pakistan', percentage: 65 },
            { country: 'United States', percentage: 15 },
            { country: 'United Kingdom', percentage: 8 },
            { country: 'Canada', percentage: 5 },
            { country: 'Other', percentage: 7 }
        ];
    }

    analyzeThreatPatterns(securityEvents) {
        return securityEvents
            .filter(event => event.event_type.includes('attack') || event.event_type.includes('suspicious'))
            .map(event => ({
                type: this.translateEventType(event.event_type),
                frequency: event.count
            }))
            .slice(0, 5);
    }

    translateEventType(eventType) {
        const translations = {
            'suspicious_pattern': 'Suspicious Pattern Detection',
            'sql_injection_attempt': 'SQL Injection Attempts',
            'xss_attempt': 'Cross-Site Scripting Attempts',
            'brute_force': 'Brute Force Attacks',
            'ddos_attempt': 'DDoS Attempts'
        };
        return translations[eventType] || eventType;
    }

    generateSecurityRecommendations(data) {
        const recommendations = [];

        if (data.securityEvents.total > 100) {
            recommendations.push('Consider implementing additional rate limiting measures');
        }

        if (data.toolUsage.byTool.some(tool => tool.success_rate < 95)) {
            recommendations.push('Review and optimize security tool configurations');
        }

        if (data.blockedAttacks > 50) {
            recommendations.push('Enhance firewall rules and IP blocking mechanisms');
        }

        recommendations.push('Conduct regular security awareness training for staff');
        recommendations.push('Implement multi-factor authentication for admin access');
        recommendations.push('Schedule monthly penetration testing assessments');

        return recommendations;
    }

    addReportHeader(doc, title) {
        doc.fontSize(20).text('SpectraOps Ltd.', { align: 'center' });
        doc.fontSize(16).text(title, { align: 'center' });
        doc.fontSize(12).text(`Generated on: ${new Date().toLocaleDateString()}`, { align: 'center' });
        doc.moveDown(2);
    }

    addSection(doc, title, contentCallback) {
        doc.fontSize(14).text(title, { underline: true });
        doc.moveDown(0.5);
        doc.fontSize(10);
        contentCallback();
        doc.moveDown(1);
    }

    async scheduleReports() {
        // Schedule weekly security reports
        setInterval(async () => {
            try {
                await this.generateSecurityReport('7d');
                console.log('📊 Weekly security report generated');
            } catch (error) {
                console.error('Failed to generate weekly security report:', error);
            }
        }, 7 * 24 * 60 * 60 * 1000); // Weekly

        // Schedule monthly business reports
        setInterval(async () => {
            try {
                await this.generateBusinessReport('30d');
                console.log('📈 Monthly business report generated');
            } catch (error) {
                console.error('Failed to generate monthly business report:', error);
            }
        }, 30 * 24 * 60 * 60 * 1000); // Monthly
    }
}

module.exports = new ReportingService();