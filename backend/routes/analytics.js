const express = require('express');
const db = require('../config/database');
const authMiddleware = require('../middleware/auth');

const router = express.Router();

// Real-time analytics endpoint
router.get('/realtime', authMiddleware, async (req, res) => {
    try {
        const realTimeData = await Promise.all([
            // Active sessions (last 5 minutes)
            db.get(`
                SELECT COUNT(DISTINCT session_id) as active_sessions
                FROM page_views 
                WHERE created_at >= datetime('now', '-5 minutes')
            `),
            
            // Current page views (last minute)
            db.get(`
                SELECT COUNT(*) as current_views
                FROM page_views 
                WHERE created_at >= datetime('now', '-1 minute')
            `),
            
            // Tool usage (last hour)
            db.get(`
                SELECT COUNT(*) as recent_tool_usage
                FROM security_tool_usage 
                WHERE created_at >= datetime('now', '-1 hour')
            `),
            
            // Contact forms (today)
            db.get(`
                SELECT COUNT(*) as todays_contacts
                FROM contact_submissions 
                WHERE DATE(created_at) = DATE('now')
            `)
        ]);

        res.json({
            success: true,
            data: {
                activeSessions: realTimeData[0].active_sessions || 0,
                currentViews: realTimeData[1].current_views || 0,
                recentToolUsage: realTimeData[2].recent_tool_usage || 0,
                todaysContacts: realTimeData[3].todays_contacts || 0,
                timestamp: new Date().toISOString()
            }
        });

    } catch (error) {
        console.error('Real-time analytics error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch real-time analytics'
        });
    }
});

// Advanced analytics with predictive insights
router.get('/insights', authMiddleware, async (req, res) => {
    try {
        const timeframe = req.query.timeframe || '30d';
        
        // Traffic trends
        const trafficTrends = await db.all(`
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as views,
                COUNT(DISTINCT ip_address) as unique_visitors,
                AVG(
                    CASE 
                        WHEN session_id IN (
                            SELECT session_id 
                            FROM page_views p2 
                            WHERE p2.session_id = page_views.session_id 
                            GROUP BY session_id 
                            HAVING COUNT(*) > 1
                        ) THEN 1 ELSE 0 
                    END
                ) * 100 as bounce_rate
            FROM page_views 
            WHERE created_at >= datetime('now', '-${timeframe}')
            GROUP BY DATE(created_at)
            ORDER BY date DESC
        `);

        // Security tool performance
        const toolPerformance = await db.all(`
            SELECT 
                tool_name,
                COUNT(*) as total_usage,
                AVG(processing_time) as avg_response_time,
                (SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) * 100.0 / COUNT(*)) as success_rate,
                COUNT(DISTINCT DATE(created_at)) as active_days
            FROM security_tool_usage
            WHERE created_at >= datetime('now', '-${timeframe}')
            GROUP BY tool_name
            ORDER BY total_usage DESC
        `);

        // User behavior analysis
        const userBehavior = await db.all(`
            SELECT 
                page_path,
                COUNT(*) as views,
                AVG(
                    julianday(
                        COALESCE(
                            (SELECT MIN(created_at) FROM page_views p2 
                             WHERE p2.session_id = page_views.session_id 
                             AND p2.created_at > page_views.created_at),
                            datetime('now')
                        )
                    ) - julianday(created_at)
                ) * 86400 as avg_time_on_page
            FROM page_views
            WHERE created_at >= datetime('now', '-${timeframe}')
            GROUP BY page_path
            ORDER BY views DESC
        `);

        // Conversion funnel
        const conversionFunnel = await db.get(`
            SELECT 
                COUNT(DISTINCT pv.session_id) as total_visitors,
                COUNT(DISTINCT CASE WHEN pv.page_path LIKE '%contact%' THEN pv.session_id END) as visited_contact,
                COUNT(DISTINCT cs.session_id) as submitted_contact,
                (COUNT(DISTINCT cs.session_id) * 100.0 / COUNT(DISTINCT pv.session_id)) as conversion_rate
            FROM page_views pv
            LEFT JOIN contact_submissions cs ON pv.session_id = cs.session_id
            WHERE pv.created_at >= datetime('now', '-${timeframe}')
        `);

        res.json({
            success: true,
            data: {
                trafficTrends,
                toolPerformance,
                userBehavior,
                conversionFunnel,
                generatedAt: new Date().toISOString()
            }
        });

    } catch (error) {
        console.error('Advanced analytics error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch analytics insights'
        });
    }
});

// Export analytics data
router.get('/export', authMiddleware, async (req, res) => {
    try {
        const format = req.query.format || 'json';
        const timeframe = req.query.timeframe || '30d';

        const data = await Promise.all([
            db.all(`SELECT * FROM page_views WHERE created_at >= datetime('now', '-${timeframe}')`),
            db.all(`SELECT * FROM contact_submissions WHERE created_at >= datetime('now', '-${timeframe}')`),
            db.all(`SELECT * FROM security_tool_usage WHERE created_at >= datetime('now', '-${timeframe}')`)
        ]);

        const exportData = {
            pageViews: data[0],
            contactSubmissions: data[1],
            securityToolUsage: data[2],
            exportedAt: new Date().toISOString(),
            timeframe
        };

        if (format === 'csv') {
            // Convert to CSV format
            const csv = this.convertToCSV(exportData);
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename=analytics-${timeframe}.csv`);
            res.send(csv);
        } else {
            res.json({
                success: true,
                data: exportData
            });
        }

    } catch (error) {
        console.error('Analytics export error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to export analytics data'
        });
    }
});

module.exports = router;