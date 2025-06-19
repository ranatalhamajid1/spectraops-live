const express = require('express');
const authMiddleware = require('../middleware/auth');
const db = require('../config/database');

const router = express.Router();

// Apply auth middleware to all admin routes
router.use(authMiddleware);

// Dashboard statistics
router.get('/dashboard/stats', async (req, res) => {
    try {
        const timeframe = req.query.timeframe || '30d';
        
        const stats = await Promise.all([
            // Contact submissions
            db.get(`
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'new' THEN 1 ELSE 0 END) as new_count,
                    SUM(CASE WHEN created_at >= datetime('now', '-7d') THEN 1 ELSE 0 END) as week_count
                FROM contact_submissions
                WHERE created_at >= datetime('now', '-${timeframe}')
            `),
            
            // Security tool usage
            db.get(`
                SELECT 
                    COUNT(*) as total_usage,
                    COUNT(DISTINCT ip_address) as unique_users,
                    AVG(processing_time) as avg_processing_time
                FROM security_tool_usage
                WHERE created_at >= datetime('now', '-${timeframe}')
            `),
            
            // Page views
            db.get(`
                SELECT 
                    COUNT(*) as total_views,
                    COUNT(DISTINCT ip_address) as unique_visitors,
                    COUNT(DISTINCT session_id) as sessions
                FROM page_views
                WHERE created_at >= datetime('now', '-${timeframe}')
            `),
            
            // News articles
            db.get(`
                SELECT 
                    COUNT(*) as published_articles,
                    SUM(views) as total_article_views
                FROM news_articles
                WHERE published = 1
            `),
            
            // Security events
            db.get(`
                SELECT 
                    COUNT(*) as total_events,
                    COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_severity,
                    COUNT(CASE WHEN resolved = 0 THEN 1 END) as unresolved
                FROM security_events
                WHERE created_at >= datetime('now', '-${timeframe}')
            `)
        ]);

        res.json({
            success: true,
            data: {
                contacts: stats[0],
                tools: stats[1],
                views: stats[2],
                news: stats[3],
                security: stats[4],
                timeframe
            }
        });

    } catch (error) {
        console.error('Dashboard stats error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch dashboard statistics'
        });
    }
});

// Get contact submissions
router.get('/contacts', async (req, res) => {
    try {
        const { status, limit = 50, offset = 0 } = req.query;
        
        let query = `
            SELECT 
                id, name, email, phone, company, subject, 
                service_interest, status, created_at
            FROM contact_submissions
        `;
        const params = [];

        if (status) {
            query += ` WHERE status = ?`;
            params.push(status);
        }

        query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
        params.push(parseInt(limit), parseInt(offset));

        const contacts = await db.all(query, params);
        
        // Get total count
        let countQuery = 'SELECT COUNT(*) as total FROM contact_submissions';
        if (status) {
            countQuery += ' WHERE status = ?';
        }
        const countResult = await db.get(countQuery, status ? [status] : []);

        res.json({
            success: true,
            data: {
                contacts,
                total: countResult.total,
                limit: parseInt(limit),
                offset: parseInt(offset)
            }
        });

    } catch (error) {
        console.error('Get contacts error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch contacts'
        });
    }
});

// Update contact status
router.put('/contacts/:id/status', async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;

        if (!['new', 'in_progress', 'resolved'].includes(status)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid status'
            });
        }

        await db.run(`
            UPDATE contact_submissions 
            SET status = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        `, [status, id]);

        res.json({
            success: true,
            message: 'Contact status updated successfully'
        });

    } catch (error) {
        console.error('Update contact status error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to update contact status'
        });
    }
});

// Get all news articles (including drafts)
router.get('/news', async (req, res) => {
    try {
        const { published, limit = 20, offset = 0 } = req.query;
        
        let query = `
            SELECT 
                na.id, na.title, na.slug, na.excerpt, na.category, 
                na.published, na.views, na.created_at, na.updated_at,
                u.username as author
            FROM news_articles na
            LEFT JOIN users u ON na.author_id = u.id
        `;
        const params = [];

        if (published !== undefined) {
            query += ` WHERE na.published = ?`;
            params.push(published === 'true' ? 1 : 0);
        }

        query += ` ORDER BY na.created_at DESC LIMIT ? OFFSET ?`;
        params.push(parseInt(limit), parseInt(offset));

        const articles = await db.all(query, params);
        
        // Get total count
        let countQuery = 'SELECT COUNT(*) as total FROM news_articles';
        if (published !== undefined) {
            countQuery += ' WHERE published = ?';
        }
        const countResult = await db.get(countQuery, published !== undefined ? [published === 'true' ? 1 : 0] : []);

        res.json({
            success: true,
            data: {
                articles,
                total: countResult.total,
                limit: parseInt(limit),
                offset: parseInt(offset)
            }
        });

    } catch (error) {
        console.error('Get admin news error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch news articles'
        });
    }
});

// Get security events
router.get('/security/events', async (req, res) => {
    try {
        const { severity, resolved, limit = 100, offset = 0 } = req.query;
        
        let query = `
            SELECT 
                id, ip_address, event_type, details, severity, 
                resolved, created_at
            FROM security_events
        `;
        const params = [];
        const conditions = [];

        if (severity) {
            conditions.push('severity = ?');
            params.push(severity);
        }

        if (resolved !== undefined) {
            conditions.push('resolved = ?');
            params.push(resolved === 'true' ? 1 : 0);
        }

        if (conditions.length > 0) {
            query += ` WHERE ${conditions.join(' AND ')}`;
        }

        query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
        params.push(parseInt(limit), parseInt(offset));

        const events = await db.all(query, params);
        
        // Get total count
        let countQuery = 'SELECT COUNT(*) as total FROM security_events';
        if (conditions.length > 0) {
            countQuery += ` WHERE ${conditions.join(' AND ')}`;
        }
        const countParams = params.slice(0, -2); // Remove limit and offset
        const countResult = await db.get(countQuery, countParams);

        res.json({
            success: true,
            data: {
                events,
                total: countResult.total,
                limit: parseInt(limit),
                offset: parseInt(offset)
            }
        });

    } catch (error) {
        console.error('Get security events error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch security events'
        });
    }
});

// Mark security event as resolved
router.put('/security/events/:id/resolve', async (req, res) => {
    try {
        const { id } = req.params;
        
        await db.run(`
            UPDATE security_events 
            SET resolved = 1, updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        `, [id]);

        res.json({
            success: true,
            message: 'Security event marked as resolved'
        });

    } catch (error) {
        console.error('Resolve security event error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to resolve security event'
        });
    }
});

// Get system settings
router.get('/settings', async (req, res) => {
    try {
        const settings = await db.all('SELECT key, value, description FROM settings ORDER BY key');
        
        res.json({
            success: true,
            data: settings
        });

    } catch (error) {
        console.error('Get settings error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch settings'
        });
    }
});

// Update system setting
router.put('/settings/:key', async (req, res) => {
    try {
        const { key } = req.params;
        const { value } = req.body;
        
        await db.run(`
            INSERT OR REPLACE INTO settings (key, value, updated_at) 
            VALUES (?, ?, CURRENT_TIMESTAMP)
        `, [key, value]);

        res.json({
            success: true,
            message: 'Setting updated successfully'
        });

    } catch (error) {
        console.error('Update setting error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to update setting'
        });
    }
});

module.exports = router;