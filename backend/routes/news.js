const express = require('express');
const { body, validationResult } = require('express-validator');
const db = require('../config/database');
const authMiddleware = require('../middleware/auth');

const router = express.Router();

// Get published news articles
router.get('/', async (req, res) => {
    try {
        const { category, limit = 10, offset = 0 } = req.query;
        
        let query = `
            SELECT 
                id, title, slug, excerpt, category, featured_image,
                published_at, views,
                (SELECT username FROM users WHERE id = author_id) as author
            FROM news_articles 
            WHERE published = 1
        `;
        const params = [];

        if (category) {
            query += ` AND category = ?`;
            params.push(category);
        }

        query += ` ORDER BY published_at DESC LIMIT ? OFFSET ?`;
        params.push(parseInt(limit), parseInt(offset));

        const articles = await db.all(query, params);
        
        // Get total count
        let countQuery = 'SELECT COUNT(*) as total FROM news_articles WHERE published = 1';
        if (category) {
            countQuery += ' AND category = ?';
        }
        const countResult = await db.get(countQuery, category ? [category] : []);

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
        console.error('Get news error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch news articles'
        });
    }
});

// Get single article by slug
router.get('/:slug', async (req, res) => {
    try {
        const { slug } = req.params;
        
        const article = await db.get(`
            SELECT 
                na.*, 
                u.username as author
            FROM news_articles na
            LEFT JOIN users u ON na.author_id = u.id
            WHERE na.slug = ? AND na.published = 1
        `, [slug]);

        if (!article) {
            return res.status(404).json({
                success: false,
                error: 'Article not found'
            });
        }

        // Increment view count
        await db.run(`
            UPDATE news_articles 
            SET views = views + 1 
            WHERE id = ?
        `, [article.id]);

        res.json({
            success: true,
            data: article
        });

    } catch (error) {
        console.error('Get article error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch article'
        });
    }
});

// Create new article (admin only)
router.post('/', authMiddleware, [
    body('title').trim().isLength({ min: 5, max: 200 }),
    body('content').trim().isLength({ min: 50 }),
    body('excerpt').optional().trim().isLength({ max: 500 }),
    body('category').optional().trim().isLength({ max: 50 }),
    body('tags').optional().trim()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                error: 'Invalid input data',
                details: errors.array()
            });
        }

        const { title, content, excerpt, category, tags, published = false } = req.body;
        
        // Generate slug from title
        const slug = title.toLowerCase()
            .replace(/[^a-z0-9]+/g, '-')
            .replace(/^-|-$/g, '');

        // Check if slug already exists
        const existingSlug = await db.get('SELECT id FROM news_articles WHERE slug = ?', [slug]);
        if (existingSlug) {
            return res.status(400).json({
                success: false,
                error: 'Article with this title already exists'
            });
        }

        const result = await db.run(`
            INSERT INTO news_articles (
                title, slug, content, excerpt, category, tags, 
                author_id, published, published_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            title, slug, content, excerpt, category, tags,
            req.user.id, published ? 1 : 0, 
            published ? new Date().toISOString() : null
        ]);

        res.status(201).json({
            success: true,
            message: 'Article created successfully',
            data: {
                id: result.id,
                slug
            }
        });

    } catch (error) {
        console.error('Create article error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to create article'
        });
    }
});

// Update article (admin only)
router.put('/:id', authMiddleware, [
    body('title').optional().trim().isLength({ min: 5, max: 200 }),
    body('content').optional().trim().isLength({ min: 50 }),
    body('excerpt').optional().trim().isLength({ max: 500 }),
    body('category').optional().trim().isLength({ max: 50 }),
    body('tags').optional().trim()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                error: 'Invalid input data',
                details: errors.array()
            });
        }

        const { id } = req.params;
        const updateFields = req.body;
        
        // Remove undefined fields
        Object.keys(updateFields).forEach(key => {
            if (updateFields[key] === undefined) {
                delete updateFields[key];
            }
        });

        if (Object.keys(updateFields).length === 0) {
            return res.status(400).json({
                success: false,
                error: 'No fields to update'
            });
        }

        // If publishing, set published_at
        if (updateFields.published && updateFields.published !== '0') {
            updateFields.published_at = new Date().toISOString();
        }

        updateFields.updated_at = new Date().toISOString();

        // Build dynamic update query
        const setClause = Object.keys(updateFields).map(key => `${key} = ?`).join(', ');
        const values = Object.values(updateFields);
        values.push(id);

        await db.run(`
            UPDATE news_articles 
            SET ${setClause}
            WHERE id = ?
        `, values);

        res.json({
            success: true,
            message: 'Article updated successfully'
        });

    } catch (error) {
        console.error('Update article error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to update article'
        });
    }
});

// Delete article (admin only)
router.delete('/:id', authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        
        const result = await db.run('DELETE FROM news_articles WHERE id = ?', [id]);
        
        if (result.changes === 0) {
            return res.status(404).json({
                success: false,
                error: 'Article not found'
            });
        }

        res.json({
            success: true,
            message: 'Article deleted successfully'
        });

    } catch (error) {
        console.error('Delete article error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to delete article'
        });
    }
});

// Get categories
router.get('/meta/categories', async (req, res) => {
    try {
        const categories = await db.all(`
            SELECT 
                category,
                COUNT(*) as article_count
            FROM news_articles 
            WHERE published = 1 AND category IS NOT NULL
            GROUP BY category
            ORDER BY article_count DESC
        `);

        res.json({
            success: true,
            data: categories
        });

    } catch (error) {
        console.error('Get categories error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch categories'
        });
    }
});

module.exports = router;