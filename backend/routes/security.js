const express = require('express');
const { body, validationResult } = require('express-validator');
const securityService = require('../services/securityService');
const db = require('../config/database');
const crypto = require('crypto');

const router = express.Router();

// Email breach checker
router.post('/check-email', [
    body('email').isEmail().normalizeEmail()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                error: 'Invalid email address'
            });
        }

        const { email } = req.body;
        const startTime = Date.now();

        try {
            const result = await securityService.checkEmailBreach(email);
            
            // Log usage
            await db.run(`
                INSERT INTO security_tool_usage (
                    tool_name, input_hash, success, processing_time, ip_address, user_agent
                ) VALUES (?, ?, ?, ?, ?, ?)
            `, [
                'email_breach_check',
                crypto.createHash('sha256').update(email).digest('hex'),
                1,
                Date.now() - startTime,
                req.ip,
                req.get('User-Agent')
            ]);

            res.json({
                success: true,
                data: result
            });

        } catch (error) {
            // Log failed usage
            await db.run(`
                INSERT INTO security_tool_usage (
                    tool_name, input_hash, success, processing_time, error_message, ip_address, user_agent
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            `, [
                'email_breach_check',
                crypto.createHash('sha256').update(email).digest('hex'),
                0,
                Date.now() - startTime,
                error.message,
                req.ip,
                req.get('User-Agent')
            ]);

            throw error;
        }

    } catch (error) {
        console.error('Email breach check error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to check email breach status'
        });
    }
});

// URL scanner
router.post('/scan-url', [
    body('url').isURL()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                error: 'Invalid URL'
            });
        }

        const { url } = req.body;
        const startTime = Date.now();

        try {
            const result = await securityService.scanUrl(url);
            
            // Log usage
            await db.run(`
                INSERT INTO security_tool_usage (
                    tool_name, input_hash, success, processing_time, ip_address, user_agent
                ) VALUES (?, ?, ?, ?, ?, ?)
            `, [
                'url_scan',
                crypto.createHash('sha256').update(url).digest('hex'),
                1,
                Date.now() - startTime,
                req.ip,
                req.get('User-Agent')
            ]);

            res.json({
                success: true,
                data: result
            });

        } catch (error) {
            // Log failed usage
            await db.run(`
                INSERT INTO security_tool_usage (
                    tool_name, input_hash, success, processing_time, error_message, ip_address, user_agent
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            `, [
                'url_scan',
                crypto.createHash('sha256').update(url).digest('hex'),
                0,
                Date.now() - startTime,
                error.message,
                req.ip,
                req.get('User-Agent')
            ]);

            throw error;
        }

    } catch (error) {
        console.error('URL scan error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to scan URL'
        });
    }
});

// Password analyzer
router.post('/analyze-password', [
    body('password').isLength({ min: 1, max: 200 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                error: 'Invalid password'
            });
        }

        const { password } = req.body;
        const startTime = Date.now();

        try {
            const result = securityService.analyzePassword(password);
            
            // Log usage (without storing actual password)
            await db.run(`
                INSERT INTO security_tool_usage (
                    tool_name, input_hash, success, processing_time, ip_address, user_agent
                ) VALUES (?, ?, ?, ?, ?, ?)
            `, [
                'password_analysis',
                crypto.createHash('sha256').update('password_check').digest('hex'), // Generic hash
                1,
                Date.now() - startTime,
                req.ip,
                req.get('User-Agent')
            ]);

            res.json({
                success: true,
                data: result
            });

        } catch (error) {
            // Log failed usage
            await db.run(`
                INSERT INTO security_tool_usage (
                    tool_name, input_hash, success, processing_time, error_message, ip_address, user_agent
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            `, [
                'password_analysis',
                crypto.createHash('sha256').update('password_check').digest('hex'),
                0,
                Date.now() - startTime,
                error.message,
                req.ip,
                req.get('User-Agent')
            ]);

            throw error;
        }

    } catch (error) {
        console.error('Password analysis error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to analyze password'
        });
    }
});

// Get security tool statistics
router.get('/stats', async (req, res) => {
    try {
        const timeframe = req.query.timeframe || '30d';
        
        const stats = await db.all(`
            SELECT 
                tool_name,
                COUNT(*) as total_usage,
                SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful_requests,
                AVG(processing_time) as avg_processing_time,
                COUNT(DISTINCT ip_address) as unique_users
            FROM security_tool_usage
            WHERE created_at >= datetime('now', '-${timeframe}')
            GROUP BY tool_name
            ORDER BY total_usage DESC
        `);

        res.json({
            success: true,
            data: stats
        });

    } catch (error) {
        console.error('Security stats error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch security statistics'
        });
    }
});

module.exports = router;