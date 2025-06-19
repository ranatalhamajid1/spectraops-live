const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const db = require('../config/database');
const emailService = require('../services/emailService');
const crypto = require('crypto');

const router = express.Router();

// Login
router.post('/login', [
    body('username').trim().isLength({ min: 3, max: 50 }),
    body('password').isLength({ min: 6, max: 200 })
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

        const { username, password } = req.body;
        
        // Find user
        const user = await db.get(`
            SELECT id, username, email, password_hash, role 
            FROM users 
            WHERE username = ? OR email = ?
        `, [username, username]);

        if (!user) {
            // Log failed login attempt
            await db.run(`
                INSERT INTO security_events (ip_address, event_type, details)
                VALUES (?, ?, ?)
            `, [req.ip, 'failed_login', `Failed login attempt for username: ${username}`]);

            return res.status(401).json({
                success: false,
                error: 'Invalid credentials'
            });
        }

        // Verify password
        const isValidPassword = await bcrypt.compare(password, user.password_hash);
        if (!isValidPassword) {
            // Log failed login attempt
            await db.run(`
                INSERT INTO security_events (ip_address, event_type, details)
                VALUES (?, ?, ?)
            `, [req.ip, 'failed_login', `Failed login attempt for user ID: ${user.id}`]);

            return res.status(401).json({
                success: false,
                error: 'Invalid credentials'
            });
        }

        // Generate JWT token
        const token = jwt.sign(
            { 
                id: user.id, 
                username: user.username, 
                role: user.role 
            },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
        );

        // Log successful login
        await db.run(`
            INSERT INTO security_events (ip_address, event_type, details, severity)
            VALUES (?, ?, ?, ?)
        `, [req.ip, 'successful_login', `User ${user.username} logged in`, 'low']);

        res.json({
            success: true,
            message: 'Login successful',
            data: {
                token,
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role
                }
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            error: 'Login failed'
        });
    }
});

// Register (admin only or disabled in production)
router.post('/register', [
    body('username').trim().isLength({ min: 3, max: 50 }).isAlphanumeric(),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8, max: 200 })
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
        .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character')
], async (req, res) => {
    try {
        // Disable registration in production unless explicitly enabled
        if (process.env.NODE_ENV === 'production' && process.env.ALLOW_REGISTRATION !== 'true') {
            return res.status(403).json({
                success: false,
                error: 'Registration is disabled'
            });
        }

        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                error: 'Invalid input data',
                details: errors.array()
            });
        }

        const { username, email, password } = req.body;
        
        // Check if user already exists
        const existingUser = await db.get(`
            SELECT id FROM users 
            WHERE username = ? OR email = ?
        `, [username, email]);

        if (existingUser) {
            return res.status(400).json({
                success: false,
                error: 'Username or email already exists'
            });
        }

        // Hash password
        const saltRounds = 12;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // Create user
        const result = await db.run(`
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)
        `, [username, email, passwordHash]);

        // Log user registration
        await db.run(`
            INSERT INTO security_events (ip_address, event_type, details, severity)
            VALUES (?, ?, ?, ?)
        `, [req.ip, 'user_registration', `New user registered: ${username}`, 'low']);

        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            data: {
                id: result.id,
                username,
                email
            }
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            error: 'Registration failed'
        });
    }
});

// Forgot password
router.post('/forgot-password', [
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
        
        // Find user
        const user = await db.get('SELECT id, username, email FROM users WHERE email = ?', [email]);
        
        // Always return success to prevent email enumeration
        if (!user) {
            return res.json({
                success: true,
                message: 'If an account with that email exists, a password reset link has been sent.'
            });
        }

        // Generate reset token
        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
        const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

        // Store reset token
        await db.run(`
            INSERT OR REPLACE INTO password_resets (user_id, token_hash, expires_at)
            VALUES (?, ?, ?)
        `, [user.id, resetTokenHash, expiresAt.toISOString()]);

        // Send reset email
        try {
            await emailService.sendPasswordResetEmail(email, resetToken);
        } catch (emailError) {
            console.error('Failed to send password reset email:', emailError);
        }

        // Log password reset request
        await db.run(`
            INSERT INTO security_events (ip_address, event_type, details, severity)
            VALUES (?, ?, ?, ?)
        `, [req.ip, 'password_reset_request', `Password reset requested for user: ${user.username}`, 'medium']);

        res.json({
            success: true,
            message: 'If an account with that email exists, a password reset link has been sent.'
        });

    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to process password reset request'
        });
    }
});

// Reset password
router.post('/reset-password', [
    body('token').isLength({ min: 64, max: 64 }).isHexadecimal(),
    body('password').isLength({ min: 8, max: 200 })
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
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

        const { token, password } = req.body;
        
        // Hash the token to compare with database
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        
        // Find valid reset token
        const resetRequest = await db.get(`
            SELECT pr.user_id, u.username 
            FROM password_resets pr
            JOIN users u ON pr.user_id = u.id
            WHERE pr.token_hash = ? AND pr.expires_at > datetime('now')
        `, [tokenHash]);

        if (!resetRequest) {
            return res.status(400).json({
                success: false,
                error: 'Invalid or expired reset token'
            });
        }

        // Hash new password
        const saltRounds = 12;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // Update password and remove reset token
        await db.transaction(async () => {
            await db.run(`
                UPDATE users 
                SET password_hash = ?, updated_at = CURRENT_TIMESTAMP 
                WHERE id = ?
            `, [passwordHash, resetRequest.user_id]);

            await db.run(`
                DELETE FROM password_resets 
                WHERE user_id = ?
            `, [resetRequest.user_id]);
        });

        // Log password reset
        await db.run(`
            INSERT INTO security_events (ip_address, event_type, details, severity)
            VALUES (?, ?, ?, ?)
        `, [req.ip, 'password_reset', `Password reset completed for user: ${resetRequest.username}`, 'medium']);

        res.json({
            success: true,
            message: 'Password reset successfully'
        });

    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to reset password'
        });
    }
});

// Verify token
router.post('/verify', async (req, res) => {
    try {
        const token = req.headers.authorization?.replace('Bearer ', '');
        
        if (!token) {
            return res.status(401).json({
                success: false,
                error: 'No token provided'
            });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Check if user still exists
        const user = await db.get(`
            SELECT id, username, email, role 
            FROM users 
            WHERE id = ?
        `, [decoded.id]);

        if (!user) {
            return res.status(401).json({
                success: false,
                error: 'User not found'
            });
        }

        res.json({
            success: true,
            data: {
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role
                }
            }
        });

    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                success: false,
                error: 'Invalid token'
            });
        }
        
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                error: 'Token expired'
            });
        }

        console.error('Token verification error:', error);
        res.status(500).json({
            success: false,
            error: 'Token verification failed'
        });
    }
});

module.exports = router;