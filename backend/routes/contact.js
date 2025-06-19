const express = require('express');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const xss = require('xss');
const db = require('../config/database');
const router = express.Router();

// Rate limiting for contact form
const contactLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // 5 submissions per hour
    message: {
        success: false,
        error: 'Too many contact form submissions. Please try again later.'
    }
});

// Validation rules
const contactValidation = [
    body('name')
        .trim()
        .isLength({ min: 2, max: 100 })
        .escape()
        .withMessage('Name must be between 2 and 100 characters'),
    
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Please provide a valid email address'),
    
    body('phone')
        .optional()
        .isMobilePhone()
        .withMessage('Please provide a valid phone number'),
    
    body('company')
        .optional()
        .trim()
        .isLength({ max: 200 })
        .escape(),
    
    body('subject')
        .trim()
        .isLength({ min: 5, max: 200 })
        .escape()
        .withMessage('Subject must be between 5 and 200 characters'),
    
    body('message')
        .trim()
        .isLength({ min: 10, max: 2000 })
        .escape()
        .withMessage('Message must be between 10 and 2000 characters'),
    
    body('service')
        .optional()
        .isIn(['penetration-testing', 'soc-consultation', 'web-development', 'security-training', 'red-teaming', 'consulting', 'general-inquiry'])
        .withMessage('Invalid service type'),
    
    body('captchaAnswer')
        .isInt({ min: 0, max: 20 })
        .withMessage('Please solve the captcha correctly')
];

// Submit contact form
router.post('/contact', contactLimiter, contactValidation, async (req, res) => {
    try {
        // Check validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                error: 'Validation failed',
                details: errors.array()
            });
        }

        const {
            name, email, phone, company, subject, message, 
            service, captchaAnswer
        } = req.body;

        // Simple captcha validation (you can make this more sophisticated)
        const expectedAnswer = req.session?.captchaAnswer || 8; // Default for demo
        if (parseInt(captchaAnswer) !== expectedAnswer) {
            return res.status(400).json({
                success: false,
                error: 'Incorrect captcha answer. Please try again.'
            });
        }

        // Sanitize inputs
        const sanitizedData = {
            name: xss(name),
            email: email.toLowerCase(),
            phone: phone ? xss(phone) : null,
            company: company ? xss(company) : null,
            subject: xss(subject),
            message: xss(message),
            serviceType: service || 'general-inquiry',
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            referrer: req.get('Referrer') || null,
            source: 'website'
        };

        // Save to database
        const contactId = await db.createContact(sanitizedData);

        // Log the submission
        console.log(`📧 New contact submission #${contactId}:`, {
            name: sanitizedData.name,
            email: sanitizedData.email,
            subject: sanitizedData.subject,
            service: sanitizedData.serviceType,
            ip: sanitizedData.ipAddress,
            timestamp: new Date().toISOString()
        });

        // Send auto-response email (implement this based on your email setup)
        await sendAutoResponse(sanitizedData, contactId);

        // Send notification to team (implement this based on your notification setup)
        await sendTeamNotification(sanitizedData, contactId);

        res.json({
            success: true,
            message: 'Thank you for your message! We\'ll get back to you soon.',
            data: {
                submissionId: contactId,
                estimatedResponse: '24-48 hours'
            }
        });

    } catch (error) {
        console.error('Contact form submission error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to submit contact form. Please try again later.'
        });
    }
});

// Get captcha (simple math captcha)
router.get('/captcha', (req, res) => {
    const num1 = Math.floor(Math.random() * 10) + 1;
    const num2 = Math.floor(Math.random() * 10) + 1;
    const answer = num1 + num2;
    
    // Store answer in session (in production, use more secure method)
    req.session = req.session || {};
    req.session.captchaAnswer = answer;
    
    res.json({
        success: true,
        question: `${num1} + ${num2} = ?`,
        sessionId: Date.now() // Simple session tracking
    });
});

// Admin routes (require authentication)
router.get('/admin/contacts', authenticateAdmin, async (req, res) => {
    try {
        const {
            status, service, assignedTo, dateFrom, dateTo, 
            limit = 50, offset = 0, page = 1
        } = req.query;

        const filters = {
            status,
            service,
            assignedTo,
            dateFrom,
            dateTo,
            limit: parseInt(limit),
            offset: (parseInt(page) - 1) * parseInt(limit)
        };

        const contacts = await db.getContacts(filters);
        const stats = await db.getContactStats();

        res.json({
            success: true,
            data: {
                contacts,
                stats,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total: stats.total
                }
            }
        });

    } catch (error) {
        console.error('Error fetching contacts:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch contacts'
        });
    }
});

// Update contact status (admin only)
router.put('/admin/contacts/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { status, assignedTo, responseMessage } = req.body;

        await db.updateContactStatus(id, status, assignedTo, responseMessage);

        res.json({
            success: true,
            message: 'Contact updated successfully'
        });

    } catch (error) {
        console.error('Error updating contact:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to update contact'
        });
    }
});

// Get contact services
router.get('/services', async (req, res) => {
    try {
        const services = await db.all(`
            SELECT service_code, service_name, description, estimated_response_time
            FROM contact_services 
            WHERE is_active = 1
            ORDER BY priority_level DESC, service_name
        `);

        res.json({
            success: true,
            data: services
        });

    } catch (error) {
        console.error('Error fetching services:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch services'
        });
    }
});

// Middleware for admin authentication
async function authenticateAdmin(req, res, next) {
    try {
        const token = req.headers.authorization?.replace('Bearer ', '');
        
        if (!token) {
            return res.status(401).json({
                success: false,
                error: 'Authentication required'
            });
        }

        // Verify JWT token (implement your JWT verification here)
        // For now, we'll use a simple check
        if (token !== 'admin-demo-token') {
            return res.status(401).json({
                success: false,
                error: 'Invalid authentication token'
            });
        }

        next();
    } catch (error) {
        res.status(401).json({
            success: false,
            error: 'Authentication failed'
        });
    }
}

// Helper functions
async function sendAutoResponse(contactData, contactId) {
    try {
        // Log email notification (implement actual email sending based on your SMTP setup)
        await db.run(`
            INSERT INTO email_notifications (recipient_email, subject, email_type, related_id, status)
            VALUES (?, ?, ?, ?, ?)
        `, [
            contactData.email,
            `Thank you for contacting SpectraOps - Ref: #${contactId}`,
            'auto_response',
            contactId,
            'pending'
        ]);

        console.log(`📧 Auto-response queued for ${contactData.email}`);
    } catch (error) {
        console.error('Error sending auto-response:', error);
    }
}

async function sendTeamNotification(contactData, contactId) {
    try {
        // Log team notification
        await db.run(`
            INSERT INTO email_notifications (recipient_email, subject, email_type, related_id, status)
            VALUES (?, ?, ?, ?, ?)
        `, [
            'ranatalhamajid1@gmail.com',
            `New Contact Submission #${contactId} - ${contactData.subject}`,
            'team_notification',
            contactId,
            'pending'
        ]);

        console.log(`🔔 Team notification queued for contact #${contactId}`);
    } catch (error) {
        console.error('Error sending team notification:', error);
    }
}

module.exports = router;