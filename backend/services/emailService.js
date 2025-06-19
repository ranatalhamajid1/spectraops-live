const nodemailer = require('nodemailer');
const db = require('../config/database');
const fs = require('fs').promises;
const path = require('path');

class EmailService {
    constructor() {
        this.transporter = null;
        this.templates = new Map();
        this.init();
    }

    async init() {
        await this.loadEmailTemplates();
        await this.setupTransporter();
    }

    async setupTransporter() {
        const smtpConfig = {
            host: process.env.SMTP_HOST || 'smtp.gmail.com',
            port: parseInt(process.env.SMTP_PORT || '587'),
            secure: process.env.SMTP_SECURE === 'true',
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS
            },
            tls: {
                rejectUnauthorized: false
            }
        };

        this.transporter = nodemailer.createTransporter(smtpConfig);
        
        try {
            await this.transporter.verify();
            console.log('✅ Email service initialized successfully');
        } catch (error) {
            console.error('❌ Email service initialization failed:', error);
        }
    }

    async loadEmailTemplates() {
        const templatesDir = path.join(__dirname, '../templates/email');
        try {
            const files = await fs.readdir(templatesDir);
            for (const file of files) {
                if (file.endsWith('.html')) {
                    const templateName = file.replace('.html', '');
                    const content = await fs.readFile(path.join(templatesDir, file), 'utf8');
                    this.templates.set(templateName, content);
                }
            }
        } catch (error) {
            console.error('Failed to load email templates:', error);
        }
    }

    async sendEmail(to, subject, templateName, data = {}) {
        if (!this.transporter) {
            throw new Error('Email service not configured');
        }

        const template = this.templates.get(templateName) || this.getDefaultTemplate();
        const html = this.processTemplate(template, data);

        const mailOptions = {
            from: `"SpectraOps Ltd." <${process.env.SMTP_USER}>`,
            to,
            subject,
            html,
            text: this.htmlToText(html)
        };

        try {
            const result = await this.transporter.sendMail(mailOptions);
            
            // Log email activity
            await db.run(`
                INSERT INTO email_logs (recipient, subject, template_name, status, message_id)
                VALUES (?, ?, ?, ?, ?)
            `, [to, subject, templateName, 'sent', result.messageId]);

            return result;
        } catch (error) {
            await db.run(`
                INSERT INTO email_logs (recipient, subject, template_name, status, error_message)
                VALUES (?, ?, ?, ?, ?)
            `, [to, subject, templateName, 'failed', error.message]);
            
            throw error;
        }
    }

    processTemplate(template, data) {
        let processed = template;
        for (const [key, value] of Object.entries(data)) {
            const regex = new RegExp(`{{${key}}}`, 'g');
            processed = processed.replace(regex, value);
        }
        return processed;
    }

    htmlToText(html) {
        return html.replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim();
    }

    getDefaultTemplate() {
        return `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>{{subject}}</title>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background: #6366f1; color: white; padding: 20px; text-align: center; }
                    .content { padding: 20px; background: #f8f9fa; }
                    .footer { background: #e5e7eb; padding: 15px; text-align: center; font-size: 12px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h2>🔒 SpectraOps Ltd.</h2>
                    </div>
                    <div class="content">
                        {{content}}
                    </div>
                    <div class="footer">
                        <p>This is an automated message from SpectraOps Ltd.</p>
                        <p>Visit us at <a href="https://spectraops.com">spectraops.com</a></p>
                    </div>
                </div>
            </body>
            </html>
        `;
    }
}

module.exports = new EmailService();