const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');

class Database {
    constructor() {
        this.dbPath = process.env.DATABASE_PATH || path.join(__dirname, '../data/spectraops.db');
        this.db = null;
    }

    async initialize() {
        try {
            const dataDir = path.dirname(this.dbPath);
            if (!fs.existsSync(dataDir)) {
                fs.mkdirSync(dataDir, { recursive: true });
            }

            this.db = new sqlite3.Database(this.dbPath);
            await this.createTables();
            await this.seedDefaultData();
            console.log('✅ Database initialized successfully');
        } catch (error) {
            console.error('❌ Database initialization error:', error);
            throw error;
        }
    }

    async createTables() {
        const tables = [
            // Contact submissions table
            `CREATE TABLE IF NOT EXISTS contact_submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                phone TEXT,
                company TEXT,
                subject TEXT NOT NULL,
                message TEXT NOT NULL,
                service_type TEXT,
                priority TEXT DEFAULT 'medium',
                status TEXT DEFAULT 'new',
                ip_address TEXT,
                user_agent TEXT,
                referrer TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                responded_at DATETIME,
                assigned_to TEXT,
                response_message TEXT,
                follow_up_date DATETIME,
                source TEXT DEFAULT 'website'
            )`,

            // Contact responses table
            `CREATE TABLE IF NOT EXISTS contact_responses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contact_id INTEGER NOT NULL,
                responder_name TEXT NOT NULL,
                response_text TEXT NOT NULL,
                response_type TEXT DEFAULT 'email',
                sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                delivery_status TEXT DEFAULT 'pending',
                FOREIGN KEY (contact_id) REFERENCES contact_submissions (id)
            )`,

            // Contact categories/services table
            `CREATE TABLE IF NOT EXISTS contact_services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_code TEXT UNIQUE NOT NULL,
                service_name TEXT NOT NULL,
                description TEXT,
                priority_level INTEGER DEFAULT 3,
                auto_assign_to TEXT,
                estimated_response_time TEXT DEFAULT '24 hours',
                is_active BOOLEAN DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`,

            // Admin users table
            `CREATE TABLE IF NOT EXISTS admin_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                role TEXT DEFAULT 'admin',
                is_active BOOLEAN DEFAULT 1,
                last_login DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`,

            // Security tool usage table
            `CREATE TABLE IF NOT EXISTS security_tool_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tool_name TEXT NOT NULL,
                input_data_hash TEXT NOT NULL,
                result_summary TEXT,
                ip_address TEXT,
                user_agent TEXT,
                processing_time_ms INTEGER,
                success BOOLEAN NOT NULL,
                error_message TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`,

            // Website analytics table
            `CREATE TABLE IF NOT EXISTS website_analytics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                page_url TEXT NOT NULL,
                visitor_ip TEXT,
                user_agent TEXT,
                referrer TEXT,
                session_id TEXT,
                visit_duration INTEGER,
                actions_taken TEXT,
                device_type TEXT,
                browser_name TEXT,
                country TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`,

            // Email notifications log
            `CREATE TABLE IF NOT EXISTS email_notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient_email TEXT NOT NULL,
                subject TEXT NOT NULL,
                body TEXT,
                email_type TEXT NOT NULL,
                related_id INTEGER,
                status TEXT DEFAULT 'pending',
                sent_at DATETIME,
                delivery_status TEXT,
                error_message TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`
        ];

        for (const table of tables) {
            await this.run(table);
        }

        // Create indexes for better performance
        const indexes = [
            'CREATE INDEX IF NOT EXISTS idx_contact_email ON contact_submissions(email)',
            'CREATE INDEX IF NOT EXISTS idx_contact_status ON contact_submissions(status)',
            'CREATE INDEX IF NOT EXISTS idx_contact_created ON contact_submissions(created_at)',
            'CREATE INDEX IF NOT EXISTS idx_tool_usage_created ON security_tool_usage(created_at)',
            'CREATE INDEX IF NOT EXISTS idx_analytics_page ON website_analytics(page_url)'
        ];

        for (const index of indexes) {
            await this.run(index);
        }
    }

    async seedDefaultData() {
        // Check if services already exist
        const existingServices = await this.get('SELECT COUNT(*) as count FROM contact_services');
        
        if (existingServices.count === 0) {
            const services = [
                {
                    code: 'penetration-testing',
                    name: 'Penetration Testing',
                    description: 'Comprehensive security assessments and vulnerability analysis',
                    priority: 4,
                    assignTo: 'Jamshed Fareed',
                    responseTime: '24 hours'
                },
                {
                    code: 'soc-consultation',
                    name: 'SOC Consultation',
                    description: '24/7 security operations center setup and management',
                    priority: 5,
                    assignTo: 'Jamshed Fareed',
                    responseTime: '12 hours'
                },
                {
                    code: 'web-development',
                    name: 'Web Development',
                    description: 'Secure web application development and API creation',
                    priority: 3,
                    assignTo: 'Rana Talha Majid',
                    responseTime: '48 hours'
                },
                {
                    code: 'security-training',
                    name: 'Security Training',
                    description: 'Employee awareness and technical security training',
                    priority: 3,
                    assignTo: 'Jamshed Fareed',
                    responseTime: '48 hours'
                },
                {
                    code: 'red-teaming',
                    name: 'Red Team Assessment',
                    description: 'Advanced persistent threat simulation and testing',
                    priority: 5,
                    assignTo: 'Jamshed Fareed',
                    responseTime: '24 hours'
                },
                {
                    code: 'consulting',
                    name: 'Security Consulting',
                    description: 'Strategic cybersecurity guidance and advisory services',
                    priority: 4,
                    assignTo: 'Ali Haider',
                    responseTime: '24 hours'
                },
                {
                    code: 'general-inquiry',
                    name: 'General Inquiry',
                    description: 'General questions and information requests',
                    priority: 2,
                    assignTo: 'Muhammad Ammar',
                    responseTime: '72 hours'
                }
            ];

            for (const service of services) {
                await this.run(`
                    INSERT INTO contact_services (service_code, service_name, description, priority_level, auto_assign_to, estimated_response_time)
                    VALUES (?, ?, ?, ?, ?, ?)
                `, [service.code, service.name, service.description, service.priority, service.assignTo, service.responseTime]);
            }

            console.log('✅ Default services seeded');
        }

        // Check if admin user exists
        const existingAdmin = await this.get('SELECT COUNT(*) as count FROM admin_users');
        
        if (existingAdmin.count === 0) {
            const defaultPassword = 'SpectraOps2025!';
            const hashedPassword = await bcrypt.hash(defaultPassword, 12);
            
            await this.run(`
                INSERT INTO admin_users (username, email, password_hash, full_name, role)
                VALUES (?, ?, ?, ?, ?)
            `, ['admin', 'ranatalhamajid1@gmail.com', hashedPassword, 'Rana Talha Majid', 'super_admin']);

            console.log('✅ Default admin user created');
            console.log('🔑 Username: admin, Password: SpectraOps2025!');
        }
    }

    // Database helper methods
    run(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.run(sql, params, function(err) {
                if (err) reject(err);
                else resolve({ id: this.lastID, changes: this.changes });
            });
        });
    }

    get(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.get(sql, params, (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
    }

    all(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.all(sql, params, (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
    }

    // Contact-specific methods
    async createContact(contactData) {
        const {
            name, email, phone, company, subject, message, 
            serviceType, ipAddress, userAgent, referrer, source
        } = contactData;

        const result = await this.run(`
            INSERT INTO contact_submissions (
                name, email, phone, company, subject, message, 
                service_type, ip_address, user_agent, referrer, source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [name, email, phone, company, subject, message, serviceType, ipAddress, userAgent, referrer, source]);

        return result.id;
    }

    async getContacts(filters = {}) {
        let sql = `
            SELECT c.*, s.service_name, s.priority_level, s.estimated_response_time
            FROM contact_submissions c
            LEFT JOIN contact_services s ON c.service_type = s.service_code
            WHERE 1=1
        `;
        
        const params = [];

        if (filters.status) {
            sql += ' AND c.status = ?';
            params.push(filters.status);
        }

        if (filters.service) {
            sql += ' AND c.service_type = ?';
            params.push(filters.service);
        }

        if (filters.assignedTo) {
            sql += ' AND c.assigned_to = ?';
            params.push(filters.assignedTo);
        }

        if (filters.dateFrom) {
            sql += ' AND c.created_at >= ?';
            params.push(filters.dateFrom);
        }

        if (filters.dateTo) {
            sql += ' AND c.created_at <= ?';
            params.push(filters.dateTo);
        }

        sql += ' ORDER BY c.created_at DESC';

        if (filters.limit) {
            sql += ' LIMIT ?';
            params.push(filters.limit);
        }

        return await this.all(sql, params);
    }

    async updateContactStatus(contactId, status, assignedTo = null, responseMessage = null) {
        const updates = ['status = ?', 'updated_at = CURRENT_TIMESTAMP'];
        const params = [status];

        if (assignedTo) {
            updates.push('assigned_to = ?');
            params.push(assignedTo);
        }

        if (responseMessage) {
            updates.push('response_message = ?', 'responded_at = CURRENT_TIMESTAMP');
            params.push(responseMessage);
        }

        params.push(contactId);

        return await this.run(`
            UPDATE contact_submissions 
            SET ${updates.join(', ')} 
            WHERE id = ?
        `, params);
    }

    async getContactStats() {
        const stats = {};

        // Total contacts
        const total = await this.get('SELECT COUNT(*) as count FROM contact_submissions');
        stats.total = total.count;

        // Contacts by status
        const byStatus = await this.all(`
            SELECT status, COUNT(*) as count 
            FROM contact_submissions 
            GROUP BY status
        `);
        stats.byStatus = byStatus.reduce((acc, row) => {
            acc[row.status] = row.count;
            return acc;
        }, {});

        // Recent contacts (last 7 days)
        const recent = await this.get(`
            SELECT COUNT(*) as count 
            FROM contact_submissions 
            WHERE created_at >= datetime('now', '-7 days')
        `);
        stats.recent = recent.count;

        // Contacts by service
        const byService = await this.all(`
            SELECT c.service_type, s.service_name, COUNT(*) as count
            FROM contact_submissions c
            LEFT JOIN contact_services s ON c.service_type = s.service_code
            GROUP BY c.service_type, s.service_name
            ORDER BY count DESC
        `);
        stats.byService = byService;

        // Response time stats
        const responseTime = await this.get(`
            SELECT 
                AVG(julianday(responded_at) - julianday(created_at)) * 24 as avg_hours,
                COUNT(*) as responded_count
            FROM contact_submissions 
            WHERE responded_at IS NOT NULL
        `);
        stats.responseTime = responseTime;

        return stats;
    }
}

module.exports = new Database();