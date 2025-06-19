const axios = require('axios');
const crypto = require('crypto');
const db = require('../config/database');

class SecurityService {
    constructor() {
        this.hibpApiKey = process.env.HIBP_API_KEY;
        this.vtApiKey = process.env.VIRUSTOTAL_API_KEY;
        this.cache = new Map();
        this.cacheTimeout = 24 * 60 * 60 * 1000; // 24 hours
    }

    // Have I Been Pwned Integration
    async checkEmailBreach(email) {
        const startTime = Date.now();
        const cacheKey = `email_${crypto.createHash('sha256').update(email).digest('hex')}`;
        
        // Check cache first
        const cached = this.cache.get(cacheKey);
        if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
            return cached.data;
        }

        try {
            const response = await axios.get(
                `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}`,
                {
                    headers: {
                        'hibp-api-key': this.hibpApiKey,
                        'User-Agent': 'SpectraOps-Security-Checker'
                    },
                    timeout: 10000
                }
            );

            const breaches = response.data || [];
            const result = {
                email,
                breached: breaches.length > 0,
                breachCount: breaches.length,
                breaches: breaches.map(breach => ({
                    name: breach.Name,
                    domain: breach.Domain,
                    breachDate: breach.BreachDate,
                    compromisedData: breach.DataClasses,
                    verified: breach.IsVerified
                })),
                checkedAt: new Date().toISOString()
            };

            // Cache result
            this.cache.set(cacheKey, {
                data: result,
                timestamp: Date.now()
            });

            // Log usage
            await this.logToolUsage('email_breach_check', email, true, Date.now() - startTime);

            return result;

        } catch (error) {
            if (error.response && error.response.status === 404) {
                // No breaches found
                const result = {
                    email,
                    breached: false,
                    breachCount: 0,
                    breaches: [],
                    checkedAt: new Date().toISOString()
                };

                this.cache.set(cacheKey, {
                    data: result,
                    timestamp: Date.now()
                });

                await this.logToolUsage('email_breach_check', email, true, Date.now() - startTime);
                return result;
            }

            await this.logToolUsage('email_breach_check', email, false, Date.now() - startTime, error.message);
            throw new Error('Failed to check email breach status');
        }
    }

    // VirusTotal URL Scanner
    async scanUrl(url) {
        const startTime = Date.now();
        const urlHash = crypto.createHash('sha256').update(url).digest('hex');
        const cacheKey = `url_${urlHash}`;

        // Check cache
        const cached = this.cache.get(cacheKey);
        if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
            return cached.data;
        }

        try {
            // Submit URL for analysis
            const submitResponse = await axios.post(
                'https://www.virustotal.com/api/v3/urls',
                `url=${encodeURIComponent(url)}`,
                {
                    headers: {
                        'x-apikey': this.vtApiKey,
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                }
            );

            const analysisId = submitResponse.data.data.id;

            // Wait a moment then get results
            await new Promise(resolve => setTimeout(resolve, 2000));

            const analysisResponse = await axios.get(
                `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
                {
                    headers: {
                        'x-apikey': this.vtApiKey
                    }
                }
            );

            const analysis = analysisResponse.data.data.attributes;
            const stats = analysis.stats;

            const result = {
                url,
                scanDate: new Date().toISOString(),
                malicious: stats.malicious > 0,
                suspicious: stats.suspicious > 0,
                clean: stats.harmless > 0,
                stats: {
                    malicious: stats.malicious,
                    suspicious: stats.suspicious,
                    undetected: stats.undetected,
                    harmless: stats.harmless,
                    timeout: stats.timeout
                },
                engines: analysis.results,
                reputation: this.calculateReputation(stats)
            };

            // Cache result
            this.cache.set(cacheKey, {
                data: result,
                timestamp: Date.now()
            });

            await this.logToolUsage('url_scan', url, true, Date.now() - startTime);
            return result;

        } catch (error) {
            await this.logToolUsage('url_scan', url, false, Date.now() - startTime, error.message);
            throw new Error('Failed to scan URL');
        }
    }

    // Password Strength Analysis
    analyzePassword(password) {
        const analysis = {
            score: 0,
            strength: 'Very Weak',
            issues: [],
            suggestions: [],
            entropy: this.calculateEntropy(password),
            estimatedCrackTime: ''
        };

        // Length check
        if (password.length < 8) {
            analysis.issues.push('Password is too short');
            analysis.suggestions.push('Use at least 8 characters');
        } else if (password.length >= 12) {
            analysis.score += 2;
        } else {
            analysis.score += 1;
        }

        // Character variety
        if (/[a-z]/.test(password)) analysis.score += 1;
        else analysis.issues.push('Missing lowercase letters');

        if (/[A-Z]/.test(password)) analysis.score += 1;
        else analysis.issues.push('Missing uppercase letters');

        if (/\d/.test(password)) analysis.score += 1;
        else analysis.issues.push('Missing numbers');

        if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) analysis.score += 2;
        else analysis.suggestions.push('Add special characters');

        // Common patterns
        if (/(.)\1{2,}/.test(password)) {
            analysis.issues.push('Repeated characters detected');
            analysis.score -= 1;
        }

        if (/123|abc|qwe|password|admin/i.test(password)) {
            analysis.issues.push('Common patterns detected');
            analysis.score -= 2;
        }

        // Determine strength
        if (analysis.score >= 7) analysis.strength = 'Very Strong';
        else if (analysis.score >= 5) analysis.strength = 'Strong';
        else if (analysis.score >= 3) analysis.strength = 'Medium';
        else if (analysis.score >= 1) analysis.strength = 'Weak';

        // Estimate crack time
        analysis.estimatedCrackTime = this.estimateCrackTime(analysis.entropy);

        return analysis;
    }

    calculateEntropy(password) {
        const charset = this.getCharsetSize(password);
        return password.length * Math.log2(charset);
    }

    getCharsetSize(password) {
        let size = 0;
        if (/[a-z]/.test(password)) size += 26;
        if (/[A-Z]/.test(password)) size += 26;
        if (/\d/.test(password)) size += 10;
        if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) size += 32;
        return size;
    }

    estimateCrackTime(entropy) {
        const guessesPerSecond = 1e9; // 1 billion guesses per second
        const totalGuesses = Math.pow(2, entropy) / 2; // Average case
        const seconds = totalGuesses / guessesPerSecond;

        if (seconds < 60) return 'Less than a minute';
        if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
        if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
        if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
        return `${Math.round(seconds / 31536000)} years`;
    }

    calculateReputation(stats) {
        const total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
        if (total === 0) return 'Unknown';
        
        const maliciousRatio = stats.malicious / total;
        const suspiciousRatio = stats.suspicious / total;

        if (maliciousRatio > 0.1) return 'Malicious';
        if (suspiciousRatio > 0.2) return 'Suspicious';
        if (stats.harmless > stats.malicious + stats.suspicious) return 'Clean';
        return 'Unknown';
    }

    async logToolUsage(toolName, input, success, processingTime, error = null) {
        try {
            await db.run(`
                INSERT INTO security_tool_usage (
                    tool_name, input_hash, success, processing_time, error_message
                ) VALUES (?, ?, ?, ?, ?)
            `, [
                toolName,
                crypto.createHash('sha256').update(input).digest('hex'),
                success ? 1 : 0,
                processingTime,
                error
            ]);
        } catch (err) {
            console.error('Failed to log tool usage:', err);
        }
    }
}

module.exports = new SecurityService();