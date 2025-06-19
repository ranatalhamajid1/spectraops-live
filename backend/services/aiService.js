const { Configuration, OpenAIApi } = require('openai');
const tf = require('@tensorflow/tfjs-node');

class AIService {
    constructor() {
        this.openai = new OpenAIApi(new Configuration({
            apiKey: process.env.OPENAI_API_KEY
        }));
        this.loadModels();
    }

    async loadModels() {
        try {
            // Load pre-trained threat detection model
            this.threatModel = await tf.loadLayersModel('file://./models/threat-detection/model.json');
            console.log('✅ AI threat detection model loaded');
        } catch (error) {
            console.warn('⚠️ AI model loading failed:', error.message);
        }
    }

    // AI-powered chatbot for customer support
    async generateChatResponse(message, context = []) {
        try {
            const prompt = this.buildChatPrompt(message, context);
            
            const response = await this.openai.createChatCompletion({
                model: 'gpt-3.5-turbo',
                messages: [
                    {
                        role: 'system',
                        content: `You are a helpful cybersecurity expert representing SpectraOps Ltd. 
                                 Provide accurate, professional advice about cybersecurity, web development, 
                                 and our services. Be concise but informative.`
                    },
                    ...context,
                    {
                        role: 'user',
                        content: message
                    }
                ],
                max_tokens: 150,
                temperature: 0.7
            });

            return {
                response: response.data.choices[0].message.content,
                confidence: this.calculateConfidence(response.data.choices[0])
            };
        } catch (error) {
            console.error('Chat AI error:', error);
            return {
                response: "I'm sorry, I'm having trouble responding right now. Please contact our support team directly.",
                confidence: 0
            };
        }
    }

    buildChatPrompt(message, context) {
        const companyInfo = `
        SpectraOps Ltd. is a cybersecurity and web development company with offices in Multan and Islamabad, Pakistan.
        Services: Penetration Testing, SOC Consultation, Web Development, Security Training, Red Teaming
        CEO: Zohaib Ahmad Tariq
        Contact: contact@spectraops.com
        `;
        
        return companyInfo + '\n\nUser question: ' + message;
    }

    // Intelligent threat analysis
    async analyzeThreatPattern(logData) {
        if (!this.threatModel) {
            return this.fallbackThreatAnalysis(logData);
        }

        try {
            // Preprocess log data for model input
            const features = this.preprocessLogData(logData);
            
            // Make prediction
            const prediction = this.threatModel.predict(features);
            const threatScore = await prediction.data();
            
            return {
                threatLevel: this.classifyThreatLevel(threatScore[0]),
                confidence: threatScore[0],
                recommendations: this.generateThreatRecommendations(threatScore[0], logData)
            };
        } catch (error) {
            console.error('AI threat analysis error:', error);
            return this.fallbackThreatAnalysis(logData);
        }
    }

    preprocessLogData(logData) {
        // Convert log data to feature vector
        const features = [
            logData.requestCount || 0,
            logData.errorRate || 0,
            logData.uniqueIPs || 0,
            logData.suspiciousPatterns || 0,
            logData.timeSpan || 0
        ];
        
        // Normalize features
        const normalized = features.map(f => f / 100);
        
        return tf.tensor2d([normalized]);
    }

    classifyThreatLevel(score) {
        if (score > 0.8) return 'HIGH';
        if (score > 0.6) return 'MEDIUM';
        if (score > 0.3) return 'LOW';
        return 'MINIMAL';
    }

    generateThreatRecommendations(score, logData) {
        const recommendations = [];
        
        if (score > 0.8) {
            recommendations.push('Immediate action required: Block suspicious IPs');
            recommendations.push('Activate incident response protocol');
            recommendations.push('Notify security team immediately');
        } else if (score > 0.6) {
            recommendations.push('Increase monitoring frequency');
            recommendations.push('Review firewall rules');
            recommendations.push('Consider rate limiting');
        } else if (score > 0.3) {
            recommendations.push('Continue monitoring');
            recommendations.push('Update security signatures');
        }
        
        return recommendations;
    }

    fallbackThreatAnalysis(logData) {
        // Rule-based threat analysis when AI model isn't available
        let threatLevel = 'LOW';
        const recommendations = [];
        
        if (logData.errorRate > 50) {
            threatLevel = 'HIGH';
            recommendations.push('High error rate detected - potential DDoS attack');
        } else if (logData.suspiciousPatterns > 10) {
            threatLevel = 'MEDIUM';
            recommendations.push('Suspicious patterns detected - review logs');
        }
        
        return {
            threatLevel,
            confidence: 0.7,
            recommendations
        };
    }

    // Smart content generation for news articles
    async generateContentSuggestions(topic, keywords = []) {
        try {
            const prompt = `Generate cybersecurity article ideas about "${topic}" 
                           with focus on: ${keywords.join(', ')}. 
                           Provide 3 article titles and brief descriptions suitable for a 
                           professional cybersecurity company blog.`;

            const response = await this.openai.createCompletion({
                model: 'text-davinci-003',
                prompt,
                max_tokens: 300,
                temperature: 0.8
            });

            return this.parseContentSuggestions(response.data.choices[0].text);
        } catch (error) {
            console.error('Content generation error:', error);
            return this.getFallbackContentSuggestions(topic);
        }
    }

    parseContentSuggestions(text) {
        const lines = text.split('\n').filter(line => line.trim());
        const suggestions = [];
        
        for (let i = 0; i < lines.length; i += 2) {
            if (lines[i] && lines[i + 1]) {
                suggestions.push({
                    title: lines[i].replace(/^\d+\.\s*/, ''),
                    description: lines[i + 1]
                });
            }
        }
        
        return suggestions;
    }

getFallbackContentSuggestions(topic) {
    const fallbackSuggestions = {
        'cybersecurity': [
            {
                title: 'Top 10 Cybersecurity Threats in 2025',
                description: 'Comprehensive overview of emerging cyber threats and how to protect against them'
            },
            {
                title: 'Zero Trust Architecture Implementation Guide',
                description: 'Step-by-step guide to implementing zero trust security model in your organization'
            },
            {
                title: 'AI in Cybersecurity: Friend or Foe?',
                description: 'Exploring how artificial intelligence is reshaping the cybersecurity landscape'
            }
        ],
        'web development': [
            {
                title: 'Secure Coding Practices for Modern Web Apps',
                description: 'Essential security practices every web developer should follow'
            },
            {
                title: 'Building Resilient Web Applications',
                description: 'Techniques for creating web applications that can withstand various attacks'
            },
            {
                title: 'The Future of Web Security',
                description: 'Emerging trends and technologies in web application security'
            }
        ]
    };
    
    return fallbackSuggestions[topic.toLowerCase()] || fallbackSuggestions['cybersecurity'];
}

    // Automated vulnerability assessment using AI
    async assessVulnerability(targetData) {
        try {
            const analysis = await this.performVulnerabilityAnalysis(targetData);
            return {
                riskLevel: analysis.riskLevel,
                vulnerabilities: analysis.vulnerabilities,
                recommendations: analysis.recommendations,
                confidence: analysis.confidence
            };
        } catch (error) {
            console.error('Vulnerability assessment error:', error);
            return {
                riskLevel: 'UNKNOWN',
                vulnerabilities: [],
                recommendations: ['Manual assessment required'],
                confidence: 0
            };
        }
    }

    async performVulnerabilityAnalysis(targetData) {
        // Simulate AI-powered vulnerability analysis
        const vulnerabilities = [];
        let riskLevel = 'LOW';
        const recommendations = [];

        // Analyze different aspects
        if (targetData.openPorts && targetData.openPorts.length > 10) {
            vulnerabilities.push({
                type: 'Excessive Open Ports',
                severity: 'MEDIUM',
                description: 'Multiple unnecessary ports are open'
            });
            riskLevel = 'MEDIUM';
            recommendations.push('Close unnecessary open ports');
        }

        if (targetData.outdatedSoftware && targetData.outdatedSoftware.length > 0) {
            vulnerabilities.push({
                type: 'Outdated Software',
                severity: 'HIGH',
                description: 'System contains outdated software with known vulnerabilities'
            });
            riskLevel = 'HIGH';
            recommendations.push('Update all software to latest versions');
        }

        if (targetData.weakPasswords) {
            vulnerabilities.push({
                type: 'Weak Password Policy',
                severity: 'HIGH',
                description: 'Weak password policies detected'
            });
            riskLevel = 'HIGH';
            recommendations.push('Implement strong password policies');
        }

        return {
            riskLevel,
            vulnerabilities,
            recommendations,
            confidence: 0.85
        };
    }

    // Intelligent log analysis
    async analyzeSecurityLogs(logs) {
        const patterns = await this.detectAnomalousPatterns(logs);
        const insights = await this.generateSecurityInsights(patterns);
        
        return {
            anomalies: patterns,
            insights: insights,
            actionItems: this.generateActionItems(patterns)
        };
    }

    async detectAnomalousPatterns(logs) {
        // AI-powered pattern detection
        const patterns = [];
        
        // Time-based analysis
        const timePatterns = this.analyzeTimePatterns(logs);
        if (timePatterns.anomalous) {
            patterns.push({
                type: 'Temporal Anomaly',
                description: 'Unusual activity patterns detected outside normal hours',
                severity: 'MEDIUM'
            });
        }

        // IP-based analysis
        const ipPatterns = this.analyzeIPPatterns(logs);
        if (ipPatterns.suspicious.length > 0) {
            patterns.push({
                type: 'Suspicious IP Activity',
                description: `${ipPatterns.suspicious.length} suspicious IP addresses detected`,
                severity: 'HIGH'
            });
        }

        // Request pattern analysis
        const requestPatterns = this.analyzeRequestPatterns(logs);
        if (requestPatterns.anomalous) {
            patterns.push({
                type: 'Anomalous Request Patterns',
                description: 'Unusual request patterns that may indicate automated attacks',
                severity: 'MEDIUM'
            });
        }

        return patterns;
    }

    analyzeTimePatterns(logs) {
        const hourCounts = new Array(24).fill(0);
        
        logs.forEach(log => {
            const hour = new Date(log.timestamp).getHours();
            hourCounts[hour]++;
        });

        // Check for unusual activity during off-hours (11 PM - 6 AM)
        const offHoursActivity = hourCounts.slice(23, 24).concat(hourCounts.slice(0, 6));
        const totalOffHours = offHoursActivity.reduce((sum, count) => sum + count, 0);
        const totalActivity = hourCounts.reduce((sum, count) => sum + count, 0);
        
        return {
            anomalous: totalOffHours / totalActivity > 0.3, // More than 30% off-hours activity
            offHoursPercentage: (totalOffHours / totalActivity) * 100
        };
    }

    analyzeIPPatterns(logs) {
        const ipCounts = {};
        const ipLocations = {};
        
        logs.forEach(log => {
            ipCounts[log.ip] = (ipCounts[log.ip] || 0) + 1;
            // In production, you'd use IP geolocation service
            ipLocations[log.ip] = log.location || 'Unknown';
        });

        const suspicious = [];
        
        // Detect IPs with excessive requests
        Object.entries(ipCounts).forEach(([ip, count]) => {
            if (count > 100) { // More than 100 requests
                suspicious.push({
                    ip,
                    requestCount: count,
                    reason: 'Excessive requests'
                });
            }
        });

        return { suspicious, totalIPs: Object.keys(ipCounts).length };
    }

    analyzeRequestPatterns(logs) {
        const pathCounts = {};
        const userAgents = {};
        
        logs.forEach(log => {
            pathCounts[log.path] = (pathCounts[log.path] || 0) + 1;
            userAgents[log.userAgent] = (userAgents[log.userAgent] || 0) + 1;
        });

        // Detect bot-like behavior
        const botIndicators = Object.entries(userAgents).filter(([ua, count]) => {
            return count > 50 && (ua.includes('bot') || ua.includes('crawler') || ua.length < 20);
        });

        return {
            anomalous: botIndicators.length > 5,
            botCount: botIndicators.length
        };
    }

    async generateSecurityInsights(patterns) {
        const insights = [];
        
        patterns.forEach(pattern => {
            switch (pattern.type) {
                case 'Temporal Anomaly':
                    insights.push('Consider implementing time-based access controls');
                    break;
                case 'Suspicious IP Activity':
                    insights.push('Review and update IP blacklists');
                    insights.push('Consider implementing geo-blocking');
                    break;
                case 'Anomalous Request Patterns':
                    insights.push('Implement advanced bot protection');
                    insights.push('Review rate limiting policies');
                    break;
            }
        });

        return insights;
    }

    generateActionItems(patterns) {
        const actions = [];
        
        if (patterns.some(p => p.severity === 'HIGH')) {
            actions.push({
                priority: 'HIGH',
                action: 'Immediate security review required',
                deadline: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
            });
        }

        if (patterns.some(p => p.type === 'Suspicious IP Activity')) {
            actions.push({
                priority: 'MEDIUM',
                action: 'Update firewall rules to block suspicious IPs',
                deadline: new Date(Date.now() + 48 * 60 * 60 * 1000) // 48 hours
            });
        }

        return actions;
    }

    calculateConfidence(choice) {
        // Simple confidence calculation based on response characteristics
        const text = choice.message.content;
        if (text.length < 20) return 0.3;
        if (text.includes('sorry') || text.includes('don\'t know')) return 0.4;
        if (text.includes('SpectraOps') || text.includes('cybersecurity')) return 0.9;
        return 0.7;
    }
}

module.exports = new AIService();