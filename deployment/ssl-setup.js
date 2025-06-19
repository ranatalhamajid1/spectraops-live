const fs = require('fs');
const https = require('https');
const express = require('express');
const acme = require('acme-client');

class SSLManager {
    constructor() {
        this.domain = process.env.DOMAIN || 'spectraops.com';
        this.email = process.env.SSL_EMAIL || 'admin@spectraops.com';
        this.certPath = './ssl';
    }

    async setupLetsEncrypt() {
        console.log('🔒 Setting up Let\'s Encrypt SSL certificate...');
        
        try {
            // Create ACME client
            const client = new acme.Client({
                directoryUrl: acme.directory.letsencrypt.production,
                accountKey: await acme.crypto.createPrivateKey()
            });

            // Create account
            const account = await client.createAccount({
                termsOfServiceAgreed: true,
                contact: [`mailto:${this.email}`]
            });

            console.log('✅ ACME account created');

            // Create certificate key
            const [key, csr] = await acme.crypto.createCsr({
                altNames: [this.domain, `www.${this.domain}`]
            });

            // Request certificate
            const cert = await client.auto({
                csr,
                email: this.email,
                termsOfServiceAgreed: true,
                challengeCreateFn: this.createChallenge.bind(this),
                challengeRemoveFn: this.removeChallenge.bind(this)
            });

            // Save certificate files
            await this.saveCertificates(key, cert);
            
            console.log('✅ SSL certificate obtained and saved');
            
            // Schedule renewal
            this.scheduleRenewal();
            
            return { key, cert };

        } catch (error) {
            console.error('❌ SSL setup failed:', error);
            throw error;
        }
    }

    async createChallenge(authz, challenge, keyAuthorization) {
        console.log(`Creating challenge for ${authz.identifier.value}`);
        
        if (challenge.type === 'http-01') {
            const challengePath = `./public/.well-known/acme-challenge/${challenge.token}`;
            await fs.promises.mkdir('./public/.well-known/acme-challenge', { recursive: true });
            await fs.promises.writeFile(challengePath, keyAuthorization);
            console.log(`✅ Challenge file created: ${challengePath}`);
        }
    }

    async removeChallenge(authz, challenge) {
        if (challenge.type === 'http-01') {
            const challengePath = `./public/.well-known/acme-challenge/${challenge.token}`;
            try {
                await fs.promises.unlink(challengePath);
                console.log(`🗑️ Challenge file removed: ${challengePath}`);
            } catch (error) {
                console.warn('Failed to remove challenge file:', error.message);
            }
        }
    }

    async saveCertificates(key, cert) {
        await fs.promises.mkdir(this.certPath, { recursive: true });
        
        await fs.promises.writeFile(`${this.certPath}/private.key`, key);
        await fs.promises.writeFile(`${this.certPath}/certificate.crt`, cert);
        
        console.log(`💾 Certificates saved to ${this.certPath}/`);
    }

    scheduleRenewal() {
        // Check for renewal every day
        setInterval(async () => {
            try {
                await this.checkAndRenewCertificate();
            } catch (error) {
                console.error('Certificate renewal check failed:', error);
            }
        }, 24 * 60 * 60 * 1000); // 24 hours

        console.log('📅 Certificate renewal scheduled');
    }

    async checkAndRenewCertificate() {
        try {
            const certPath = `${this.certPath}/certificate.crt`;
            const certData = await fs.promises.readFile(certPath);
            const cert = new crypto.X509Certificate(certData);
            
            const expiryDate = new Date(cert.validTo);
            const now = new Date();
            const daysUntilExpiry = Math.floor((expiryDate - now) / (1000 * 60 * 60 * 24));
            
            console.log(`📅 Certificate expires in ${daysUntilExpiry} days`);
            
            if (daysUntilExpiry <= 30) {
                console.log('🔄 Renewing certificate...');
                await this.setupLetsEncrypt();
                console.log('✅ Certificate renewed successfully');
            }
        } catch (error) {
            console.error('Certificate check failed:', error);
        }
    }

    createHTTPSServer(app) {
        try {
            const options = {
                key: fs.readFileSync(`${this.certPath}/private.key`),
                cert: fs.readFileSync(`${this.certPath}/certificate.crt`)
            };

            const httpsServer = https.createServer(options, app);
            
            console.log('🔒 HTTPS server created with SSL certificates');
            return httpsServer;
            
        } catch (error) {
            console.warn('⚠️ HTTPS setup failed, falling back to HTTP:', error.message);
            return null;
        }
    }

    // HTTP to HTTPS redirect
    setupHTTPRedirect() {
        const app = express();
        
        app.use((req, res) => {
            res.redirect(301, `https://${req.headers.host}${req.url}`);
        });

        app.listen(80, () => {
            console.log('📤 HTTP to HTTPS redirect server running on port 80');
        });
    }
}

module.exports = SSLManager;