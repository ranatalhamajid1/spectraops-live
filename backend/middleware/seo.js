const express = require('express');
const fs = require('fs').promises;
const path = require('path');

class SEOMiddleware {
    constructor() {
        this.seoData = new Map();
        this.loadSEOData();
    }

    async loadSEOData() {
        try {
            const seoConfigPath = path.join(__dirname, '../config/seo.json');
            const seoConfig = await fs.readFile(seoConfigPath, 'utf8');
            const config = JSON.parse(seoConfig);
            
            for (const [route, data] of Object.entries(config)) {
                this.seoData.set(route, data);
            }
        } catch (error) {
            console.error('Failed to load SEO configuration:', error);
        }
    }

    middleware() {
        return (req, res, next) => {
            const route = req.path;
            const seoInfo = this.seoData.get(route) || this.seoData.get('/');

            // Add SEO headers
            if (seoInfo) {
                res.locals.seo = {
                    title: seoInfo.title,
                    description: seoInfo.description,
                    keywords: seoInfo.keywords,
                    ogTitle: seoInfo.ogTitle || seoInfo.title,
                    ogDescription: seoInfo.ogDescription || seoInfo.description,
                    ogImage: seoInfo.ogImage,
                    canonicalUrl: `${req.protocol}://${req.get('host')}${req.originalUrl}`,
                    structuredData: seoInfo.structuredData
                };
            }

            next();
        };
    }

    generateSitemap() {
        const urls = [
            { loc: '/', changefreq: 'daily', priority: '1.0' },
            { loc: '/services', changefreq: 'weekly', priority: '0.8' },
            { loc: '/about', changefreq: 'monthly', priority: '0.7' },
            { loc: '/contact', changefreq: 'monthly', priority: '0.6' },
            { loc: '/news', changefreq: 'daily', priority: '0.8' }
        ];

        const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map(url => `
    <url>
        <loc>https://spectraops.com${url.loc}</loc>
        <changefreq>${url.changefreq}</changefreq>
        <priority>${url.priority}</priority>
        <lastmod>${new Date().toISOString().split('T')[0]}</lastmod>
    </url>
`).join('')}
</urlset>`;

        return sitemap;
    }

    generateRobotsTxt() {
        return `User-agent: *
Allow: /
Disallow: /admin/
Disallow: /api/

Sitemap: https://spectraops.com/sitemap.xml`;
    }
}

module.exports = new SEOMiddleware();