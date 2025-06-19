const i18n = require('i18n');
const path = require('path');

class InternationalizationService {
    constructor() {
        this.setupI18n();
    }

    setupI18n() {
        i18n.configure({
            locales: ['en', 'ur', 'ar', 'fr', 'es'],
            directory: path.join(__dirname, '../locales'),
            defaultLocale: 'en',
            cookie: 'language',
            queryParameter: 'lang',
            autoReload: true,
            updateFiles: false,
            api: {
                '__': 't',
                '__n': 'tn'
            }
        });
    }

    middleware() {
        return i18n.init;
    }

    detectLanguage() {
        return (req, res, next) => {
            // Language detection priority:
            // 1. Query parameter (?lang=ur)
            // 2. Cookie
            // 3. Accept-Language header
            // 4. Default (en)

            let locale = req.query.lang || 
                        req.cookies.language ||
                        req.acceptsLanguages(['en', 'ur', 'ar', 'fr', 'es']) ||
                        'en';

            // Validate locale
            const supportedLocales = ['en', 'ur', 'ar', 'fr', 'es'];
            if (!supportedLocales.includes(locale)) {
                locale = 'en';
            }

            res.setLocale(locale);
            res.cookie('language', locale, { 
                maxAge: 365 * 24 * 60 * 60 * 1000, // 1 year
                httpOnly: false // Allow client-side access
            });

            next();
        };
    }

    getTranslations() {
        return (req, res, next) => {
            res.locals.translations = {
                currentLocale: res.getLocale(),
                t: res.__,
                tn: res.__n
            };
            next();
        };
    }
}

module.exports = new InternationalizationService();