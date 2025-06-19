// SpectraOps Website - Main JavaScript

// Theme Management
class ThemeManager {
    constructor() {
        this.theme = localStorage.getItem('theme') || 'light';
        this.init();
    }

    init() {
        this.setTheme(this.theme);
        this.bindEvents();
    }

    setTheme(theme) {
        this.theme = theme;
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('theme', theme);
        
        const themeToggle = document.getElementById('theme-toggle');
        if (themeToggle) {
            const icon = themeToggle.querySelector('i');
            icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        }
    }

    toggle() {
        this.setTheme(this.theme === 'dark' ? 'light' : 'dark');
    }

    bindEvents() {
        const themeToggle = document.getElementById('theme-toggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', () => this.toggle());
        }
    }
}

// Navigation Management
class NavigationManager {
    constructor() {
        this.navbar = document.getElementById('navbar');
        this.hamburger = document.getElementById('hamburger');
        this.navMenu = document.getElementById('nav-menu');
        this.navLinks = document.querySelectorAll('.nav-link');
        this.init();
    }

    init() {
        this.bindEvents();
        this.handleScroll();
    }

    bindEvents() {
        // Hamburger menu toggle
        if (this.hamburger) {
            this.hamburger.addEventListener('click', () => this.toggleMobileMenu());
        }

        // Close mobile menu when clicking on links
        this.navLinks.forEach(link => {
            link.addEventListener('click', () => this.closeMobileMenu());
        });

        // Scroll event for navbar styling
        window.addEventListener('scroll', () => this.handleScroll());

        // Smooth scrolling for navigation links
        this.navLinks.forEach(link => {
            link.addEventListener('click', (e) => this.smoothScroll(e));
        });
    }

    toggleMobileMenu() {
        this.navMenu.classList.toggle('active');
        this.hamburger.classList.toggle('active');
    }

    closeMobileMenu() {
        this.navMenu.classList.remove('active');
        this.hamburger.classList.remove('active');
    }

    handleScroll() {
        if (window.scrollY > 50) {
            this.navbar.style.background = 'rgba(255, 255, 255, 0.98)';
            this.navbar.style.boxShadow = '0 2px 20px rgba(0, 0, 0, 0.1)';
        } else {
            this.navbar.style.background = 'rgba(255, 255, 255, 0.95)';
            this.navbar.style.boxShadow = 'none';
        }
    }

    smoothScroll(e) {
        const href = e.target.getAttribute('href');
        if (href && href.startsWith('#')) {
            e.preventDefault();
            const targetId = href.substring(1);
            const targetElement = document.getElementById(targetId);
            
            if (targetElement) {
                const offsetTop = targetElement.offsetTop - 70; // Account for navbar height
                window.scrollTo({
                    top: offsetTop,
                    behavior: 'smooth'
                });
            }
        }
    }
}

// Animation Manager
class AnimationManager {
    constructor() {
        this.observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };
        this.init();
    }

    init() {
        this.createObserver();
        this.animateCounters();
        this.startDashboardAnimation();
    }

    createObserver() {
        this.observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('animate-in');
                }
            });
        }, this.observerOptions);

        // Observe all animated elements
        const animatedElements = document.querySelectorAll(
            '.service-card, .tool-card, .team-member, .news-card, .story-item'
        );
        
        animatedElements.forEach(el => {
            el.style.opacity = '0';
            el.style.transform = 'translateY(20px)';
            el.style.transition = 'all 0.6s ease';
            this.observer.observe(el);
        });

        // Add CSS for animation
        const style = document.createElement('style');
        style.textContent = `
            .animate-in {
                opacity: 1 !important;
                transform: translateY(0) !important;
            }
        `;
        document.head.appendChild(style);
    }

    animateCounters() {
        const counters = document.querySelectorAll('[data-target]');
        
        const animateCounter = (counter) => {
            const target = parseInt(counter.getAttribute('data-target'));
            const increment = target / 100;
            let current = 0;
            
            const updateCounter = () => {
                if (current < target) {
                    current += increment;
                    if (target > 100) {
                        counter.textContent = Math.ceil(current).toLocaleString();
                    } else {
                        counter.textContent = Math.ceil(current * 10) / 10;
                    }
                    requestAnimationFrame(updateCounter);
                } else {
                    if (target > 100) {
                        counter.textContent = target.toLocaleString();
                    } else {
                        counter.textContent = target;
                    }
                }
            };
            
            updateCounter();
        };

        const counterObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    animateCounter(entry.target);
                    counterObserver.unobserve(entry.target);
                }
            });
        });

        counters.forEach(counter => counterObserver.observe(counter));
    }

    startDashboardAnimation() {
        // Animate dashboard metrics on load
        setTimeout(() => {
            const dashboardMetrics = document.querySelectorAll('.metric-value[data-target]');
            dashboardMetrics.forEach(metric => {
                const target = parseFloat(metric.getAttribute('data-target'));
                const increment = target / 50;
                let current = 0;
                
                const animateMetric = () => {
                    if (current < target) {
                        current += increment;
                        if (target > 100) {
                            metric.textContent = Math.ceil(current).toLocaleString();
                        } else {
                            metric.textContent = Math.ceil(current * 10) / 10;
                        }
                        requestAnimationFrame(animateMetric);
                    } else {
                        if (target > 100) {
                            metric.textContent = target.toLocaleString();
                        } else {
                            metric.textContent = target;
                        }
                    }
                };
                
                animateMetric();
            });
        }, 1000);
    }
}

// Security Tools Manager
class SecurityToolsManager {
    constructor() {
        this.init();
    }

    init() {
        this.generateCaptcha();
        this.bindEvents();
    }

    bindEvents() {
        // Contact form submission
        const contactForm = document.getElementById('contact-form');
        if (contactForm) {
            contactForm.addEventListener('submit', (e) => this.handleContactForm(e));
        }
    }

    // Email Breach Checker
    async checkEmailBreach() {
        const emailInput = document.getElementById('email-check');
        const resultDiv = document.getElementById('email-result');
        const email = emailInput.value.trim();

        if (!email || !this.isValidEmail(email)) {
            this.showResult(resultDiv, 'Please enter a valid email address.', 'error');
            return;
        }

        this.showLoading(resultDiv);

        try {
            const response = await fetch('/api/security/check-email', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email })
            });

            const data = await response.json();

            if (data.success) {
                const result = data.data;
                if (result.breached) {
                    this.showResult(
                        resultDiv, 
                        `⚠️ This email has been found in ${result.breachCount} known data breaches. Consider changing your passwords.`, 
                        'warning'
                    );
                } else {
                    this.showResult(
                        resultDiv, 
                        '✅ Great news! This email was not found in any known data breaches.', 
                        'success'
                    );
                }
            } else {
                this.showResult(resultDiv, data.error || 'Error checking email', 'error');
            }
        } catch (error) {
            this.showResult(resultDiv, 'Error checking email. Please try again later.', 'error');
        }
    }

    // Password Strength Checker
    checkPasswordStrength(password) {
        const strengthFill = document.getElementById('strength-fill');
        const strengthText = document.getElementById('strength-text');
        const tipsDiv = document.getElementById('password-tips');

        if (!password) {
            strengthFill.style.width = '0%';
            strengthText.textContent = 'Enter a password';
            strengthText.style.color = 'var(--text-secondary)';
            tipsDiv.innerHTML = '';
            return;
        }

        const criteria = [
            { regex: /.{8,}/, text: 'At least 8 characters' },
            { regex: /[A-Z]/, text: 'At least one uppercase letter' },
            { regex: /[a-z]/, text: 'At least one lowercase letter' },
            { regex: /\d/, text: 'At least one number' },
            { regex: /[!@#$%^&*(),.?":{}|<>]/, text: 'At least one special character' }
        ];

        const passed = criteria.filter(criterion => criterion.regex.test(password)).length;
        const strength = (passed / criteria.length) * 100;

        // Update strength meter
        strengthFill.style.width = `${strength}%`;

        // Update color and text based on strength
        let strengthLevel, color;
        if (strength < 40) {
            strengthLevel = 'Weak';
            color = 'var(--warning-color)';
            strengthFill.style.background = 'var(--warning-color)';
        } else if (strength < 70) {
            strengthLevel = 'Medium';
            color = 'var(--accent-color)';
            strengthFill.style.background = 'var(--accent-color)';
        } else {
            strengthLevel = 'Strong';
            color = 'var(--secondary-color)';
            strengthFill.style.background = 'var(--secondary-color)';
        }

        strengthText.textContent = strengthLevel;
        strengthText.style.color = color;

        // Show tips
        const tipsList = criteria.map(criterion => {
            const isValid = criterion.regex.test(password);
            return `<li class="${isValid ? 'valid' : ''}">${criterion.text}</li>`;
        }).join('');

        tipsDiv.innerHTML = `<ul>${tipsList}</ul>`;
    }

    // Toggle Password Visibility
    togglePasswordVisibility() {
        const passwordInput = document.getElementById('password-check');
        const toggleBtn = document.querySelector('.toggle-password i');

        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            toggleBtn.className = 'fas fa-eye-slash';
        } else {
            passwordInput.type = 'password';
            toggleBtn.className = 'fas fa-eye';
        }
    }

    // Phishing Link Scanner
    async scanPhishingLink() {
        const urlInput = document.getElementById('url-check');
        const resultDiv = document.getElementById('url-result');
        const url = urlInput.value.trim();

        if (!url || !this.isValidURL(url)) {
            this.showResult(resultDiv, 'Please enter a valid URL.', 'error');
            return;
        }

        this.showLoading(resultDiv);

        try {
            const response = await fetch('/api/security/scan-url', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url })
            });

            const data = await response.json();

            if (data.success) {
                const result = data.data;
                if (result.malicious) {
                    this.showResult(
                        resultDiv, 
                        '⚠️ Warning! This URL may be malicious. Proceed with caution.', 
                        'warning'
                    );
                } else {
                    this.showResult(
                        resultDiv, 
                        '✅ This URL appears to be safe. No known threats detected.', 
                        'success'
                    );
                }
            } else {
                this.showResult(resultDiv, data.error || 'Error scanning URL', 'error');
            }
        } catch (error) {
            this.showResult(resultDiv, 'Error scanning URL. Please try again later.', 'error');
        }
    }

    // Contact Form Handler
    async handleContactForm(e) {
        e.preventDefault();
        
        const formData = new FormData(e.target);
        const captchaAnswer = parseInt(formData.get('captcha-answer'));
        
        // Verify captcha
        if (captchaAnswer !== this.captchaResult) {
            this.showFormError('Incorrect captcha answer. Please try again.');
            this.generateCaptcha();
            return;
        }

        // Simulate form submission
        const submitBtn = e.target.querySelector('.btn-submit');
        submitBtn.classList.add('loading');
        submitBtn.disabled = true;

        try {
            const response = await fetch('/api/contact', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    name: formData.get('name'),
                    email: formData.get('email'),
                    phone: formData.get('phone'),
                    company: formData.get('company'),
                    service: formData.get('service'),
                    subject: formData.get('subject'),
                    message: formData.get('message'),
                    captchaAnswer: captchaAnswer
                })
            });

            const data = await response.json();

            if (data.success) {
                this.showFormSuccess('Thank you for your message! We\'ll get back to you soon.');
                e.target.reset();
                this.generateCaptcha();
            } else {
                this.showFormError(data.error || 'Failed to send message. Please try again.');
            }
        } catch (error) {
            this.showFormError('Failed to send message. Please try again.');
        } finally {
            submitBtn.classList.remove('loading');
            submitBtn.disabled = false;
        }
    }

    // Generate Simple Math Captcha
    generateCaptcha() {
        const num1 = Math.floor(Math.random() * 10) + 1;
        const num2 = Math.floor(Math.random() * 10) + 1;
        this.captchaResult = num1 + num2;
        
        const captchaQuestion = document.getElementById('captcha-question');
        if (captchaQuestion) {
            captchaQuestion.textContent = `${num1} + ${num2} = ?`;
        }
    }

    // Utility Functions
    isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    isValidURL(url) {
        try {
            new URL(url);
            return true;
        } catch {
            return false;
        }
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    showResult(element, message, type) {
        element.innerHTML = message;
        element.className = `tool-result ${type}`;
        element.style.display = 'block';
        element.style.opacity = '1';
    }

    showLoading(element) {
        element.innerHTML = 'Checking...';
        element.className = 'tool-result';
        element.style.display = 'block';
        element.style.opacity = '0.7';
    }

    showFormSuccess(message) {
        this.showFormMessage(message, 'success');
    }

    showFormError(message) {
        this.showFormMessage(message, 'error');
    }

    showFormMessage(message, type) {
        // Create or update message element
        let messageEl = document.querySelector('.form-message');
        if (!messageEl) {
            messageEl = document.createElement('div');
            messageEl.className = 'form-message';
            const form = document.getElementById('contact-form');
            form.insertBefore(messageEl, form.firstChild);
        }

        messageEl.innerHTML = message;
        messageEl.className = `form-message ${type}`;
        messageEl.style.cssText = `
            padding: 1rem;
            margin-bottom: 1rem;
            border-radius: 8px;
            font-weight: 600;
            ${type === 'success' ? 
                'background: rgba(16, 185, 129, 0.1); color: var(--secondary-color); border: 1px solid var(--secondary-color);' :
                'background: rgba(239, 68, 68, 0.1); color: var(--warning-color); border: 1px solid var(--warning-color);'
            }
        `;

        // Auto-hide after 5 seconds
        setTimeout(() => {
            if (messageEl) {
                messageEl.remove();
            }
        }, 5000);
    }
}

// News Manager
class NewsManager {
    constructor() {
        this.init();
    }

    init() {
        this.loadNews();
    }

    async loadNews() {
        try {
            // For demo purposes, we'll use static content
            // In production, you'd fetch from an API
            const newsContainer = document.getElementById('news-grid');
            if (!newsContainer) return;

            const demoArticles = [
                {
                    title: "Latest Cybersecurity Threats in 2025",
                    excerpt: "Understanding emerging threats and how to protect your organization from advanced persistent threats...",
                    category: "Cybersecurity",
                    date: "Jun 10, 2025",
                    author: "Security Team",
                    image: "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=400&h=250&fit=crop&auto=format"
                },
                {
                    title: "Modern Web Development Trends",
                    excerpt: "Exploring the latest trends in web development and how they impact business growth...",
                    category: "Web Development",
                    date: "Jun 8, 2025",
                    author: "Dev Team",
                    image: "https://images.unsplash.com/photo-1461749280684-dccba630e2f6?w=400&h=250&fit=crop&auto=format"
                },
                {
                    title: "Building a Secure Digital Presence",
                    excerpt: "Essential steps for businesses to establish and maintain a secure online presence...",
                    category: "Digital Security",
                    date: "Jun 5, 2025",
                    author: "Consulting Team",
                    image: "https://images.unsplash.com/photo-1563986768609-322da13575f3?w=400&h=250&fit=crop&auto=format"
                }
            ];

            newsContainer.innerHTML = demoArticles.map(article => `
                <div class="news-card">
                    <div class="news-image">
                        <img src="${article.image}" alt="${article.title}">
                        <div class="news-category">${article.category}</div>
                    </div>
                    <div class="news-content">
                        <h3>${article.title}</h3>
                        <p>${article.excerpt}</p>
                        <div class="news-meta">
                            <span class="news-date">${article.date}</span>
                            <span class="news-author">${article.author}</span>
                        </div>
                    </div>
                </div>
            `).join('');

        } catch (error) {
            console.error('Error loading news:', error);
        }
    }
}

// Global Functions (needed for inline event handlers)
function checkEmailBreach() {
    if (window.securityTools) {
        window.securityTools.checkEmailBreach();
    }
}

function checkPasswordStrength(password) {
    if (window.securityTools) {
        window.securityTools.checkPasswordStrength(password);
    }
}

function togglePasswordVisibility() {
    if (window.securityTools) {
        window.securityTools.togglePasswordVisibility();
    }
}

function scanPhishingLink() {
    if (window.securityTools) {
        window.securityTools.scanPhishingLink();
    }
}

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
    // Initialize all managers
    window.themeManager = new ThemeManager();
    window.navigationManager = new NavigationManager();
    window.animationManager = new AnimationManager();
    window.securityTools = new SecurityToolsManager();
    window.newsManager = new NewsManager();

    // Add loading animation
    document.body.style.opacity = '0';
    setTimeout(() => {
        document.body.style.transition = 'opacity 0.5s ease';
        document.body.style.opacity = '1';
    }, 100);

    // Performance optimization
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('/sw.js').catch(console.error);
    }
});

// Error handling
window.addEventListener('error', (e) => {
    console.error('Application error:', e.error);
});

// Handle visibility change for performance
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        // Pause animations when tab is not visible
        document.body.style.animationPlayState = 'paused';
    } else {
        // Resume animations when tab becomes visible
        document.body.style.animationPlayState = 'running';
    }
});