// SpectraOps Navigation Manager - Fixed Version
console.log('🧭 Navigation loading...');

// Check if NavigationManager already exists
if (typeof window.NavigationManager === 'undefined') {
    window.NavigationManager = class NavigationManager {
        constructor() {
            this.currentPage = window.location.pathname;
            this.initializeNavigation();
        }

        initializeNavigation() {
            this.setActiveNavItem();
            this.bindNavigationEvents();
            console.log(`🧭 Navigation initialized for: ${this.currentPage}`);
        }

        setActiveNavItem() {
            const navItems = document.querySelectorAll('.nav-link');
            navItems.forEach(item => {
                const href = item.getAttribute('href');
                if (href && this.currentPage.includes(href)) {
                    item.classList.add('active');
                }
            });
        }

        bindNavigationEvents() {
            const mobileToggle = document.querySelector('.mobile-toggle');
            const navMenu = document.querySelector('.nav-menu');

            if (mobileToggle && navMenu) {
                mobileToggle.addEventListener('click', () => {
                    navMenu.classList.toggle('active');
                });
            }
        }

        navigateTo(path) {
            window.location.href = path;
        }
    };

    // Initialize only if not already initialized
    if (!window.navigationManagerInstance) {
        window.navigationManagerInstance = new window.NavigationManager();
        console.log('✅ Navigation Manager initialized successfully');
    }
} else {
    console.log('⚠️ Navigation Manager already loaded, skipping...');
}

console.log('✅ Navigation script loaded - v1.0');