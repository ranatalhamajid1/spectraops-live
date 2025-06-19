// SpectraOps Theme Manager - Fixed Version
console.log('🎨 Theme Manager loading...');

// Check if ThemeManager already exists
if (typeof window.ThemeManager === 'undefined') {
    window.ThemeManager = class ThemeManager {
        constructor() {
            this.currentTheme = localStorage.getItem('spectraops-theme') || 'dark';
            this.initializeTheme();
        }

        initializeTheme() {
            document.documentElement.setAttribute('data-theme', this.currentTheme);
            console.log(`🎨 Theme initialized: ${this.currentTheme}`);
        }

        toggleTheme() {
            this.currentTheme = this.currentTheme === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', this.currentTheme);
            localStorage.setItem('spectraops-theme', this.currentTheme);
            console.log(`🎨 Theme switched to: ${this.currentTheme}`);
        }

        setTheme(theme) {
            this.currentTheme = theme;
            document.documentElement.setAttribute('data-theme', theme);
            localStorage.setItem('spectraops-theme', theme);
            console.log(`🎨 Theme set to: ${theme}`);
        }
    };

    // Initialize only if not already initialized
    if (!window.themeManagerInstance) {
        window.themeManagerInstance = new window.ThemeManager();
        console.log('✅ Theme Manager initialized successfully');
    }
} else {
    console.log('⚠️ Theme Manager already loaded, skipping...');
}

console.log('✅ Theme Manager script loaded');