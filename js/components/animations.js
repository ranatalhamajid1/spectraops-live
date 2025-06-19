// SpectraOps Animations Manager - Fixed Version
console.log('🎬 Animations loading...');

// Check if AnimationManager already exists
if (typeof window.AnimationManager === 'undefined') {
    window.AnimationManager = class AnimationManager {
        constructor() {
            this.observers = [];
            this.initializeAnimations();
        }

        initializeAnimations() {
            this.setupIntersectionObservers();
            this.bindAnimationEvents();
            console.log('🎬 Animations initialized');
        }

        setupIntersectionObservers() {
            const observerOptions = {
                threshold: 0.1,
                rootMargin: '50px 0px -50px 0px'
            };

            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        entry.target.classList.add('animate-fade-in');
                    }
                });
            }, observerOptions);

            // Observe all animatable elements
            document.querySelectorAll('.animate-on-scroll').forEach(el => {
                observer.observe(el);
            });

            this.observers.push(observer);
        }

        bindAnimationEvents() {
            // Button click animations
            document.addEventListener('click', (e) => {
                if (e.target.matches('.btn-primary, .tool-button')) {
                    e.target.classList.add('animate-pulse');
                    setTimeout(() => {
                        e.target.classList.remove('animate-pulse');
                    }, 600);
                }
            });
        }

        fadeIn(element, delay = 0) {
            setTimeout(() => {
                element.style.opacity = '0';
                element.style.transform = 'translateY(20px)';
                element.style.transition = 'all 0.6s ease';
                
                requestAnimationFrame(() => {
                    element.style.opacity = '1';
                    element.style.transform = 'translateY(0)';
                });
            }, delay);
        }

        slideIn(element, direction = 'right', delay = 0) {
            const translateX = direction === 'right' ? '50px' : '-50px';
            
            setTimeout(() => {
                element.style.opacity = '0';
                element.style.transform = `translateX(${translateX})`;
                element.style.transition = 'all 0.6s ease';
                
                requestAnimationFrame(() => {
                    element.style.opacity = '1';
                    element.style.transform = 'translateX(0)';
                });
            }, delay);
        }
    };

    // Initialize only if not already initialized
    if (!window.animationManagerInstance) {
        window.animationManagerInstance = new window.AnimationManager();
        console.log('✅ Animation Manager initialized successfully');
    }
} else {
    console.log('⚠️ Animation Manager already loaded, skipping...');
}

console.log('✅ Animations loaded - v1.0');