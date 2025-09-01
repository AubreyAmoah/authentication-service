// Documentation page functionality
document.addEventListener('DOMContentLoaded', function () {
    // Mobile navigation
    createMobileNavToggle();

    // Smooth scrolling for navigation
    initializeNavigation();

    // Code copy functionality
    initializeCodeCopy();

    // Active section highlighting
    initializeScrollSpy();
});

function createMobileNavToggle() {
    const toggleButton = document.createElement('button');
    toggleButton.className = 'mobile-nav-toggle';
    toggleButton.innerHTML = '☰';
    toggleButton.addEventListener('click', function () {
        const sidebar = document.querySelector('.sidebar');
        sidebar.classList.toggle('open');
    });

    document.body.appendChild(toggleButton);

    // Close sidebar when clicking outside on mobile
    document.addEventListener('click', function (event) {
        const sidebar = document.querySelector('.sidebar');
        const toggle = document.querySelector('.mobile-nav-toggle');

        if (window.innerWidth <= 1024 &&
            !sidebar.contains(event.target) &&
            !toggle.contains(event.target)) {
            sidebar.classList.remove('open');
        }
    });
}

function initializeNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');

    navLinks.forEach(link => {
        link.addEventListener('click', function (e) {
            e.preventDefault();

            const targetId = this.getAttribute('href').substring(1);
            const targetElement = document.getElementById(targetId);

            if (targetElement) {
                // Update active nav link
                navLinks.forEach(l => l.classList.remove('active'));
                this.classList.add('active');

                // Smooth scroll to target
                targetElement.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });

                // Close mobile nav if open
                if (window.innerWidth <= 1024) {
                    document.querySelector('.sidebar').classList.remove('open');
                }
            }
        });
    });
}

function initializeCodeCopy() {
    // Copy code functionality is already defined in the HTML
    // This function can be used to add more copy buttons dynamically
    const codeBlocks = document.querySelectorAll('pre code');

    codeBlocks.forEach(block => {
        if (!block.parentElement.parentElement.querySelector('.copy-btn')) {
            const copyBtn = document.createElement('button');
            copyBtn.className = 'copy-btn';
            copyBtn.textContent = 'Copy';
            copyBtn.onclick = () => copyCode(copyBtn);

            // Add to code header if exists, otherwise create one
            let header = block.parentElement.previousElementSibling;
            if (!header || !header.classList.contains('code-header')) {
                header = document.createElement('div');
                header.className = 'code-header';
                header.innerHTML = '<span>Code</span>';
                block.parentElement.parentElement.insertBefore(header, block.parentElement);
            }
            header.appendChild(copyBtn);
        }
    });
}

function copyCode(button) {
    const codeBlock = button.closest('.code-example').querySelector('code');
    const text = codeBlock.textContent;

    navigator.clipboard.writeText(text).then(() => {
        const originalText = button.textContent;
        button.textContent = 'Copied!';
        button.style.background = '#27ae60';

        setTimeout(() => {
            button.textContent = originalText;
            button.style.background = '#3498db';
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy text: ', err);

        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();

        try {
            document.execCommand('copy');
            button.textContent = 'Copied!';
            setTimeout(() => {
                button.textContent = 'Copy';
            }, 2000);
        } catch (err) {
            button.textContent = 'Copy failed';
            setTimeout(() => {
                button.textContent = 'Copy';
            }, 2000);
        }

        document.body.removeChild(textArea);
    });
}

function initializeScrollSpy() {
    const sections = document.querySelectorAll('.section');
    const navLinks = document.querySelectorAll('.nav-link');

    function updateActiveNav() {
        const scrollPosition = window.scrollY + 100; // Offset for header

        let activeSection = null;

        sections.forEach(section => {
            const sectionTop = section.offsetTop;
            const sectionBottom = sectionTop + section.offsetHeight;

            if (scrollPosition >= sectionTop && scrollPosition < sectionBottom) {
                activeSection = section.id;
            }
        });

        // Update navigation
        navLinks.forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('href') === `#${activeSection}`) {
                link.classList.add('active');
            }
        });
    }

    // Throttled scroll event
    let ticking = false;

    function onScroll() {
        if (!ticking) {
            requestAnimationFrame(() => {
                updateActiveNav();
                ticking = false;
            });
            ticking = true;
        }
    }

    window.addEventListener('scroll', onScroll);

    // Initial check
    updateActiveNav();
}

// Add some nice animations for feature cards
function animateFeatureCards() {
    const cards = document.querySelectorAll('.feature-card, .security-item, .faq-item');

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, {
        threshold: 0.1
    });

    cards.forEach(card => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(20px)';
        card.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
        observer.observe(card);
    });
}

// Initialize animations when DOM is loaded
document.addEventListener('DOMContentLoaded', animateFeatureCards);