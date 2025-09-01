// Add some interactivity to the welcome page
document.addEventListener('DOMContentLoaded', function() {
    const features = document.querySelectorAll('.feature');
    features.forEach((feature, index) => {
        feature.style.opacity = '0';
        feature.style.transform = 'translateY(20px)';
        setTimeout(() => {
            feature.style.transition = 'all 0.6s ease';
            feature.style.opacity = '1';
            feature.style.transform = 'translateY(0)';
        }, index * 100);
    });

    // Add smooth scrolling for any potential future links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
});