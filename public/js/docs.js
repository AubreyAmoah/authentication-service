// API testing functionality for the docs page
async function testEndpoint(url) {
    const responseDiv = document.getElementById('response');
    responseDiv.style.display = 'block';
    responseDiv.textContent = 'Loading...';

    try {
        const response = await fetch(url);
        const data = await response.json();
        responseDiv.textContent = JSON.stringify(data, null, 2);
    } catch (error) {
        responseDiv.textContent = 'Error: ' + error.message;
    }
}

// Count total endpoints and update stats
document.addEventListener('DOMContentLoaded', function () {
    const endpoints = document.querySelectorAll('.endpoint-item');
    const totalEndpointsElement = document.getElementById('total-endpoints');
    if (totalEndpointsElement) {
        totalEndpointsElement.textContent = endpoints.length;
    }

    // Add click handlers for endpoint items to show method details
    endpoints.forEach(endpoint => {
        endpoint.addEventListener('click', function () {
            const method = this.querySelector('.endpoint-method').textContent;
            const name = this.querySelector('.endpoint-name').textContent;

            // Simple visual feedback
            this.style.backgroundColor = '#e3f2fd';
            setTimeout(() => {
                this.style.backgroundColor = '';
            }, 200);

            // You could expand this to show more details about the endpoint
            console.log(`Clicked on ${name}: ${method}`);
        });
    });

    // Add smooth hover effects
    const sections = document.querySelectorAll('.endpoint-section');
    sections.forEach(section => {
        section.addEventListener('mouseenter', function () {
            this.style.transform = 'translateY(-2px)';
        });

        section.addEventListener('mouseleave', function () {
            this.style.transform = 'translateY(0)';
        });
    });
});