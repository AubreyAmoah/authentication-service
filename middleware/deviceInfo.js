
const axios = require('axios');
const UAParser = require('ua-parser-js');

/**
 * Middleware to extract comprehensive device and location information
 * 
 * Dependencies required:
 * npm install axios ua-parser-js
 * 
 * Optional: Sign up for ipapi.co or similar service for better geolocation
 */

const deviceInfoMiddleware = async (req, res, next) => {
    try {
        const deviceInfo = {};

        // 1. Get IP Address
        const getClientIP = (req) => {
            return req.ip ||
                req.connection.remoteAddress ||
                req.socket.remoteAddress ||
                (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
                req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
                req.headers['x-real-ip'] ||
                req.headers['x-client-ip'] ||
                req.headers['cf-connecting-ip'] || // Cloudflare
                req.headers['x-forwarded-for'] ||
                '127.0.0.1';
        };

        deviceInfo.ip = getClientIP(req);

        // 2. Parse User Agent
        const userAgent = req.headers['user-agent'] || '';
        const parser = new UAParser(userAgent);
        const uaResult = parser.getResult();

        deviceInfo.userAgent = userAgent;
        deviceInfo.browser = {
            name: uaResult.browser.name || 'Unknown',
            version: uaResult.browser.version || 'Unknown'
        };

        deviceInfo.deviceType = uaResult.device.type ||
            (uaResult.device.model ? 'mobile' : 'desktop');

        deviceInfo.os = {
            name: uaResult.os.name || 'Unknown',
            version: uaResult.os.version || 'Unknown'
        };

        // 3. Get Timezone from headers (if available)
        deviceInfo.timezone = req.headers['timezone'] ||
            req.headers['x-timezone'] ||
            null;

        // 4. Get Location Data (Country, City) from IP
        if (deviceInfo.ip && deviceInfo.ip !== '127.0.0.1' && deviceInfo.ip !== '::1') {
            try {
                // Using ipapi.co (free tier: 30,000 requests/month)
                // Alternative services: ipinfo.io, freegeoip.app, ip-api.com
                const geoResponse = await axios.get(`https://ipapi.co/${deviceInfo.ip}/json/`, {
                    timeout: 5000,
                    headers: {
                        'User-Agent': 'Device-Info-Middleware/1.0'
                    }
                });

                const geoData = geoResponse.data;

                deviceInfo.country = {
                    code: geoData.country_code || null,
                    name: geoData.country_name || null
                };

                deviceInfo.city = geoData.city || null;
                deviceInfo.region = geoData.region || null;

                // If timezone wasn't in headers, use geo data
                if (!deviceInfo.timezone) {
                    deviceInfo.timezone = geoData.timezone || null;
                }

            } catch (geoError) {
                console.warn('Failed to get location data:', geoError.message);

                // Fallback to a simpler service
                try {
                    const fallbackResponse = await axios.get(`http://ip-api.com/json/${deviceInfo.ip}`, {
                        timeout: 3000
                    });

                    const fallbackData = fallbackResponse.data;

                    deviceInfo.country = {
                        code: fallbackData.countryCode || null,
                        name: fallbackData.country || null
                    };

                    deviceInfo.city = fallbackData.city || null;
                    deviceInfo.region = fallbackData.regionName || null;

                    if (!deviceInfo.timezone) {
                        deviceInfo.timezone = fallbackData.timezone || null;
                    }

                } catch (fallbackError) {
                    console.warn('Fallback geolocation also failed:', fallbackError.message);

                    // Set defaults when geolocation fails
                    deviceInfo.country = { code: null, name: null };
                    deviceInfo.city = null;
                    deviceInfo.region = null;
                }
            }
        } else {
            // Local/development environment defaults
            deviceInfo.country = { code: 'LOCAL', name: 'Local Environment' };
            deviceInfo.city = 'Local';
            deviceInfo.region = 'Local';
        }

        // 5. Additional device detection refinements
        if (deviceInfo.deviceType === 'desktop') {
            // Check for tablet indicators in user agent
            const tabletIndicators = /tablet|ipad|playbook|silk/i;
            if (tabletIndicators.test(userAgent)) {
                deviceInfo.deviceType = 'tablet';
            }
        }

        // 6. Enhanced browser detection
        if (deviceInfo.browser.name === 'Unknown') {
            // Manual fallback detection for edge cases
            if (/chrome/i.test(userAgent)) deviceInfo.browser.name = 'Chrome';
            else if (/firefox/i.test(userAgent)) deviceInfo.browser.name = 'Firefox';
            else if (/safari/i.test(userAgent)) deviceInfo.browser.name = 'Safari';
            else if (/edge/i.test(userAgent)) deviceInfo.browser.name = 'Edge';
        }

        // 7. Add timestamp
        deviceInfo.timestamp = new Date().toISOString();

        // Attach to request object
        req.deviceInfo = deviceInfo;

        // Optional: Log the information (remove in production if not needed)
        console.log('Device Info:', JSON.stringify(deviceInfo, null, 2));

        next();

    } catch (error) {
        console.error('Device info middleware error:', error);

        // Create minimal fallback object
        req.deviceInfo = {
            ip: '127.0.0.1',
            userAgent: req.headers['user-agent'] || '',
            browser: { name: 'Unknown', version: 'Unknown' },
            deviceType: 'unknown',
            os: { name: 'Unknown', version: 'Unknown' },
            country: { code: null, name: null },
            city: null,
            region: null,
            timezone: null,
            timestamp: new Date().toISOString()
        };

        next(); // Continue even if middleware fails
    }
};

module.exports = deviceInfoMiddleware;