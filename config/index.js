const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

const config = {
    server: {
        port: parseInt(process.env.PORT) || 3000,
        host: process.env.HOST || 'localhost',
        nodeEnv: process.env.NODE_ENV || 'development'
    },

    database: {
        url: process.env.DATABASE_URL
    },

    jwt: {
        secret: process.env.JWT_SECRET || 'fallback-secret-change-in-production',
        expiresIn: process.env.JWT_EXPIRES_IN || '7d',
        refreshSecret: process.env.JWT_REFRESH_SECRET || 'fallback-refresh-secret',
        refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '30d'
    },

    session: {
        secret: process.env.SESSION_SECRET || 'fallback-session-secret'
    },

    email: {
        smtp: {
            host: process.env.SMTP_HOST,
            port: parseInt(process.env.SMTP_PORT) || 587,
            secure: false,
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASSWORD
            }
        },
        from: {
            email: process.env.FROM_EMAIL,
            name: process.env.FROM_NAME
        }
    },

    oauth: {
        google: {
            clientId: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackUrl: process.env.GOOGLE_CALLBACK_URL
        },
        github: {
            clientId: process.env.GITHUB_CLIENT_ID,
            clientSecret: process.env.GITHUB_CLIENT_SECRET,
            callbackUrl: process.env.GITHUB_CALLBACK_URL
        }
    },

    cors: {
        origin: process.env.CORS_ORIGIN || 'http://localhost:3001',
        credentials: true
    },

    rateLimit: {
        windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
        maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100
    },

    security: {
        bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS) || 12
    },

    tokenExpiry: {
        emailVerification: parseInt(process.env.EMAIL_VERIFICATION_EXPIRES) || 24 * 60, // 24 hours in minutes
        passwordReset: parseInt(process.env.PASSWORD_RESET_EXPIRES) || 60, // 1 hour in minutes
        invitation: parseInt(process.env.INVITATION_EXPIRES) || 7 * 24 * 60 // 7 days in minutes
    },

    frontend: {
        url: process.env.FRONTEND_URL || 'http://localhost:3001'
    },

    mfa: {
        issuer: process.env.MFA_ISSUER || 'Authentication Service',
        serviceName: process.env.MFA_SERVICE_NAME || 'Auth Service'
    }
};

// Validate required configuration
const requiredVars = [
    'DATABASE_URL',
    'JWT_SECRET'
];

const missingVars = requiredVars.filter(varName => !process.env[varName]);

if (missingVars.length > 0) {
    console.error('Missing required environment variables:', missingVars.join(', '));
    process.exit(1);
}

module.exports = config;