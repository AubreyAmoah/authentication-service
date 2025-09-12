const express = require('express');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const passport = require('passport');
const rateLimit = require('express-rate-limit');

// Import configuration and utilities
const { corsConfig, createCorsConfig } = require('./config/cors');
const config = require('./config');
const { connectDatabase } = require('./utils/database');
const { initializeOAuth } = require('./plugins/oauth');
const { errorHandler, notFoundHandler, handleUncaughtException, handleUnhandledRejection } = require('./middleware/errorHandler');
const deviceInfoMiddleware = require('./middleware/deviceInfo');

// Import routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const organizationRoutes = require('./routes/organizations');
const roleRoutes = require('./routes/roles');
const oauthRoutes = require('./routes/oauth');
const mfaRoutes = require('./routes/mfa');
const superAdminRoutes = require('./routes/superAdmin');
const superAdminAuthRoutes = require('./routes/superAdminAuthRoutes');

// Handle uncaught exceptions
process.on('uncaughtException', handleUncaughtException);
process.on('unhandledRejection', handleUnhandledRejection);

// Create Express application
const app = express();

// Trust proxy for accurate IP addresses
app.set('trust proxy', 1);

// Security middleware
app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"]
        }
    }
}));

// CORS configuration
// app.use(cors(config.cors));
// const corsOptions = await createCorsConfig();
app.use(cors(corsConfig));

// Device info middleware
app.use(deviceInfoMiddleware);

// Rate limiting
const limiter = rateLimit({
    windowMs: config.rateLimit.windowMs,
    max: config.rateLimit.maxRequests,
    message: {
        success: false,
        message: 'Too many requests from this IP, please try again later'
    },
    standardHeaders: true,
    legacyHeaders: false
});
app.use(limiter);

// Serve static files from public directory
app.use(express.static(path.join(__dirname, 'public')));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Compression middleware
app.use(compression());

// Logging middleware
if (config.server.nodeEnv === 'development') {
    app.use(morgan('dev'));
} else {
    app.use(morgan('combined'));
}

// Session configuration for OAuth
app.use(session({
    secret: config.session.secret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: config.server.nodeEnv === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Initialize Passport for OAuth
app.use(passport.initialize());
app.use(passport.session());

// Initialize OAuth strategies
initializeOAuth();

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        success: true,
        message: 'Authentication service is running',
        timestamp: new Date().toISOString(),
        version: require('./package.json').version,
        environment: config.server.nodeEnv
    });
});

// Health check GUI (HTML response)
app.get('/health/gui', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'health.html'));
});

// Serve HTML documentation and welcome pages
app.get('/api/docs', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'docs.html'));
});

app.get('/docs', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'documentation.html'));
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/organizations', organizationRoutes);
app.use('/api/roles', roleRoutes);
app.use('/api/oauth', oauthRoutes);
app.use('/api/mfa', mfaRoutes);
app.use('/api/super-admin', superAdminRoutes);
app.use('/api/super/auth', superAdminAuthRoutes);

// 404 handler
app.use(notFoundHandler);

// Error handling middleware (must be last)
app.use(errorHandler);

/**
 * Start the server
 */
const startServer = async () => {
    try {
        // Connect to database
        await connectDatabase();

        // Start server
        const server = app.listen(config.server.port, config.server.host, () => {
            console.log(`
🚀 Authentication Service is running!

📍 Server: http://${config.server.host}:${config.server.port}
📚 API Docs: http://${config.server.host}:${config.server.port}/api/docs
🏥 Health Check: http://${config.server.host}:${config.server.port}/health
🌍 Environment: ${config.server.nodeEnv}
📦 Version: ${require('./package.json').version}

🔐 Available OAuth Providers:
${config.oauth.google.clientId ? '✅ Google OAuth' : '❌ Google OAuth (not configured)'}
${config.oauth.github.clientId ? '✅ GitHub OAuth' : '❌ GitHub OAuth (not configured)'}

📧 Email Service: ${config.email.smtp.host ? '✅ Enabled' : '❌ Disabled (SMTP not configured)'}

⚡ Super Admin Routes: http://${config.server.host}:${config.server.port}/api/super-admin/*
      `);
        });

        // Graceful shutdown
        const gracefulShutdown = (signal) => {
            console.log(`\n📴 Received ${signal}. Shutting down gracefully...`);

            server.close(() => {
                console.log('✅ HTTP server closed');
                process.exit(0);
            });

            // Force close after 30 seconds
            setTimeout(() => {
                console.error('❌ Could not close connections in time, forcefully shutting down');
                process.exit(1);
            }, 30000);
        };

        process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
        process.on('SIGINT', () => gracefulShutdown('SIGINT'));

        return server;
    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
};

// Start the server if this file is run directly
if (require.main === module) {
    startServer();
}

module.exports = { app, startServer };