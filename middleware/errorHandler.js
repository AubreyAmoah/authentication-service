const { sendError } = require('../utils/response');

/**
 * Handle Prisma errors
 */
const handlePrismaError = (error) => {
    if (error.code) {
        switch (error.code) {
            case 'P2002':
                return {
                    status: 409,
                    message: 'A record with this data already exists'
                };
            case 'P2014':
                return {
                    status: 400,
                    message: 'Invalid relationship data provided'
                };
            case 'P2003':
                return {
                    status: 400,
                    message: 'Foreign key constraint failed'
                };
            case 'P2025':
                return {
                    status: 404,
                    message: 'Record not found'
                };
            default:
                return {
                    status: 500,
                    message: 'Database operation failed'
                };
        }
    }

    return {
        status: 500,
        message: 'Database error occurred'
    };
};

/**
 * Handle JWT errors
 */
const handleJWTError = (error) => {
    if (error.name === 'JsonWebTokenError') {
        return {
            status: 401,
            message: 'Invalid token'
        };
    }

    if (error.name === 'TokenExpiredError') {
        return {
            status: 401,
            message: 'Token has expired'
        };
    }

    return {
        status: 401,
        message: 'Authentication failed'
    };
};

/**
 * Main error handling middleware
 */
const errorHandler = (error, req, res, next) => {
    console.error('Error occurred:', {
        message: error.message,
        stack: error.stack,
        url: req.url,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent')
    });

    let status = 500;
    let message = 'Internal Server Error';

    // Handle known error types
    if (error.name === 'PrismaClientKnownRequestError' || error.name === 'PrismaClientValidationError') {
        const prismaError = handlePrismaError(error);
        status = prismaError.status;
        message = prismaError.message;
    } else if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
        const jwtError = handleJWTError(error);
        status = jwtError.status;
        message = jwtError.message;
    } else if (error.name === 'ValidationError') {
        status = 400;
        message = error.message;
    } else if (error.status) {
        status = error.status;
        message = error.message;
    } else if (error.message) {
        // For custom thrown errors with messages
        if (error.message.includes('not found')) {
            status = 404;
        } else if (error.message.includes('already exists') || error.message.includes('duplicate')) {
            status = 409;
        } else if (error.message.includes('unauthorized') || error.message.includes('invalid')) {
            status = 401;
        } else if (error.message.includes('forbidden') || error.message.includes('permission')) {
            status = 403;
        } else if (error.message.includes('validation') || error.message.includes('required')) {
            status = 400;
        }
        message = error.message;
    }

    sendError(res, message, status);
};

/**
 * 404 handler for undefined routes
 */
const notFoundHandler = (req, res) => {
    sendError(res, `Route ${req.method} ${req.originalUrl} not found`, 404);
};

/**
 * Handle uncaught exceptions
 */
const handleUncaughtException = (error) => {
    console.error('Uncaught Exception:', error);
    process.exit(1);
};

/**
 * Handle unhandled promise rejections
 */
const handleUnhandledRejection = (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
};

module.exports = {
    errorHandler,
    notFoundHandler,
    handleUncaughtException,
    handleUnhandledRejection
};