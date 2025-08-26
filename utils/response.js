/**
 * Send success response
 * @param {Object} res - Express response object
 * @param {*} data - Response data
 * @param {string} message - Success message
 * @param {number} statusCode - HTTP status code
 */
const sendSuccess = (res, data = null, message = 'Success', statusCode = 200) => {
    return res.status(statusCode).json({
        success: true,
        message,
        data,
        timestamp: new Date().toISOString()
    });
};

/**
 * Send error response
 * @param {Object} res - Express response object
 * @param {string} message - Error message
 * @param {number} statusCode - HTTP status code
 * @param {*} errors - Detailed errors
 */
const sendError = (res, message = 'Internal Server Error', statusCode = 500, errors = null) => {
    const response = {
        success: false,
        message,
        timestamp: new Date().toISOString()
    };

    if (errors) {
        response.errors = errors;
    }

    // Don't expose sensitive error details in production
    if (process.env.NODE_ENV === 'production' && statusCode === 500) {
        response.message = 'Internal Server Error';
    }

    return res.status(statusCode).json(response);
};

/**
 * Send paginated response
 * @param {Object} res - Express response object
 * @param {Array} data - Response data
 * @param {Object} pagination - Pagination metadata
 * @param {string} message - Success message
 */
const sendPaginated = (res, data, pagination, message = 'Success') => {
    return res.status(200).json({
        success: true,
        message,
        data,
        pagination: {
            page: pagination.page,
            limit: pagination.limit,
            total: pagination.total,
            totalPages: Math.ceil(pagination.total / pagination.limit),
            hasNext: pagination.page < Math.ceil(pagination.total / pagination.limit),
            hasPrev: pagination.page > 1
        },
        timestamp: new Date().toISOString()
    });
};

/**
 * Send authentication response with tokens
 * @param {Object} res - Express response object
 * @param {Object} user - User data
 * @param {Object} tokens - Access and refresh tokens
 * @param {string} message - Success message
 */
const sendAuthResponse = (res, user, tokens, message = 'Authentication successful') => {
    return res.status(200).json({
        success: true,
        message,
        data: {
            user: {
                id: user.id,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                avatar: user.avatar,
                isEmailVerified: user.isEmailVerified,
                organization: user.organization ? {
                    id: user.organization.id,
                    name: user.organization.name,
                    slug: user.organization.slug
                } : null,
                roles: user.roles || []
            },
            tokens
        },
        timestamp: new Date().toISOString()
    });
};

/**
 * Create pagination parameters from query
 * @param {Object} query - Query parameters
 * @returns {Object} - Pagination parameters
 */
const getPaginationParams = (query) => {
    const page = Math.max(1, parseInt(query.page) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(query.limit) || 10));
    const skip = (page - 1) * limit;

    return { page, limit, skip };
};

/**
 * Create sort parameters from query
 * @param {Object} query - Query parameters
 * @param {Array} allowedFields - Allowed sort fields
 * @returns {Object} - Sort parameters for Prisma
 */
const getSortParams = (query, allowedFields = ['createdAt']) => {
    const sortBy = query.sortBy || 'createdAt';
    const sortOrder = query.sortOrder === 'asc' ? 'asc' : 'desc';

    // Validate sort field
    if (!allowedFields.includes(sortBy)) {
        return { createdAt: 'desc' };
    }

    return { [sortBy]: sortOrder };
};

/**
 * Create search parameters from query
 * @param {Object} query - Query parameters
 * @param {Array} searchFields - Fields to search in
 * @returns {Object} - Search parameters for Prisma
 */
const getSearchParams = (query, searchFields = []) => {
    const search = query.search?.trim();

    if (!search || searchFields.length === 0) {
        return {};
    }

    return {
        OR: searchFields.map(field => ({
            [field]: {
                contains: search,
                mode: 'insensitive'
            }
        }))
    };
};

/**
 * Handle async controller errors
 * @param {Function} fn - Async controller function
 * @returns {Function} - Wrapped controller with error handling
 */
const asyncHandler = (fn) => {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
};

/**
 * Standard error codes
 */
const ERROR_CODES = {
    VALIDATION_ERROR: 400,
    UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    CONFLICT: 409,
    RATE_LIMITED: 429,
    INTERNAL_ERROR: 500
};

/**
 * Standard success codes
 */
const SUCCESS_CODES = {
    OK: 200,
    CREATED: 201,
    ACCEPTED: 202,
    NO_CONTENT: 204
};

module.exports = {
    sendSuccess,
    sendError,
    sendPaginated,
    sendAuthResponse,
    getPaginationParams,
    getSortParams,
    getSearchParams,
    asyncHandler,
    ERROR_CODES,
    SUCCESS_CODES
};