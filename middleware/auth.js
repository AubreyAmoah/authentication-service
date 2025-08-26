const { verifyAccessToken, extractTokenFromHeader } = require('../utils/jwt');
const { sendError } = require('../utils/response');
const { prisma } = require('../utils/database');
const userService = require('../services/userService');
const roleService = require('../services/roleService');

/**
 * Authenticate user with JWT token
 */
const authenticate = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        const token = extractTokenFromHeader(authHeader);

        if (!token) {
            return sendError(res, 'Access token is required', 401);
        }

        // Verify token
        const decoded = verifyAccessToken(token);

        // Check if session exists and is active
        const session = await prisma.session.findFirst({
            where: {
                token,
                isActive: true,
                expiresAt: { gt: new Date() }
            }
        });

        if (!session) {
            return sendError(res, 'Invalid or expired session', 401);
        }

        // Get user details
        const user = await userService.findUserById(decoded.userId);

        if (!user || !user.isActive) {
            return sendError(res, 'User not found or inactive', 401);
        }

        if (!user.organization?.isActive) {
            return sendError(res, 'Organization is inactive', 401);
        }

        // Add user and session to request
        req.user = user;
        req.session = session;
        req.token = token;

        next();
    } catch (error) {
        console.error('Authentication error:', error);
        return sendError(res, 'Invalid access token', 401);
    }
};

/**
 * Optional authentication - doesn't fail if no token provided
 */
const optionalAuth = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        const token = extractTokenFromHeader(authHeader);

        if (!token) {
            req.user = null;
            return next();
        }

        // Try to authenticate
        const decoded = verifyAccessToken(token);
        const session = await prisma.session.findFirst({
            where: {
                token,
                isActive: true,
                expiresAt: { gt: new Date() }
            }
        });

        if (session) {
            const user = await userService.findUserById(decoded.userId);
            if (user && user.isActive && user.organization?.isActive) {
                req.user = user;
                req.session = session;
                req.token = token;
            }
        }

        next();
    } catch (error) {
        // If optional auth fails, just continue without user
        req.user = null;
        next();
    }
};

/**
 * Require specific permission
 * @param {string} permission - Required permission
 */
const requirePermission = (permission) => {
    return async (req, res, next) => {
        try {
            if (!req.user) {
                return sendError(res, 'Authentication required', 401);
            }

            const hasPermission = await roleService.userHasPermission(
                req.user.id,
                permission,
                req.user.organizationId
            );

            if (!hasPermission) {
                return sendError(res, 'Insufficient permissions', 403);
            }

            next();
        } catch (error) {
            console.error('Permission check error:', error);
            return sendError(res, 'Permission check failed', 500);
        }
    };
};

/**
 * Require any of the specified permissions
 * @param {Array} permissions - Array of permissions (user needs at least one)
 */
const requireAnyPermission = (permissions) => {
    return async (req, res, next) => {
        try {
            if (!req.user) {
                return sendError(res, 'Authentication required', 401);
            }

            let hasAnyPermission = false;

            for (const permission of permissions) {
                const hasPermission = await roleService.userHasPermission(
                    req.user.id,
                    permission,
                    req.user.organizationId
                );

                if (hasPermission) {
                    hasAnyPermission = true;
                    break;
                }
            }

            if (!hasAnyPermission) {
                return sendError(res, 'Insufficient permissions', 403);
            }

            next();
        } catch (error) {
            console.error('Permission check error:', error);
            return sendError(res, 'Permission check failed', 500);
        }
    };
};

/**
 * Require all specified permissions
 * @param {Array} permissions - Array of permissions (user needs all)
 */
const requireAllPermissions = (permissions) => {
    return async (req, res, next) => {
        try {
            if (!req.user) {
                return sendError(res, 'Authentication required', 401);
            }

            for (const permission of permissions) {
                const hasPermission = await roleService.userHasPermission(
                    req.user.id,
                    permission,
                    req.user.organizationId
                );

                if (!hasPermission) {
                    return sendError(res, 'Insufficient permissions', 403);
                }
            }

            next();
        } catch (error) {
            console.error('Permission check error:', error);
            return sendError(res, 'Permission check failed', 500);
        }
    };
};

/**
 * Require specific role
 * @param {string} roleSlug - Required role slug
 */
const requireRole = (roleSlug) => {
    return async (req, res, next) => {
        try {
            if (!req.user) {
                return sendError(res, 'Authentication required', 401);
            }

            const userRoles = req.user.roles || [];
            const hasRole = userRoles.some(role => role.slug === roleSlug);

            if (!hasRole) {
                return sendError(res, `Role '${roleSlug}' required`, 403);
            }

            next();
        } catch (error) {
            console.error('Role check error:', error);
            return sendError(res, 'Role check failed', 500);
        }
    };
};

/**
 * Require user to own the resource or have admin role
 * @param {string} userIdParam - Request parameter name containing user ID
 */
const requireOwnershipOrAdmin = (userIdParam = 'userId') => {
    return async (req, res, next) => {
        try {
            if (!req.user) {
                return sendError(res, 'Authentication required', 401);
            }

            const targetUserId = req.params[userIdParam];
            const isOwner = req.user.id === targetUserId;

            // Check if user has admin role
            const userRoles = req.user.roles || [];
            const isAdmin = userRoles.some(role => role.slug === 'admin');

            if (!isOwner && !isAdmin) {
                return sendError(res, 'Access denied', 403);
            }

            next();
        } catch (error) {
            console.error('Ownership check error:', error);
            return sendError(res, 'Ownership check failed', 500);
        }
    };
};

/**
 * Ensure user belongs to the same organization as the resource
 * @param {string} orgIdParam - Request parameter name containing organization ID
 */
const requireSameOrganization = (orgIdParam = 'organizationId') => {
    return async (req, res, next) => {
        try {
            if (!req.user) {
                return sendError(res, 'Authentication required', 401);
            }

            const targetOrgId = req.params[orgIdParam] || req.body[orgIdParam];

            if (req.user.organizationId !== targetOrgId) {
                return sendError(res, 'Access denied - different organization', 403);
            }

            next();
        } catch (error) {
            console.error('Organization check error:', error);
            return sendError(res, 'Organization check failed', 500);
        }
    };
};

/**
 * Rate limiting per user
 * @param {number} maxRequests - Maximum requests per window
 * @param {number} windowMs - Time window in milliseconds
 */
const rateLimitPerUser = (maxRequests = 100, windowMs = 15 * 60 * 1000) => {
    const requests = new Map();

    return (req, res, next) => {
        if (!req.user) {
            return next();
        }

        const userId = req.user.id;
        const now = Date.now();
        const windowStart = now - windowMs;

        // Clean old entries
        if (requests.has(userId)) {
            const userRequests = requests.get(userId);
            requests.set(userId, userRequests.filter(time => time > windowStart));
        }

        // Get current requests for user
        const userRequests = requests.get(userId) || [];

        if (userRequests.length >= maxRequests) {
            return sendError(res, 'Too many requests', 429);
        }

        // Add current request
        userRequests.push(now);
        requests.set(userId, userRequests);

        next();
    };
};

/**
 * Require email verification
 */
const requireEmailVerification = (req, res, next) => {
    if (!req.user) {
        return sendError(res, 'Authentication required', 401);
    }

    if (!req.user.isEmailVerified) {
        return sendError(res, 'Email verification required', 403);
    }

    next();
};

module.exports = {
    authenticate,
    optionalAuth,
    requirePermission,
    requireAnyPermission,
    requireAllPermissions,
    requireRole,
    requireOwnershipOrAdmin,
    requireSameOrganization,
    rateLimitPerUser,
    requireEmailVerification
};