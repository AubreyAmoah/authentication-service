const { sendError } = require('../utils/response');

/**
 * Middleware to check if user is a super admin
 */
const requireSuperAdmin = (req, res, next) => {
    if (!req.user) {
        return sendError(res, 'Authentication required', 401);
    }

    if (!req.user.isSuperAdmin) {
        return sendError(res, 'Super admin access required', 403);
    }

    next();
};

/**
 * Middleware to check if user is super admin OR has specific permission
 */
const requireSuperAdminOrPermission = (permission) => {
    return async (req, res, next) => {
        if (!req.user) {
            return sendError(res, 'Authentication required', 401);
        }

        // If user is super admin, allow access
        if (req.user.isSuperAdmin) {
            return next();
        }

        // Otherwise check permission normally
        const { userHasPermission } = require('../services/roleService');

        if (!req.user.organizationId) {
            return sendError(res, 'Access denied', 403);
        }

        const hasPermission = await userHasPermission(
            req.user.id,
            permission,
            req.user.organizationId
        );

        if (!hasPermission) {
            return sendError(res, 'Insufficient permissions', 403);
        }

        next();
    };
};

module.exports = {
    requireSuperAdmin,
    requireSuperAdminOrPermission
};