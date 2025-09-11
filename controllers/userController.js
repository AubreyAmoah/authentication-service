const userService = require('../services/userService');
const roleService = require('../services/roleService');
const { sendSuccess, sendError, sendPaginated, asyncHandler, getPaginationParams, getSortParams, getSearchParams } = require('../utils/response');
const prisma = require('../utils/database');
const { AUDIT_ACTIONS } = require('../config/constants');
/**
 * Get all users in organization
 */
const getUsers = asyncHandler(async (req, res) => {
    const { page, limit, skip } = getPaginationParams(req.query);
    const { search, sortBy, sortOrder } = req.query;

    const result = await userService.getOrganizationUsers(req.user.organizationId, {
        page,
        limit,
        search,
        sortBy,
        sortOrder
    });

    sendPaginated(res, result.users, result.pagination, 'Users retrieved successfully');
});

/**
 * Get specific user by ID
 */
const getUserById = asyncHandler(async (req, res) => {
    const { id } = req.params;

    const user = await userService.findUserById(id);

    if (!user) {
        return sendError(res, 'User not found', 404);
    }

    // Check if user belongs to the same organization
    if (user.organizationId !== req.user.organizationId) {
        return sendError(res, 'Access denied', 403);
    }

    sendSuccess(res, { user }, 'User retrieved successfully');
});

/**
 * Update user profile (admin only)
 */
const updateUser = asyncHandler(async (req, res) => {
    const { id } = req.params;

    // Check if user exists and belongs to same organization
    const existingUser = await userService.findUserById(id);

    if (!existingUser) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.USER_UPDATED,
                userId: req.user.id,
                ipAddress: req.deviceInfo.ip || null,
                userAgent: req.deviceInfo.userAgent || null,
                deviceType: req.deviceInfo.deviceType || null,
                country: req.deviceInfo.country.name || null,
                city: req.deviceInfo.city || null,
                riskLevel: RISK_LEVELS.MEDIUM,
                timestamp: new Date(),
                user: { connect: { id: req.user.id } },
                details: {
                    userId: id,
                    organizationId: null,
                    email: null,
                    info: 'Attempted to update non-existent user'
                }
            }
        });
        return sendError(res, 'User not found', 404);
    }

    if (existingUser.organizationId !== req.user.organizationId) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.USER_UPDATED,
                userId: req.user.id,
                ipAddress: req.deviceInfo.ip || null,
                userAgent: req.deviceInfo.userAgent || null,
                deviceType: req.deviceInfo.deviceType || null,
                country: req.deviceInfo.country.name || null,
                city: req.deviceInfo.city || null,
                riskLevel: RISK_LEVELS.MEDIUM,
                timestamp: new Date(),
                user: { connect: { id: req.user.id } },
                details: {
                    userId: existingUser.id,
                    organizationId: existingUser.organizationId || null,
                    email: existingUser.email,
                    info: 'Attempted to update user from a different organization'
                }
            }
        });
        return sendError(res, 'Access denied', 403);
    }

    const updatedUser = await userService.updateUser(id, req.validatedData);

    await prisma.auditLog.create({
        data: {
            action: AUDIT_ACTIONS.USER_UPDATED,
            userId: req.user.id,
            ipAddress: req.deviceInfo.ip || null,
            userAgent: req.deviceInfo.userAgent || null,
            deviceType: req.deviceInfo.deviceType || null,
            country: req.deviceInfo.country.name || null,
            city: req.deviceInfo.city || null,
            riskLevel: RISK_LEVELS.LOW,
            timestamp: new Date(),
            user: { connect: { id: req.user.id } },
            details: {
                userId: updatedUser.id,
                organizationId: updatedUser.organizationId || null,
                email: updatedUser.email,
                info: 'User profile updated'
            }
        }
    });

    sendSuccess(res, { user: updatedUser }, 'User updated successfully');


});

/**
 * Deactivate user
 */
const deactivateUser = asyncHandler(async (req, res) => {
    const { id } = req.params;

    // Check if user exists and belongs to same organization
    const existingUser = await userService.findUserById(id);

    if (!existingUser) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.USER_DEACTIVATED,
                userId: req.user.id,
                ipAddress: req.deviceInfo.ip || null,
                userAgent: req.deviceInfo.userAgent || null,
                deviceType: req.deviceInfo.deviceType || null,
                country: req.deviceInfo.country.name || null,
                city: req.deviceInfo.city || null,
                riskLevel: RISK_LEVELS.MEDIUM,
                timestamp: new Date(),
                user: { connect: { id: req.user.id } },
                details: {
                    userId: id,
                    organizationId: null,
                    email: null,
                    info: 'Attempted to deactivate non-existent user'
                }
            }
        });
        return sendError(res, 'User not found', 404);
    }

    if (existingUser.organizationId !== req.user.organizationId) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.USER_DEACTIVATED,
                userId: req.user.id,
                ipAddress: req.deviceInfo.ip || null,
                userAgent: req.deviceInfo.userAgent || null,
                deviceType: req.deviceInfo.deviceType || null,
                country: req.deviceInfo.country.name || null,
                city: req.deviceInfo.city || null,
                riskLevel: RISK_LEVELS.MEDIUM,
                timestamp: new Date(),
                user: { connect: { id: req.user.id } },
                details: {
                    userId: existingUser.id,
                    organizationId: existingUser.organizationId || null,
                    email: existingUser.email,
                    info: 'Attempted to deactivate user from a different organization'
                }
            }
        });
        return sendError(res, 'Access denied', 403);
    }

    // Prevent self-deactivation
    if (id === req.user.id) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.USER_DEACTIVATED,
                userId: req.user.id,
                ipAddress: req.deviceInfo.ip || null,
                userAgent: req.deviceInfo.userAgent || null,
                deviceType: req.deviceInfo.deviceType || null,
                country: req.deviceInfo.country.name || null,
                city: req.deviceInfo.city || null,
                riskLevel: RISK_LEVELS.MEDIUM,
                timestamp: new Date(),
                user: { connect: { id: req.user.id } },
                details: {
                    userId: req.user.id,
                    organizationId: req.user.organizationId || null,
                    email: req.user.email,
                    info: 'Attempted to deactivate own account'
                }
            }
        });
        return sendError(res, 'Cannot deactivate your own account', 400);
    }

    const user = await userService.deactivateUser(id);

    await prisma.auditLog.create({
        data: {
            action: AUDIT_ACTIONS.USER_DEACTIVATED,
            userId: req.user.id,
            ipAddress: req.deviceInfo.ip || null,
            userAgent: req.deviceInfo.userAgent || null,
            deviceType: req.deviceInfo.deviceType || null,
            country: req.deviceInfo.country.name || null,
            city: req.deviceInfo.city || null,
            riskLevel: RISK_LEVELS.MEDIUM,
            timestamp: new Date(),
            user: { connect: { id: req.user.id } },
            details: {
                userId: user.id,
                organizationId: user.organizationId || null,
                email: user.email,
                info: 'User deactivated'
            }
        }
    });

    sendSuccess(res, { user }, 'User deactivated successfully');
});

/**
 * Reactivate user
 */
const reactivateUser = asyncHandler(async (req, res) => {
    const { id } = req.params;

    // Check if user exists and belongs to same organization
    const existingUser = await userService.findUserById(id);

    if (!existingUser) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.UNAUTHORIZED_ACCESS,
                userId: req.user.id,
                ipAddress: req.deviceInfo.ip || null,
                userAgent: req.deviceInfo.userAgent || null,
                deviceType: req.deviceInfo.deviceType || null,
                country: req.deviceInfo.country.name || null,
                city: req.deviceInfo.city || null,
                riskLevel: RISK_LEVELS.MEDIUM,
                timestamp: new Date(),
                user: { connect: { id: req.user.id } },
                details: {
                    userId: id,
                    organizationId: null,
                    email: null,
                    info: 'Attempted to reactivate non-existent user'
                }
            }
        });
        return sendError(res, 'User not found', 404);
    }

    if (existingUser.organizationId !== req.user.organizationId) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.UNAUTHORIZED_ACCESS,
                userId: req.user.id,
                ipAddress: req.deviceInfo.ip || null,
                userAgent: req.deviceInfo.userAgent || null,
                deviceType: req.deviceInfo.deviceType || null,
                country: req.deviceInfo.country.name || null,
                city: req.deviceInfo.city || null,
                riskLevel: RISK_LEVELS.MEDIUM,
                timestamp: new Date(),
                user: { connect: { id: req.user.id } },
                details: {
                    userId: existingUser.id,
                    organizationId: existingUser.organizationId || null,
                    email: existingUser.email,
                    info: 'Attempted to reactivate user from a different organization'
                }
            }
        });
        return sendError(res, 'Access denied', 403);
    }

    const user = await userService.reactivateUser(id);

    await prisma.auditLog.create({
        data: {
            action: AUDIT_ACTIONS.USER_REACTIVATED,
            userId: req.user.id,
            ipAddress: req.deviceInfo.ip || null,
            userAgent: req.deviceInfo.userAgent || null,
            deviceType: req.deviceInfo.deviceType || null,
            country: req.deviceInfo.country.name || null,
            city: req.deviceInfo.city || null,
            riskLevel: RISK_LEVELS.MEDIUM,
            timestamp: new Date(),
            user: { connect: { id: req.user.id } },
            details: {
                userId: user.id,
                organizationId: user.organizationId || null,
                email: user.email,
                info: 'User reactivated'
            }
        }
    });

    sendSuccess(res, { user }, 'User reactivated successfully');
});

/**
 * Delete user
 */
const deleteUser = asyncHandler(async (req, res) => {
    const { id } = req.params;

    // Check if user exists and belongs to same organization
    const existingUser = await userService.findUserById(id);

    if (!existingUser) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.UNAUTHORIZED_ACCESS,
                userId: req.user.id,
                ipAddress: req.deviceInfo.ip || null,
                userAgent: req.deviceInfo.userAgent || null,
                deviceType: req.deviceInfo.deviceType || null,
                country: req.deviceInfo.country.name || null,
                city: req.deviceInfo.city || null,
                riskLevel: RISK_LEVELS.MEDIUM,
                timestamp: new Date(),
                user: { connect: { id: req.user.id } },
                details: {
                    userId: id,
                    organizationId: null,
                    email: null,
                    info: 'Attempted to delete non-existent user'
                }
            }
        });
        return sendError(res, 'User not found', 404);
    }

    if (existingUser.organizationId !== req.user.organizationId) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.UNAUTHORIZED_ACCESS,
                userId: req.user.id,
                ipAddress: req.deviceInfo.ip || null,
                userAgent: req.deviceInfo.userAgent || null,
                deviceType: req.deviceInfo.deviceType || null,
                country: req.deviceInfo.country.name || null,
                city: req.deviceInfo.city || null,
                riskLevel: RISK_LEVELS.MEDIUM,
                timestamp: new Date(),
                user: { connect: { id: req.user.id } },
                details: {
                    userId: existingUser.id,
                    organizationId: existingUser.organizationId || null,
                    email: existingUser.email,
                    info: 'Attempted to delete user from a different organization'
                }
            }
        });
        return sendError(res, 'Access denied', 403);
    }

    // Prevent self-deletion
    if (id === req.user.id) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.UNAUTHORIZED_ACCESS,
                userId: req.user.id,
                ipAddress: req.deviceInfo.ip || null,
                userAgent: req.deviceInfo.userAgent || null,
                deviceType: req.deviceInfo.deviceType || null,
                country: req.deviceInfo.country.name || null,
                city: req.deviceInfo.city || null,
                riskLevel: RISK_LEVELS.MEDIUM,
                timestamp: new Date(),
                user: { connect: { id: req.user.id } },
                details: {
                    userId: req.user.id,
                    organizationId: req.user.organizationId || null,
                    email: req.user.email,
                    info: 'Attempted to delete own account'
                }
            }
        });
        return sendError(res, 'Cannot delete your own account', 400);
    }

    await userService.deleteUser(id);

    await prisma.auditLog.create({
        data: {
            action: AUDIT_ACTIONS.USER_DELETED,
            userId: req.user.id,
            ipAddress: req.deviceInfo.ip || null,
            userAgent: req.deviceInfo.userAgent || null,
            deviceType: req.deviceInfo.deviceType || null,
            country: req.deviceInfo.country.name || null,
            city: req.deviceInfo.city || null,
            riskLevel: RISK_LEVELS.MEDIUM,
            timestamp: new Date(),
            user: { connect: { id: req.user.id } },
            details: {
                userId: existingUser.id,
                organizationId: existingUser.organizationId || null,
                email: existingUser.email,
                info: 'User deleted'
            }
        }
    });

    sendSuccess(res, null, 'User deleted successfully');
});

/**
 * Get user roles
 */
const getUserRoles = asyncHandler(async (req, res) => {
    const { id } = req.params;

    // Check if user exists and belongs to same organization
    const existingUser = await userService.findUserById(id);

    if (!existingUser) {
        return sendError(res, 'User not found', 404);
    }

    if (existingUser.organizationId !== req.user.organizationId) {
        return sendError(res, 'Access denied', 403);
    }

    const roles = await roleService.getUserRoles(id, req.user.organizationId);

    sendSuccess(res, { roles }, 'User roles retrieved successfully');
});

/**
 * Assign role to user
 */
const assignRole = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { roleId } = req.validatedData;

    // Check if user exists and belongs to same organization
    const existingUser = await userService.findUserById(id);

    if (!existingUser) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.UNAUTHORIZED_ACCESS,
                userId: req.user.id,
                ipAddress: req.deviceInfo.ip || null,
                userAgent: req.deviceInfo.userAgent || null,
                deviceType: req.deviceInfo.deviceType || null,
                country: req.deviceInfo.country.name || null,
                city: req.deviceInfo.city || null,
                riskLevel: RISK_LEVELS.MEDIUM,
                timestamp: new Date(),
                user: { connect: { id: req.user.id } },
                details: {
                    userId: id,
                    organizationId: null,
                    email: null,
                    info: 'Attempted to assign role to non-existent user'
                }
            }
        });
        return sendError(res, 'User not found', 404);
    }

    if (existingUser.organizationId !== req.user.organizationId) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.UNAUTHORIZED_ACCESS,
                userId: req.user.id,
                ipAddress: req.deviceInfo.ip || null,
                userAgent: req.deviceInfo.userAgent || null,
                deviceType: req.deviceInfo.deviceType || null,
                country: req.deviceInfo.country.name || null,
                city: req.deviceInfo.city || null,
                riskLevel: RISK_LEVELS.MEDIUM,
                timestamp: new Date(),
                user: { connect: { id: req.user.id } },
                details: {
                    userId: existingUser.id,
                    organizationId: existingUser.organizationId || null,
                    email: existingUser.email,
                    info: 'Attempted to assign role to user from a different organization'
                }
            }
        });
        return sendError(res, 'Access denied', 403);
    }

    const userRole = await roleService.assignRoleToUser(id, roleId, req.user.organizationId);

    await prisma.auditLog.create({
        data: {
            action: AUDIT_ACTIONS.ROLE_ASSIGNED,
            userId: req.user.id,
            ipAddress: req.deviceInfo.ip || null,
            userAgent: req.deviceInfo.userAgent || null,
            deviceType: req.deviceInfo.deviceType || null,
            country: req.deviceInfo.country.name || null,
            city: req.deviceInfo.city || null,
            riskLevel: RISK_LEVELS.LOW,
            timestamp: new Date(),
            user: { connect: { id: req.user.id } },
            details: {
                userId: existingUser.id,
                organizationId: existingUser.organizationId || null,
                email: existingUser.email,
                info: `Role ID ${roleId} assigned to user`
            }
        }
    });

    sendSuccess(res, { userRole }, 'Role assigned successfully');
});

/**
 * Remove role from user
 */
const removeRole = asyncHandler(async (req, res) => {
    const { id, roleId } = req.params;

    // Check if user exists and belongs to same organization
    const existingUser = await userService.findUserById(id);

    if (!existingUser) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.UNAUTHORIZED_ACCESS,
                userId: req.user.id,
                ipAddress: req.deviceInfo.ip || null,
                userAgent: req.deviceInfo.userAgent || null,
                deviceType: req.deviceInfo.deviceType || null,
                country: req.deviceInfo.country.name || null,
                city: req.deviceInfo.city || null,
                riskLevel: RISK_LEVELS.MEDIUM,
                timestamp: new Date(),
                user: { connect: { id: req.user.id } },
                details: {
                    userId: id,
                    organizationId: null,
                    email: null,
                    info: 'Attempted to remove role from non-existent user'
                }
            }
        });
        return sendError(res, 'User not found', 404);
    }

    if (existingUser.organizationId !== req.user.organizationId) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.UNAUTHORIZED_ACCESS,
                userId: req.user.id,
                ipAddress: req.deviceInfo.ip || null,
                userAgent: req.deviceInfo.userAgent || null,
                deviceType: req.deviceInfo.deviceType || null,
                country: req.deviceInfo.country.name || null,
                city: req.deviceInfo.city || null,
                riskLevel: RISK_LEVELS.MEDIUM,
                timestamp: new Date(),
                user: { connect: { id: req.user.id } },
                details: {
                    userId: existingUser.id,
                    organizationId: existingUser.organizationId || null,
                    email: existingUser.email,
                    info: 'Attempted to remove role from user from a different organization'
                }
            }
        });
        return sendError(res, 'Access denied', 403);
    }

    await roleService.removeRoleFromUser(id, roleId, req.user.organizationId);

    await prisma.auditLog.create({
        data: {
            action: AUDIT_ACTIONS.ROLE_REMOVED,
            userId: req.user.id,
            ipAddress: req.deviceInfo.ip || null,
            userAgent: req.deviceInfo.userAgent || null,
            deviceType: req.deviceInfo.deviceType || null,
            country: req.deviceInfo.country.name || null,
            city: req.deviceInfo.city || null,
            riskLevel: RISK_LEVELS.LOW,
            timestamp: new Date(),
            user: { connect: { id: req.user.id } },
            details: {
                userId: existingUser.id,
                organizationId: existingUser.organizationId || null,
                email: existingUser.email,
                info: `Role ID ${roleId} removed from user`
            }
        }
    });

    sendSuccess(res, null, 'Role removed successfully');
});

/**
 * Search users
 */
const searchUsers = asyncHandler(async (req, res) => {
    const { q: search } = req.query;
    const { page, limit } = getPaginationParams(req.query);

    if (!search || search.trim().length < 2) {
        return sendError(res, 'Search query must be at least 2 characters', 400);
    }

    const result = await userService.getOrganizationUsers(req.user.organizationId, {
        page,
        limit,
        search: search.trim(),
        sortBy: 'firstName',
        sortOrder: 'asc'
    });
    await prisma.auditLog.create({
        data: {
            action: AUDIT_ACTIONS.USER_SEARCHED,
            userId: req.user.id,
            ipAddress: req.deviceInfo.ip || null,
            userAgent: req.deviceInfo.userAgent || null,
            deviceType: req.deviceInfo.deviceType || null,
            country: req.deviceInfo.country.name || null,
            city: req.deviceInfo.city || null,
            riskLevel: RISK_LEVELS.LOW,
            timestamp: new Date(),
            user: { connect: { id: req.user.id } },
            details: {
                userId: req.user.id,
                organizationId: req.user.organizationId || null,
                email: req.user.email,
                info: `Searched users with query: ${search.trim()}`
            }

        }
    });

    sendPaginated(res, result.users, result.pagination, 'Search results retrieved successfully');
});

/**
 * Get user statistics for organization
 */
const getUserStats = asyncHandler(async (req, res) => {
    const [
        totalUsers,
        activeUsers,
        verifiedUsers,
        recentLogins
    ] = await Promise.all([
        prisma.user.count({
            where: { organizationId: req.user.organizationId }
        }),
        prisma.user.count({
            where: {
                organizationId: req.user.organizationId,
                isActive: true
            }
        }),
        prisma.user.count({
            where: {
                organizationId: req.user.organizationId,
                isEmailVerified: true
            }
        }),
        prisma.user.count({
            where: {
                organizationId: req.user.organizationId,
                lastLoginAt: {
                    gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // Last 30 days
                }
            }
        })
    ]);

    const stats = {
        total: totalUsers,
        active: activeUsers,
        inactive: totalUsers - activeUsers,
        verified: verifiedUsers,
        unverified: totalUsers - verifiedUsers,
        recentLogins
    };

    sendSuccess(res, { stats }, 'User statistics retrieved successfully');
});

module.exports = {
    getUsers,
    getUserById,
    updateUser,
    deactivateUser,
    reactivateUser,
    deleteUser,
    getUserRoles,
    assignRole,
    removeRole,
    searchUsers,
    getUserStats
};