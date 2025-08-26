const userService = require('../services/userService');
const roleService = require('../services/roleService');
const { sendSuccess, sendError, sendPaginated, asyncHandler, getPaginationParams, getSortParams, getSearchParams } = require('../utils/response');

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
        return sendError(res, 'User not found', 404);
    }

    if (existingUser.organizationId !== req.user.organizationId) {
        return sendError(res, 'Access denied', 403);
    }

    const updatedUser = await userService.updateUser(id, req.validatedData);

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
        return sendError(res, 'User not found', 404);
    }

    if (existingUser.organizationId !== req.user.organizationId) {
        return sendError(res, 'Access denied', 403);
    }

    // Prevent self-deactivation
    if (id === req.user.id) {
        return sendError(res, 'Cannot deactivate your own account', 400);
    }

    const user = await userService.deactivateUser(id);

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
        return sendError(res, 'User not found', 404);
    }

    if (existingUser.organizationId !== req.user.organizationId) {
        return sendError(res, 'Access denied', 403);
    }

    const user = await userService.reactivateUser(id);

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
        return sendError(res, 'User not found', 404);
    }

    if (existingUser.organizationId !== req.user.organizationId) {
        return sendError(res, 'Access denied', 403);
    }

    // Prevent self-deletion
    if (id === req.user.id) {
        return sendError(res, 'Cannot delete your own account', 400);
    }

    await userService.deleteUser(id);

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
        return sendError(res, 'User not found', 404);
    }

    if (existingUser.organizationId !== req.user.organizationId) {
        return sendError(res, 'Access denied', 403);
    }

    const userRole = await roleService.assignRoleToUser(id, roleId, req.user.organizationId);

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
        return sendError(res, 'User not found', 404);
    }

    if (existingUser.organizationId !== req.user.organizationId) {
        return sendError(res, 'Access denied', 403);
    }

    await roleService.removeRoleFromUser(id, roleId, req.user.organizationId);

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

    sendPaginated(res, result.users, result.pagination, 'Search results retrieved successfully');
});

/**
 * Get user statistics for organization
 */
const getUserStats = asyncHandler(async (req, res) => {
    const { prisma } = require('../utils/database');

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