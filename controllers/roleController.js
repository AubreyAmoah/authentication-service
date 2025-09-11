const roleService = require('../services/roleService');
const { sendSuccess, sendError, sendPaginated, asyncHandler, getPaginationParams } = require('../utils/response');
const prisma = require('../utils/database')

/**
 * Get all roles for current organization
 */
const getRoles = asyncHandler(async (req, res) => {
    const { page, limit } = getPaginationParams(req.query);
    const { search, sortBy, sortOrder } = req.query;
    const result = await roleService.getOrganizationRoles(req.user.organizationId, {
        page,
        limit,
        search,
        sortBy,
        sortOrder
    });

    sendPaginated(res, result.roles, result.pagination, 'Roles retrieved successfully');
});

/**
 * Get specific role by ID
 */
const getRoleById = asyncHandler(async (req, res) => {
    const { id } = req.params;

    const role = await roleService.findRoleById(id, req.user.organizationId);

    if (!role) {
        return sendError(res, 'Role not found', 404);
    }

    sendSuccess(res, { role }, 'Role retrieved successfully');
});

/**
 * Create new role
 */
const createRole = asyncHandler(async (req, res) => {
    const role = await roleService.createRole(req.validatedData, req.user.organizationId);

    await prisma.auditLog.create({
        data: {
            action: 'ROLE_CREATED',
            ipAddress: req.ip || null,
            userAgent: req.headers['user-agent'] || null,
            deviceType: req.deviceType || null,
            country: req.country ? req.country.name : null,
            city: req.city ? req.city.name : null,
            riskLevel: 'LOW',
            timestamp: new Date(),
            user: { connect: { id: req.user.id } },
            details: {
                userId: req.user.id,
                organizationId: req.user.organizationId || null,
                roleId: role.id,
                roleName: role.name,
                info: 'Role created successfully'
            }
        }
    });
    sendSuccess(res, { role }, 'Role created successfully', 201);
});

/**
 * Update role
 */
const updateRole = asyncHandler(async (req, res) => {
    const { id } = req.params;

    // Check if role exists
    const existingRole = await roleService.findRoleById(id, req.user.organizationId);

    if (!existingRole) {
        await prisma.auditLog.create({
            data: {
                action: 'ROLE_UPDATED',
                ipAddress: req.ip || null,
                userAgent: req.headers['user-agent'] || null,
                deviceType: req.deviceType || null,
                country: req.country ? req.country.name : null,
                city: req.city ? req.city.name : null,
                riskLevel: 'LOW',
                timestamp: new Date(),
                user: { connect: { id: req.user.id } },
                details: {
                    userId: req.user.id,
                    organizationId: req.user.organizationId || null,
                    roleId: id,
                    info: 'Failed role update attempt - role not found'
                }
            }
        });
        return sendError(res, 'Role not found', 404);
    }

    // Prevent updating default role
    if (existingRole.isDefault) {
        await prisma.auditLog.create({
            data: {
                action: 'ROLE_UPDATED',
                ipAddress: req.ip || null,
                userAgent: req.headers['user-agent'] || null,
                deviceType: req.deviceType || null,
                country: req.country ? req.country.name : null,
                city: req.city ? req.city.name : null,
                riskLevel: 'LOW',
                timestamp: new Date(),
                user: { connect: { id: req.user.id } },
                details: {
                    userId: req.user.id,
                    organizationId: req.user.organizationId || null,
                    roleId: id,
                    info: 'Failed role update attempt - cannot modify default role'
                }
            }
        });
        return sendError(res, 'Cannot modify default role', 400);
    }

    const updatedRole = await roleService.updateRole(id, req.user.organizationId, req.validatedData);
    await prisma.auditLog.create({
        data: {
            action: 'ROLE_UPDATED',
            ipAddress: req.ip || null,
            userAgent: req.headers['user-agent'] || null,
            deviceType: req.deviceType || null,
            country: req.country ? req.country.name : null,
            city: req.city ? req.city.name : null,
            riskLevel: 'LOW',
            timestamp: new Date(),
            user: { connect: { id: req.user.id } },
            details: {
                userId: req.user.id,
                organizationId: req.user.organizationId || null,
                roleId: updatedRole.id,
                roleName: updatedRole.name,
                info: 'Role updated successfully'
            }
        }
    });
    sendSuccess(res, { role: updatedRole }, 'Role updated successfully');
});

/**
 * Delete role
 */
const deleteRole = asyncHandler(async (req, res) => {
    const { id } = req.params;

    await roleService.deleteRole(id, req.user.organizationId);

    await prisma.auditLog.create({
        data: {
            action: 'ROLE_DELETED',
            ipAddress: req.deviceInfo.ip || null,
            userAgent: req.deviceInfo.userAgent || null,
            deviceType: req.deviceInfo.deviceType || null,
            country: req.deviceInfo.country.name || null,
            city: req.deviceInfo.city || null,
            riskLevel: 'LOW',
            timestamp: new Date(),
            user: { connect: { id: req.user.id } },
            details: {
                userId: req.user.id,
                organizationId: req.user.organizationId || null,
                roleId: id,
                info: 'Role deleted successfully'
            }
        }
    });

    sendSuccess(res, null, 'Role deleted successfully');
});

/**
 * Get users assigned to a role
 */
const getRoleUsers = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { page, limit } = getPaginationParams(req.query);
    const { search } = req.query;

    // Check if role exists
    const role = await roleService.findRoleById(id, req.user.organizationId);

    if (!role) {
        return sendError(res, 'Role not found', 404);
    }

    const result = await roleService.getRoleUsers(id, req.user.organizationId, {
        page,
        limit,
        search
    });

    sendPaginated(res, result.users, result.pagination, 'Role users retrieved successfully');
});

/**
 * Assign role to user
 */
const assignRoleToUser = asyncHandler(async (req, res) => {
    const { userId, roleId } = req.validatedData;

    const userRole = await roleService.assignRoleToUser(userId, roleId, req.user.organizationId);

    await prisma.auditLog.create({
        data: {
            action: 'ROLE_ASSIGNED',
            ipAddress: req.deviceInfo.ip || null,
            userAgent: req.deviceInfo.userAgent || null,
            deviceType: req.deviceInfo.deviceType || null,
            country: req.deviceInfo.country.name || null,
            city: req.deviceInfo.city || null,
            riskLevel: 'LOW',
            timestamp: new Date(),
            user: { connect: { id: req.user.id } },
            details: {
                userId: req.user.id,
                organizationId: req.user.organizationId || null,
                assignedUserId: userRole.userId,
                roleId: userRole.roleId,
                info: 'Role assigned to user successfully'
            }
        }
    });
    sendSuccess(res, { userRole }, 'Role assigned to user successfully');
});

/**
 * Remove role from user
 */
const removeRoleFromUser = asyncHandler(async (req, res) => {
    const { userId, roleId } = req.params;

    await roleService.removeRoleFromUser(userId, roleId, req.user.organizationId);

    await prisma.auditLog.create({
        data: {
            action: 'ROLE_REMOVED',
            ipAddress: req.deviceInfo.ip || null,
            userAgent: req.deviceInfo.userAgent || null,
            deviceType: req.deviceInfo.deviceType || null,
            country: req.deviceInfo.country.name || null,
            city: req.deviceInfo.city || null,
            riskLevel: 'LOW',
            timestamp: new Date(),
            user: { connect: { id: req.user.id } },
            details: {
                userId: req.user.id,
                organizationId: req.user.organizationId || null,
                removedUserId: userId,
                roleId: roleId,
                info: 'Role removed from user successfully'
            }
        }
    });
    sendSuccess(res, null, 'Role removed from user successfully');
});

/**
 * Get available permissions
 */
const getAvailablePermissions = asyncHandler(async (req, res) => {
    const permissions = roleService.getAvailablePermissions();

    // Group permissions by category
    const groupedPermissions = permissions.reduce((acc, permission) => {
        const [category] = permission.split('.');
        if (!acc[category]) {
            acc[category] = [];
        }
        acc[category].push(permission);
        return acc;
    }, {});

    sendSuccess(res, {
        permissions,
        groupedPermissions
    }, 'Available permissions retrieved successfully');
});

/**
 * Check user permissions
 */
const checkUserPermission = asyncHandler(async (req, res) => {
    const { userId, permission } = req.query;

    if (!userId || !permission) {
        return sendError(res, 'userId and permission parameters are required', 400);
    }

    const hasPermission = await roleService.userHasPermission(
        userId,
        permission,
        req.user.organizationId
    );

    sendSuccess(res, {
        userId,
        permission,
        hasPermission
    }, 'Permission check completed');
});

/**
 * Get role statistics
 */
const getRoleStats = asyncHandler(async (req, res) => {
    const [
        totalRoles,
        defaultRoles,
        customRoles,
        rolesWithUsers
    ] = await Promise.all([
        prisma.role.count({
            where: { organizationId: req.user.organizationId }
        }),
        prisma.role.count({
            where: {
                organizationId: req.user.organizationId,
                isDefault: true
            }
        }),
        prisma.role.count({
            where: {
                organizationId: req.user.organizationId,
                isDefault: false
            }
        }),
        prisma.role.count({
            where: {
                organizationId: req.user.organizationId,
                users: {
                    some: {}
                }
            }
        })
    ]);

    // Get role usage breakdown
    const roleUsage = await prisma.role.findMany({
        where: { organizationId: req.user.organizationId },
        select: {
            id: true,
            name: true,
            slug: true,
            _count: {
                select: {
                    users: true
                }
            }
        },
        orderBy: {
            users: {
                _count: 'desc'
            }
        }
    });

    const stats = {
        total: totalRoles,
        default: defaultRoles,
        custom: customRoles,
        withUsers: rolesWithUsers,
        withoutUsers: totalRoles - rolesWithUsers,
        usage: roleUsage.map(role => ({
            id: role.id,
            name: role.name,
            slug: role.slug,
            userCount: role._count.users
        }))
    };

    sendSuccess(res, { stats }, 'Role statistics retrieved successfully');
});

/**
 * Duplicate role
 */
const duplicateRole = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { name } = req.body;

    if (!name) {
        return sendError(res, 'New role name is required', 400);
    }

    // Get original role
    const originalRole = await roleService.findRoleById(id, req.user.organizationId);

    if (!originalRole) {
        return sendError(res, 'Role not found', 404);
    }

    // Create new role with same permissions
    const newRole = await roleService.createRole({
        name,
        description: `Copy of ${originalRole.name}`,
        permissions: originalRole.permissions
    }, req.user.organizationId);

    sendSuccess(res, { role: newRole }, 'Role duplicated successfully', 201);
});

module.exports = {
    getRoles,
    getRoleById,
    createRole,
    updateRole,
    deleteRole,
    getRoleUsers,
    assignRoleToUser,
    removeRoleFromUser,
    getAvailablePermissions,
    checkUserPermission,
    getRoleStats,
    duplicateRole
};