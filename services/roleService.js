const { prisma } = require('../utils/database');

/**
 * Generate unique slug from role name within organization
 * @param {string} name - Role name
 * @param {string} organizationId - Organization ID
 * @returns {Promise<string>} - Unique slug
 */
const generateUniqueSlug = async (name, organizationId) => {
    let baseSlug = name
        .toLowerCase()
        .replace(/[^a-z0-9\s-]/g, '')
        .replace(/\s+/g, '-')
        .replace(/-+/g, '-')
        .trim('-');

    let slug = baseSlug;
    let counter = 1;

    while (await prisma.role.findFirst({
        where: {
            slug,
            organizationId
        }
    })) {
        slug = `${baseSlug}-${counter}`;
        counter++;
    }

    return slug;
};

/**
 * Create a new role
 * @param {Object} roleData - Role data
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} - Created role
 */
const createRole = async (roleData, organizationId) => {
    const { name, description, permissions = [] } = roleData;

    // Generate unique slug
    const slug = await generateUniqueSlug(name, organizationId);

    // Create role
    const role = await prisma.role.create({
        data: {
            name,
            slug,
            description,
            permissions,
            organizationId
        }
    });

    return role;
};

/**
 * Find role by ID
 * @param {string} roleId - Role ID
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object|null>} - Role or null
 */
const findRoleById = async (roleId, organizationId) => {
    const role = await prisma.role.findFirst({
        where: {
            id: roleId,
            organizationId
        },
        include: {
            _count: {
                select: {
                    users: true
                }
            }
        }
    });

    return role;
};

/**
 * Find role by slug
 * @param {string} slug - Role slug
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object|null>} - Role or null
 */
const findRoleBySlug = async (slug, organizationId) => {
    const role = await prisma.role.findFirst({
        where: {
            slug,
            organizationId
        },
        include: {
            _count: {
                select: {
                    users: true
                }
            }
        }
    });

    return role;
};

/**
 * Get all roles for an organization
 * @param {string} organizationId - Organization ID
 * @param {Object} options - Query options
 * @returns {Promise<Object>} - Roles with pagination
 */
const getOrganizationRoles = async (organizationId, options = {}) => {
    const {
        page = 1,
        limit = 10,
        search = '',
        sortBy = 'createdAt',
        sortOrder = 'desc'
    } = options;

    const skip = (page - 1) * limit;

    const whereClause = {
        organizationId,
        ...(search && {
            OR: [
                { name: { contains: search, mode: 'insensitive' } },
                { description: { contains: search, mode: 'insensitive' } }
            ]
        })
    };

    const [roles, total] = await Promise.all([
        prisma.role.findMany({
            where: whereClause,
            include: {
                _count: {
                    select: {
                        users: true
                    }
                }
            },
            orderBy: { [sortBy]: sortOrder },
            skip,
            take: limit
        }),
        prisma.role.count({ where: whereClause })
    ]);

    return {
        roles,
        pagination: {
            page,
            limit,
            total,
            totalPages: Math.ceil(total / limit)
        }
    };
};

/**
 * Update role
 * @param {string} roleId - Role ID
 * @param {string} organizationId - Organization ID
 * @param {Object} updateData - Data to update
 * @returns {Promise<Object>} - Updated role
 */
const updateRole = async (roleId, organizationId, updateData) => {
    const { name, ...otherData } = updateData;

    let dataToUpdate = { ...otherData };

    // If name is being updated, generate new slug
    if (name) {
        const existingRole = await prisma.role.findFirst({
            where: {
                name,
                organizationId,
                id: { not: roleId }
            }
        });

        if (existingRole) {
            throw new Error('Role with this name already exists in the organization');
        }

        dataToUpdate.name = name;
        dataToUpdate.slug = await generateUniqueSlug(name, organizationId);
    }

    const role = await prisma.role.update({
        where: {
            id: roleId,
            organizationId
        },
        data: dataToUpdate,
        include: {
            _count: {
                select: {
                    users: true
                }
            }
        }
    });

    return role;
};

/**
 * Delete role
 * @param {string} roleId - Role ID
 * @param {string} organizationId - Organization ID
 * @returns {Promise<boolean>} - Success status
 */
const deleteRole = async (roleId, organizationId) => {
    // Check if role exists
    const role = await prisma.role.findFirst({
        where: {
            id: roleId,
            organizationId
        },
        include: {
            _count: {
                select: {
                    users: true
                }
            }
        }
    });

    if (!role) {
        throw new Error('Role not found');
    }

    // Prevent deletion of default role
    if (role.isDefault) {
        throw new Error('Cannot delete default role');
    }

    // Check if role has assigned users
    if (role._count.users > 0) {
        throw new Error('Cannot delete role that has assigned users');
    }

    // Delete role
    await prisma.role.delete({
        where: { id: roleId }
    });

    return true;
};

/**
 * Assign role to user
 * @param {string} userId - User ID
 * @param {string} roleId - Role ID
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} - User role assignment
 */
const assignRoleToUser = async (userId, roleId, organizationId) => {
    // Verify user belongs to the organization
    const user = await prisma.user.findFirst({
        where: {
            id: userId,
            organizationId
        }
    });

    if (!user) {
        throw new Error('User not found in the organization');
    }

    // Verify role belongs to the organization
    const role = await prisma.role.findFirst({
        where: {
            id: roleId,
            organizationId
        }
    });

    if (!role) {
        throw new Error('Role not found in the organization');
    }

    // Check if user already has this role
    const existingUserRole = await prisma.userRole.findFirst({
        where: {
            userId,
            roleId
        }
    });

    if (existingUserRole) {
        throw new Error('User already has this role');
    }

    // Create user role assignment
    const userRole = await prisma.userRole.create({
        data: {
            userId,
            roleId
        },
        include: {
            role: {
                select: {
                    id: true,
                    name: true,
                    slug: true,
                    permissions: true
                }
            },
            user: {
                select: {
                    id: true,
                    email: true,
                    firstName: true,
                    lastName: true
                }
            }
        }
    });

    return userRole;
};

/**
 * Remove role from user
 * @param {string} userId - User ID
 * @param {string} roleId - Role ID
 * @param {string} organizationId - Organization ID
 * @returns {Promise<boolean>} - Success status
 */
const removeRoleFromUser = async (userId, roleId, organizationId) => {
    // Verify user belongs to the organization
    const user = await prisma.user.findFirst({
        where: {
            id: userId,
            organizationId
        }
    });

    if (!user) {
        throw new Error('User not found in the organization');
    }

    // Find and delete user role assignment
    const deleted = await prisma.userRole.deleteMany({
        where: {
            userId,
            roleId,
            role: {
                organizationId
            }
        }
    });

    if (deleted.count === 0) {
        throw new Error('User role assignment not found');
    }

    return true;
};

/**
 * Get user roles
 * @param {string} userId - User ID
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Array>} - User roles
 */
const getUserRoles = async (userId, organizationId) => {
    const userRoles = await prisma.userRole.findMany({
        where: {
            userId,
            role: {
                organizationId
            }
        },
        include: {
            role: {
                select: {
                    id: true,
                    name: true,
                    slug: true,
                    description: true,
                    permissions: true
                }
            }
        }
    });

    return userRoles.map(userRole => userRole.role);
};

/**
 * Get role users
 * @param {string} roleId - Role ID
 * @param {string} organizationId - Organization ID
 * @param {Object} options - Query options
 * @returns {Promise<Object>} - Role users with pagination
 */
const getRoleUsers = async (roleId, organizationId, options = {}) => {
    const {
        page = 1,
        limit = 10,
        search = ''
    } = options;

    const skip = (page - 1) * limit;

    const whereClause = {
        roleId,
        role: {
            organizationId
        },
        ...(search && {
            user: {
                OR: [
                    { firstName: { contains: search, mode: 'insensitive' } },
                    { lastName: { contains: search, mode: 'insensitive' } },
                    { email: { contains: search, mode: 'insensitive' } }
                ]
            }
        })
    };

    const [userRoles, total] = await Promise.all([
        prisma.userRole.findMany({
            where: whereClause,
            include: {
                user: {
                    select: {
                        id: true,
                        email: true,
                        firstName: true,
                        lastName: true,
                        avatar: true,
                        isActive: true,
                        createdAt: true
                    }
                }
            },
            orderBy: { createdAt: 'desc' },
            skip,
            take: limit
        }),
        prisma.userRole.count({ where: whereClause })
    ]);

    const users = userRoles.map(userRole => userRole.user);

    return {
        users,
        pagination: {
            page,
            limit,
            total,
            totalPages: Math.ceil(total / limit)
        }
    };
};

/**
 * Check if user has permission
 * @param {string} userId - User ID
 * @param {string} permission - Permission to check
 * @param {string} organizationId - Organization ID
 * @returns {Promise<boolean>} - Has permission
 */
const userHasPermission = async (userId, permission, organizationId) => {
    const userRoles = await prisma.userRole.findMany({
        where: {
            userId,
            role: {
                organizationId
            }
        },
        include: {
            role: {
                select: {
                    permissions: true
                }
            }
        }
    });

    // Check if any role has the required permission
    for (const userRole of userRoles) {
        if (userRole.role.permissions.includes(permission)) {
            return true;
        }
    }

    return false;
};

/**
 * Get all available permissions
 * @returns {Array} - Available permissions
 */
const getAvailablePermissions = () => {
    return [
        // User permissions
        'users.create',
        'users.read',
        'users.update',
        'users.delete',
        'users.invite',

        // Role permissions
        'roles.create',
        'roles.read',
        'roles.update',
        'roles.delete',
        'roles.assign',

        // Organization permissions
        'organization.read',
        'organization.update',
        'organization.settings',

        // Session permissions
        'sessions.read',
        'sessions.revoke',

        // API Key permissions
        'api-keys.create',
        'api-keys.read',
        'api-keys.delete',

        // Invitation permissions
        'invitations.send',
        'invitations.read',
        'invitations.revoke'
    ];
};

module.exports = {
    createRole,
    findRoleById,
    findRoleBySlug,
    getOrganizationRoles,
    updateRole,
    deleteRole,
    assignRoleToUser,
    removeRoleFromUser,
    getUserRoles,
    getRoleUsers,
    userHasPermission,
    getAvailablePermissions
};