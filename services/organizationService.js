const { prisma } = require('../utils/database');

/**
 * Generate unique slug from organization name
 * @param {string} name - Organization name
 * @returns {Promise<string>} - Unique slug
 */
const generateUniqueSlug = async (name) => {
    let baseSlug = name
        .toLowerCase()
        .replace(/[^a-z0-9\s-]/g, '')
        .replace(/\s+/g, '-')
        .replace(/-+/g, '-')
        .trim('-');

    let slug = baseSlug;
    let counter = 1;

    while (await prisma.organization.findUnique({ where: { slug } })) {
        slug = `${baseSlug}-${counter}`;
        counter++;
    }

    return slug;
};

/**
 * Create a new organization
 * @param {Object} orgData - Organization data
 * @returns {Promise<Object>} - Created organization
 */
const createOrganization = async (orgData) => {
    const { name, email, phone, address, website, logoUrl } = orgData;

    // Check if organization with this name already exists
    const existingOrg = await prisma.organization.findUnique({
        where: { name }
    });

    if (existingOrg) {
        throw new Error('Organization with this name already exists');
    }

    // Generate unique slug
    const slug = await generateUniqueSlug(name);

    // Create organization
    const organization = await prisma.organization.create({
        data: {
            name,
            slug,
            email,
            phone,
            address,
            website,
            logoUrl,
            settings: {}
        }
    });

    // Create default roles for the organization
    await createDefaultRoles(organization.id);

    return organization;
};

/**
 * Create default roles for organization
 * @param {string} organizationId - Organization ID
 */
const createDefaultRoles = async (organizationId) => {
    const defaultRoles = [
        {
            name: 'Admin',
            slug: 'admin',
            description: 'Full access to all features',
            permissions: [
                'users.create',
                'users.read',
                'users.update',
                'users.delete',
                'roles.create',
                'roles.read',
                'roles.update',
                'roles.delete',
                'organization.read',
                'organization.update',
                'invitations.send',
                'api-keys.create',
                'api-keys.read',
                'api-keys.delete'
            ],
            isDefault: false
        },
        {
            name: 'Member',
            slug: 'member',
            description: 'Standard user access',
            permissions: [
                'users.read',
                'organization.read'
            ],
            isDefault: true
        },
        {
            name: 'Viewer',
            slug: 'viewer',
            description: 'Read-only access',
            permissions: [
                'users.read',
                'organization.read'
            ],
            isDefault: false
        }
    ];

    for (const roleData of defaultRoles) {
        await prisma.role.create({
            data: {
                ...roleData,
                organizationId
            }
        });
    }
};

/**
 * Find organization by ID
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object|null>} - Organization or null
 */
const findOrganizationById = async (organizationId) => {
    const organization = await prisma.organization.findUnique({
        where: { id: organizationId },
        include: {
            _count: {
                select: {
                    users: true,
                    roles: true
                }
            }
        }
    });

    return organization;
};

/**
 * Find organization by slug
 * @param {string} slug - Organization slug
 * @returns {Promise<Object|null>} - Organization or null
 */
const findOrganizationBySlug = async (slug) => {
    const organization = await prisma.organization.findUnique({
        where: { slug },
        include: {
            _count: {
                select: {
                    users: true,
                    roles: true
                }
            }
        }
    });

    return organization;
};

/**
 * Update organization
 * @param {string} organizationId - Organization ID
 * @param {Object} updateData - Data to update
 * @returns {Promise<Object>} - Updated organization
 */
const updateOrganization = async (organizationId, updateData) => {
    const { name, ...otherData } = updateData;

    let dataToUpdate = { ...otherData };

    // If name is being updated, generate new slug
    if (name) {
        const existingOrg = await prisma.organization.findFirst({
            where: {
                name,
                id: { not: organizationId }
            }
        });

        if (existingOrg) {
            throw new Error('Organization with this name already exists');
        }

        dataToUpdate.name = name;
        dataToUpdate.slug = await generateUniqueSlug(name);
    }

    const organization = await prisma.organization.update({
        where: { id: organizationId },
        data: dataToUpdate,
        include: {
            _count: {
                select: {
                    users: true,
                    roles: true
                }
            }
        }
    });

    return organization;
};

/**
 * Get organization settings
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} - Organization settings
 */
const getOrganizationSettings = async (organizationId) => {
    const organization = await prisma.organization.findUnique({
        where: { id: organizationId },
        select: { settings: true }
    });

    return organization?.settings || {};
};

/**
 * Update organization settings
 * @param {string} organizationId - Organization ID
 * @param {Object} settings - Settings to update
 * @returns {Promise<Object>} - Updated settings
 */
const updateOrganizationSettings = async (organizationId, settings) => {
    const currentOrg = await prisma.organization.findUnique({
        where: { id: organizationId },
        select: { settings: true }
    });

    const currentSettings = currentOrg?.settings || {};
    const updatedSettings = { ...currentSettings, ...settings };

    const organization = await prisma.organization.update({
        where: { id: organizationId },
        data: { settings: updatedSettings }
    });

    return organization.settings;
};

/**
 * Get organization statistics
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} - Organization statistics
 */
const getOrganizationStats = async (organizationId) => {
    const [
        totalUsers,
        activeUsers,
        totalRoles,
        pendingInvitations,
        recentLogins
    ] = await Promise.all([
        prisma.user.count({
            where: { organizationId }
        }),
        prisma.user.count({
            where: {
                organizationId,
                isActive: true
            }
        }),
        prisma.role.count({
            where: { organizationId }
        }),
        prisma.invitation.count({
            where: {
                organizationId,
                acceptedAt: null,
                expiresAt: { gt: new Date() }
            }
        }),
        prisma.user.count({
            where: {
                organizationId,
                lastLoginAt: {
                    gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // Last 30 days
                }
            }
        })
    ]);

    return {
        users: {
            total: totalUsers,
            active: activeUsers,
            inactive: totalUsers - activeUsers,
            recentLogins
        },
        roles: {
            total: totalRoles
        },
        invitations: {
            pending: pendingInvitations
        }
    };
};

/**
 * Deactivate organization
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} - Updated organization
 */
const deactivateOrganization = async (organizationId) => {
    const organization = await prisma.organization.update({
        where: { id: organizationId },
        data: { isActive: false }
    });

    // Deactivate all users in the organization
    await prisma.user.updateMany({
        where: { organizationId },
        data: { isActive: false }
    });

    // Invalidate all sessions for the organization
    await prisma.session.updateMany({
        where: { organizationId },
        data: { isActive: false }
    });

    return organization;
};

/**
 * Reactivate organization
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Object>} - Updated organization
 */
const reactivateOrganization = async (organizationId) => {
    const organization = await prisma.organization.update({
        where: { id: organizationId },
        data: { isActive: true }
    });

    // Reactivate all users in the organization
    await prisma.user.updateMany({
        where: { organizationId },
        data: { isActive: true }
    });

    return organization;
};

/**
 * Get all organizations with pagination
 * @param {Object} options - Query options
 * @returns {Promise<Object>} - Organizations with pagination
 */
const getAllOrganizations = async (options = {}) => {
    const {
        page = 1,
        limit = 10,
        search = '',
        sortBy = 'createdAt',
        sortOrder = 'desc',
        isActive
    } = options;

    const skip = (page - 1) * limit;

    const whereClause = {
        ...(search && {
            OR: [
                { name: { contains: search, mode: 'insensitive' } },
                { email: { contains: search, mode: 'insensitive' } }
            ]
        }),
        ...(isActive !== undefined && { isActive })
    };

    const [organizations, total] = await Promise.all([
        prisma.organization.findMany({
            where: whereClause,
            include: {
                _count: {
                    select: {
                        users: true,
                        roles: true
                    }
                }
            },
            orderBy: { [sortBy]: sortOrder },
            skip,
            take: limit
        }),
        prisma.organization.count({ where: whereClause })
    ]);

    return {
        organizations,
        pagination: {
            page,
            limit,
            total,
            totalPages: Math.ceil(total / limit)
        }
    };
};

/**
 * Delete organization (with cascade)
 * @param {string} organizationId - Organization ID
 * @returns {Promise<boolean>} - Success status
 */
const deleteOrganization = async (organizationId) => {
    // Delete organization (cascade will handle related records)
    await prisma.organization.delete({
        where: { id: organizationId }
    });

    return true;
};

module.exports = {
    createOrganization,
    findOrganizationById,
    findOrganizationBySlug,
    updateOrganization,
    getOrganizationSettings,
    updateOrganizationSettings,
    getOrganizationStats,
    deactivateOrganization,
    reactivateOrganization,
    getAllOrganizations,
    deleteOrganization
};