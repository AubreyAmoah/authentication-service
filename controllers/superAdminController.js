const userService = require('../services/userService');
const { sendSuccess, sendError, sendPaginated, asyncHandler, getPaginationParams } = require('../utils/response');
const { prisma } = require('../utils/database');
const { AUDIT_ACTIONS, RISK_LEVELS } = require('../config/constants');
const { addAllowedOrigin } = require('../config/cors');
const { listAllowedOrigins } = require('../config/cors');
const { removeAllowedOrigin } = require('../config/cors');
const { exportData } = require('../utils/exportUtils');

/**
 * Get system-wide statistics
 */
const getSystemStats = asyncHandler(async (req, res) => {
    const [
        totalUsers,
        totalOrganizations,
        activeOrganizations,
        totalSuperAdmins,
        recentUsers,
        recentOrganizations,
        totalSessions,
        activeSessions
    ] = await Promise.all([
        prisma.user.count(),
        prisma.organization.count(),
        prisma.organization.count({ where: { isActive: true } }),
        prisma.user.count({ where: { isSuperAdmin: true } }),
        prisma.user.count({
            where: {
                createdAt: {
                    gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // Last 30 days
                }
            }
        }),
        prisma.organization.count({
            where: {
                createdAt: {
                    gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // Last 30 days
                }
            }
        }),
        prisma.session.count(),
        prisma.session.count({
            where: {
                isActive: true,
                expiresAt: { gt: new Date() }
            }
        })
    ]);

    const stats = {
        users: {
            total: totalUsers,
            recent: recentUsers,
            superAdmins: totalSuperAdmins,
            regular: totalUsers - totalSuperAdmins
        },
        organizations: {
            total: totalOrganizations,
            active: activeOrganizations,
            inactive: totalOrganizations - activeOrganizations,
            recent: recentOrganizations
        },
        sessions: {
            total: totalSessions,
            active: activeSessions,
            inactive: totalSessions - activeSessions
        }
    };

    sendSuccess(res, { stats }, 'System statistics retrieved successfully');
});

/**
 * Get all users across all organizations
 */
const getAllUsers = asyncHandler(async (req, res) => {
    const { page, limit } = getPaginationParams(req.query);
    const { search, sortBy = 'createdAt', sortOrder = 'desc', organizationId, isSuperAdmin } = req.query;

    const skip = (page - 1) * limit;

    const whereClause = {
        ...(search && {
            OR: [
                { firstName: { contains: search, mode: 'insensitive' } },
                { lastName: { contains: search, mode: 'insensitive' } },
                { email: { contains: search, mode: 'insensitive' } }
            ]
        }),
        ...(organizationId && { organizationId }),
        ...(isSuperAdmin !== undefined && { isSuperAdmin: isSuperAdmin === 'true' })
    };

    const [users, total] = await Promise.all([
        prisma.user.findMany({
            where: whereClause,
            select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true,
                phone: true,
                avatar: true,
                isEmailVerified: true,
                isActive: true,
                isSuperAdmin: true,
                lastLoginAt: true,
                createdAt: true,
                updatedAt: true,
                organizationId: true,
                organization: {
                    select: {
                        id: true,
                        name: true,
                        slug: true
                    }
                }
            },
            orderBy: { [sortBy]: sortOrder },
            skip,
            take: limit
        }),
        prisma.user.count({ where: whereClause })
    ]);

    sendPaginated(res, users, {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
    }, 'Users retrieved successfully');
});

/**
 * Create super admin user
 */
const createSuperAdmin = asyncHandler(async (req, res) => {
    const { email, password, firstName, lastName } = req.validatedData;
    const deviceInfo = req.deviceInfo || {};
    const userId = req.user.userId;

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
        where: { email }
    });

    if (existingUser) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.SUPER_ADMIN_CREATED,
                userId,
                ipAddress: deviceInfo.ip || null,
                userAgent: deviceInfo.userAgent || null,
                deviceType: deviceInfo.deviceType || null,
                country: deviceInfo.country.name || null,
                city: deviceInfo.city || null,
                riskLevel: RISK_LEVELS.CRITICAL,
                timestamp: new Date(),
                success: false,
                details: {
                    userId,
                    organizationId: req.user.organizationId || null,
                    email: req.user.email || null,
                    info: 'User tried creating super admin but email already exists'
                }
            }
        });
        return sendError(res, 'User with this email already exists', 400);
    }

    // Create user without organization (super admins don't need one)
    const user = await userService.createUser({
        email,
        password,
        firstName,
        lastName
    }, null); // organizationId = null

    // Make the user a super admin
    const superAdminUser = await prisma.user.update({
        where: { id: user.id },
        data: {
            isSuperAdmin: true,
            isEmailVerified: true // Auto-verify super admin emails
        },
        select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            isSuperAdmin: true,
            isEmailVerified: true,
            isActive: true,
            createdAt: true
        }
    });

    sendSuccess(res, { user: superAdminUser }, 'Super admin created successfully', 201);

    await prisma.auditLog.create({
        data: {
            action: AUDIT_ACTIONS.SUPER_ADMIN_CREATED,
            userId,
            ipAddress: deviceInfo.ip || null,
            userAgent: deviceInfo.userAgent || null,
            deviceType: deviceInfo.deviceType || null,
            country: deviceInfo.country.name || null,
            city: deviceInfo.city || null,
            riskLevel: RISK_LEVELS.CRITICAL,
            timestamp: new Date(),
            success: true,
            details: {
                userId,
                organizationId: req.user.organizationId || null,
                email: req.user.email || null
            }
        }
    });
});

/**
 * Deactivate or reactivate a user (super admin only)
 */
const toggleUserActivation = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { isActive } = req.body;
    const userId = req.user.userId;
    const deviceInfo = req.deviceInfo || {};

    if (typeof isActive !== 'boolean') {
        return sendError(res, 'isActive must be a boolean', 400);
    }

    const user = await prisma.user.findUnique({
        where: { id },
        select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            isSuperAdmin: true,
            isActive: true
        }
    });

    if (!user) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.USER_DEACTIVATED,
                userId,
                ipAddress: deviceInfo.ip || null,
                userAgent: deviceInfo.userAgent || null,
                deviceType: deviceInfo.deviceType || null,
                country: deviceInfo.country.name || null,
                city: deviceInfo.city || null,
                riskLevel: RISK_LEVELS.CRITICAL,
                timestamp: new Date(),
                success: false,
                details: {
                    userId,
                    organizationId: req.user.organizationId || null,
                    email: req.user.email || null,
                    info: 'User tried deactivating a user but user not found'
                }
            }
        });
        return sendError(res, 'User not found', 404);
    }

    // Prevent deactivating yourself
    if (req.user.id === id) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.USER_DEACTIVATED,
                userId,
                ipAddress: deviceInfo.ip || null,
                userAgent: deviceInfo.userAgent || null,
                deviceType: deviceInfo.deviceType || null,
                country: deviceInfo.country.name || null,
                city: deviceInfo.city || null,
                riskLevel: RISK_LEVELS.CRITICAL,
                timestamp: new Date(),
                success: false,
                details: {
                    userId,
                    organizationId: req.user.organizationId || null,
                    email: req.user.email || null,
                    info: 'User tried deactivating their own account'
                }
            }
        });
        return sendError(res, 'Cannot deactivate your own account', 400);
    }

    // Prevent deactivating other super admins
    if (user.isSuperAdmin) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.USER_DEACTIVATED,
                userId,
                ipAddress: deviceInfo.ip || null,
                userAgent: deviceInfo.userAgent || null,
                deviceType: deviceInfo.deviceType || null,
                country: deviceInfo.country.name || null,
                city: deviceInfo.city || null,
                riskLevel: RISK_LEVELS.CRITICAL,
                timestamp: new Date(),
                success: false,
                details: {
                    userId,
                    organizationId: req.user.organizationId || null,
                    email: req.user.email || null,
                    info: 'User tried deactivating another super admin'
                }
            }
        });
        return sendError(res, 'Cannot deactivate another super admin', 400);
    }

    if (user.isActive === isActive) {
        return sendError(res, `User is already ${isActive ? 'active' : 'inactive'}`, 400);
    }

    const updatedUser = await prisma.user.update({
        where: { id },
        data: { isActive },
        select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            isSuperAdmin: true,
            isActive: true
        }
    });

    sendSuccess(res, { user: updatedUser }, `User has been ${isActive ? 'reactivated' : 'deactivated'} successfully`);

    await prisma.auditLog.create({
        data: {
            action: isActive ? AUDIT_ACTIONS.USER_ACTIVATED : AUDIT_ACTIONS.USER_DEACTIVATED,
            userId,
            ipAddress: deviceInfo.ip || null,
            userAgent: deviceInfo.userAgent || null,
            deviceType: deviceInfo.deviceType || null,
            country: deviceInfo.country.name || null,
            city: deviceInfo.city || null,
            riskLevel: RISK_LEVELS.CRITICAL,
            timestamp: new Date(),
            success: true,
            details: {
                userId,
                organizationId: req.user.organizationId || null,
                email: req.user.email || null,
                info: `User ${isActive ? 'reactivated' : 'deactivated'}: ${user.email}`
            }
        }
    });
});


/**Get Organization Users */
const getAllOrganizationUsers = asyncHandler(async (req, res) => {
    const { page, limit } = getPaginationParams(req.query);
    const { organizationId } = req.query;
    if (!organizationId) {
        return sendError(res, 'organizationId query parameter is required', 400);
    }
    const skip = (page - 1) * limit;
    const [users, total] = await Promise.all([
        prisma.user.findMany({
            where: { organizationId },
            select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true,
                phone: true,
                avatar: true,
                isEmailVerified: true,
                isActive: true,
                isSuperAdmin: true,
                lastLoginAt: true,
                createdAt: true,
                updatedAt: true,
                organizationId: true,
                organization: {
                    select: {

                        id: true,
                        name: true,
                        slug: true
                    }
                }
            },
            orderBy: { createdAt: 'desc' },
            skip,
            take: limit
        }),
        prisma.user.count({ where: { organizationId } })
    ]);
    sendPaginated(res, users, {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
    }, 'Organization users retrieved successfully');
});

/**
 * Deactive or reactivate an organization (super admin only)
 */

const toggleOrganizationActivation = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { isActive } = req.body;
    const userId = req.user.userId;
    const deviceInfo = req.deviceInfo || {};

    if (typeof isActive !== 'boolean') {
        return sendError(res, 'isActive must be a boolean', 400);
    }

    const organization = await prisma.organization.findUnique({
        where: { id },
        select: {
            id: true,
            name: true,
            slug: true,
            isActive: true
        }
    });

    if (!organization) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.ORGANIZATION_DEACTIVATED,
                userId,
                ipAddress: deviceInfo.ip || null,
                userAgent: deviceInfo.userAgent || null,
                deviceType: deviceInfo.deviceType || null,
                country: deviceInfo.country.name || null,
                city: deviceInfo.city || null,
                riskLevel: RISK_LEVELS.CRITICAL,
                timestamp: new Date(),
                success: false,
                details: {
                    userId,
                    organizationId: req.user.organizationId || null,
                    email: req.user.email || null,
                    info: 'User tried deactivating an organization but organization not found'
                }
            }
        });
        return sendError(res, 'Organization not found', 404);
    }

    if (organization.isActive === isActive) {
        return sendError(res, `Organization is already ${isActive ? 'active' : 'inactive'}`, 400);
    }

    const updatedOrganization = await prisma.organization.update({
        where: { id },
        data: { isActive },
        select: {
            id: true,
            name: true,
            slug: true,
            isActive: true
        }
    });

    sendSuccess(res, { organization: updatedOrganization }, `Organization has been ${isActive ? 're-activated' : 'deactivated'} successfully`);
    await prisma.auditLog.create({
        data: {
            action: isActive ? AUDIT_ACTIONS.ORGANIZATION_ACTIVATED : AUDIT_ACTIONS.ORGANIZATION_DEACTIVATED,
            userId,
            ipAddress: deviceInfo.ip || null,
            userAgent: deviceInfo.userAgent || null,
            deviceType: deviceInfo.deviceType || null,
            country: deviceInfo.country.name || null,
            city: deviceInfo.city || null,
            riskLevel: RISK_LEVELS.CRITICAL,
            timestamp: new Date(),
            success: true,
            details: {
                userId,
                organizationId: req.user.organizationId || null,
                email: req.user.email || null,
                info: `Organization ${isActive ? 're-activated' : 'deactivated'}: ${organization.name}`
            }
        }
    });
});


/**
 * Toggle super admin status for a user
 */
const toggleSuperAdmin = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const userId = req.user.userId;

    const user = await prisma.user.findUnique({
        where: { id },
        select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            isSuperAdmin: true
        }
    });

    if (!user) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.SUPER_ADMIN_TOGGLED,
                userId,
                ipAddress: req.deviceInfo.ip || null,
                userAgent: req.deviceInfo.userAgent || null,
                deviceType: req.deviceInfo.deviceType || null,
                country: req.deviceInfo.country.name || null,
                city: req.deviceInfo.city || null,
                riskLevel: RISK_LEVELS.CRITICAL,
                timestamp: new Date(),
                success: false,
                details: {
                    userId,
                    organizationId: req.user.organizationId || null,
                    email: req.user.email || null,
                    info: 'User tried toggling super admin but user not found'
                }
            }
        });
        return sendError(res, 'User not found', 404);
    }

    // Prevent removing super admin status from yourself
    if (req.user.id === id && user.isSuperAdmin) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.SUPER_ADMIN_TOGGLED,
                userId,
                ipAddress: req.deviceInfo.ip || null,
                userAgent: req.deviceInfo.userAgent || null,
                deviceType: req.deviceInfo.deviceType || null,
                country: req.deviceInfo.country.name || null,
                city: req.deviceInfo.city || null,
                riskLevel: RISK_LEVELS.CRITICAL,
                timestamp: new Date(),
                success: false,
                details: {
                    userId,
                    organizationId: req.user.organizationId || null,
                    email: req.user.email || null,
                    info: 'User tried removing their own super admin status'
                }
            }
        });
        return sendError(res, 'Cannot remove super admin status from yourself', 400);
    }

    const updatedUser = await prisma.user.update({
        where: { id },
        data: { isSuperAdmin: !user.isSuperAdmin },
        select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            isSuperAdmin: true,
            isActive: true
        }
    });

    const action = updatedUser.isSuperAdmin ? 'granted' : 'revoked';
    sendSuccess(res, { user: updatedUser }, `Super admin access ${action} successfully`);

    await prisma.auditLog.create({
        data: {
            action: AUDIT_ACTIONS.SUPER_ADMIN_TOGGLED,
            userId,
            ipAddress: req.deviceInfo.ip || null,
            userAgent: req.deviceInfo.userAgent || null,
            deviceType: req.deviceInfo.deviceType || null,
            country: req.deviceInfo.country.name || null,
            city: req.deviceInfo.city || null,
            riskLevel: RISK_LEVELS.CRITICAL,
            timestamp: new Date(),
            success: true,
            details: {
                userId,
                organizationId: req.user.organizationId || null,
                email: req.user.email || null,
                indo: `Super admin status ${action} for user ${updatedUser.email}`
            }
        }
    });
});

/**
 * Delete any user (including from other organizations)
 */
const deleteAnyUser = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const userId = req.user.userId;

    const user = await prisma.user.findUnique({
        where: { id },
        select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            isSuperAdmin: true
        }
    });

    if (!user) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.USER_DELETED,
                userId,
                ipAddress: req.deviceInfo.ip || null,
                userAgent: req.deviceInfo.userAgent || null,
                deviceType: req.deviceInfo.deviceType || null,
                country: req.deviceInfo.country.name || null,
                city: req.deviceInfo.city || null,
                riskLevel: RISK_LEVELS.CRITICAL,
                timestamp: new Date(),
                success: false,
                details: {
                    userId,
                    organizationId: req.user.organizationId || null,
                    email: req.user.email || null,
                    info: 'User tried deleting a user but user not found'
                }
            }
        });
        return sendError(res, 'User not found', 404);
    }

    // Prevent self-deletion
    if (req.user.id === id) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.USER_DELETED,
                userId,
                ipAddress: req.deviceInfo.ip || null,
                userAgent: req.deviceInfo.userAgent || null,
                deviceType: req.deviceInfo.deviceType || null,
                country: req.deviceInfo.country.name || null,
                city: req.deviceInfo.city || null,
                riskLevel: RISK_LEVELS.CRITICAL,
                timestamp: new Date(),
                success: false,
                details: {
                    userId,
                    organizationId: req.user.organizationId || null,
                    email: req.user.email || null,
                    info: 'User tried deleting their own account'
                }
            }
        });
        return sendError(res, 'Cannot delete your own account', 400);
    }

    // Delete user (cascade will handle related records)
    await prisma.user.delete({
        where: { id }
    });

    sendSuccess(res, null, 'User deleted successfully');

    await prisma.auditLog.create({
        data: {
            action: AUDIT_ACTIONS.USER_DELETED,
            userId,
            ipAddress: req.deviceInfo.ip || null,
            userAgent: req.deviceInfo.userAgent || null,
            deviceType: req.deviceInfo.deviceType || null,
            country: req.deviceInfo.country.name || null,
            city: req.deviceInfo.city || null,
            riskLevel: RISK_LEVELS.CRITICAL,
            timestamp: new Date(),
            success: true,
            details: {
                userId,
                organizationId: req.user.organizationId || null,
                email: req.user.email || null,
                info: `User deleted: ${user.email}`
            }
        }
    });
});

/**
 * View user's profile (super admin can view any user's profile)
 */
const getUserProfile = asyncHandler(async (req, res) => {
    const { id } = req.params;

    const user = await prisma.user.findUnique({
        where: { id },
        select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            phone: true,
            avatar: true,
            isEmailVerified: true,
            isActive: true,
            isSuperAdmin: true,
            lastLoginAt: true,
            emailVerifiedAt: true,
            passwordChangedAt: true,
            createdAt: true,
            updatedAt: true,
            organizationId: true,
            organization: {
                select: {
                    id: true,
                    name: true,
                    slug: true,
                    isActive: true
                }
            },
            roles: {
                include: {
                    role: {
                        select: {
                            id: true,
                            name: true,
                            slug: true,
                            permissions: true
                        }
                    }
                }
            },
            sessions: {
                where: {
                    isActive: true,
                    expiresAt: { gt: new Date() }
                },
                select: {
                    id: true,
                    userAgent: true,
                    ipAddress: true,
                    createdAt: true,
                    expiresAt: true
                }
            },
            _count: {
                select: {
                    sessions: true,
                    passwordResets: true,
                    emailVerifications: true
                }
            }
        }
    });

    if (!user) {
        return sendError(res, 'User not found', 404);
    }

    // Transform roles for easier access
    if (user.roles) {
        user.roles = user.roles.map(userRole => userRole.role);
    }

    sendSuccess(res, { user }, 'User profile retrieved successfully');
});

/**
 * View organization details (super admin can view any organization)
 */
const getOrganizationDetails = asyncHandler(async (req, res) => {
    const { id } = req.params;

    const organization = await prisma.organization.findUnique({
        where: { id },
        select: {
            id: true,
            name: true,
            slug: true,
            isActive: true,
            createdAt: true,
            updatedAt: true,
            users: {
                select: {
                    id: true,
                    email: true,
                    firstName: true,
                    lastName: true,
                    isSuperAdmin: true,
                    isActive: true,
                    createdAt: true
                }
            },
            _count: {
                select: {
                    users: true
                }
            }
        }
    });

    if (!organization) {
        return sendError(res, 'Organization not found', 404);
    }

    sendSuccess(res, { organization }, 'Organization details retrieved successfully');
});


/**
 * Get all sessions across all organizations
 */
const getAllSessions = asyncHandler(async (req, res) => {
    const { page, limit } = getPaginationParams(req.query);
    const { organizationId, userId, isActive } = req.query;


    const skip = (page - 1) * limit;

    const whereClause = {
        ...(organizationId && { organizationId }),
        ...(userId && { userId }),
        ...(isActive !== undefined && {
            isActive: isActive === 'true',
            expiresAt: { gt: new Date() }
        })
    };

    const [sessions, total] = await Promise.all([
        prisma.session.findMany({
            where: whereClause,
            select: {
                id: true,
                token: true,
                userId: true,
                userAgent: true,
                mfaVerifiedAt: true,
                ipAddress: true,
                isActive: true,
                expiresAt: true,
                createdAt: true,
                updatedAt: true,
                organizationId: true,
                user: {
                    select: {
                        id: true,
                        email: true,
                        firstName: true,
                        lastName: true,
                        isSuperAdmin: true
                    }
                },
                organization: {
                    select: {
                        id: true,
                        name: true,
                        slug: true
                    }
                }
            },
            orderBy: { createdAt: 'desc' },
            skip,
            take: limit
        }),
        prisma.session.count({ where: whereClause })
    ]);

    sendPaginated(res, sessions, {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
    }, 'Sessions retrieved successfully');

    await prisma.auditLog.create({
        data: {
            action: "USER SESSIONS RETIEVED",
            userId,
            ipAddress: req.deviceInfo.ip || null,
            userAgent: req.deviceInfo.userAgent || null,
            deviceType: req.deviceInfo.deviceType || null,
            country: req.deviceInfo.country.name || null,
            city: req.deviceInfo.city || null,
            riskLevel: RISK_LEVELS.CRITICAL,
            timestamp: new Date(),
            success: true,
            details: {
                userId,
                organizationId: req.user.organizationId || null,
                email: req.user.email || null,
                info: `User sessions retrieved`
            }
        }
    });
});

/**
 * Revoke any session
 */
const revokeAnySession = asyncHandler(async (req, res) => {
    const { sessionId } = req.params;

    const session = await prisma.session.findUnique({
        where: { id: sessionId },
        select: {
            id: true,
            userId: true,
            user: {
                select: {
                    email: true,
                    firstName: true,
                    lastName: true
                }
            }
        }
    });

    if (!session) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.USER_SESSION_REVOKED,
                userId: req.user.userId,
                ipAddress: req.deviceInfo.ip || null,
                userAgent: req.deviceInfo.userAgent || null,
                deviceType: req.deviceInfo.deviceType || null,
                country: req.deviceInfo.country.name || null,
                city: req.deviceInfo.city || null,
                riskLevel: RISK_LEVELS.CRITICAL,
                timestamp: new Date(),
                success: false,
                details: {
                    userId: req.user.userId,
                    organizationId: req.user.organizationId || null,
                    email: req.user.email || null,
                    info: 'User tried revoking session but session notfound'
                }
            }
        });
        return sendError(res, 'Session not found', 404);
    }

    // Prevent revoking your own session
    if (req.user.id === session.userId && req.userSession.id === sessionId) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.USER_SESSION_REVOKED,
                userId: req.user.userId,
                ipAddress: req.deviceInfo.ip || null,
                userAgent: req.deviceInfo.userAgent || null,
                deviceType: req.deviceInfo.deviceType || null,
                country: req.deviceInfo.country.name || null,
                city: req.deviceInfo.city || null,
                riskLevel: RISK_LEVELS.CRITICAL,
                timestamp: new Date(),
                success: false,
                details: {
                    userId: req.user.userId,
                    organizationId: req.user.organizationId || null,
                    email: req.user.email || null,
                    info: 'User tried revoking own session'
                }
            }
        });
        return sendError(res, 'Cannot revoke your own current session', 400);
    }

    await prisma.session.update({
        where: { id: sessionId },
        data: { isActive: false }
    });

    sendSuccess(res, null, 'Session revoked successfully');
    await prisma.auditLog.create({
        data: {
            action: AUDIT_ACTIONS.USER_SESSION_REVOKED,
            userId: req.user.userId,
            ipAddress: req.deviceInfo.ip || null,
            userAgent: req.deviceInfo.userAgent || null,
            deviceType: req.deviceInfo.deviceType || null,
            country: req.deviceInfo.country.name || null,
            city: req.deviceInfo.city || null,
            riskLevel: RISK_LEVELS.CRITICAL,
            timestamp: new Date(),
            success: true,
            details: {
                userId: req.user.userId,
                organizationId: req.user.organizationId || null,
                email: req.user.email || null,
                info: `Session revoked for user ${session.user.email}`
            }
        }
    });
});

/**
 * Get detailed user information (super admin view)
 */
const getUserDetails = asyncHandler(async (req, res) => {
    const { id } = req.params;

    const user = await prisma.user.findUnique({
        where: { id },
        select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            phone: true,
            avatar: true,
            isEmailVerified: true,
            isActive: true,
            isSuperAdmin: true,
            lastLoginAt: true,
            emailVerifiedAt: true,
            passwordChangedAt: true,
            createdAt: true,
            updatedAt: true,
            organizationId: true,
            organization: {
                select: {
                    id: true,
                    name: true,
                    slug: true,
                    isActive: true
                }
            },
            roles: {
                include: {
                    role: {
                        select: {
                            id: true,
                            name: true,
                            slug: true,
                            permissions: true
                        }
                    }
                }
            },
            sessions: {
                where: {
                    isActive: true,
                    expiresAt: { gt: new Date() }
                },
                select: {
                    id: true,
                    userAgent: true,
                    ipAddress: true,
                    createdAt: true,
                    expiresAt: true
                }
            },
            _count: {
                select: {
                    sessions: true,
                    passwordResets: true,
                    emailVerifications: true
                }
            }
        }
    });

    if (!user) {
        return sendError(res, 'User not found', 404);
    }

    // Transform roles for easier access
    if (user.roles) {
        user.roles = user.roles.map(userRole => userRole.role);
    }

    sendSuccess(res, { user }, 'User details retrieved successfully');
});

const transferOrganizationMembership = asyncHandler(async (req, res) => {
    const { userId, newOrganizationId } = req.body;

    // Validate input
    if (!userId || !newOrganizationId) {
        return sendError(res, 'userId and newOrganizationId are required', 400);
    }

    // Check if user exists
    const user = await prisma.user.findUnique({
        where: { id: userId }
    });

    if (!user) {
        return sendError(res, 'User not found', 404);
    }

    // Check if new organization exists and is active
    const newOrg = await prisma.organization.findUnique({
        where: { id: newOrganizationId }
    });

    if (!newOrg || !newOrg.isActive) {
        return sendError(res, 'New organization not found or inactive', 404);
    }

    // Transfer user to new organization
    const updatedUser = await prisma.user.update({
        where: { id: userId },
        data: { organizationId: newOrganizationId },
        select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            organizationId: true
        }
    });

    sendSuccess(res, { user: updatedUser }, 'User organization membership transferred successfully');
});

const getCorsUrls = asyncHandler(async (req, res) => {
    try {
        const origins = await listAllowedOrigins();
        sendSuccess(res, { origins }, 'CORS origins retrieved successfully');
    }
    catch (error) {
        console.error('Error fetching CORS origins:', error);
        sendError(res, 'Failed to fetch CORS origins', 500);
    }
});

const deleteCorsUrl = asyncHandler(async (req, res) => {
    const { id } = req.params;

    try {
        const deletedOrigin = await removeAllowedOrigin(id);
        if (!deletedOrigin) {
            return sendError(res, 'CORS origin not found', 404);
        }
        sendSuccess(res, null, 'CORS origin deleted successfully');
    }
    catch (error) {
        console.error('Error deleting CORS origin:', error);
        sendError(res, 'Failed to delete CORS origin', 500);
    }
});

const createCorsUrl = asyncHandler(async (req, res) => {
    const { url } = req.body;

    if (!url) {
        return sendError(res, 'CORS URL is required', 400);
    }

    try {
        const newOrigin = await addAllowedOrigin(url);
        sendSuccess(res, { origin: newOrigin }, 'CORS origin added successfully', 201);
    }
    catch (error) {
        console.error('Error adding CORS origin:', error);
        sendError(res, 'Failed to add CORS origin', 500);
    }
});


/** Get all user logs */

const getAuditLogs = asyncHandler(async (req, res) => {
    const { page, limit } = getPaginationParams(req.query);
    const { userId, action, startDate, endDate } = req.query;

    const skip = (page - 1) * limit;

    const whereClause = {
        ...(userId && { userId }),
        ...(action && { action: { contains: action, mode: 'insensitive' } }),
        ...(startDate && endDate && {
            timestamp: {
                gte: new Date(startDate),
                lte: new Date(endDate)
            }
        }),
        ...(startDate && !endDate && {
            timestamp: {
                gte: new Date(startDate)
            }
        }),
        ...(!startDate && endDate && {
            timestamp: {
                lte: new Date(endDate)
            }
        })
    };

    const [logs, total] = await Promise.all([
        prisma.auditLog.findMany({
            where: whereClause,
            select: {
                id: true,
                action: true,
                userId: true,
                ipAddress: true,
                userAgent: true,
                deviceType: true,
                country: true,
                city: true,
                riskLevel: true,
                timestamp: true,
                success: true,
                details: true
            },
            orderBy: { timestamp: 'desc' },
            skip,
            take: limit
        }),
        prisma.auditLog.count({ where: whereClause })
    ]);

    sendPaginated(res, logs, {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
    }, 'Audit logs retrieved successfully');
});

const getAllAuditLogs = asyncHandler(async (req, res) => {
    const { page, limit } = getPaginationParams(req.query);

    const skip = (page - 1) * limit;
    const logs = await prisma.auditLog.findMany({
        select: {
            id: true,
            action: true,
            userId: true,
            ipAddress: true,
            userAgent: true,
            deviceType: true,
            country: true,
            city: true,
            riskLevel: true,
            timestamp: true,
            success: true,
            details: true
        },
        orderBy: { timestamp: 'desc' },
        skip,
        take: limit
    });

    sendPaginated(res, logs, {
        page,
        limit,
        total: logs.length,
        totalPages: Math.ceil(logs.length / limit)
    }, 'Audit logs retrieved successfully');
});

const exportAuditLogs = asyncHandler(async (req, res) => {
    try {
        const { format = 'csv', limit = 10000 } = req.query; // Get format from query params (csv or excel)

        // Validate format
        const validFormats = ['csv', 'excel'];
        const exportFormat = validFormats.includes(format.toLowerCase()) ? format.toLowerCase() : 'csv';

        // Validate limit
        const recordLimit = Math.min(parseInt(limit) || 10000, 50000); // Max 50k records

        const logs = await prisma.auditLog.findMany({
            take: recordLimit,
            select: {
                id: true,
                action: true,
                userId: true,
                ipAddress: true,
                userAgent: true,
                deviceType: true,
                country: true,
                city: true,
                riskLevel: true,
                timestamp: true,
                success: true,
                details: true
            },
            orderBy: { timestamp: 'desc' }
        });

        if (logs.length === 0) {
            return sendError(res, 'No audit logs available for export', 404);
        }

        // Format the data for export
        const formattedLogs = logs.map(log => ({
            ID: log.id,
            Action: log.action,
            'User ID': log.userId,
            'IP Address': log.ipAddress,
            'User Agent': log.userAgent || 'N/A',
            'Device Type': log.deviceType || 'Unknown',
            Country: log.country || 'N/A',
            City: log.city || 'N/A',
            'Risk Level': log.riskLevel,
            Timestamp: new Date(log.timestamp).toISOString(),
            Success: log.success ? 'Yes' : 'No',
            Details: log.details ? JSON.stringify(log.details) : '{}'
        }));

        if (exportFormat === 'excel') {
            // Export as Excel
            const ExcelJS = require('exceljs');
            const workbook = new ExcelJS.Workbook();
            const worksheet = workbook.addWorksheet('Audit Logs');

            // Add metadata
            workbook.creator = 'Audit System';
            workbook.created = new Date();
            workbook.modified = new Date();

            // Define columns
            worksheet.columns = [
                { header: 'ID', key: 'ID', width: 10 },
                { header: 'Action', key: 'Action', width: 20 },
                { header: 'User ID', key: 'User ID', width: 15 },
                { header: 'IP Address', key: 'IP Address', width: 15 },
                { header: 'User Agent', key: 'User Agent', width: 30 },
                { header: 'Device Type', key: 'Device Type', width: 15 },
                { header: 'Country', key: 'Country', width: 15 },
                { header: 'City', key: 'City', width: 15 },
                { header: 'Risk Level', key: 'Risk Level', width: 12 },
                { header: 'Timestamp', key: 'Timestamp', width: 25 },
                { header: 'Success', key: 'Success', width: 10 },
                { header: 'Details', key: 'Details', width: 40 }
            ];

            // Style header row
            worksheet.getRow(1).font = { bold: true, size: 12 };
            worksheet.getRow(1).fill = {
                type: 'pattern',
                pattern: 'solid',
                fgColor: { argb: 'FF4472C4' }
            };
            worksheet.getRow(1).font.color = { argb: 'FFFFFFFF' };
            worksheet.getRow(1).alignment = { vertical: 'middle', horizontal: 'center' };
            worksheet.getRow(1).height = 20;

            // Add data rows
            formattedLogs.forEach((log, index) => {
                const row = worksheet.addRow(log);

                // Alternate row colors for better readability
                if (index % 2 === 0) {
                    row.fill = {
                        type: 'pattern',
                        pattern: 'solid',
                        fgColor: { argb: 'FFF2F2F2' }
                    };
                }

                // Color code risk levels
                const riskCell = row.getCell('Risk Level');
                switch (log['Risk Level']) {
                    case 'HIGH':
                        riskCell.font = { color: { argb: 'FFFF0000' }, bold: true };
                        break;
                    case 'MEDIUM':
                        riskCell.font = { color: { argb: 'FFFF9900' }, bold: true };
                        break;
                    case 'LOW':
                        riskCell.font = { color: { argb: 'FF00AA00' } };
                        break;
                }

                // Color code success/failure
                const successCell = row.getCell('Success');
                if (log.Success === 'No') {
                    successCell.font = { color: { argb: 'FFFF0000' }, bold: true };
                } else {
                    successCell.font = { color: { argb: 'FF00AA00' } };
                }
            });

            // Freeze header row
            worksheet.views = [
                { state: 'frozen', ySplit: 1 }
            ];

            // Add filters to header row
            worksheet.autoFilter = {
                from: 'A1',
                to: 'L1'
            };

            // Generate filename with timestamp
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
            const fileName = `audit-logs-${timestamp}.xlsx`;

            // Set response headers for Excel
            res.setHeader(
                'Content-Type',
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            );
            res.setHeader(
                'Content-Disposition',
                `attachment; filename="${fileName}"`
            );
            res.setHeader(
                'Cache-Control',
                'no-cache, no-store, must-revalidate'
            );
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');

            // Write to response using streaming
            await workbook.xlsx.write(res);
            res.end();

        } else {
            // Export as CSV (default)
            const createCsvWriter = require('csv-writer').createObjectCsvWriter;
            const path = require('path');
            const fs = require('fs').promises;
            const fsSync = require('fs');

            // Generate filename with timestamp
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
            const fileName = `audit-logs-${timestamp}.csv`;
            const exportDir = path.join(__dirname, '../exports');
            const filePath = path.join(exportDir, fileName);

            try {
                // Ensure exports directory exists
                if (!fsSync.existsSync(exportDir)) {
                    await fs.mkdir(exportDir, { recursive: true });
                }

                const csvWriter = createCsvWriter({
                    path: filePath,
                    header: [
                        { id: 'ID', title: 'ID' },
                        { id: 'Action', title: 'Action' },
                        { id: 'User ID', title: 'User ID' },
                        { id: 'IP Address', title: 'IP Address' },
                        { id: 'User Agent', title: 'User Agent' },
                        { id: 'Device Type', title: 'Device Type' },
                        { id: 'Country', title: 'Country' },
                        { id: 'City', title: 'City' },
                        { id: 'Risk Level', title: 'Risk Level' },
                        { id: 'Timestamp', title: 'Timestamp' },
                        { id: 'Success', title: 'Success' },
                        { id: 'Details', title: 'Details' }
                    ]
                });

                await csvWriter.writeRecords(formattedLogs);

                // Set response headers
                res.setHeader('Content-Type', 'text/csv');
                res.setHeader(
                    'Content-Disposition',
                    `attachment; filename="${fileName}"`
                );
                res.setHeader(
                    'Cache-Control',
                    'no-cache, no-store, must-revalidate'
                );
                res.setHeader('Pragma', 'no-cache');
                res.setHeader('Expires', '0');

                // Send file for download
                res.download(filePath, fileName, async (err) => {
                    if (err) {
                        console.error('Error downloading file:', err);
                        if (!res.headersSent) {
                            return sendError(res, 'Error exporting audit logs', 500);
                        }
                    }

                    // Delete file after download
                    try {
                        await fs.unlink(filePath);
                    } catch (unlinkError) {
                        console.error('Error deleting temporary file:', unlinkError);
                        // Don't send error to user as download was successful
                    }
                });

            } catch (fileError) {
                console.error('File system error:', fileError);
                return sendError(res, 'Failed to create export file', 500);
            }
        }

        // setImmediate(async () => {
        //     try {
        //         await prisma.auditLog.create({
        //             action: 'AUDIT LOGS EXPORTED',
        //             userId: req.user.userId,
        //             ipAddress: req.deviceInfo.ip || null,
        //             userAgent: req.deviceInfo.userAgent || null,
        //             deviceType: req.deviceInfo.deviceType || null,
        //             country: req.deviceInfo.country.name || null,
        //             city: req.deviceInfo.city || null,
        //             riskLevel: RISK_LEVELS.CRITICAL,
        //             timestamp: new Date(),
        //             success: true,
        //             details: {
        //                 userId: req.user.userId,
        //                 organizationId: req.user.organizationId || null,
        //                 email: req.user.email || null,
        //                 info: `Audit logs exported in ${format.toUpperCase()} format`
        //             }
        //         });
        //     } catch (auditError) {
        //         console.error('Audit log creation failed:', auditError);
        //     }
        // })


    } catch (error) {
        console.error('Export audit logs error:', error);
        return sendError(res, 'Failed to export audit logs', 500);
    }
});

/** Get all login attempts (successful and failed) */

const getLoginAttempts = asyncHandler(async (req, res) => {
    const { page, limit } = getPaginationParams(req.query);
    const { userId, startDate, endDate, country, city, deviceType } = req.query;

    const skip = (page - 1) * limit;

    // Build where clause based on query parameters
    const whereClause = {
        ...(userId && { userId }),
        ...(country && { country: { contains: country, mode: 'insensitive' } }),
        ...(city && { city: { contains: city, mode: 'insensitive' } }),
        ...(deviceType && { deviceType: { contains: deviceType, mode: 'insensitive' } }),
        ...(startDate && endDate && {
            createdAt: {
                gte: new Date(startDate),
                lte: new Date(endDate)
            }
        }),
        ...(startDate && !endDate && {
            createdAt: {
                gte: new Date(startDate)
            }
        }),
        ...(!startDate && endDate && {
            createdAt: {
                lte: new Date(endDate)
            }
        })
    };

    // Fetch login attempts and total count
    const [loginAttempts, total] = await Promise.all([
        prisma.loginAttempts.findMany({
            where: whereClause,
            select: {
                id: true,
                userId: true,
                ipAddress: true,
                userAgent: true,
                deviceType: true,
                country: true,
                city: true,
                browser: true,
                createdAt: true,
                user: {
                    select: {
                        id: true,
                        firstName: true,
                        lastName: true,
                        lastLoginAt: true,
                        lastLoginIp: true,
                        email: true
                    }
                }
            },
            orderBy: { createdAt: 'desc' },
            skip,
            take: limit
        }),
        prisma.loginAttempts.count({ where: whereClause })
    ]);

    // Format the response data
    const formattedAttempts = loginAttempts.map(attempt => ({
        id: attempt.id,
        userId: attempt.userId,
        userName: attempt.user?.firstName || 'N/A',
        userEmail: attempt.user?.email || 'N/A',
        ipAddress: attempt.ipAddress,
        userAgent: attempt.userAgent,
        deviceType: attempt.deviceType,
        browser: attempt.browser,
        country: attempt.country,
        city: attempt.city,
        timestamp: attempt.createdAt
    }));

    sendPaginated(res, formattedAttempts, {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
    }, 'Login attempts retrieved successfully');
});

/**
 * Export login attempts
 * @route GET /api/login-attempts/export
 * @access Private/Admin
 */
const exportLoginAttempts = asyncHandler(async (req, res) => {
    const { format = 'csv', userId, startDate, endDate, country, city, deviceType, limit = 10000 } = req.query;

    // Validate limit
    const recordLimit = Math.min(parseInt(limit) || 10000, 50000);

    // Build where clause
    const whereClause = {
        ...(userId && { userId }),
        ...(country && { country: { contains: country, mode: 'insensitive' } }),
        ...(city && { city: { contains: city, mode: 'insensitive' } }),
        ...(deviceType && { deviceType: { contains: deviceType, mode: 'insensitive' } }),
        ...(startDate && endDate && {
            createdAt: {
                gte: new Date(startDate),
                lte: new Date(endDate)
            }
        }),
        ...(startDate && !endDate && {
            createdAt: {
                gte: new Date(startDate)
            }
        }),
        ...(!startDate && endDate && {
            createdAt: {
                lte: new Date(endDate)
            }
        })
    };

    // Fetch login attempts
    const loginAttempts = await prisma.loginAttempts.findMany({
        where: whereClause,
        take: recordLimit,
        select: {
            id: true,
            userId: true,
            ipAddress: true,
            userAgent: true,
            deviceType: true,
            country: true,
            city: true,
            browser: true,
            createdAt: true,
            user: {
                select: {
                    id: true,
                    name: true,
                    email: true
                }
            }
        },
        orderBy: { createdAt: 'desc' }
    });

    if (loginAttempts.length === 0) {
        return sendError(res, 'No login attempts available for export', 404);
    }

    // Format data for export
    const formattedData = loginAttempts.map(attempt => ({
        'Attempt ID': attempt.id,
        'User ID': attempt.userId,
        'User Name': attempt.user?.name || 'N/A',
        'User Email': attempt.user?.email || 'N/A',
        'IP Address': attempt.ipAddress || 'N/A',
        'User Agent': attempt.userAgent || 'N/A',
        'Device Type': attempt.deviceType || 'Unknown',
        'Browser': attempt.browser || 'Unknown',
        'Country': attempt.country || 'N/A',
        'City': attempt.city || 'N/A',
        'Timestamp': new Date(attempt.createdAt).toISOString()
    }));

    // Define columns
    const columns = [
        { key: 'Attempt ID', header: 'Attempt ID', width: 20 },
        { key: 'User ID', header: 'User ID', width: 20 },
        { key: 'User Name', header: 'User Name', width: 25 },
        { key: 'User Email', header: 'User Email', width: 30 },
        { key: 'IP Address', header: 'IP Address', width: 15 },
        { key: 'User Agent', header: 'User Agent', width: 40 },
        { key: 'Device Type', header: 'Device Type', width: 15 },
        { key: 'Browser', header: 'Browser', width: 15 },
        { key: 'Country', header: 'Country', width: 15 },
        { key: 'City', header: 'City', width: 15 },
        { key: 'Timestamp', header: 'Timestamp', width: 25 }
    ];

    // Custom cell formatter
    const loginAttemptCellFormatter = (row, item) => {
        // Highlight suspicious IPs (example logic)
        const ipCell = row.getCell('IP Address');
        if (item['IP Address'] && item['IP Address'] !== 'N/A') {
            ipCell.font = { color: { argb: 'FF0066CC' } };
        }

        // Format timestamp cell
        const timestampCell = row.getCell('Timestamp');
        timestampCell.alignment = { horizontal: 'left' };
    };

    // Export data
    try {
        await exportData({
            data: formattedData,
            columns,
            res,
            format,
            fileName: 'login-attempts',
            excelOptions: {
                sheetName: 'Login Attempts',
                autoFilter: true,
                freezeHeader: true,
                alternateRows: true,
                cellFormatter: loginAttemptCellFormatter
            },
            metadata: {
                creator: 'Security System',
                modifiedBy: req.user?.name || 'System'
            }
        });
    } catch (error) {
        console.error('Export error:', error);
        if (!res.headersSent) {
            return sendError(res, 'Failed to export login attempts', 500);
        }
    }
});

/**
 * Get login attempts statistics
 * @route GET /api/login-attempts/stats
 * @access Private/Admin
 */
const getLoginAttemptsStats = asyncHandler(async (req, res) => {
    const { userId, startDate, endDate } = req.query;

    // Build where clause
    const whereClause = {
        ...(userId && { userId }),
        ...(startDate && endDate && {
            createdAt: {
                gte: new Date(startDate),
                lte: new Date(endDate)
            }
        })
    };

    // Get statistics
    const [
        totalAttempts,
        uniqueUsers,
        topCountries,
        topDevices,
        topBrowsers,
        recentAttempts
    ] = await Promise.all([
        // Total login attempts
        prisma.loginAttempts.count({ where: whereClause }),

        // Unique users
        prisma.loginAttempts.findMany({
            where: whereClause,
            select: { userId: true },
            distinct: ['userId']
        }),

        // Top countries
        prisma.loginAttempts.groupBy({
            by: ['country'],
            where: {
                ...whereClause,
                country: { not: null }
            },
            _count: { country: true },
            orderBy: { _count: { country: 'desc' } },
            take: 5
        }),

        // Top device types
        prisma.loginAttempts.groupBy({
            by: ['deviceType'],
            where: {
                ...whereClause,
                deviceType: { not: null }
            },
            _count: { deviceType: true },
            orderBy: { _count: { deviceType: 'desc' } },
            take: 5
        }),

        // Top browsers
        prisma.loginAttempts.groupBy({
            by: ['browser'],
            where: {
                ...whereClause,
                browser: { not: null }
            },
            _count: { browser: true },
            orderBy: { _count: { browser: 'desc' } },
            take: 5
        }),

        // Recent attempts
        prisma.loginAttempts.findMany({
            where: whereClause,
            select: {
                id: true,
                userId: true,
                country: true,
                city: true,
                createdAt: true,
                user: {
                    select: {
                        firstName: true,
                        email: true
                    }
                }
            },
            orderBy: { createdAt: 'desc' },
            take: 10
        })
    ]);

    const stats = {
        totalAttempts,
        uniqueUsers: uniqueUsers.length,
        topCountries: topCountries.map(c => ({
            country: c.country,
            count: c._count.country
        })),
        topDevices: topDevices.map(d => ({
            deviceType: d.deviceType,
            count: d._count.deviceType
        })),
        topBrowsers: topBrowsers.map(b => ({
            browser: b.browser,
            count: b._count.browser
        })),
        recentAttempts: recentAttempts.map(a => ({
            id: a.id,
            userId: a.userId,
            userName: a.user?.firstName || 'N/A',
            userEmail: a.user?.email || 'N/A',
            location: `${a.city || 'Unknown'}, ${a.country || 'Unknown'}`,
            timestamp: a.createdAt
        }))
    };

    sendSuccess(res, stats, 'Login attempts statistics retrieved successfully');
});

/**
 * Get all login attempts (paginated)
 * @route GET /api/login-attempts/all
 * @access Private/Admin
 */
const getAllLoginAttempts = asyncHandler(async (req, res) => {
    const { page, limit } = getPaginationParams(req.query);

    const skip = (page - 1) * limit;

    // Fetch login attempts and total count in parallel
    const [loginAttempts, total] = await Promise.all([
        prisma.loginAttempts.findMany({
            select: {
                id: true,
                userId: true,
                ipAddress: true,
                userAgent: true,
                deviceType: true,
                browser: true,
                country: true,
                city: true,
                createdAt: true,
                user: {
                    select: {
                        id: true,
                        firstName: true,
                        email: true
                    }
                }
            },
            orderBy: { createdAt: 'desc' },
            skip,
            take: limit
        }),
        prisma.loginAttempts.count()
    ]);

    // Format the response data
    const formattedAttempts = loginAttempts.map(attempt => ({
        id: attempt.id,
        userId: attempt.userId,
        userName: attempt.user?.firstName || 'N/A',
        userEmail: attempt.user?.email || 'N/A',
        ipAddress: attempt.ipAddress || 'N/A',
        userAgent: attempt.userAgent || 'N/A',
        deviceType: attempt.deviceType || 'Unknown',
        browser: attempt.browser || 'Unknown',
        country: attempt.country || 'N/A',
        city: attempt.city || 'N/A',
        timestamp: attempt.createdAt
    }));

    sendPaginated(res, formattedAttempts, {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
    }, 'All login attempts retrieved successfully');
});

/**
 * Get user-specific login attempts
 * @route GET /api/login-attempts/user/:userId
 * @access Private/Admin or Own User
 */
const getUserLoginAttempts = asyncHandler(async (req, res) => {
    const { userId } = req.params;
    const { page, limit } = getPaginationParams(req.query);


    const skip = (page - 1) * limit;

    const [loginAttempts, total] = await Promise.all([
        prisma.loginAttempts.findMany({
            where: { userId },
            select: {
                id: true,
                ipAddress: true,
                userAgent: true,
                deviceType: true,
                browser: true,
                country: true,
                city: true,
                createdAt: true
            },
            orderBy: { createdAt: 'desc' },
            skip,
            take: limit
        }),
        prisma.loginAttempts.count({ where: { userId } })
    ]);

    const formattedAttempts = loginAttempts.map(attempt => ({
        id: attempt.id,
        ipAddress: attempt.ipAddress || 'N/A',
        userAgent: attempt.userAgent || 'N/A',
        deviceType: attempt.deviceType || 'Unknown',
        browser: attempt.browser || 'Unknown',
        location: `${attempt.city || 'Unknown'}, ${attempt.country || 'Unknown'}`,
        timestamp: attempt.createdAt
    }));

    sendPaginated(res, formattedAttempts, {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
    }, 'User login attempts retrieved successfully');
});

/**
 * Get recent login attempts (last 24 hours)
 * @route GET /api/login-attempts/recent
 * @access Private/Admin
 */
const getRecentLoginAttempts = asyncHandler(async (req, res) => {
    const { limit = 50 } = req.query;

    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

    const recentAttempts = await prisma.loginAttempts.findMany({
        where: {
            createdAt: {
                gte: twentyFourHoursAgo
            }
        },
        select: {
            id: true,
            userId: true,
            ipAddress: true,
            deviceType: true,
            browser: true,
            country: true,
            city: true,
            createdAt: true,
            user: {
                select: {
                    firstName: true,
                    email: true
                }
            }
        },
        orderBy: { createdAt: 'desc' },
        take: parseInt(limit)
    });

    const formattedAttempts = recentAttempts.map(attempt => ({
        id: attempt.id,
        userId: attempt.userId,
        userName: attempt.user?.firstName || 'N/A',
        userEmail: attempt.user?.email || 'N/A',
        ipAddress: attempt.ipAddress || 'N/A',
        device: `${attempt.deviceType || 'Unknown'} - ${attempt.browser || 'Unknown'}`,
        location: `${attempt.city || 'Unknown'}, ${attempt.country || 'Unknown'}`,
        timestamp: attempt.createdAt,
        timeAgo: getTimeAgo(attempt.createdAt)
    }));

    sendSuccess(res, {
        total: formattedAttempts.length,
        attempts: formattedAttempts
    }, 'Recent login attempts retrieved successfully');
});

/**
 * Get login attempts by IP address
 * @route GET /api/login-attempts/ip/:ipAddress
 * @access Private/Admin
 */
const getLoginAttemptsByIP = asyncHandler(async (req, res) => {
    const { ipAddress } = req.params;
    const { page, limit } = getPaginationParams(req.query);

    const skip = (page - 1) * limit;

    const [loginAttempts, total] = await Promise.all([
        prisma.loginAttempts.findMany({
            where: { ipAddress },
            select: {
                id: true,
                userId: true,
                userAgent: true,
                deviceType: true,
                browser: true,
                country: true,
                city: true,
                createdAt: true,
                user: {
                    select: {
                        firstName: true,
                        email: true
                    }
                }
            },
            orderBy: { createdAt: 'desc' },
            skip,
            take: limit
        }),
        prisma.loginAttempts.count({ where: { ipAddress } })
    ]);

    const formattedAttempts = loginAttempts.map(attempt => ({
        id: attempt.id,
        userId: attempt.userId,
        userName: attempt.user?.firstName || 'N/A',
        userEmail: attempt.user?.email || 'N/A',
        userAgent: attempt.userAgent || 'N/A',
        deviceType: attempt.deviceType || 'Unknown',
        browser: attempt.browser || 'Unknown',
        location: `${attempt.city || 'Unknown'}, ${attempt.country || 'Unknown'}`,
        timestamp: attempt.createdAt
    }));

    sendPaginated(res, formattedAttempts, {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
    }, `Login attempts from IP ${ipAddress} retrieved successfully`);
});

/**
 * Delete old login attempts
 * @route DELETE /api/login-attempts/cleanup
 * @access Private/Admin
 */
const cleanupOldLoginAttempts = asyncHandler(async (req, res) => {
    const { days = 90 } = req.query; // Default: delete attempts older than 90 days

    const cutoffDate = new Date(Date.now() - parseInt(days) * 24 * 60 * 60 * 1000);

    const result = await prisma.loginAttempts.deleteMany({
        where: {
            createdAt: {
                lt: cutoffDate
            }
        }
    });

    sendSuccess(res, {
        deletedCount: result.count,
        cutoffDate
    }, `Deleted ${result.count} login attempts older than ${days} days`);
});

// Helper function to calculate time ago
const getTimeAgo = (date) => {
    const seconds = Math.floor((new Date() - new Date(date)) / 1000);

    const intervals = {
        year: 31536000,
        month: 2592000,
        week: 604800,
        day: 86400,
        hour: 3600,
        minute: 60,
        second: 1
    };

    for (const [unit, secondsInUnit] of Object.entries(intervals)) {
        const interval = Math.floor(seconds / secondsInUnit);
        if (interval >= 1) {
            return `${interval} ${unit}${interval === 1 ? '' : 's'} ago`;
        }
    }

    return 'just now';
};

/**
 * Role Management
 * - Create Role
 * - Assign Role to User
 * - Revoke Role from User
 */

const createRole = asyncHandler(async (req, res) => {
    const { name, slug, permissions } = req.body;

    // Basic validation
    if (!name || !slug) {
        return sendError(res, 'Role name and slug are required', 400);
    }

    // Check for existing role with same slug
    const existingRole = await prisma.role.findUnique({
        where: { slug }
    });

    if (existingRole) {
        return sendError(res, 'Role with this slug already exists', 400);
    }

    // Create new role
    const newRole = await prisma.role.create({
        data: {
            name,
            slug,
            permissions: permissions || []
        },
        select: {
            id: true,
            name: true,
            slug: true,
            permissions: true,
            createdAt: true,
            updatedAt: true
        }
    });

    sendSuccess(res, { role: newRole }, 'Role created successfully', 201);
});

const assignRoleToUser = asyncHandler(async (userId, roleId) => {
    // Check if user already has the role
    const existingAssignment = await prisma.userRole.findFirst({
        where: { userId, roleId }
    });

    if (existingAssignment) {
        return; // Role already assigned, no action needed
    }

    // Assign role to user
    await prisma.userRole.create({
        data: { userId, roleId }
    });
});


const revokeRoleFromUser = asyncHandler(async (userId, roleId) => {
    // Check if user has the role
    const existingAssignment = await prisma.userRole.findFirst({
        where: { userId, roleId }
    });

    if (!existingAssignment) {
        return; // Role not assigned, no action needed
    }

    // Revoke role from user
    await prisma.userRole.delete({
        where: { id: existingAssignment.id }
    });
});




/**
 * Get user sessions
 * @route GET /api/sessions/user/:userId
 * @access Private (Admin or own user)
 */
const getUserSessions = asyncHandler(async (req, res) => {
    const { userId } = req.params;
    const { page, limit } = getPaginationParams(req.query);
    const { isActive } = req.query;

    const skip = (page - 1) * limit;

    // Build where clause
    const whereClause = {
        userId,
        ...(isActive !== undefined && { isActive: isActive === 'true' })
    };

    const [sessions, total] = await Promise.all([
        prisma.session.findMany({
            where: whereClause,
            select: {
                id: true,
                userAgent: true,
                ipAddress: true,
                isActive: true,
                mfaVerifiedAt: true,
                expiresAt: true,
                createdAt: true,
                updatedAt: true
            },
            orderBy: { createdAt: 'desc' },
            skip,
            take: limit
        }),
        prisma.session.count({ where: whereClause })
    ]);

    const formattedSessions = sessions.map(session => ({
        id: session.id,
        ipAddress: session.ipAddress || 'N/A',
        userAgent: session.userAgent || 'N/A',
        isActive: session.isActive,
        isMfaVerified: !!session.mfaVerifiedAt,
        expiresAt: session.expiresAt,
        createdAt: session.createdAt,
        isExpired: new Date() > new Date(session.expiresAt),
        isCurrent: session.id === req.sessionId, // If you track current session
        timeUntilExpiry: getTimeUntilExpiry(session.expiresAt)
    }));

    sendPaginated(res, formattedSessions, {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
    }, 'User sessions retrieved successfully');
});

/**
 * Get current session
 * @route GET /api/sessions/current
 * @access Private
 */
const getCurrentSession = asyncHandler(async (req, res) => {
    const sessionToken = req.headers.authorization?.split(' ')[1];

    console.log('Session Token:', sessionToken); // Debug log

    if (!sessionToken) {
        return sendError(res, 'Session token not found', 401);
    }

    const session = await prisma.session.findUnique({
        where: { token: sessionToken },
        select: {
            id: true,
            userId: true,
            userAgent: true,
            ipAddress: true,
            isActive: true,
            mfaVerifiedAt: true,
            expiresAt: true,
            createdAt: true,
            updatedAt: true,
            organizationId: true,
            user: {
                select: {
                    id: true,
                    firstName: true,
                    lastName: true,
                    email: true
                }
            },
            organization: {
                select: {
                    id: true,
                    name: true
                }
            }
        }
    });

    if (!session) {
        return sendError(res, 'Session not found', 404);
    }

    const formattedSession = {
        id: session.id,
        userId: session.userId,
        userName: session.user?.name || 'N/A',
        userEmail: session.user?.email || 'N/A',
        userRole: session.user?.role || 'N/A',
        organizationId: session.organizationId,
        organizationName: session.organization?.name || 'N/A',
        ipAddress: session.ipAddress || 'N/A',
        userAgent: session.userAgent || 'N/A',
        isActive: session.isActive,
        isMfaVerified: !!session.mfaVerifiedAt,
        mfaVerifiedAt: session.mfaVerifiedAt,
        expiresAt: session.expiresAt,
        createdAt: session.createdAt,
        updatedAt: session.updatedAt,
        isExpired: new Date() > new Date(session.expiresAt),
        timeUntilExpiry: getTimeUntilExpiry(session.expiresAt)
    };

    sendSuccess(res, formattedSession, 'Current session retrieved successfully');
});

/**
 * Get active sessions count
 * @route GET /api/sessions/active/count
 * @access Private/Admin
 */
const getActiveSessionsCount = asyncHandler(async (req, res) => {
    const { userId, organizationId } = req.query;

    const whereClause = {
        isActive: true,
        expiresAt: {
            gte: new Date()
        },
        ...(userId && { userId }),
        ...(organizationId && { organizationId })
    };

    const count = await prisma.session.count({
        where: whereClause
    });

    sendSuccess(res, { count }, 'Active sessions count retrieved successfully');
});

/**
 * Get sessions statistics
 * @route GET /api/sessions/stats
 * @access Private/Admin
 */
const getSessionsStats = asyncHandler(async (req, res) => {
    const { userId, organizationId, startDate, endDate } = req.query;

    const whereClause = {
        ...(userId && { userId }),
        ...(organizationId && { organizationId }),
        ...(startDate && endDate && {
            createdAt: {
                gte: new Date(startDate),
                lte: new Date(endDate)
            }
        })
    };

    const now = new Date();

    const [
        totalSessions,
        activeSessions,
        expiredSessions,
        mfaVerifiedSessions,
        uniqueUsers,
        topUsers,
        recentSessions
    ] = await Promise.all([
        // Total sessions
        prisma.session.count({ where: whereClause }),

        // Active sessions
        prisma.session.count({
            where: {
                ...whereClause,
                isActive: true,
                expiresAt: { gte: now }
            }
        }),

        // Expired sessions
        prisma.session.count({
            where: {
                ...whereClause,
                expiresAt: { lt: now }
            }
        }),

        // MFA verified sessions
        prisma.session.count({
            where: {
                ...whereClause,
                mfaVerifiedAt: { not: null }
            }
        }),

        // Unique users with sessions
        prisma.session.findMany({
            where: whereClause,
            select: { userId: true },
            distinct: ['userId']
        }),

        // Top users by session count
        prisma.session.groupBy({
            by: ['userId'],
            where: whereClause,
            _count: { userId: true },
            orderBy: { _count: { userId: 'desc' } },
            take: 10
        }),

        // Recent sessions
        prisma.session.findMany({
            where: whereClause,
            select: {
                id: true,
                userId: true,
                ipAddress: true,
                isActive: true,
                createdAt: true,
                expiresAt: true,
                user: {
                    select: {
                        firstName: true,
                        email: true
                    }
                }
            },
            orderBy: { createdAt: 'desc' },
            take: 10
        })
    ]);

    // Get user details for top users
    const topUserIds = topUsers.map(u => u.userId);
    const userDetails = await prisma.user.findMany({
        where: { id: { in: topUserIds } },
        select: { id: true, firstName: true, email: true }
    });

    const userMap = Object.fromEntries(
        userDetails.map(u => [u.id, u])
    );

    const stats = {
        totalSessions,
        activeSessions,
        expiredSessions,
        inactiveSessions: totalSessions - activeSessions - expiredSessions,
        mfaVerifiedSessions,
        mfaVerificationRate: totalSessions > 0
            ? ((mfaVerifiedSessions / totalSessions) * 100).toFixed(2) + '%'
            : '0%',
        uniqueUsers: uniqueUsers.length,
        topUsers: topUsers.map(u => ({
            userId: u.userId,
            userName: userMap[u.userId]?.firstName || 'N/A',
            userEmail: userMap[u.userId]?.email || 'N/A',
            sessionCount: u._count.userId
        })),
        recentSessions: recentSessions.map(s => ({
            id: s.id,
            userId: s.userId,
            userName: s.user?.firstName || 'N/A',
            userEmail: s.user?.email || 'N/A',
            ipAddress: s.ipAddress || 'N/A',
            isActive: s.isActive,
            createdAt: s.createdAt,
            expiresAt: s.expiresAt,
            isExpired: now > new Date(s.expiresAt)
        }))
    };

    sendSuccess(res, stats, 'Session statistics retrieved successfully');
});

/**
 * Revoke all user sessions except current
 * @route DELETE /api/sessions/user/:userId/revoke-all
 * @access Private (Admin or own user)
 */
const revokeAllUserSessions = asyncHandler(async (req, res) => {
    const { userId } = req.params;
    const { exceptCurrent } = req.query;
    const currentSessionToken = req.headers.authorization?.split(' ')[1];

    let currentSessionId = null;

    // Get current session ID if we want to keep it
    if (exceptCurrent === 'true' && currentSessionToken) {
        const currentSession = await prisma.session.findUnique({
            where: { token: currentSessionToken },
            select: { id: true }
        });
        currentSessionId = currentSession?.id;
    }

    // Revoke all sessions
    const result = await prisma.session.updateMany({
        where: {
            userId,
            isActive: true,
            ...(currentSessionId && { id: { not: currentSessionId } })
        },
        data: { isActive: false }
    });

    await prisma.auditLog.create({
        data: {
            action: 'REVOKE ALL SESSIONS',
            userId: req.user.userId,
            ipAddress: req.deviceInfo.ip || null,
            userAgent: req.deviceInfo.userAgent || null,
            deviceType: req.deviceInfo.deviceType || null,
            country: req.deviceInfo.country.name || null,
            city: req.deviceInfo.city || null,
            riskLevel: RISK_LEVELS.CRITICAL,
            timestamp: new Date(),
            success: false,
            details: {
                userId,
                organizationId: req.user.organizationId || null,
                email: req.user.email || null,
                info: 'Revoked all sessions except current session'
            }
        }
    });

    sendSuccess(
        res,
        { revokedCount: result.count },
        `Revoked ${result.count} session(s) successfully`
    );
});

/**
 * Clean up expired sessions
 * @route DELETE /api/sessions/cleanup
 * @access Private/Admin
 */
const cleanupExpiredSessions = asyncHandler(async (req, res) => {
    const { days = 30 } = req.query;

    const cutoffDate = new Date(Date.now() - parseInt(days) * 24 * 60 * 60 * 1000);
    const now = new Date();

    const result = await prisma.session.deleteMany({
        where: {
            OR: [
                {
                    expiresAt: { lt: now },
                    updatedAt: { lt: cutoffDate }
                },
                {
                    isActive: false,
                    updatedAt: { lt: cutoffDate }
                }
            ]
        }
    });

    sendSuccess(
        res,
        {
            deletedCount: result.count,
            cutoffDate
        },
        `Deleted ${result.count} expired/inactive sessions older than ${days} days`
    );
});

/**
 * Export sessions
 * @route GET /api/sessions/export
 * @access Private/Admin
 */
const exportSessions = asyncHandler(async (req, res) => {
    const {
        format = 'csv',
        userId,
        organizationId,
        isActive,
        startDate,
        endDate,
        limit = 10000
    } = req.query;

    // Validate limit
    const recordLimit = Math.min(parseInt(limit) || 10000, 50000);

    // Build where clause
    const whereClause = {
        ...(userId && { userId }),
        ...(organizationId && { organizationId }),
        ...(isActive !== undefined && { isActive: isActive === 'true' }),
        ...(startDate && endDate && {
            createdAt: {
                gte: new Date(startDate),
                lte: new Date(endDate)
            }
        })
    };


    const sessions = await prisma.session.findMany({
        where: whereClause,
        take: recordLimit,
        select: {
            id: true,
            userId: true,
            userAgent: true,
            ipAddress: true,
            isActive: true,
            mfaVerifiedAt: true,
            expiresAt: true,
            createdAt: true,
            updatedAt: true,
            organizationId: true,
            user: {
                select: {
                    id: true,
                    firstName: true,
                    email: true
                }
            },
            organization: {
                select: {
                    id: true,
                    name: true
                }
            }
        },
        orderBy: { createdAt: 'desc' }
    });

    console.log(sessions)

    if (sessions.length === 0) {
        return sendError(res, 'No sessions available for export', 404);
    }

    // Format data for export
    const formattedData = sessions.map(session => ({
        'Session ID': session.id,
        'User ID': session.userId,
        'User Name': session.user?.firstName || 'N/A',
        'User Email': session.user?.email || 'N/A',
        'Organization ID': session.organizationId || 'N/A',
        'Organization Name': session.organization?.name || 'N/A',
        'IP Address': session.ipAddress || 'N/A',
        'User Agent': session.userAgent || 'N/A',
        'Status': session.isActive ? 'Active' : 'Inactive',
        'MFA Verified': session.mfaVerifiedAt ? 'Yes' : 'No',
        'MFA Verified At': session.mfaVerifiedAt ? new Date(session.mfaVerifiedAt).toISOString() : 'N/A',
        'Expires At': new Date(session.expiresAt).toISOString(),
        'Created At': new Date(session.createdAt).toISOString(),
        'Updated At': new Date(session.updatedAt).toISOString(),
        'Is Expired': new Date() > new Date(session.expiresAt) ? 'Yes' : 'No'
    }));

    // Define columns
    const columns = [
        { key: 'Session ID', header: 'Session ID', width: 25 },
        { key: 'User ID', header: 'User ID', width: 20 },
        { key: 'User Name', header: 'User Name', width: 25 },
        { key: 'User Email', header: 'User Email', width: 30 },
        { key: 'Organization ID', header: 'Organization ID', width: 20 },
        { key: 'Organization Name', header: 'Organization Name', width: 25 },
        { key: 'IP Address', header: 'IP Address', width: 15 },
        { key: 'User Agent', header: 'User Agent', width: 40 },
        { key: 'Status', header: 'Status', width: 12 },
        { key: 'MFA Verified', header: 'MFA Verified', width: 12 },
        { key: 'MFA Verified At', header: 'MFA Verified At', width: 25 },
        { key: 'Expires At', header: 'Expires At', width: 25 },
        { key: 'Created At', header: 'Created At', width: 25 },
        { key: 'Updated At', header: 'Updated At', width: 25 },
        { key: 'Is Expired', header: 'Is Expired', width: 12 }
    ];

    // Custom cell formatter
    const sessionCellFormatter = (row, item) => {
        // Color code status
        const statusCell = row.getCell('Status');
        if (item.Status === 'Active') {
            statusCell.font = { color: { argb: 'FF00AA00' }, bold: true };
        } else {
            statusCell.font = { color: { argb: 'FFFF0000' } };
        }

        // Color code expired sessions
        const expiredCell = row.getCell('Is Expired');
        if (item['Is Expired'] === 'Yes') {
            expiredCell.font = { color: { argb: 'FFFF0000' }, bold: true };
        } else {
            expiredCell.font = { color: { argb: 'FF00AA00' } };
        }

        // Highlight MFA verified
        const mfaCell = row.getCell('MFA Verified');
        if (item['MFA Verified'] === 'Yes') {
            mfaCell.font = { color: { argb: 'FF0066CC' }, bold: true };
        }
    };


    // Export data
    try {
        await exportData({
            data: formattedData,
            columns,
            res,
            format,
            fileName: 'sessions',
            excelOptions: {
                sheetName: 'Sessions',
                autoFilter: true,
                freezeHeader: true,
                alternateRows: true,
                cellFormatter: sessionCellFormatter
            },
            metadata: {
                creator: 'Session Management System',
                modifiedBy: req.user?.name || 'System'
            }
        });
    } catch (error) {
        console.error('Export error:', error);
        if (!res.headersSent) {
            return sendError(res, 'Failed to export sessions', 500);
        }
    }
});

// Helper functions
const getTimeUntilExpiry = (expiresAt) => {
    const now = new Date();
    const expiry = new Date(expiresAt);
    const diff = expiry - now;

    if (diff <= 0) return 'Expired';

    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));

    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
};


module.exports = {
    createRole,
    assignRoleToUser,
    revokeRoleFromUser,
    getSystemStats,
    getAllUsers,
    getAllOrganizationUsers,
    createSuperAdmin,
    toggleSuperAdmin,
    deleteAnyUser,
    getAllSessions,
    getUserSessions,
    getCurrentSession,
    getActiveSessionsCount,
    getSessionsStats,
    revokeAllUserSessions,
    cleanupExpiredSessions,
    exportSessions,
    revokeAnySession,
    getUserDetails,
    toggleOrganizationActivation,
    toggleUserActivation,
    getUserProfile,
    getOrganizationDetails,
    transferOrganizationMembership,
    getCorsUrls,
    deleteCorsUrl,
    createCorsUrl,
    getAuditLogs,
    getAllAuditLogs,
    exportAuditLogs,
    getLoginAttempts,
    exportLoginAttempts,
    getLoginAttemptsStats,
    getAllLoginAttempts,
    getUserLoginAttempts,
    getRecentLoginAttempts,
    getLoginAttemptsByIP,
    cleanupOldLoginAttempts
};