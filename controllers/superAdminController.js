const userService = require('../services/userService');
const organizationService = require('../services/organizationService');
const { sendSuccess, sendError, sendPaginated, asyncHandler, getPaginationParams } = require('../utils/response');
const { prisma } = require('../utils/database');
const { AUDIT_ACTIONS, RISK_LEVELS } = require('../config/constants');

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
                info: `User deleted: ${user.email}`
            }
        }
    });
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
                userAgent: true,
                ipAddress: true,
                isActive: true,
                mfaVerifiedAt: true,
                expiresAt: true,
                createdAt: true,
                updatedAt: true,
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
                ipAddress: deviceInfo.ip || null,
                userAgent: deviceInfo.userAgent || null,
                deviceType: deviceInfo.deviceType || null,
                country: deviceInfo.country.name || null,
                city: deviceInfo.city || null,
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
                ipAddress: deviceInfo.ip || null,
                userAgent: deviceInfo.userAgent || null,
                deviceType: deviceInfo.deviceType || null,
                country: deviceInfo.country.name || null,
                city: deviceInfo.city || null,
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
            ipAddress: deviceInfo.ip || null,
            userAgent: deviceInfo.userAgent || null,
            deviceType: deviceInfo.deviceType || null,
            country: deviceInfo.country.name || null,
            city: deviceInfo.city || null,
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

module.exports = {
    getSystemStats,
    getAllUsers,
    createSuperAdmin,
    toggleSuperAdmin,
    deleteAnyUser,
    getAllSessions,
    revokeAnySession,
    getUserDetails
};