const { prisma } = require('../utils/database');
const { generateTokenPair, generateSecureToken, verifyRefreshToken } = require('../utils/jwt');
const { sendPasswordReset, sendInvitation } = require('../utils/email');
const { hashPassword } = require('../utils/hash');
const userService = require('./userService');
const organizationService = require('./organizationService');
const config = require('../config');

/**
 * Register a new user and organization
 * @param {Object} registrationData - Registration data
 * @returns {Promise<Object>} - Registration result with tokens
 */
const register = async (registrationData) => {
    const { email, password, firstName, lastName, phone, organizationName } = registrationData;

    return await prisma.$transaction(async (tx) => {
        let organization = null;

        // Create organization if provided
        if (organizationName) {
            organization = await organizationService.createOrganization({
                name: organizationName
            });
        }

        // Create user
        const user = await userService.createUser({
            email,
            password,
            firstName,
            lastName,
            phone
        }, organization?.id);

        // If organization was created, assign admin role to the user
        if (organization) {
            const adminRole = await tx.role.findFirst({
                where: {
                    organizationId: organization.id,
                    slug: 'admin'
                }
            });

            if (adminRole) {
                await tx.userRole.create({
                    data: {
                        userId: user.id,
                        roleId: adminRole.id
                    }
                });
            }
        }

        // Get user with roles for token generation
        const userWithRoles = await userService.findUserById(user.id);

        // Generate tokens
        const tokens = generateTokenPair({
            userId: user.id,
            email: user.email,
            organizationId: user.organizationId,
            roles: userWithRoles.roles?.map(role => role.slug) || []
        });

        // Create session
        await createSession(user.id, user.organizationId, tokens.accessToken);

        return {
            user: userWithRoles,
            tokens,
            organization
        };
    });
};

/**
 * Login user
 * @param {string} email - User email
 * @param {string} password - User password
 * @param {string} organizationSlug - Organization slug (optional)
 * @param {Object} sessionData - Session metadata
 * @returns {Promise<Object>} - Login result with tokens
 */
const login = async (email, password, organizationSlug = null, sessionData = {}) => {
    // Verify credentials
    const user = await userService.verifyCredentials(email, password);

    if (!user) {
        throw new Error('Invalid email or password');
    }

    if (!user.isActive) {
        throw new Error('Account is deactivated');
    }

    if (!user.organization?.isActive) {
        throw new Error('Organization is deactivated');
    }

    // If organization slug is provided, verify user belongs to that organization
    if (organizationSlug && user.organization?.slug !== organizationSlug) {
        throw new Error('User does not belong to the specified organization');
    }

    // Generate tokens
    const tokens = generateTokenPair({
        userId: user.id,
        email: user.email,
        organizationId: user.organizationId,
        roles: user.roles?.map(role => role.slug) || []
    });

    // Create session
    await createSession(user.id, user.organizationId, tokens.accessToken, sessionData);

    return {
        user,
        tokens
    };
};

/**
 * Refresh access token
 * @param {string} refreshToken - Refresh token
 * @returns {Promise<Object>} - New tokens
 */
const refreshToken = async (refreshToken) => {
    try {
        // Verify refresh token
        const decoded = verifyRefreshToken(refreshToken);

        // Get user with current data
        const user = await userService.findUserById(decoded.userId);

        if (!user || !user.isActive) {
            throw new Error('User not found or inactive');
        }

        if (!user.organization?.isActive) {
            throw new Error('Organization is deactivated');
        }

        // Generate new tokens
        const tokens = generateTokenPair({
            userId: user.id,
            email: user.email,
            organizationId: user.organizationId,
            roles: user.roles?.map(role => role.slug) || []
        });

        // Update session with new token
        await prisma.session.updateMany({
            where: {
                userId: user.id,
                isActive: true
            },
            data: {
                token: tokens.accessToken,
                expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
            }
        });

        return {
            user,
            tokens
        };
    } catch (error) {
        throw new Error('Invalid refresh token');
    }
};

/**
 * Logout user
 * @param {string} userId - User ID
 * @param {string} token - Access token (optional)
 * @returns {Promise<boolean>} - Success status
 */
const logout = async (userId, token = null) => {
    const whereClause = {
        userId,
        isActive: true
    };

    if (token) {
        whereClause.token = token;
    }

    await prisma.session.updateMany({
        where: whereClause,
        data: { isActive: false }
    });

    return true;
};

/**
 * Logout from all devices
 * @param {string} userId - User ID
 * @returns {Promise<boolean>} - Success status
 */
const logoutAll = async (userId) => {
    await prisma.session.updateMany({
        where: {
            userId,
            isActive: true
        },
        data: { isActive: false }
    });

    return true;
};

/**
 * Create session
 * @param {string} userId - User ID
 * @param {string} organizationId - Organization ID
 * @param {string} token - Access token
 * @param {Object} sessionData - Additional session data
 * @returns {Promise<Object>} - Created session
 */
const createSession = async (userId, organizationId, token, sessionData = {}) => {
    const { userAgent, ipAddress } = sessionData;

    const session = await prisma.session.create({
        data: {
            userId,
            organizationId,
            token,
            userAgent: userAgent || null,
            ipAddress: ipAddress || null,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
        }
    });

    return session;
};

/**
 * Get user sessions
 * @param {string} userId - User ID
 * @returns {Promise<Array>} - User sessions
 */
const getUserSessions = async (userId) => {
    const sessions = await prisma.session.findMany({
        where: {
            userId,
            isActive: true,
            expiresAt: { gt: new Date() }
        },
        select: {
            id: true,
            userAgent: true,
            ipAddress: true,
            createdAt: true,
            expiresAt: true
        },
        orderBy: { createdAt: 'desc' }
    });

    return sessions;
};

/**
 * Revoke specific session
 * @param {string} userId - User ID
 * @param {string} sessionId - Session ID
 * @returns {Promise<boolean>} - Success status
 */
const revokeSession = async (userId, sessionId) => {
    await prisma.session.updateMany({
        where: {
            id: sessionId,
            userId,
            isActive: true
        },
        data: { isActive: false }
    });

    return true;
};

/**
 * Generate password reset token
 * @param {string} email - User email
 * @returns {Promise<boolean>} - Success status
 */
const forgotPassword = async (email) => {
    const user = await userService.findUserByEmail(email);

    if (!user) {
        // Don't reveal if user exists or not
        return true;
    }

    // Delete existing password reset tokens
    await prisma.passwordReset.deleteMany({
        where: { userId: user.id }
    });

    // Generate new reset token
    const token = generateSecureToken();
    const expiresAt = new Date(Date.now() + config.tokenExpiry.passwordReset * 60 * 1000);

    await prisma.passwordReset.create({
        data: {
            userId: user.id,
            email,
            token,
            expiresAt
        }
    });

    // Send password reset email
    await sendPasswordReset(email, token, user.firstName);

    return true;
};

/**
 * Reset password with token
 * @param {string} token - Reset token
 * @param {string} newPassword - New password
 * @returns {Promise<Object>} - Reset result
 */
const resetPassword = async (token, newPassword) => {
    const passwordReset = await prisma.passwordReset.findUnique({
        where: { token },
        include: {
            user: {
                select: {
                    id: true,
                    email: true,
                    firstName: true
                }
            }
        }
    });

    if (!passwordReset) {
        throw new Error('Invalid reset token');
    }

    if (passwordReset.usedAt) {
        throw new Error('Reset token has already been used');
    }

    if (new Date() > passwordReset.expiresAt) {
        throw new Error('Reset token has expired');
    }

    // Hash new password
    const hashedPassword = await hashPassword(newPassword);

    // Update password and mark token as used
    await prisma.$transaction([
        prisma.user.update({
            where: { id: passwordReset.userId },
            data: {
                password: hashedPassword,
                passwordChangedAt: new Date()
            }
        }),
        prisma.passwordReset.update({
            where: { id: passwordReset.id },
            data: { usedAt: new Date() }
        }),
        // Invalidate all existing sessions
        prisma.session.updateMany({
            where: { userId: passwordReset.userId },
            data: { isActive: false }
        })
    ]);

    return {
        success: true,
        user: passwordReset.user
    };
};

/**
 * Send invitation to join organization
 * @param {string} email - Invitee email
 * @param {string} organizationId - Organization ID
 * @param {string} invitedById - Inviter user ID
 * @param {string} role - Role slug (optional)
 * @returns {Promise<Object>} - Invitation
 */
const sendInvite = async (email, organizationId, invitedById, role = null) => {
    // Check if user already exists in the organization
    const existingUser = await prisma.user.findFirst({
        where: {
            email,
            organizationId
        }
    });

    if (existingUser) {
        throw new Error('User is already a member of this organization');
    }

    // Check for existing pending invitation
    const existingInvitation = await prisma.invitation.findFirst({
        where: {
            email,
            organizationId,
            acceptedAt: null,
            expiresAt: { gt: new Date() }
        }
    });

    if (existingInvitation) {
        throw new Error('Invitation already sent and pending');
    }

    // Delete any expired invitations
    await prisma.invitation.deleteMany({
        where: {
            email,
            organizationId,
            expiresAt: { lte: new Date() }
        }
    });

    // Generate invitation token
    const token = generateSecureToken();
    const expiresAt = new Date(Date.now() + config.tokenExpiry.invitation * 60 * 1000);

    // Create invitation
    const invitation = await prisma.invitation.create({
        data: {
            email,
            token,
            role,
            organizationId,
            invitedById,
            expiresAt
        },
        include: {
            organization: {
                select: {
                    name: true
                }
            },
            invitedBy: {
                select: {
                    firstName: true,
                    lastName: true
                }
            }
        }
    });

    // Send invitation email
    const inviterName = `${invitation.invitedBy.firstName} ${invitation.invitedBy.lastName}`;
    await sendInvitation(
        email,
        token,
        invitation.organization.name,
        inviterName,
        role
    );

    return invitation;
};

/**
 * Accept invitation and create user
 * @param {string} token - Invitation token
 * @param {Object} userData - User data
 * @returns {Promise<Object>} - Acceptance result
 */
const acceptInvitation = async (token, userData) => {
    const { firstName, lastName, password } = userData;

    const invitation = await prisma.invitation.findUnique({
        where: { token },
        include: {
            organization: {
                select: {
                    id: true,
                    name: true,
                    slug: true
                }
            }
        }
    });

    if (!invitation) {
        throw new Error('Invalid invitation token');
    }

    if (invitation.acceptedAt) {
        throw new Error('Invitation has already been accepted');
    }

    if (new Date() > invitation.expiresAt) {
        throw new Error('Invitation has expired');
    }

    return await prisma.$transaction(async (tx) => {
        // Create user
        const user = await userService.createUser({
            email: invitation.email,
            password,
            firstName,
            lastName
        }, invitation.organizationId);

        // Assign role if specified
        if (invitation.role) {
            const role = await tx.role.findFirst({
                where: {
                    slug: invitation.role,
                    organizationId: invitation.organizationId
                }
            });

            if (role) {
                await tx.userRole.create({
                    data: {
                        userId: user.id,
                        roleId: role.id
                    }
                });
            }
        } else {
            // Assign default role
            const defaultRole = await tx.role.findFirst({
                where: {
                    organizationId: invitation.organizationId,
                    isDefault: true
                }
            });

            if (defaultRole) {
                await tx.userRole.create({
                    data: {
                        userId: user.id,
                        roleId: defaultRole.id
                    }
                });
            }
        }

        // Mark invitation as accepted
        await tx.invitation.update({
            where: { id: invitation.id },
            data: { acceptedAt: new Date() }
        });

        // Get user with roles
        const userWithRoles = await userService.findUserById(user.id);

        // Generate tokens
        const tokens = generateTokenPair({
            userId: user.id,
            email: user.email,
            organizationId: user.organizationId,
            roles: userWithRoles.roles?.map(role => role.slug) || []
        });

        // Create session
        await createSession(user.id, user.organizationId, tokens.accessToken);

        return {
            user: userWithRoles,
            tokens,
            organization: invitation.organization
        };
    });
};

module.exports = {
    register,
    login,
    refreshToken,
    logout,
    logoutAll,
    createSession,
    getUserSessions,
    revokeSession,
    forgotPassword,
    resetPassword,
    sendInvite,
    acceptInvitation
};