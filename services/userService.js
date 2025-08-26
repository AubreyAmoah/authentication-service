const { prisma } = require('../utils/database');
const { hashPassword, comparePassword, needsRehash } = require('../utils/hash');
const { generateSecureToken } = require('../utils/jwt');
const { sendEmailVerification, sendWelcomeEmail } = require('../utils/email');
const config = require('../config');

/**
 * Create a new user
 * @param {Object} userData - User registration data
 * @param {string} organizationId - Organization ID (optional)
 * @returns {Promise<Object>} - Created user
 */
const createUser = async (userData, organizationId = null) => {
    const { email, password, firstName, lastName, phone } = userData;

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
        where: { email }
    });

    if (existingUser) {
        throw new Error('User with this email already exists');
    }

    // Hash password
    const hashedPassword = await hashPassword(password);

    // Create user
    const user = await prisma.user.create({
        data: {
            email,
            password: hashedPassword,
            firstName,
            lastName,
            phone,
            organizationId
        },
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

    // Generate email verification token
    if (config.email.smtp.host) {
        await generateEmailVerificationToken(user.id, email);
    }

    // Remove password from response
    const { password: _, ...userWithoutPassword } = user;
    return userWithoutPassword;
};

/**
 * Find user by email
 * @param {string} email - User email
 * @param {boolean} includePassword - Whether to include password in result
 * @returns {Promise<Object|null>} - User or null
 */
const findUserByEmail = async (email, includePassword = false) => {
    const selectFields = {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        phone: true,
        avatar: true,
        isEmailVerified: true,
        isActive: true,
        lastLoginAt: true,
        organizationId: true,
        createdAt: true,
        updatedAt: true,
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
        }
    };

    if (includePassword) {
        selectFields.password = true;
    }

    const user = await prisma.user.findUnique({
        where: { email },
        select: selectFields
    });

    if (!user) return null;

    // Transform roles for easier access
    if (user.roles) {
        user.roles = user.roles.map(userRole => userRole.role);
    }

    return user;
};

/**
 * Find user by ID
 * @param {string} userId - User ID
 * @returns {Promise<Object|null>} - User or null
 */
const findUserById = async (userId) => {
    const user = await prisma.user.findUnique({
        where: { id: userId },
        select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            phone: true,
            avatar: true,
            isEmailVerified: true,
            isActive: true,
            lastLoginAt: true,
            organizationId: true,
            createdAt: true,
            updatedAt: true,
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
            }
        }
    });

    if (!user) return null;

    // Transform roles for easier access
    if (user.roles) {
        user.roles = user.roles.map(userRole => userRole.role);
    }

    return user;
};

/**
 * Update user profile
 * @param {string} userId - User ID
 * @param {Object} updateData - Data to update
 * @returns {Promise<Object>} - Updated user
 */
const updateUser = async (userId, updateData) => {
    const user = await prisma.user.update({
        where: { id: userId },
        data: updateData,
        select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            phone: true,
            avatar: true,
            isEmailVerified: true,
            isActive: true,
            lastLoginAt: true,
            organizationId: true,
            updatedAt: true,
            organization: {
                select: {
                    id: true,
                    name: true,
                    slug: true
                }
            }
        }
    });

    return user;
};

/**
 * Change user password
 * @param {string} userId - User ID
 * @param {string} currentPassword - Current password
 * @param {string} newPassword - New password
 * @returns {Promise<boolean>} - Success status
 */
const changePassword = async (userId, currentPassword, newPassword) => {
    // Get user with password
    const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { id: true, password: true }
    });

    if (!user) {
        throw new Error('User not found');
    }

    // Verify current password
    const isCurrentPasswordValid = await comparePassword(currentPassword, user.password);
    if (!isCurrentPasswordValid) {
        throw new Error('Current password is incorrect');
    }

    // Hash new password
    const hashedNewPassword = await hashPassword(newPassword);

    // Update password
    await prisma.user.update({
        where: { id: userId },
        data: {
            password: hashedNewPassword,
            passwordChangedAt: new Date()
        }
    });

    return true;
};

/**
 * Verify user credentials
 * @param {string} email - User email
 * @param {string} password - User password
 * @returns {Promise<Object|null>} - User or null
 */
const verifyCredentials = async (email, password) => {
    const user = await findUserByEmail(email, true);

    if (!user || !user.password) {
        return null;
    }

    const isPasswordValid = await comparePassword(password, user.password);
    if (!isPasswordValid) {
        return null;
    }

    // Check if password needs rehashing
    if (needsRehash(user.password)) {
        const newHashedPassword = await hashPassword(password);
        await prisma.user.update({
            where: { id: user.id },
            data: { password: newHashedPassword }
        });
    }

    // Update last login
    await prisma.user.update({
        where: { id: user.id },
        data: { lastLoginAt: new Date() }
    });

    // Remove password from response
    const { password: _, ...userWithoutPassword } = user;
    return userWithoutPassword;
};

/**
 * Generate email verification token
 * @param {string} userId - User ID
 * @param {string} email - User email
 * @returns {Promise<string>} - Verification token
 */
const generateEmailVerificationToken = async (userId, email) => {
    const token = generateSecureToken();
    const expiresAt = new Date(Date.now() + config.tokenExpiry.emailVerification * 60 * 1000);

    await prisma.emailVerification.create({
        data: {
            userId,
            email,
            token,
            expiresAt
        }
    });

    // Send verification email
    const user = await findUserById(userId);
    if (user) {
        await sendEmailVerification(email, token, user.firstName);
    }

    return token;
};

/**
 * Verify email with token
 * @param {string} token - Verification token
 * @returns {Promise<Object>} - Verification result
 */
const verifyEmail = async (token) => {
    const verification = await prisma.emailVerification.findUnique({
        where: { token },
        include: {
            user: {
                select: {
                    id: true,
                    email: true,
                    firstName: true,
                    isEmailVerified: true,
                    organization: {
                        select: {
                            name: true
                        }
                    }
                }
            }
        }
    });

    if (!verification) {
        throw new Error('Invalid verification token');
    }

    if (verification.verifiedAt) {
        throw new Error('Email already verified');
    }

    if (new Date() > verification.expiresAt) {
        throw new Error('Verification token has expired');
    }

    // Mark email as verified
    await prisma.$transaction([
        prisma.user.update({
            where: { id: verification.userId },
            data: {
                isEmailVerified: true,
                emailVerifiedAt: new Date()
            }
        }),
        prisma.emailVerification.update({
            where: { id: verification.id },
            data: { verifiedAt: new Date() }
        })
    ]);

    // Send welcome email
    if (verification.user.organization) {
        await sendWelcomeEmail(
            verification.user.email,
            verification.user.firstName,
            verification.user.organization.name
        );
    }

    return {
        success: true,
        user: verification.user
    };
};

/**
 * Resend email verification
 * @param {string} email - User email
 * @returns {Promise<boolean>} - Success status
 */
const resendEmailVerification = async (email) => {
    const user = await findUserByEmail(email);

    if (!user) {
        throw new Error('User not found');
    }

    if (user.isEmailVerified) {
        throw new Error('Email is already verified');
    }

    // Delete existing verification tokens
    await prisma.emailVerification.deleteMany({
        where: { userId: user.id }
    });

    // Generate new token
    await generateEmailVerificationToken(user.id, email);

    return true;
};

/**
 * Get users for an organization with pagination and search
 * @param {string} organizationId - Organization ID
 * @param {Object} options - Query options
 * @returns {Promise<Object>} - Users with pagination
 */
const getOrganizationUsers = async (organizationId, options = {}) => {
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
                { firstName: { contains: search, mode: 'insensitive' } },
                { lastName: { contains: search, mode: 'insensitive' } },
                { email: { contains: search, mode: 'insensitive' } }
            ]
        })
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
                lastLoginAt: true,
                createdAt: true,
                roles: {
                    include: {
                        role: {
                            select: {
                                id: true,
                                name: true,
                                slug: true
                            }
                        }
                    }
                }
            },
            orderBy: { [sortBy]: sortOrder },
            skip,
            take: limit
        }),
        prisma.user.count({ where: whereClause })
    ]);

    // Transform roles for easier access
    const transformedUsers = users.map(user => ({
        ...user,
        roles: user.roles.map(userRole => userRole.role)
    }));

    return {
        users: transformedUsers,
        pagination: {
            page,
            limit,
            total,
            totalPages: Math.ceil(total / limit)
        }
    };
};

/**
 * Deactivate user
 * @param {string} userId - User ID
 * @returns {Promise<Object>} - Updated user
 */
const deactivateUser = async (userId) => {
    const user = await prisma.user.update({
        where: { id: userId },
        data: { isActive: false },
        select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            isActive: true
        }
    });

    // Invalidate all user sessions
    await prisma.session.updateMany({
        where: { userId },
        data: { isActive: false }
    });

    return user;
};

/**
 * Reactivate user
 * @param {string} userId - User ID
 * @returns {Promise<Object>} - Updated user
 */
const reactivateUser = async (userId) => {
    const user = await prisma.user.update({
        where: { id: userId },
        data: { isActive: true },
        select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            isActive: true
        }
    });

    return user;
};

/**
 * Delete user (soft delete by deactivation)
 * @param {string} userId - User ID
 * @returns {Promise<boolean>} - Success status
 */
const deleteUser = async (userId) => {
    // For now, we'll just deactivate the user
    // In a real system, you might want to implement hard delete or data anonymization
    await deactivateUser(userId);
    return true;
};

module.exports = {
    createUser,
    findUserByEmail,
    findUserById,
    updateUser,
    changePassword,
    verifyCredentials,
    generateEmailVerificationToken,
    verifyEmail,
    resendEmailVerification,
    getOrganizationUsers,
    deactivateUser,
    reactivateUser,
    deleteUser
};