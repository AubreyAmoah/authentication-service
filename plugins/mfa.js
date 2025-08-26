const crypto = require('crypto');
const qrcode = require('qrcode');
const { authenticator } = require('otplib');
const { prisma } = require('../utils/database');
const { sendError, sendSuccess, asyncHandler } = require('../utils/response');
const { authenticate } = require('../middleware/auth');
const config = require('../config');

// Configure TOTP settings
authenticator.options = {
    step: 30,        // 30 seconds validity
    window: 1,       // Allow 1 step before/after for clock drift
    digits: 6,       // 6 digit codes
};

/**
 * Generate TOTP secret for user
 * @param {string} userId - User ID
 * @param {string} userEmail - User email
 * @param {string} organizationName - Organization name
 * @returns {Promise<Object>} - Secret and QR code
 */
const generateTOTPSecret = async (userId, userEmail, organizationName) => {
    // Generate secret
    const secret = authenticator.generateSecret();

    // Create service name for authenticator app
    const serviceName = organizationName || 'Auth Service';
    const issuer = config.mfa?.issuer || 'Authentication Service';

    // Generate TOTP URI for QR code
    const otpauth = authenticator.keyuri(userEmail, issuer, secret);

    // Generate QR code
    const qrCodeDataURL = await qrcode.toDataURL(otpauth);

    // Store secret temporarily (will be activated when user verifies)
    await prisma.mFASecret.create({
        data: {
            userId,
            secret,
            isActive: false,
            type: 'TOTP'
        }
    });

    return {
        secret,
        qrCode: qrCodeDataURL,
        manualEntryCode: secret,
        issuer,
        serviceName
    };
};

/**
 * Verify TOTP token
 * @param {string} secret - TOTP secret
 * @param {string} token - User provided token
 * @returns {boolean} - Whether token is valid
 */
const verifyTOTPToken = (secret, token) => {
    try {
        return authenticator.verify({ token, secret });
    } catch (error) {
        return false;
    }
};

/**
 * Generate backup codes
 * @returns {Array<string>} - Array of backup codes
 */
const generateBackupCodes = () => {
    const codes = [];
    for (let i = 0; i < 10; i++) {
        // Generate 8-character alphanumeric codes
        const code = crypto.randomBytes(4).toString('hex').toUpperCase();
        codes.push(code);
    }
    return codes;
};

/**
 * Hash backup codes for storage
 * @param {Array<string>} codes - Plain backup codes
 * @returns {Array<string>} - Hashed backup codes
 */
const hashBackupCodes = (codes) => {
    return codes.map(code => crypto.createHash('sha256').update(code).digest('hex'));
};

/**
 * Verify backup code
 * @param {string} providedCode - User provided code
 * @param {Array<string>} hashedCodes - Stored hashed codes
 * @returns {string|null} - Hash of matching code or null
 */
const verifyBackupCode = (providedCode, hashedCodes) => {
    const hashedProvided = crypto.createHash('sha256').update(providedCode.toUpperCase()).digest('hex');
    return hashedCodes.find(hash => hash === hashedProvided) || null;
};

/**
 * Check if user has MFA enabled
 * @param {string} userId - User ID
 * @returns {Promise<Object>} - MFA status and methods
 */
const getMFAStatus = async (userId) => {
    const mfaSecrets = await prisma.mFASecret.findMany({
        where: {
            userId,
            isActive: true
        },
        select: {
            type: true,
            createdAt: true,
            lastUsedAt: true
        }
    });

    const backupCodes = await prisma.mFABackupCode.findMany({
        where: {
            userId,
            usedAt: null
        }
    });

    return {
        isEnabled: mfaSecrets.length > 0,
        methods: mfaSecrets,
        backupCodesCount: backupCodes.length,
        hasBackupCodes: backupCodes.length > 0
    };
};

/**
 * MFA Controller functions
 */
const mfaController = {
    /**
     * Get MFA status for current user
     */
    getStatus: asyncHandler(async (req, res) => {
        const status = await getMFAStatus(req.user.id);
        sendSuccess(res, { mfa: status }, 'MFA status retrieved successfully');
    }),

    /**
     * Start MFA setup - generate secret and QR code
     */
    setupStart: asyncHandler(async (req, res) => {
        const userId = req.user.id;

        // Check if user already has active MFA
        const existingMFA = await prisma.mFASecret.findFirst({
            where: {
                userId,
                isActive: true,
                type: 'TOTP'
            }
        });

        if (existingMFA) {
            return sendError(res, 'MFA is already enabled for this account', 400);
        }

        // Remove any pending (inactive) MFA secrets
        await prisma.mFASecret.deleteMany({
            where: {
                userId,
                isActive: false
            }
        });

        // Generate new secret
        const mfaData = await generateTOTPSecret(
            userId,
            req.user.email,
            req.user.organization?.name
        );

        sendSuccess(res, {
            setup: {
                qrCode: mfaData.qrCode,
                manualEntryCode: mfaData.manualEntryCode,
                issuer: mfaData.issuer,
                serviceName: mfaData.serviceName
            }
        }, 'MFA setup initiated successfully');
    }),

    /**
     * Complete MFA setup - verify token and activate
     */
    setupComplete: asyncHandler(async (req, res) => {
        const { token } = req.body;
        const userId = req.user.id;

        if (!token || token.length !== 6) {
            return sendError(res, 'Valid 6-digit verification code is required', 400);
        }

        // Get pending MFA secret
        const mfaSecret = await prisma.mFASecret.findFirst({
            where: {
                userId,
                isActive: false,
                type: 'TOTP'
            }
        });

        if (!mfaSecret) {
            return sendError(res, 'No pending MFA setup found. Please start setup again.', 400);
        }

        // Verify the token
        const isValid = verifyTOTPToken(mfaSecret.secret, token);

        if (!isValid) {
            return sendError(res, 'Invalid verification code. Please try again.', 400);
        }

        // Generate backup codes
        const backupCodes = generateBackupCodes();
        const hashedBackupCodes = hashBackupCodes(backupCodes);

        await prisma.$transaction(async (tx) => {
            // Activate MFA secret
            await tx.mFASecret.update({
                where: { id: mfaSecret.id },
                data: {
                    isActive: true,
                    lastUsedAt: new Date()
                }
            });

            // Store backup codes
            await tx.mFABackupCode.createMany({
                data: hashedBackupCodes.map(hash => ({
                    userId,
                    codeHash: hash
                }))
            });
        });

        sendSuccess(res, {
            mfa: {
                enabled: true,
                backupCodes
            }
        }, 'MFA setup completed successfully');
    }),

    /**
     * Disable MFA
     */
    disable: asyncHandler(async (req, res) => {
        const { password, token } = req.body;
        const userId = req.user.id;

        if (!password) {
            return sendError(res, 'Password is required to disable MFA', 400);
        }

        // Verify password
        const { comparePassword } = require('../utils/hash');
        const user = await prisma.user.findUnique({
            where: { id: userId },
            select: { password: true }
        });

        const isPasswordValid = await comparePassword(password, user.password);
        if (!isPasswordValid) {
            return sendError(res, 'Invalid password', 400);
        }

        // If token provided, verify it
        if (token) {
            const mfaSecret = await prisma.mFASecret.findFirst({
                where: {
                    userId,
                    isActive: true,
                    type: 'TOTP'
                }
            });

            if (mfaSecret) {
                const isValidToken = verifyTOTPToken(mfaSecret.secret, token);
                if (!isValidToken) {
                    return sendError(res, 'Invalid MFA token', 400);
                }
            }
        }

        await prisma.$transaction(async (tx) => {
            // Remove MFA secrets
            await tx.mFASecret.deleteMany({
                where: { userId }
            });

            // Remove backup codes
            await tx.mFABackupCode.deleteMany({
                where: { userId }
            });
        });

        sendSuccess(res, null, 'MFA disabled successfully');
    }),

    /**
     * Verify MFA token (for login process)
     */
    verify: asyncHandler(async (req, res) => {
        const { token, isBackupCode = false } = req.body;
        const userId = req.user.id;

        if (!token) {
            return sendError(res, 'Verification code is required', 400);
        }

        if (isBackupCode) {
            // Verify backup code
            const backupCodes = await prisma.mFABackupCode.findMany({
                where: {
                    userId,
                    usedAt: null
                }
            });

            const matchingCodeHash = verifyBackupCode(token, backupCodes.map(bc => bc.codeHash));

            if (!matchingCodeHash) {
                return sendError(res, 'Invalid backup code', 400);
            }

            // Mark backup code as used
            await prisma.mFABackupCode.updateMany({
                where: {
                    userId,
                    codeHash: matchingCodeHash
                },
                data: { usedAt: new Date() }
            });

            sendSuccess(res, { verified: true }, 'Backup code verified successfully');
        } else {
            // Verify TOTP token
            const mfaSecret = await prisma.mFASecret.findFirst({
                where: {
                    userId,
                    isActive: true,
                    type: 'TOTP'
                }
            });

            if (!mfaSecret) {
                return sendError(res, 'MFA not enabled for this account', 400);
            }

            const isValid = verifyTOTPToken(mfaSecret.secret, token);

            if (!isValid) {
                return sendError(res, 'Invalid verification code', 400);
            }

            // Update last used timestamp
            await prisma.mFASecret.update({
                where: { id: mfaSecret.id },
                data: { lastUsedAt: new Date() }
            });

            sendSuccess(res, { verified: true }, 'MFA token verified successfully');
        }
    }),

    /**
     * Generate new backup codes
     */
    regenerateBackupCodes: asyncHandler(async (req, res) => {
        const { password } = req.body;
        const userId = req.user.id;

        if (!password) {
            return sendError(res, 'Password is required to regenerate backup codes', 400);
        }

        // Verify password
        const { comparePassword } = require('../utils/hash');
        const user = await prisma.user.findUnique({
            where: { id: userId },
            select: { password: true }
        });

        const isPasswordValid = await comparePassword(password, user.password);
        if (!isPasswordValid) {
            return sendError(res, 'Invalid password', 400);
        }

        // Check if MFA is enabled
        const mfaStatus = await getMFAStatus(userId);
        if (!mfaStatus.isEnabled) {
            return sendError(res, 'MFA must be enabled to generate backup codes', 400);
        }

        // Generate new backup codes
        const backupCodes = generateBackupCodes();
        const hashedBackupCodes = hashBackupCodes(backupCodes);

        await prisma.$transaction(async (tx) => {
            // Remove old backup codes
            await tx.mFABackupCode.deleteMany({
                where: { userId }
            });

            // Create new backup codes
            await tx.mFABackupCode.createMany({
                data: hashedBackupCodes.map(hash => ({
                    userId,
                    codeHash: hash
                }))
            });
        });

        sendSuccess(res, {
            backupCodes
        }, 'Backup codes regenerated successfully');
    }),

    /**
     * Get remaining backup codes count
     */
    getBackupCodesCount: asyncHandler(async (req, res) => {
        const userId = req.user.id;

        const count = await prisma.mFABackupCode.count({
            where: {
                userId,
                usedAt: null
            }
        });

        sendSuccess(res, {
            remainingBackupCodes: count
        }, 'Backup codes count retrieved successfully');
    })
};

/**
 * MFA middleware to check if MFA verification is required
 */
const requireMFAVerification = asyncHandler(async (req, res, next) => {
    const userId = req.user.id;

    // Check if user has MFA enabled
    const mfaStatus = await getMFAStatus(userId);

    if (!mfaStatus.isEnabled) {
        return next(); // No MFA required
    }

    // Check if MFA was verified in this session
    const sessionId = req.session?.id || req.headers['x-session-id'];

    if (sessionId) {
        const session = await prisma.session.findUnique({
            where: { id: sessionId },
            select: { mfaVerifiedAt: true }
        });

        // If MFA was verified within the last 30 minutes, allow access
        if (session?.mfaVerifiedAt &&
            (Date.now() - session.mfaVerifiedAt.getTime()) < 30 * 60 * 1000) {
            return next();
        }
    }

    return sendError(res, 'MFA verification required', 423, {
        mfaRequired: true,
        methods: mfaStatus.methods
    });
});

module.exports = {
    mfaController,
    requireMFAVerification,
    getMFAStatus,
    verifyTOTPToken,
    verifyBackupCode
};