const authService = require('../services/authService');
const userService = require('../services/userService');
const { sendSuccess, sendError, sendAuthResponse, asyncHandler } = require('../utils/response');
const { prisma } = require('../utils/database');

/**
 * Register new user and organization
 */
const register = asyncHandler(async (req, res) => {
    const result = await authService.register(req.validatedData);

    sendAuthResponse(
        res,
        result.user,
        result.tokens,
        'Registration successful'
    );
});

/**
 * Login user with optional MFA verification
 */
const login = asyncHandler(async (req, res) => {
    const { email, password, organizationSlug, mfaToken, isBackupCode = false } = req.validatedData;

    const sessionData = {
        userAgent: req.get('User-Agent'),
        ipAddress: req.ip || req.connection.remoteAddress
    };

    // Step 1: Verify credentials
    const result = await authService.login(email, password, organizationSlug, sessionData);

    // Step 2: Check if MFA is enabled
    const { getMFAStatus } = require('../plugins/mfa');
    const mfaStatus = await getMFAStatus(result.user.id);

    if (mfaStatus.isEnabled) {
        // MFA is enabled, check if token is provided
        if (!mfaToken) {
            return res.status(200).json({
                success: true,
                mfaRequired: true,
                message: 'MFA verification required',
                data: {
                    tempToken: result.tokens.accessToken, // Temporary limited token
                    mfaMethods: mfaStatus.methods,
                    hasBackupCodes: mfaStatus.hasBackupCodes
                }
            });
        }

        // Verify MFA token
        const { verifyTOTPToken, verifyBackupCode } = require('../plugins/mfa');
        let isValidMFA = false;

        if (isBackupCode) {
            // Verify backup code
            const backupCodes = await prisma.mFABackupCode.findMany({
                where: {
                    userId: result.user.id,
                    usedAt: null
                }
            });

            const matchingCodeHash = verifyBackupCode(mfaToken, backupCodes.map(bc => bc.codeHash));

            if (matchingCodeHash) {
                isValidMFA = true;
                // Mark backup code as used
                await prisma.mFABackupCode.updateMany({
                    where: {
                        userId: result.user.id,
                        codeHash: matchingCodeHash
                    },
                    data: { usedAt: new Date() }
                });
            }
        } else {
            // Verify TOTP token
            const mfaSecret = await prisma.mFASecret.findFirst({
                where: {
                    userId: result.user.id,
                    isActive: true,
                    type: 'TOTP'
                }
            });

            if (mfaSecret) {
                isValidMFA = verifyTOTPToken(mfaSecret.secret, mfaToken);

                if (isValidMFA) {
                    // Update last used timestamp
                    await prisma.mFASecret.update({
                        where: { id: mfaSecret.id },
                        data: { lastUsedAt: new Date() }
                    });
                }
            }
        }

        if (!isValidMFA) {
            // Invalidate the session since MFA failed
            await authService.logout(result.user.id, result.tokens.accessToken);
            return sendError(res, 'Invalid MFA token', 401);
        }

        // Update session to mark MFA as verified
        await prisma.session.updateMany({
            where: {
                userId: result.user.id,
                token: result.tokens.accessToken
            },
            data: {
                mfaVerifiedAt: new Date()
            }
        });
    }

    sendAuthResponse(
        res,
        result.user,
        result.tokens,
        'Login successful'
    );
});

/**
 * Refresh access token
 */
const refreshToken = asyncHandler(async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return sendError(res, 'Refresh token is required', 400);
    }

    const result = await authService.refreshToken(refreshToken);

    sendAuthResponse(
        res,
        result.user,
        result.tokens,
        'Token refreshed successfully'
    );
});

/**
 * Logout user
 */
const logout = asyncHandler(async (req, res) => {
    await authService.logout(req.user.id, req.token);

    sendSuccess(res, null, 'Logout successful');
});

/**
 * Logout from all devices
 */
const logoutAll = asyncHandler(async (req, res) => {
    await authService.logoutAll(req.user.id);

    sendSuccess(res, null, 'Logged out from all devices');
});

/**
 * Get current user profile
 */
const getProfile = asyncHandler(async (req, res) => {
    const user = await userService.findUserById(req.user.id);

    sendSuccess(res, { user }, 'Profile retrieved successfully');
});

/**
 * Update current user profile
 */
const updateProfile = asyncHandler(async (req, res) => {
    const updatedUser = await userService.updateUser(req.user.id, req.validatedData);

    sendSuccess(res, { user: updatedUser }, 'Profile updated successfully');
});

/**
 * Change password
 */
const changePassword = asyncHandler(async (req, res) => {
    const { currentPassword, newPassword } = req.validatedData;

    await userService.changePassword(req.user.id, currentPassword, newPassword);

    sendSuccess(res, null, 'Password changed successfully');
});

/**
 * Forgot password
 */
const forgotPassword = asyncHandler(async (req, res) => {
    const { email } = req.validatedData;

    await authService.forgotPassword(email);

    sendSuccess(res, null, 'Password reset instructions sent to your email');
});

/**
 * Reset password
 */
const resetPassword = asyncHandler(async (req, res) => {
    const { token, password } = req.validatedData;

    const result = await authService.resetPassword(token, password);

    sendSuccess(res, result, 'Password reset successfully');
});

/**
 * Verify email
 */
const verifyEmail = asyncHandler(async (req, res) => {
    const { token } = req.query;

    if (!token) {
        return sendError(res, 'Verification token is required', 400);
    }

    const result = await userService.verifyEmail(token);

    sendSuccess(res, result, 'Email verified successfully');
});

/**
 * Resend email verification
 */
const resendEmailVerification = asyncHandler(async (req, res) => {
    const { email } = req.validatedData;

    await userService.resendEmailVerification(email);

    sendSuccess(res, null, 'Verification email sent');
});

/**
 * Send invitation
 */
const sendInvitation = asyncHandler(async (req, res) => {
    const { email, role } = req.validatedData;

    const invitation = await authService.sendInvite(
        email,
        req.user.organizationId,
        req.user.id,
        role
    );

    sendSuccess(res, { invitation }, 'Invitation sent successfully');
});

/**
 * Accept invitation
 */
const acceptInvitation = asyncHandler(async (req, res) => {
    const { token, firstName, lastName, password } = req.validatedData;

    const result = await authService.acceptInvitation(token, {
        firstName,
        lastName,
        password
    });

    sendAuthResponse(
        res,
        result.user,
        result.tokens,
        'Invitation accepted successfully'
    );
});

/**
 * Get user sessions
 */
const getSessions = asyncHandler(async (req, res) => {
    const sessions = await authService.getUserSessions(req.user.id);

    sendSuccess(res, { sessions }, 'Sessions retrieved successfully');
});

/**
 * Revoke specific session
 */
const revokeSession = asyncHandler(async (req, res) => {
    const { sessionId } = req.params;

    await authService.revokeSession(req.user.id, sessionId);

    sendSuccess(res, null, 'Session revoked successfully');
});

/**
 * Check authentication status
 */
const checkAuth = asyncHandler(async (req, res) => {
    if (!req.user) {
        return sendError(res, 'Not authenticated', 401);
    }

    sendSuccess(res, {
        user: req.user,
        authenticated: true
    }, 'User is authenticated');
});

module.exports = {
    register,
    login,
    refreshToken,
    logout,
    logoutAll,
    getProfile,
    updateProfile,
    changePassword,
    forgotPassword,
    resetPassword,
    verifyEmail,
    resendEmailVerification,
    sendInvitation,
    acceptInvitation,
    getSessions,
    revokeSession,
    checkAuth
};