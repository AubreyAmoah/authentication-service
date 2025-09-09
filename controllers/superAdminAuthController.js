// ===== SUPER ADMIN LOGIN CONTROLLER =====
// controllers/superAdminAuth.controller.js

const superAdminAuthService = require('../services/superAdminAuthService');

const superAdminAuthController = {
    // Super Admin Login
    login: async (req, res) => {
        try {
            const { email, password } = req.body;
            const deviceInfo = req.deviceInfo || {};

            // Validate input
            if (!email || !password) {
                return res.status(400).json({
                    success: 0,
                    message: 'Email and password are required'
                });
            }

            // Email validation
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                return res.status(400).json({
                    success: 0,
                    message: 'Invalid email format'
                });
            }

            // Attempt login
            const result = await superAdminAuthService.loginSuperAdmin(email, password, deviceInfo);

            // Set secure HTTP-only cookies for tokens
            res.cookie('superAdminToken', result.token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 60 * 60 * 1000 // 1 hour
            });

            res.cookie('superAdminRefreshToken', result.refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
            });

            return res.status(200).json({
                success: 1,
                message: 'Super admin login successful',
                data: {
                    user: result.user,
                    token: result.token,
                    refreshToken: result.refreshToken,
                    permissions: result.permissions
                }
            });

        } catch (error) {
            console.error('Super admin login error:', error);

            const statusCode = error.message.includes('Invalid credentials') ||
                error.message.includes('Access denied') ? 401 : 500;

            return res.status(statusCode).json({
                success: 0,
                message: error.message || 'Super admin login failed'
            });
        }
    },

    // Get Super Admin Profile
    getProfile: async (req, res) => {
        try {
            const userId = req.user.userId;
            const deviceInfo = req.deviceInfo || {};
            const user = await superAdminAuthService.validateSuperAdminSession(userId);

            return res.status(200).json({
                success: 1,
                message: 'Super admin profile retrieved',
                data: {
                    user,
                    permissions: {
                        canAccessAllOrganizations: true,
                        canManageUsers: true,
                        canManageSuperAdmins: true,
                        canViewSystemMetrics: true,
                        canManageOrganizations: true
                    }
                }
            });

        } catch (error) {
            console.error('Get super admin profile error:', error);

            return res.status(401).json({
                success: 0,
                message: error.message || 'Failed to get super admin profile'
            });
        }
    },

    // Super Admin Logout
    logout: async (req, res) => {
        try {
            const userId = req.user.userId;
            const deviceInfo = req.deviceInfo || {};

            await superAdminAuthService.logoutSuperAdmin(userId, deviceInfo);

            // Clear cookies
            res.clearCookie('superAdminToken');
            res.clearCookie('superAdminRefreshToken');

            return res.status(200).json({
                success: 1,
                message: 'Super admin logout successful'
            });

        } catch (error) {
            console.error('Super admin logout error:', error);

            return res.status(500).json({
                success: 0,
                message: 'Logout failed'
            });
        }
    }
};

module.exports = superAdminAuthController;