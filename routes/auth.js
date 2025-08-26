const express = require('express');
const rateLimit = require('express-rate-limit');
const authController = require('../controllers/authController');
const { authenticate, optionalAuth, requirePermission } = require('../middleware/auth');
const { validateRequest, userSchemas, paramSchemas, validateParams } = require('../utils/validation');

const router = express.Router();

// Rate limiting for auth endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // limit each IP to 10 requests per windowMs
    message: {
        success: false,
        message: 'Too many authentication attempts, please try again later'
    },
    standardHeaders: true,
    legacyHeaders: false
});

const passwordResetLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // limit each IP to 3 password reset requests per hour
    message: {
        success: false,
        message: 'Too many password reset attempts, please try again later'
    }
});

// Public routes (no authentication required)
router.post('/register', authLimiter, validateRequest(userSchemas.register), authController.register);
router.post('/login', authLimiter, validateRequest(userSchemas.login), authController.login);
router.post('/refresh-token', authController.refreshToken);
router.post('/forgot-password', passwordResetLimiter, validateRequest(userSchemas.forgotPassword), authController.forgotPassword);
router.post('/reset-password', validateRequest(userSchemas.resetPassword), authController.resetPassword);
router.get('/verify-email', authController.verifyEmail);
router.post('/resend-verification', validateRequest(userSchemas.forgotPassword), authController.resendEmailVerification);
router.post('/accept-invitation', validateRequest(userSchemas.acceptInvitation), authController.acceptInvitation);

// Check auth status (optional authentication)
router.get('/check', optionalAuth, authController.checkAuth);

// Protected routes (authentication required)
router.use(authenticate);

// Profile management
router.get('/profile', authController.getProfile);
router.patch('/profile', validateRequest(userSchemas.update), authController.updateProfile);
router.patch('/change-password', validateRequest(userSchemas.changePassword), authController.changePassword);

// Session management
router.get('/sessions', authController.getSessions);
router.delete('/sessions/:sessionId', validateParams(paramSchemas.uuid), authController.revokeSession);

// Logout
router.post('/logout', authController.logout);
router.post('/logout-all', authController.logoutAll);

// Invitation management (requires permission)
router.post('/invite', requirePermission('users.invite'), validateRequest(userSchemas.invite), authController.sendInvitation);

module.exports = router;