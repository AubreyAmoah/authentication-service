const express = require('express');
const rateLimit = require('express-rate-limit');
const { mfaController } = require('../plugins/mfa');
const { authenticate } = require('../middleware/auth');
const { validateRequest } = require('../utils/validation');
const Joi = require('joi');

const router = express.Router();

// Rate limiting for MFA endpoints
const mfaLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20, // limit each IP to 20 requests per windowMs
    message: {
        success: false,
        message: 'Too many MFA attempts, please try again later'
    }
});

// Validation schemas
const mfaSchemas = {
    setupComplete: Joi.object({
        token: Joi.string().length(6).pattern(/^\d+$/).required()
            .messages({
                'string.length': 'Token must be 6 digits',
                'string.pattern.base': 'Token must contain only numbers'
            })
    }),

    verify: Joi.object({
        token: Joi.string().required(),
        isBackupCode: Joi.boolean().default(false)
    }),

    disable: Joi.object({
        password: Joi.string().required(),
        token: Joi.string().optional()
    }),

    regenerateBackupCodes: Joi.object({
        password: Joi.string().required()
    })
};

// All routes require authentication
router.use(authenticate);
router.use(mfaLimiter);

// Get MFA status
router.get('/status', mfaController.getStatus);

// Start MFA setup
router.post('/setup/start', mfaController.setupStart);

// Complete MFA setup
router.post('/setup/complete', validateRequest(mfaSchemas.setupComplete), mfaController.setupComplete);

// Verify MFA token
router.post('/verify', validateRequest(mfaSchemas.verify), mfaController.verify);

// Disable MFA
router.post('/disable', validateRequest(mfaSchemas.disable), mfaController.disable);

// Backup codes management
router.get('/backup-codes/count', mfaController.getBackupCodesCount);
router.post('/backup-codes/regenerate', validateRequest(mfaSchemas.regenerateBackupCodes), mfaController.regenerateBackupCodes);

module.exports = router;