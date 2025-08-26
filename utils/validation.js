const Joi = require('joi');

// Organization validation schemas
const organizationSchemas = {
    create: Joi.object({
        name: Joi.string().min(2).max(100).required(),
        email: Joi.string().email().optional(),
        phone: Joi.string().optional(),
        address: Joi.string().max(500).optional(),
        website: Joi.string().uri().optional(),
        logoUrl: Joi.string().uri().optional()
    }),

    update: Joi.object({
        name: Joi.string().min(2).max(100).optional(),
        email: Joi.string().email().optional(),
        phone: Joi.string().optional(),
        address: Joi.string().max(500).optional(),
        website: Joi.string().uri().optional(),
        logoUrl: Joi.string().uri().optional(),
        settings: Joi.object().optional()
    })
};

// User validation schemas
const userSchemas = {
    register: Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().min(8).max(128).pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/).required()
            .messages({
                'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
            }),
        firstName: Joi.string().min(1).max(50).required(),
        lastName: Joi.string().min(1).max(50).required(),
        phone: Joi.string().optional(),
        organizationName: Joi.string().min(2).max(100).optional()
    }),

    login: Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().required(),
        organizationSlug: Joi.string().optional(),
        mfaToken: Joi.string().optional(),
        isBackupCode: Joi.boolean().default(false)
    }),

    update: Joi.object({
        firstName: Joi.string().min(1).max(50).optional(),
        lastName: Joi.string().min(1).max(50).optional(),
        phone: Joi.string().optional(),
        avatar: Joi.string().uri().optional()
    }),

    changePassword: Joi.object({
        currentPassword: Joi.string().required(),
        newPassword: Joi.string().min(8).max(128).pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/).required()
            .messages({
                'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
            })
    }),

    forgotPassword: Joi.object({
        email: Joi.string().email().required()
    }),

    resetPassword: Joi.object({
        token: Joi.string().required(),
        password: Joi.string().min(8).max(128).pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/).required()
            .messages({
                'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
            })
    }),

    invite: Joi.object({
        email: Joi.string().email().required(),
        role: Joi.string().optional()
    }),

    acceptInvitation: Joi.object({
        token: Joi.string().required(),
        firstName: Joi.string().min(1).max(50).required(),
        lastName: Joi.string().min(1).max(50).required(),
        password: Joi.string().min(8).max(128).pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/).required()
            .messages({
                'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
            })
    })
};

// Role validation schemas
const roleSchemas = {
    create: Joi.object({
        name: Joi.string().min(2).max(50).required(),
        description: Joi.string().max(200).optional(),
        permissions: Joi.array().items(Joi.string()).default([])
    }),

    update: Joi.object({
        name: Joi.string().min(2).max(50).optional(),
        description: Joi.string().max(200).optional(),
        permissions: Joi.array().items(Joi.string()).optional()
    }),

    assignRole: Joi.object({
        userId: Joi.string().uuid().required(),
        roleId: Joi.string().uuid().required()
    })
};

// API Key validation schemas
const apiKeySchemas = {
    create: Joi.object({
        name: Joi.string().min(2).max(100).required(),
        permissions: Joi.array().items(Joi.string()).default([]),
        expiresAt: Joi.date().greater('now').optional()
    })
};

// Common validation helpers
const validateRequest = (schema) => {
    return (req, res, next) => {
        const { error, value } = schema.validate(req.body);

        if (error) {
            return res.status(400).json({
                success: false,
                message: 'Validation error',
                errors: error.details.map(detail => ({
                    field: detail.path.join('.'),
                    message: detail.message
                }))
            });
        }

        req.validatedData = value;
        next();
    };
};

const validateParams = (schema) => {
    return (req, res, next) => {
        const { error, value } = schema.validate(req.params);

        if (error) {
            return res.status(400).json({
                success: false,
                message: 'Invalid parameters',
                errors: error.details.map(detail => ({
                    field: detail.path.join('.'),
                    message: detail.message
                }))
            });
        }

        req.validatedParams = value;
        next();
    };
};

const validateQuery = (schema) => {
    return (req, res, next) => {
        const { error, value } = schema.validate(req.query);

        if (error) {
            return res.status(400).json({
                success: false,
                message: 'Invalid query parameters',
                errors: error.details.map(detail => ({
                    field: detail.path.join('.'),
                    message: detail.message
                }))
            });
        }

        req.validatedQuery = value;
        next();
    };
};

// Common parameter schemas
const paramSchemas = {
    uuid: Joi.object({
        id: Joi.string().uuid().required()
    })
};

module.exports = {
    organizationSchemas,
    userSchemas,
    roleSchemas,
    apiKeySchemas,
    paramSchemas,
    validateRequest,
    validateParams,
    validateQuery
};