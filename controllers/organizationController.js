const organizationService = require('../services/organizationService');
const { prisma } = require('../utils/database');
const { sendSuccess, sendError, sendPaginated, asyncHandler, getPaginationParams } = require('../utils/response');

/**
 * Get current organization
 */
const getCurrentOrganization = asyncHandler(async (req, res) => {
    const organization = await organizationService.findOrganizationById(req.user.organizationId);

    if (!organization) {
        return sendError(res, 'Organization not found', 404);
    }

    sendSuccess(res, { organization }, 'Organization retrieved successfully');
});

/**
 * Update current organization
 */
const updateCurrentOrganization = asyncHandler(async (req, res) => {
    const updatedOrganization = await organizationService.updateOrganization(
        req.user.organizationId,
        req.validatedData
    );

    await prisma.auditLog.create({
        data: {
            action: AUDIT_ACTIONS.ORGANIZATION_UPDATED,
            userId: req.user.userId,
            ipAddress: req.deviceInfo.ip || null,
            userAgent: req.deviceInfo.userAgent || null,
            deviceType: req.deviceInfo.deviceType || null,
            country: req.deviceInfo.country.name || null,
            city: req.deviceInfo.city || null,
            riskLevel: RISK_LEVELS.MEDIUM,
            timestamp: new Date(),
            details: {
                organizationId: req.user.organizationId,
                changes: req.validatedData,
                timestamp: new Date(),
                info: 'Organization details updated'
            }
        }
    });

    sendSuccess(res, { organization: updatedOrganization }, 'Organization updated successfully');
});

/**
 * Get organization settings
 */
const getOrganizationSettings = asyncHandler(async (req, res) => {
    const settings = await organizationService.getOrganizationSettings(req.user.organizationId);

    sendSuccess(res, { settings }, 'Organization settings retrieved successfully');
});

/**
 * Update organization settings
 */
const updateOrganizationSettings = asyncHandler(async (req, res) => {
    const updatedSettings = await organizationService.updateOrganizationSettings(
        req.user.organizationId,
        req.body
    );

    await prisma.auditLog.create({
        data: {
            action: AUDIT_ACTIONS.ORGANIZATION_UPDATED,
            userId: req.user.userId,
            ipAddress: req.deviceInfo.ip || null,
            userAgent: req.deviceInfo.userAgent || null,
            deviceType: req.deviceInfo.deviceType || null,
            country: req.deviceInfo.country.name || null,
            city: req.deviceInfo.city || null,
            riskLevel: RISK_LEVELS.MEDIUM,
            timestamp: new Date(),
            details: {
                organizationId: req.user.organizationId,
                changes: req.body,
                timestamp: new Date(),
                info: 'Organization settings updated'
            }
        }
    });

    sendSuccess(res, { settings: updatedSettings }, 'Organization settings updated successfully');
});

/**
 * Get organization statistics
 */
const getOrganizationStats = asyncHandler(async (req, res) => {
    const stats = await organizationService.getOrganizationStats(req.user.organizationId);

    sendSuccess(res, { stats }, 'Organization statistics retrieved successfully');
});

/**
 * Get organization by slug (public endpoint)
 */
const getOrganizationBySlug = asyncHandler(async (req, res) => {
    const { slug } = req.params;

    const organization = await organizationService.findOrganizationBySlug(slug);

    if (!organization) {
        return sendError(res, 'Organization not found', 404);
    }

    // Return only public information
    const publicOrganization = {
        id: organization.id,
        name: organization.name,
        slug: organization.slug,
        website: organization.website,
        logoUrl: organization.logoUrl,
        isActive: organization.isActive
    };

    sendSuccess(res, { organization: publicOrganization }, 'Organization retrieved successfully');
});

/**
 * Create new organization (super admin only)
 */
const createOrganization = asyncHandler(async (req, res) => {
    const organization = await organizationService.createOrganization(req.validatedData);

    sendSuccess(res, { organization }, 'Organization created successfully', 201);
});

/**
 * Get all organizations (super admin only)
 */
const getAllOrganizations = asyncHandler(async (req, res) => {
    const { page, limit } = getPaginationParams(req.query);
    const { search, sortBy, sortOrder, isActive } = req.query;

    const result = await organizationService.getAllOrganizations({
        page,
        limit,
        search,
        sortBy,
        sortOrder,
        isActive: isActive !== undefined ? isActive === 'true' : undefined
    });

    sendPaginated(res, result.organizations, result.pagination, 'Organizations retrieved successfully');
});

/**
 * Get organization by ID (super admin only)
 */
const getOrganizationById = asyncHandler(async (req, res) => {
    const { id } = req.params;

    const organization = await organizationService.findOrganizationById(id);

    if (!organization) {
        return sendError(res, 'Organization not found', 404);
    }

    sendSuccess(res, { organization }, 'Organization retrieved successfully');
});

/**
 * Update organization by ID (super admin only)
 */
const updateOrganizationById = asyncHandler(async (req, res) => {
    const { id } = req.params;

    const organization = await organizationService.findOrganizationById(id);

    if (!organization) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.ORGANIZATION_UPDATED,
                userId: req.user.userId,
                ipAddress: req.deviceInfo.ip || null,
                userAgent: req.deviceInfo.userAgent || null,
                deviceType: req.deviceInfo.deviceType || null,
                country: req.deviceInfo.country.name || null,
                city: req.deviceInfo.city || null,
                riskLevel: RISK_LEVELS.HIGH,
                timestamp: new Date(),
                success: false,
                details: {
                    attemptedOrganizationId: id,
                    timestamp: new Date(),
                    info: 'Attempted to update a non-existent organization'
                }
            }
        });
        return sendError(res, 'Organization not found', 404);
    }

    const updatedOrganization = await organizationService.updateOrganization(id, req.validatedData);

    await prisma.auditLog.create({
        data: {
            action: AUDIT_ACTIONS.ORGANIZATION_UPDATED,
            userId: req.user.userId,
            ipAddress: req.deviceInfo.ip || null,
            userAgent: req.deviceInfo.userAgent || null,
            deviceType: req.deviceInfo.deviceType || null,
            country: req.deviceInfo.country.name || null,
            city: req.deviceInfo.city || null,
            riskLevel: RISK_LEVELS.MEDIUM,
            timestamp: new Date(),
            details: {
                organizationId: id,
                changes: req.validatedData,
                timestamp: new Date(),
                info: 'Organization details updated'
            }
        }
    });
    sendSuccess(res, { organization: updatedOrganization }, 'Organization updated successfully');
});

/**
 * Deactivate organization (super admin only)
 */
const deactivateOrganization = asyncHandler(async (req, res) => {
    const { id } = req.params;

    console.log(req.user.userId)

    const organization = await organizationService.findOrganizationById(id);

    if (!organization) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.ORGANIZATION_DEACTIVATED,
                userId: req.user.userId,
                ipAddress: req.deviceInfo.ip || null,
                userAgent: req.deviceInfo.userAgent || null,
                deviceType: req.deviceInfo.deviceType || null,
                country: req.deviceInfo.country.name || null,
                city: req.deviceInfo.city || null,
                riskLevel: RISK_LEVELS.HIGH,
                timestamp: new Date(),
                success: false,
                details: {
                    attemptedOrganizationId: id,
                    timestamp: new Date(),
                    info: 'Attempted to deactivate a non-existent organization'
                }
            }
        });
        return sendError(res, 'Organization not found', 404);
    }

    if (!organization.isActive) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.ORGANIZATION_DEACTIVATED,
                userId: req.user.userId,
                ipAddress: req.deviceInfo.ip || null,
                userAgent: req.deviceInfo.userAgent || null,
                deviceType: req.deviceInfo.deviceType || null,
                country: req.deviceInfo.country.name || null,
                city: req.deviceInfo.city || null,
                riskLevel: RISK_LEVELS.HIGH,
                timestamp: new Date(),
                success: false,
                details: {
                    organizationId: id,
                    timestamp: new Date(),
                    info: 'Attempted to deactivate an already deactivated organization'
                }
            }
        });
        return sendError(res, 'Organization is already deactivated', 400);
    }

    const updatedOrganization = await organizationService.deactivateOrganization(id);

    await prisma.auditLog.create({
        data: {
            action: AUDIT_ACTIONS.ORGANIZATION_DEACTIVATED,
            userId: req.user.userId,
            ipAddress: req.deviceInfo.ip || null,
            userAgent: req.deviceInfo.userAgent || null,
            deviceType: req.deviceInfo.deviceType || null,
            country: req.deviceInfo.country.name || null,
            city: req.deviceInfo.city || null,
            riskLevel: RISK_LEVELS.MEDIUM,
            timestamp: new Date(),
            details: {
                organizationId: id,
                timestamp: new Date(),
                info: 'Organization deactivated'
            }
        }
    });

    sendSuccess(res, { organization: updatedOrganization }, 'Organization deactivated successfully');
});

/**
 * Reactivate organization (super admin only)
 */
const reactivateOrganization = asyncHandler(async (req, res) => {
    const { id } = req.params;

    const organization = await organizationService.findOrganizationById(id);

    if (!organization) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.ORGANIZATION_REACTIVATED,
                userId: req.user.userId,
                ipAddress: req.deviceInfo.ip || null,
                userAgent: req.deviceInfo.userAgent || null,
                deviceType: req.deviceInfo.deviceType || null,
                country: req.deviceInfo.country.name || null,
                city: req.deviceInfo.city || null,
                riskLevel: RISK_LEVELS.HIGH,
                timestamp: new Date(),
                success: false,
                details: {
                    attemptedOrganizationId: id,
                    timestamp: new Date(),
                    info: 'Attempted to reactivate a non-existent organization'
                }
            }
        });
        return sendError(res, 'Organization not found', 404);
    }

    if (organization.isActive) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.ORGANIZATION_REACTIVATED,
                userId: req.user.userId,
                ipAddress: req.deviceInfo.ip || null,
                userAgent: req.deviceInfo.userAgent || null,
                deviceType: req.deviceInfo.deviceType || null,
                country: req.deviceInfo.country.name || null,
                city: req.deviceInfo.city || null,
                riskLevel: RISK_LEVELS.HIGH,
                timestamp: new Date(),
                success: false,
                details: {
                    organizationId: id,
                    timestamp: new Date(),
                    info: 'Attempted to reactivate an already active organization'
                }
            }
        });
        return sendError(res, 'Organization is already active', 400);
    }

    const updatedOrganization = await organizationService.reactivateOrganization(id);

    await prisma.auditLog.create({
        data: {
            action: AUDIT_ACTIONS.ORGANIZATION_REACTIVATED,
            userId: req.user.userId,
            ipAddress: req.deviceInfo.ip || null,
            userAgent: req.deviceInfo.userAgent || null,
            deviceType: req.deviceInfo.deviceType || null,
            country: req.deviceInfo.country.name || null,
            city: req.deviceInfo.city || null,
            riskLevel: RISK_LEVELS.MEDIUM,
            timestamp: new Date(),
            details: {
                organizationId: id,
                timestamp: new Date(),
                info: 'Organization reactivated'
            }
        }
    });
    sendSuccess(res, { organization: updatedOrganization }, 'Organization reactivated successfully');
});

/**
 * Delete organization (super admin only)
 */
const deleteOrganization = asyncHandler(async (req, res) => {
    const { id } = req.params;

    const organization = await organizationService.findOrganizationById(id);

    if (!organization) {
        await prisma.auditLog.create({
            data: {
                action: AUDIT_ACTIONS.UNAUTHORIZED_ACCESS,
                userId: req.user.userId,
                ipAddress: req.deviceInfo.ip || null,
                userAgent: req.deviceInfo.userAgent || null,
                deviceType: req.deviceInfo.deviceType || null,
                country: req.deviceInfo.country.name || null,
                city: req.deviceInfo.city || null,
                riskLevel: RISK_LEVELS.HIGH,
                timestamp: new Date(),
                details: {
                    attemptedOrganizationId: id,
                    timestamp: new Date(),
                    info: 'Attempted to delete a non-existent organization'
                }
            }
        });
        return sendError(res, 'Organization not found', 404);
    }

    await organizationService.deleteOrganization(id);

    await prisma.auditLog.create({
        data: {
            action: AUDIT_ACTIONS.ORGANIZATION_DELETED,
            userId: req.user.userId,
            ipAddress: req.deviceInfo.ip || null,
            userAgent: req.deviceInfo.userAgent || null,
            deviceType: req.deviceInfo.deviceType || null,
            country: req.deviceInfo.country.name || null,
            city: req.deviceInfo.city || null,
            riskLevel: RISK_LEVELS.CRITICAL,
            timestamp: new Date(),
            details: {
                organizationId: id,
                timestamp: new Date(),
                info: 'Organization deleted'
            }
        }
    });
    sendSuccess(res, null, 'Organization deleted successfully');
});

/**
 * Check organization availability
 */
const checkOrganizationAvailability = asyncHandler(async (req, res) => {
    const { name, slug } = req.query;

    if (!name && !slug) {
        return sendError(res, 'Either name or slug parameter is required', 400);
    }

    const availability = {
        name: {
            available: true,
            checked: false
        },
        slug: {
            available: true,
            checked: false
        }
    };

    if (name) {
        const existingByName = await organizationService.findOrganizationBySlug(name
            .toLowerCase()
            .replace(/[^a-z0-9\s-]/g, '')
            .replace(/\s+/g, '-')
            .replace(/-+/g, '-')
            .trim('-')
        );
        availability.name.available = !existingByName;
        availability.name.checked = true;
    }

    if (slug) {
        const existingBySlug = await organizationService.findOrganizationBySlug(slug);
        availability.slug.available = !existingBySlug;
        availability.slug.checked = true;
    }

    sendSuccess(res, { availability }, 'Availability checked successfully');
});

module.exports = {
    getCurrentOrganization,
    updateCurrentOrganization,
    getOrganizationSettings,
    updateOrganizationSettings,
    getOrganizationStats,
    getOrganizationBySlug,
    createOrganization,
    getAllOrganizations,
    getOrganizationById,
    updateOrganizationById,
    deactivateOrganization,
    reactivateOrganization,
    deleteOrganization,
    checkOrganizationAvailability
};