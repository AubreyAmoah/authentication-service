const express = require('express');
const organizationController = require('../controllers/organizationController');
const { authenticate, requirePermission, optionalAuth } = require('../middleware/auth');
const { validateRequest, validateParams, organizationSchemas, paramSchemas } = require('../utils/validation');

const router = express.Router();

// Public routes
router.get('/check-availability', organizationController.checkOrganizationAvailability);
router.get('/:slug/public', organizationController.getOrganizationBySlug);

// Protected routes
router.use(authenticate);

// Current organization management
router.get('/current', requirePermission('organization.read'), organizationController.getCurrentOrganization);
router.patch('/current', requirePermission('organization.update'), validateRequest(organizationSchemas.update), organizationController.updateCurrentOrganization);

// Organization settings
router.get('/current/settings', requirePermission('organization.settings'), organizationController.getOrganizationSettings);
router.patch('/current/settings', requirePermission('organization.settings'), organizationController.updateOrganizationSettings);

// Organization statistics
router.get('/current/stats', requirePermission('organization.read'), organizationController.getOrganizationStats);

// Super admin routes (for managing all organizations)
// These would typically be protected by a super admin role check
// For now, we'll use a strict permission check

// Create new organization (super admin only)
router.post('/', requirePermission('organizations.create'), validateRequest(organizationSchemas.create), organizationController.createOrganization);

// Get all organizations (super admin only)
router.get('/', requirePermission('organizations.read'), organizationController.getAllOrganizations);

// Get specific organization (super admin only)
router.get('/:id', requirePermission('organizations.read'), validateParams(paramSchemas.uuid), organizationController.getOrganizationById);

// Update organization (super admin only)
router.patch('/:id', requirePermission('organizations.update'), validateParams(paramSchemas.uuid), validateRequest(organizationSchemas.update), organizationController.updateOrganizationById);

// Deactivate/reactivate organization (super admin only)
router.patch('/:id/deactivate', requirePermission('organizations.update'), validateParams(paramSchemas.uuid), organizationController.deactivateOrganization);
router.patch('/:id/reactivate', requirePermission('organizations.update'), validateParams(paramSchemas.uuid), organizationController.reactivateOrganization);

// Delete organization (super admin only)
router.delete('/:id', requirePermission('organizations.delete'), validateParams(paramSchemas.uuid), organizationController.deleteOrganization);

module.exports = router;