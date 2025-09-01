const express = require('express');
const superAdminController = require('../controllers/superAdminController');
const organizationController = require('../controllers/organizationController');
const { authenticate, requireSuperAdmin } = require('../middleware/auth');
const { validateRequest, validateParams, userSchemas, organizationSchemas, paramSchemas } = require('../utils/validation');

const router = express.Router();

// All routes require super admin authentication
router.use(authenticate);
router.use(requireSuperAdmin);

// System statistics and overview
router.get('/stats', superAdminController.getSystemStats);

// User management across all organizations
router.get('/users', superAdminController.getAllUsers);
router.get('/users/:id', validateParams(paramSchemas.uuid), superAdminController.getUserDetails);
router.post('/users/super-admin', validateRequest(userSchemas.register), superAdminController.createSuperAdmin);
router.patch('/users/:id/toggle-super-admin', validateParams(paramSchemas.uuid), superAdminController.toggleSuperAdmin);
router.delete('/users/:id', validateParams(paramSchemas.uuid), superAdminController.deleteAnyUser);

// Session management across all organizations
router.get('/sessions', superAdminController.getAllSessions);
router.delete('/sessions/:sessionId', validateParams(paramSchemas.uuid), superAdminController.revokeAnySession);

// Organization management (using existing organization controller methods)
router.get('/organizations', organizationController.getAllOrganizations);
router.post('/organizations', validateRequest(organizationSchemas.create), organizationController.createOrganization);
router.get('/organizations/:id', validateParams(paramSchemas.uuid), organizationController.getOrganizationById);
router.patch('/organizations/:id', validateParams(paramSchemas.uuid), validateRequest(organizationSchemas.update), organizationController.updateOrganizationById);
router.patch('/organizations/:id/deactivate', validateParams(paramSchemas.uuid), organizationController.deactivateOrganization);
router.patch('/organizations/:id/reactivate', validateParams(paramSchemas.uuid), organizationController.reactivateOrganization);
router.delete('/organizations/:id', validateParams(paramSchemas.uuid), organizationController.deleteOrganization);

module.exports = router;