const express = require('express');
const superAdminController = require('../controllers/superAdminController');
const organizationController = require('../controllers/organizationController');
const { validateRequest, validateParams, userSchemas, organizationSchemas, paramSchemas } = require('../utils/validation');
const verifySuperAdminToken = require('../middleware/verifySuperAdminToken');

const router = express.Router();

// All routes require super admin authentication
router.use(verifySuperAdminToken);

// System statistics and overview
router.get('/stats', superAdminController.getSystemStats);

// User management across all organizations
router.get('/users', superAdminController.getAllUsers);
router.get('/users/:id', validateParams(paramSchemas.uuid), superAdminController.getUserDetails);
router.get('/users/:id/profile', validateParams(paramSchemas.uuid), superAdminController.getUserProfile);
router.patch('/users/:id/toggle-activation', validateParams(paramSchemas.uuid), superAdminController.toggleUserActivation);
router.post('/create-super-admin', validateRequest(userSchemas.register), superAdminController.createSuperAdmin);
router.patch('/users/:id/toggle-super-admin', validateParams(paramSchemas.uuid), superAdminController.toggleSuperAdmin);
router.delete('/users/:id', validateParams(paramSchemas.uuid), superAdminController.deleteAnyUser);

// Session management across all organizations
router.get('/sessions', superAdminController.getAllSessions);
router.delete('/sessions/:sessionId', validateParams(paramSchemas.uuid), superAdminController.revokeAnySession);

// Organization management (using existing organization controller methods)
router.get('/organizations', organizationController.getAllOrganizations);
router.get('/organizations/check-availability', organizationController.checkOrganizationAvailability);
router.post('/organizations', validateRequest(organizationSchemas.create), organizationController.createOrganization);
router.post('/organizations/transfer-membership', validateRequest(organizationSchemas.transferMembership), superAdminController.transferOrganizationMembership);
router.get('/organizations/:id', validateParams(paramSchemas.uuid), superAdminController.getOrganizationDetails);
router.patch('/organizations/update/:id', validateParams(paramSchemas.uuid), validateRequest(organizationSchemas.update), organizationController.updateOrganizationById);
router.patch('/organizations/:id/toggle-activation', validateParams(paramSchemas.uuid), superAdminController.toggleOrganizationActivation);
router.patch('/organizations/:id', validateParams(paramSchemas.uuid), validateRequest(organizationSchemas.update), organizationController.updateOrganizationById);
router.patch('/organizations/:id/deactivate', validateParams(paramSchemas.uuid), organizationController.deactivateOrganization);
router.patch('/organizations/:id/reactivate', validateParams(paramSchemas.uuid), organizationController.reactivateOrganization);
router.delete('/organizations/:id', validateParams(paramSchemas.uuid), organizationController.deleteOrganization);

module.exports = router;