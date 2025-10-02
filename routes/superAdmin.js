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
router.get('/sessions/user/:userId', superAdminController.getUserSessions);
router.get('/sessions/current', superAdminController.getCurrentSession);
router.get('/sessions/active/count', superAdminController.getActiveSessionsCount);
router.get('/sessions/stats', superAdminController.getSessionsStats);
router.get('/sessions/export', superAdminController.exportSessions);
router.delete('/sessions/:sessionId', superAdminController.revokeAnySession);
router.delete('/sessions/user/:userId/revoke-all', superAdminController.revokeAllUserSessions);
router.delete('/sessions/cleanup', superAdminController.cleanupExpiredSessions);

// Organization management (using existing organization controller methods)
router.get('/organizations', organizationController.getAllOrganizations);
router.get('/organizations-users', superAdminController.getAllOrganizationUsers);
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

// Audit logs
router.get('/audit-logs', superAdminController.getAuditLogs);
router.get('/audit-logs/all', superAdminController.getAllAuditLogs);
router.get('/audit-logs/export', superAdminController.exportAuditLogs);

// Login attempts management
router.get('/login-attempts', superAdminController.getLoginAttempts);
router.get('/login-attempts/all', superAdminController.getAllLoginAttempts);
router.get('/login-attempts/user/:userId', superAdminController.getUserLoginAttempts);
router.get('/login-attempts/recent', superAdminController.getRecentLoginAttempts);
router.get('/login-attempts/ip/:ipAddress', superAdminController.getLoginAttemptsByIP);
router.get('/login-attempts/stats', superAdminController.getLoginAttemptsStats);
router.get('/login-attempts/export', superAdminController.exportLoginAttempts);
router.delete('/login-attempts/cleanup', superAdminController.cleanupOldLoginAttempts);

// Role management
router.post('/roles', superAdminController.createRole);
// Note: assignRoleToUser and revokeRoleFromUser are utility functions, not direct routes
// You may want to create wrapper routes for these if needed:
// router.post('/users/:userId/roles/:roleId', superAdminController.assignRole);
// router.delete('/users/:userId/roles/:roleId', superAdminController.revokeRole);

// CORS management
router.post('/cors', superAdminController.createCorsUrl);
router.get('/cors', superAdminController.getCorsUrls);
router.delete('/cors/:id', superAdminController.deleteCorsUrl);

module.exports = router;