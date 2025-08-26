const express = require('express');
const roleController = require('../controllers/roleController');
const { authenticate, requirePermission } = require('../middleware/auth');
const { validateRequest, validateParams, roleSchemas, paramSchemas } = require('../utils/validation');

const router = express.Router();

// All routes require authentication
router.use(authenticate);

// Get available permissions
router.get('/permissions', requirePermission('roles.read'), roleController.getAvailablePermissions);

// Get role statistics
router.get('/stats', requirePermission('roles.read'), roleController.getRoleStats);

// Check user permission
router.get('/check-permission', requirePermission('roles.read'), roleController.checkUserPermission);

// Get all roles in organization
router.get('/', requirePermission('roles.read'), roleController.getRoles);

// Create new role
router.post('/', requirePermission('roles.create'), validateRequest(roleSchemas.create), roleController.createRole);

// Get specific role
router.get('/:id', requirePermission('roles.read'), validateParams(paramSchemas.uuid), roleController.getRoleById);

// Update role
router.patch('/:id', requirePermission('roles.update'), validateParams(paramSchemas.uuid), validateRequest(roleSchemas.update), roleController.updateRole);

// Delete role
router.delete('/:id', requirePermission('roles.delete'), validateParams(paramSchemas.uuid), roleController.deleteRole);

// Duplicate role
router.post('/:id/duplicate', requirePermission('roles.create'), validateParams(paramSchemas.uuid), roleController.duplicateRole);

// Role user management
router.get('/:id/users', requirePermission('roles.read'), validateParams(paramSchemas.uuid), roleController.getRoleUsers);

// Role assignment (handled in user routes as well, but also available here)
router.post('/assign', requirePermission('roles.assign'), validateRequest(roleSchemas.assignRole), roleController.assignRoleToUser);
router.delete('/assign/:userId/:roleId', requirePermission('roles.assign'), roleController.removeRoleFromUser);

module.exports = router;