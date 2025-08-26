const express = require('express');
const userController = require('../controllers/userController');
const { authenticate, requirePermission, requireOwnershipOrAdmin } = require('../middleware/auth');
const { validateRequest, validateParams, userSchemas, roleSchemas, paramSchemas } = require('../utils/validation');

const router = express.Router();

// All routes require authentication
router.use(authenticate);

// Get user statistics (requires read permission)
router.get('/stats', requirePermission('users.read'), userController.getUserStats);

// Search users (requires read permission)
router.get('/search', requirePermission('users.read'), userController.searchUsers);

// Get all users in organization (requires read permission)
router.get('/', requirePermission('users.read'), userController.getUsers);

// Get specific user (requires read permission)
router.get('/:id', requirePermission('users.read'), validateParams(paramSchemas.uuid), userController.getUserById);

// Update user (requires update permission or ownership)
router.patch('/:id',
    validateParams(paramSchemas.uuid),
    validateRequest(userSchemas.update),
    (req, res, next) => {
        // Allow users to update their own profile or require admin permission
        if (req.user.id === req.params.id) {
            return next();
        }
        return requirePermission('users.update')(req, res, next);
    },
    userController.updateUser
);

// User role management
router.get('/:id/roles', requirePermission('users.read'), validateParams(paramSchemas.uuid), userController.getUserRoles);
router.post('/:id/roles', requirePermission('roles.assign'), validateParams(paramSchemas.uuid), validateRequest(roleSchemas.assignRole), userController.assignRole);
router.delete('/:id/roles/:roleId', requirePermission('roles.assign'), userController.removeRole);

// User activation/deactivation (requires update permission)
router.patch('/:id/deactivate', requirePermission('users.update'), validateParams(paramSchemas.uuid), userController.deactivateUser);
router.patch('/:id/reactivate', requirePermission('users.update'), validateParams(paramSchemas.uuid), userController.reactivateUser);

// Delete user (requires delete permission)
router.delete('/:id', requirePermission('users.delete'), validateParams(paramSchemas.uuid), userController.deleteUser);

module.exports = router;