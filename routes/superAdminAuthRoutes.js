// ===== SUPER ADMIN ROUTES =====
// routes/superAdminAuth.routes.js

const express = require('express');
const router = express.Router();
const superAdminAuthController = require('../controllers/superAdminAuthController');
const validateSuperAdminCredentials = require('../middleware/validateSuperAdminCredentials');
const verifySuperAdminToken = require('../middleware/verifySuperAdminToken');
const deviceInfoMiddleware = require('../middleware/deviceInfo');

// Super Admin Login
router.post('/login', validateSuperAdminCredentials, superAdminAuthController.login);

// Super Admin Profile (Protected)
router.get('/profile', verifySuperAdminToken, superAdminAuthController.getProfile);

// Super Admin Logout (Protected)
router.post('/logout', verifySuperAdminToken, superAdminAuthController.logout);

module.exports = router;