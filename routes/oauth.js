const express = require('express');
const { oauthController } = require('../plugins/oauth');
const { authenticate } = require('../middleware/auth');

const router = express.Router();

// Google OAuth routes
router.get('/google', oauthController.googleLogin);
router.get('/google/callback', oauthController.googleCallback);

// GitHub OAuth routes
router.get('/github', oauthController.githubLogin);
router.get('/github/callback', oauthController.githubCallback);

// Protected OAuth management routes
router.use(authenticate);

// Get linked providers
router.get('/providers', oauthController.getLinkedProviders);

// Unlink OAuth provider
router.delete('/providers/:provider', oauthController.unlinkProvider);

module.exports = router;