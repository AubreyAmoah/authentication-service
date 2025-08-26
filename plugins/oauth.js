const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const { prisma } = require('../utils/database');
const { generateTokenPair } = require('../utils/jwt');
const userService = require('../services/userService');
const organizationService = require('../services/organizationService');
const authService = require('../services/authService');
const config = require('../config');

/**
 * Initialize OAuth strategies
 */
const initializeOAuth = () => {
    // Serialize user for session
    passport.serializeUser((user, done) => {
        done(null, user.id);
    });

    // Deserialize user from session
    passport.deserializeUser(async (id, done) => {
        try {
            const user = await userService.findUserById(id);
            done(null, user);
        } catch (error) {
            done(error, null);
        }
    });

    // Google OAuth Strategy
    if (config.oauth.google.clientId && config.oauth.google.clientSecret) {
        passport.use(new GoogleStrategy({
            clientID: config.oauth.google.clientId,
            clientSecret: config.oauth.google.clientSecret,
            callbackURL: config.oauth.google.callbackUrl,
            scope: ['profile', 'email']
        }, googleStrategyCallback));
    }

    // GitHub OAuth Strategy
    if (config.oauth.github.clientId && config.oauth.github.clientSecret) {
        passport.use(new GitHubStrategy({
            clientID: config.oauth.github.clientId,
            clientSecret: config.oauth.github.clientSecret,
            callbackURL: config.oauth.github.callbackUrl,
            scope: ['user:email']
        }, githubStrategyCallback));
    }
};

/**
 * Google OAuth strategy callback
 */
const googleStrategyCallback = async (accessToken, refreshToken, profile, done) => {
    try {
        const result = await handleOAuthCallback('google', {
            providerId: profile.id,
            email: profile.emails[0]?.value,
            firstName: profile.name?.givenName || '',
            lastName: profile.name?.familyName || '',
            avatar: profile.photos[0]?.value,
            accessToken,
            refreshToken
        });

        done(null, result);
    } catch (error) {
        done(error, null);
    }
};

/**
 * GitHub OAuth strategy callback
 */
const githubStrategyCallback = async (accessToken, refreshToken, profile, done) => {
    try {
        const result = await handleOAuthCallback('github', {
            providerId: profile.id.toString(),
            email: profile.emails?.[0]?.value || profile.email,
            firstName: profile.displayName?.split(' ')[0] || profile.username || '',
            lastName: profile.displayName?.split(' ').slice(1).join(' ') || '',
            avatar: profile.photos?.[0]?.value,
            accessToken,
            refreshToken
        });

        done(null, result);
    } catch (error) {
        done(error, null);
    }
};

/**
 * Handle OAuth callback for any provider
 */
const handleOAuthCallback = async (provider, providerData) => {
    const { providerId, email, firstName, lastName, avatar, accessToken, refreshToken } = providerData;

    if (!email) {
        throw new Error('Email is required from OAuth provider');
    }

    return await prisma.$transaction(async (tx) => {
        // Check if OAuth account already exists
        let oauthAccount = await tx.oAuthAccount.findUnique({
            where: {
                provider_providerId: {
                    provider,
                    providerId
                }
            },
            include: {
                user: {
                    include: {
                        organization: {
                            select: {
                                id: true,
                                name: true,
                                slug: true,
                                isActive: true
                            }
                        },
                        roles: {
                            include: {
                                role: {
                                    select: {
                                        id: true,
                                        name: true,
                                        slug: true,
                                        permissions: true
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        let user;

        if (oauthAccount) {
            // Update existing OAuth account
            await tx.oAuthAccount.update({
                where: { id: oauthAccount.id },
                data: {
                    email,
                    accessToken,
                    refreshToken
                }
            });

            user = oauthAccount.user;

            // Update user's last login
            await tx.user.update({
                where: { id: user.id },
                data: { lastLoginAt: new Date() }
            });
        } else {
            // Check if user exists with this email
            const existingUser = await tx.user.findUnique({
                where: { email },
                include: {
                    organization: {
                        select: {
                            id: true,
                            name: true,
                            slug: true,
                            isActive: true
                        }
                    },
                    roles: {
                        include: {
                            role: {
                                select: {
                                    id: true,
                                    name: true,
                                    slug: true,
                                    permissions: true
                                }
                            }
                        }
                    }
                }
            });

            if (existingUser) {
                // Link OAuth account to existing user
                await tx.oAuthAccount.create({
                    data: {
                        provider,
                        providerId,
                        email,
                        accessToken,
                        refreshToken,
                        userId: existingUser.id
                    }
                });

                // Update user's last login and mark email as verified
                await tx.user.update({
                    where: { id: existingUser.id },
                    data: {
                        lastLoginAt: new Date(),
                        isEmailVerified: true,
                        emailVerifiedAt: new Date(),
                        ...(avatar && !existingUser.avatar && { avatar })
                    }
                });

                user = existingUser;
            } else {
                // Create new user and OAuth account
                // For OAuth users, we need to determine organization
                // This could be based on email domain, invitation, or create a personal org

                let organizationId = null;

                // Check if there's a pending invitation
                const invitation = await tx.invitation.findFirst({
                    where: {
                        email,
                        acceptedAt: null,
                        expiresAt: { gt: new Date() }
                    }
                });

                if (invitation) {
                    organizationId = invitation.organizationId;

                    // Mark invitation as accepted
                    await tx.invitation.update({
                        where: { id: invitation.id },
                        data: { acceptedAt: new Date() }
                    });
                } else {
                    // Create personal organization for the user
                    const personalOrg = await organizationService.createOrganization({
                        name: `${firstName}'s Organization`
                    });
                    organizationId = personalOrg.id;
                }

                // Create user without password (OAuth user)
                const newUser = await tx.user.create({
                    data: {
                        email,
                        firstName,
                        lastName,
                        avatar,
                        isEmailVerified: true,
                        emailVerifiedAt: new Date(),
                        lastLoginAt: new Date(),
                        organizationId
                    }
                });

                // Create OAuth account
                await tx.oAuthAccount.create({
                    data: {
                        provider,
                        providerId,
                        email,
                        accessToken,
                        refreshToken,
                        userId: newUser.id
                    }
                });

                // Assign default role or invitation role
                let roleToAssign = 'member'; // default

                if (invitation && invitation.role) {
                    roleToAssign = invitation.role;
                } else if (!invitation) {
                    // If it's a personal org, make them admin
                    roleToAssign = 'admin';
                }

                const role = await tx.role.findFirst({
                    where: {
                        slug: roleToAssign,
                        organizationId
                    }
                });

                if (role) {
                    await tx.userRole.create({
                        data: {
                            userId: newUser.id,
                            roleId: role.id
                        }
                    });
                }

                // Get user with full details
                user = await tx.user.findUnique({
                    where: { id: newUser.id },
                    include: {
                        organization: {
                            select: {
                                id: true,
                                name: true,
                                slug: true,
                                isActive: true
                            }
                        },
                        roles: {
                            include: {
                                role: {
                                    select: {
                                        id: true,
                                        name: true,
                                        slug: true,
                                        permissions: true
                                    }
                                }
                            }
                        }
                    }
                });
            }
        }

        if (!user.isActive) {
            throw new Error('Account is deactivated');
        }

        if (!user.organization?.isActive) {
            throw new Error('Organization is deactivated');
        }

        // Transform roles for token generation
        const roles = user.roles?.map(userRole => userRole.role) || [];

        // Generate tokens
        const tokens = generateTokenPair({
            userId: user.id,
            email: user.email,
            organizationId: user.organizationId,
            roles: roles.map(role => role.slug)
        });

        // Create session
        await authService.createSession(user.id, user.organizationId, tokens.accessToken);

        return {
            user: {
                ...user,
                roles
            },
            tokens,
            isNewUser: !oauthAccount
        };
    });
};

/**
 * OAuth controller functions
 */
const oauthController = {
    /**
     * Google OAuth login
     */
    googleLogin: (req, res, next) => {
        const state = req.query.state || JSON.stringify({
            returnUrl: req.query.returnUrl || config.frontend.url
        });

        passport.authenticate('google', {
            state,
            accessType: 'offline',
            prompt: 'consent'
        })(req, res, next);
    },

    /**
     * Google OAuth callback
     */
    googleCallback: (req, res, next) => {
        passport.authenticate('google', { session: false }, (err, result) => {
            if (err) {
                console.error('Google OAuth error:', err);
                return res.redirect(`${config.frontend.url}/auth/error?message=${encodeURIComponent('Authentication failed')}`);
            }

            if (!result) {
                return res.redirect(`${config.frontend.url}/auth/error?message=${encodeURIComponent('Authentication cancelled')}`);
            }

            try {
                const state = req.query.state ? JSON.parse(req.query.state) : {};
                const returnUrl = state.returnUrl || config.frontend.url;

                // Redirect with tokens in URL (or set cookies and redirect)
                const params = new URLSearchParams({
                    token: result.tokens.accessToken,
                    refreshToken: result.tokens.refreshToken,
                    newUser: result.isNewUser.toString()
                });

                res.redirect(`${returnUrl}/auth/callback?${params.toString()}`);
            } catch (error) {
                console.error('OAuth callback error:', error);
                res.redirect(`${config.frontend.url}/auth/error?message=${encodeURIComponent('Authentication failed')}`);
            }
        })(req, res, next);
    },

    /**
     * GitHub OAuth login
     */
    githubLogin: (req, res, next) => {
        const state = req.query.state || JSON.stringify({
            returnUrl: req.query.returnUrl || config.frontend.url
        });

        passport.authenticate('github', {
            state,
            scope: ['user:email']
        })(req, res, next);
    },

    /**
     * GitHub OAuth callback
     */
    githubCallback: (req, res, next) => {
        passport.authenticate('github', { session: false }, (err, result) => {
            if (err) {
                console.error('GitHub OAuth error:', err);
                return res.redirect(`${config.frontend.url}/auth/error?message=${encodeURIComponent('Authentication failed')}`);
            }

            if (!result) {
                return res.redirect(`${config.frontend.url}/auth/error?message=${encodeURIComponent('Authentication cancelled')}`);
            }

            try {
                const state = req.query.state ? JSON.parse(req.query.state) : {};
                const returnUrl = state.returnUrl || config.frontend.url;

                // Redirect with tokens in URL (or set cookies and redirect)
                const params = new URLSearchParams({
                    token: result.tokens.accessToken,
                    refreshToken: result.tokens.refreshToken,
                    newUser: result.isNewUser.toString()
                });

                res.redirect(`${returnUrl}/auth/callback?${params.toString()}`);
            } catch (error) {
                console.error('OAuth callback error:', error);
                res.redirect(`${config.frontend.url}/auth/error?message=${encodeURIComponent('Authentication failed')}`);
            }
        })(req, res, next);
    },

    /**
     * Unlink OAuth provider
     */
    unlinkProvider: async (req, res) => {
        try {
            const { provider } = req.params;
            const userId = req.user.id;

            // Check if user has a password (can't unlink if no password set)
            const user = await prisma.user.findUnique({
                where: { id: userId },
                select: { password: true }
            });

            if (!user.password) {
                return res.status(400).json({
                    success: false,
                    message: 'Cannot unlink OAuth provider without setting a password first'
                });
            }

            // Remove OAuth account
            const deleted = await prisma.oAuthAccount.deleteMany({
                where: {
                    userId,
                    provider
                }
            });

            if (deleted.count === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'OAuth provider not linked to this account'
                });
            }

            res.json({
                success: true,
                message: `${provider} account unlinked successfully`
            });
        } catch (error) {
            console.error('Unlink provider error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to unlink provider'
            });
        }
    },

    /**
     * Get linked OAuth providers
     */
    getLinkedProviders: async (req, res) => {
        try {
            const userId = req.user.id;

            const oauthAccounts = await prisma.oAuthAccount.findMany({
                where: { userId },
                select: {
                    provider: true,
                    email: true,
                    createdAt: true
                }
            });

            res.json({
                success: true,
                data: {
                    providers: oauthAccounts
                }
            });
        } catch (error) {
            console.error('Get linked providers error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to get linked providers'
            });
        }
    }
};

module.exports = {
    initializeOAuth,
    oauthController
};