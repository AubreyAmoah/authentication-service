// ===== SUPER ADMIN LOGIN SERVICE =====
// services/superAdminAuth.service.js

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const { AUDIT_ACTIONS, RISK_LEVELS } = require('../config/constants');

const superAdminAuthService = {
  // Super Admin Login
  loginSuperAdmin: async (email, password, deviceInfo) => {
    try {
      // Find user by email
      const user = await prisma.user.findUnique({
        where: { email },
        include: {
          organization: true
        }
      });

      if (!user) {
        throw new Error('Invalid credentials');
      }

      // Check if user is active
      if (!user.isActive) {
        throw new Error('Account is deactivated');
      }

      // Check if user is super admin
      if (!user.isSuperAdmin) {
        throw new Error('Access denied: Super admin privileges required');
      }

      // Verify password
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        throw new Error('Invalid credentials');
      }

      // Generate tokens
      const token = jwt.sign(
        {
          userId: user.id,
          email: user.email,
          role: user.role,
          isSuperAdmin: true
        },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
      );

      const refreshToken = jwt.sign(
        { userId: user.id, isSuperAdmin: true },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
      );

      // Update last login
      await prisma.user.update({
        where: { id: user.id },
        data: { lastLoginAt: new Date() }
      });

      // Log super admin login
      await prisma.auditLog.create({
        data: {
          action: AUDIT_ACTIONS.SUPER_ADMIN_LOGIN,
          ipAddress: deviceInfo.ip || null,
          userAgent: deviceInfo.userAgent || null,
          deviceType: deviceInfo.deviceType || null,
          country: deviceInfo.country.name || null,
          city: deviceInfo.city || null,
          riskLevel: RISK_LEVELS.CRITICAL,
          timestamp: new Date(),
          details: {
            userId: user.id, organizationId: user.organizationId || null, email: user.email
          }
        }
      });

      // Remove password from response
      const { password: _, ...userWithoutPassword } = user;

      return {
        user: userWithoutPassword,
        token,
        refreshToken,
        permissions: {
          canAccessAllOrganizations: true,
          canManageUsers: true,
          canManageSuperAdmins: true,
          canViewSystemMetrics: true,
          canManageOrganizations: true
        }
      };

    } catch (error) {
      throw error;
    }
  },

  // Validate Super Admin Session
  validateSuperAdminSession: async (userId) => {
    try {
      const user = await prisma.user.findUnique({
        where: { id: userId },
        include: {
          organization: true
        }
      });

      if (!user || !user.isActive || !user.isSuperAdmin) {
        throw new Error('Invalid super admin session');
      }

      const { password: _, ...userWithoutPassword } = user;
      return userWithoutPassword;

    } catch (error) {
      throw error;
    }
  },

  // Super Admin Logout
  logoutSuperAdmin: async (userId, deviceInfo) => {
    try {
      // Log super admin logout
      await prisma.auditLog.create({
        data: {
          userId,
          action: 'SUPER_ADMIN_LOGOUT',
          details: {
            timestamp: new Date()
          }
        }
      });

      // Log super admin logout
      await prisma.auditLog.create({
        data: {
          action: AUDIT_ACTIONS.SUPER_ADMIN_LOGOUT,
          ipAddress: deviceInfo.ip || null,
          userAgent: deviceInfo.userAgent || null,
          deviceType: deviceInfo.deviceType || null,
          country: deviceInfo.country.name || null,
          city: deviceInfo.city || null,
          riskLevel: RISK_LEVELS.CRITICAL,
          timestamp: new Date(),
          details: {
            userId: user.id, organizationId: user.organizationId || null, email: user.email
          }
        }
      });

      return true;
    } catch (error) {
      throw error;
    }
  }
};

module.exports = superAdminAuthService;