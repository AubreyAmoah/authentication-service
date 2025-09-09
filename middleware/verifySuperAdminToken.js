// middleware/verifySuperAdminToken.js

const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

const verifySuperAdminToken = async (req, res, next) => {
    try {
        // Get token from header or cookie
        let token = req.headers.authorization?.split(' ')[1] || req.cookies.superAdminToken;

        if (!token) {
            return res.status(401).json({
                success: 0,
                message: 'Access denied. No token provided'
            });
        }

        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Check if user exists and is super admin
        const user = await prisma.user.findUnique({
            where: { id: decoded.userId }
        });

        if (!user || !user.isActive || !user.isSuperAdmin) {
            return res.status(401).json({
                success: 0,
                message: 'Access denied. Invalid super admin token'
            });
        }

        // Add user info to request
        req.user = {
            userId: user.id,
            email: user.email,
            role: user.role,
            isSuperAdmin: true,
            organizationId: user.organizationId
        };

        next();
    } catch (error) {
        console.error('Super admin token verification error:', error);

        return res.status(401).json({
            success: 0,
            message: 'Invalid token'
        });
    }
};

module.exports = verifySuperAdminToken;