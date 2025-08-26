const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const config = require('../config');

/**
 * Generate JWT access token
 * @param {Object} payload - Token payload
 * @returns {string} - JWT token
 */
const generateAccessToken = (payload) => {
    return jwt.sign(payload, config.jwt.secret, {
        expiresIn: config.jwt.expiresIn,
        issuer: 'auth-service',
        audience: 'api-client'
    });
};

/**
 * Generate JWT refresh token
 * @param {Object} payload - Token payload
 * @returns {string} - JWT refresh token
 */
const generateRefreshToken = (payload) => {
    return jwt.sign(payload, config.jwt.refreshSecret, {
        expiresIn: config.jwt.refreshExpiresIn,
        issuer: 'auth-service',
        audience: 'api-client'
    });
};

/**
 * Verify JWT access token
 * @param {string} token - JWT token
 * @returns {Object} - Decoded payload
 */
const verifyAccessToken = (token) => {
    try {
        return jwt.verify(token, config.jwt.secret, {
            issuer: 'auth-service',
            audience: 'api-client'
        });
    } catch (error) {
        throw new Error('Invalid access token');
    }
};

/**
 * Verify JWT refresh token
 * @param {string} token - JWT refresh token
 * @returns {Object} - Decoded payload
 */
const verifyRefreshToken = (token) => {
    try {
        return jwt.verify(token, config.jwt.refreshSecret, {
            issuer: 'auth-service',
            audience: 'api-client'
        });
    } catch (error) {
        throw new Error('Invalid refresh token');
    }
};

/**
 * Generate secure random token
 * @param {number} length - Token length (default: 32)
 * @returns {string} - Random token
 */
const generateSecureToken = (length = 32) => {
    return crypto.randomBytes(length).toString('hex');
};

/**
 * Generate API key
 * @returns {string} - API key
 */
const generateApiKey = () => {
    const prefix = 'ak_';
    const randomPart = crypto.randomBytes(32).toString('hex');
    return prefix + randomPart;
};

/**
 * Extract token from authorization header
 * @param {string} authHeader - Authorization header value
 * @returns {string|null} - Extracted token or null
 */
const extractTokenFromHeader = (authHeader) => {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return null;
    }
    return authHeader.substring(7);
};

/**
 * Generate token pair (access + refresh)
 * @param {Object} payload - Token payload
 * @returns {Object} - Object containing access and refresh tokens
 */
const generateTokenPair = (payload) => {
    const accessToken = generateAccessToken(payload);
    const refreshToken = generateRefreshToken({
        userId: payload.userId,
        organizationId: payload.organizationId
    });

    return {
        accessToken,
        refreshToken,
        tokenType: 'Bearer',
        expiresIn: config.jwt.expiresIn
    };
};

/**
 * Decode JWT without verification (for extracting payload)
 * @param {string} token - JWT token
 * @returns {Object} - Decoded payload
 */
const decodeToken = (token) => {
    try {
        return jwt.decode(token);
    } catch (error) {
        return null;
    }
};

/**
 * Check if token is expired
 * @param {string} token - JWT token
 * @returns {boolean} - True if token is expired
 */
const isTokenExpired = (token) => {
    try {
        const decoded = jwt.decode(token);
        if (!decoded || !decoded.exp) {
            return true;
        }
        return Date.now() >= decoded.exp * 1000;
    } catch (error) {
        return true;
    }
};

module.exports = {
    generateAccessToken,
    generateRefreshToken,
    verifyAccessToken,
    verifyRefreshToken,
    generateSecureToken,
    generateApiKey,
    extractTokenFromHeader,
    generateTokenPair,
    decodeToken,
    isTokenExpired
};