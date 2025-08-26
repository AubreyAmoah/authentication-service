const bcrypt = require('bcryptjs');
const config = require('../config');

/**
 * Hash a password using bcrypt
 * @param {string} password - Plain text password
 * @returns {Promise<string>} - Hashed password
 */
const hashPassword = async (password) => {
    try {
        const salt = await bcrypt.genSalt(config.security.bcryptRounds);
        return await bcrypt.hash(password, salt);
    } catch (error) {
        throw new Error('Failed to hash password');
    }
};

/**
 * Compare a plain text password with a hashed password
 * @param {string} password - Plain text password
 * @param {string} hash - Hashed password
 * @returns {Promise<boolean>} - True if passwords match
 */
const comparePassword = async (password, hash) => {
    try {
        return await bcrypt.compare(password, hash);
    } catch (error) {
        throw new Error('Failed to compare passwords');
    }
};

/**
 * Check if password needs rehashing (if bcrypt rounds have increased)
 * @param {string} hash - Current password hash
 * @returns {boolean} - True if rehashing is needed
 */
const needsRehash = (hash) => {
    try {
        const rounds = bcrypt.getRounds(hash);
        return rounds < config.security.bcryptRounds;
    } catch (error) {
        return true; // If we can't determine rounds, assume rehash is needed
    }
};

module.exports = {
    hashPassword,
    comparePassword,
    needsRehash
};