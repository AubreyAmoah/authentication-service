// ===== MIDDLEWARE =====
// middleware/validateSuperAdminCredentials.js

const validateSuperAdminCredentials = (req, res, next) => {
    const { email, password } = req.body;

    // Check if credentials are provided
    if (!email || !password) {
        return res.status(400).json({
            success: 0,
            message: 'Email and password are required'
        });
    }

    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({
            success: 0,
            message: 'Invalid email format'
        });
    }

    // Password strength validation for super admin
    if (password.length < 8) {
        return res.status(400).json({
            success: 0,
            message: 'Password must be at least 8 characters long'
        });
    }

    next();
};

module.exports = validateSuperAdminCredentials;