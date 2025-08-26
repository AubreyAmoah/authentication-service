const nodemailer = require('nodemailer');
const config = require('../config');

// Create email transporter
const createTransporter = () => {
    if (!config.email.smtp.host || !config.email.smtp.auth.user) {
        console.warn('⚠️ Email configuration not found. Email features will be disabled.');
        return null;
    }

    return nodemailer.createTransport(config.email.smtp);
};

const transporter = createTransporter();

/**
 * Send email verification
 * @param {string} email - Recipient email
 * @param {string} token - Verification token
 * @param {string} firstName - User's first name
 */
const sendEmailVerification = async (email, token, firstName) => {
    if (!transporter) {
        console.warn('Email transporter not configured. Skipping email verification.');
        return;
    }

    const verificationUrl = `${config.frontend.url}/verify-email?token=${token}`;

    const mailOptions = {
        from: `${config.email.from.name} <${config.email.from.email}>`,
        to: email,
        subject: 'Verify Your Email Address',
        html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background-color: #f8f9fa; padding: 20px; text-align: center;">
          <h1 style="color: #333; margin: 0;">Welcome ${firstName}!</h1>
        </div>
        <div style="padding: 30px;">
          <p style="font-size: 16px; line-height: 1.5; color: #333;">
            Thank you for creating an account. Please verify your email address by clicking the button below:
          </p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${verificationUrl}" 
               style="background-color: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
              Verify Email Address
            </a>
          </div>
          <p style="font-size: 14px; color: #666; margin-top: 30px;">
            If the button doesn't work, copy and paste this link into your browser:<br>
            <a href="${verificationUrl}" style="color: #007bff;">${verificationUrl}</a>
          </p>
          <p style="font-size: 14px; color: #666; margin-top: 20px;">
            This verification link will expire in 24 hours.
          </p>
        </div>
        <div style="background-color: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #666;">
          If you didn't create this account, please ignore this email.
        </div>
      </div>
    `
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`📧 Email verification sent to ${email}`);
    } catch (error) {
        console.error('Failed to send email verification:', error);
        throw new Error('Failed to send verification email');
    }
};

/**
 * Send password reset email
 * @param {string} email - Recipient email
 * @param {string} token - Reset token
 * @param {string} firstName - User's first name
 */
const sendPasswordReset = async (email, token, firstName) => {
    if (!transporter) {
        console.warn('Email transporter not configured. Skipping password reset email.');
        return;
    }

    const resetUrl = `${config.frontend.url}/reset-password?token=${token}`;

    const mailOptions = {
        from: `${config.email.from.name} <${config.email.from.email}>`,
        to: email,
        subject: 'Reset Your Password',
        html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background-color: #f8f9fa; padding: 20px; text-align: center;">
          <h1 style="color: #333; margin: 0;">Password Reset Request</h1>
        </div>
        <div style="padding: 30px;">
          <p style="font-size: 16px; line-height: 1.5; color: #333;">
            Hi ${firstName},
          </p>
          <p style="font-size: 16px; line-height: 1.5; color: #333;">
            We received a request to reset your password. Click the button below to create a new password:
          </p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetUrl}" 
               style="background-color: #dc3545; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
              Reset Password
            </a>
          </div>
          <p style="font-size: 14px; color: #666; margin-top: 30px;">
            If the button doesn't work, copy and paste this link into your browser:<br>
            <a href="${resetUrl}" style="color: #dc3545;">${resetUrl}</a>
          </p>
          <p style="font-size: 14px; color: #666; margin-top: 20px;">
            This reset link will expire in 1 hour for security reasons.
          </p>
        </div>
        <div style="background-color: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #666;">
          If you didn't request this password reset, please ignore this email or contact support if you have concerns.
        </div>
      </div>
    `
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`📧 Password reset email sent to ${email}`);
    } catch (error) {
        console.error('Failed to send password reset email:', error);
        throw new Error('Failed to send password reset email');
    }
};

/**
 * Send invitation email
 * @param {string} email - Recipient email
 * @param {string} token - Invitation token
 * @param {string} organizationName - Organization name
 * @param {string} inviterName - Name of person who sent invitation
 * @param {string} role - Role being assigned (optional)
 */
const sendInvitation = async (email, token, organizationName, inviterName, role = null) => {
    if (!transporter) {
        console.warn('Email transporter not configured. Skipping invitation email.');
        return;
    }

    const invitationUrl = `${config.frontend.url}/accept-invitation?token=${token}`;
    const roleText = role ? ` as a ${role}` : '';

    const mailOptions = {
        from: `${config.email.from.name} <${config.email.from.email}>`,
        to: email,
        subject: `Invitation to join ${organizationName}`,
        html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background-color: #f8f9fa; padding: 20px; text-align: center;">
          <h1 style="color: #333; margin: 0;">You're Invited!</h1>
        </div>
        <div style="padding: 30px;">
          <p style="font-size: 16px; line-height: 1.5; color: #333;">
            ${inviterName} has invited you to join <strong>${organizationName}</strong>${roleText}.
          </p>
          <p style="font-size: 16px; line-height: 1.5; color: #333;">
            Click the button below to accept the invitation and create your account:
          </p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${invitationUrl}" 
               style="background-color: #28a745; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
              Accept Invitation
            </a>
          </div>
          <p style="font-size: 14px; color: #666; margin-top: 30px;">
            If the button doesn't work, copy and paste this link into your browser:<br>
            <a href="${invitationUrl}" style="color: #28a745;">${invitationUrl}</a>
          </p>
          <p style="font-size: 14px; color: #666; margin-top: 20px;">
            This invitation will expire in 7 days.
          </p>
        </div>
        <div style="background-color: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #666;">
          If you didn't expect this invitation, please ignore this email.
        </div>
      </div>
    `
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`📧 Invitation email sent to ${email}`);
    } catch (error) {
        console.error('Failed to send invitation email:', error);
        throw new Error('Failed to send invitation email');
    }
};

/**
 * Send welcome email after successful registration
 * @param {string} email - Recipient email
 * @param {string} firstName - User's first name
 * @param {string} organizationName - Organization name
 */
const sendWelcomeEmail = async (email, firstName, organizationName) => {
    if (!transporter) {
        console.warn('Email transporter not configured. Skipping welcome email.');
        return;
    }

    const mailOptions = {
        from: `${config.email.from.name} <${config.email.from.email}>`,
        to: email,
        subject: `Welcome to ${organizationName}!`,
        html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background-color: #f8f9fa; padding: 20px; text-align: center;">
          <h1 style="color: #333; margin: 0;">Welcome ${firstName}!</h1>
        </div>
        <div style="padding: 30px;">
          <p style="font-size: 16px; line-height: 1.5; color: #333;">
            Your account has been successfully created and verified. You're now part of <strong>${organizationName}</strong>!
          </p>
          <p style="font-size: 16px; line-height: 1.5; color: #333;">
            You can now access all the features and collaborate with your team.
          </p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${config.frontend.url}/dashboard" 
               style="background-color: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
              Go to Dashboard
            </a>
          </div>
        </div>
        <div style="background-color: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #666;">
          Need help? Contact our support team anytime.
        </div>
      </div>
    `
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`📧 Welcome email sent to ${email}`);
    } catch (error) {
        console.error('Failed to send welcome email:', error);
        // Don't throw error for welcome email as it's not critical
    }
};

module.exports = {
    sendEmailVerification,
    sendPasswordReset,
    sendInvitation,
    sendWelcomeEmail
};