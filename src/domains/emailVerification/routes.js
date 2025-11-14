// src/domains/emailVerification/routes.js
const express = require('express');
const router = express.Router();

const { verifyEmailOTP, verify2FAOTP, requestPasswordResetOTP, verifyPasswordResetOTP, resetPassword } = require('./controller');

router.post('/verify-email-otp', async (req, res) => {
    try {
        const { userId, otp } = req.body;
        const result = await verifyEmailOTP({ userId, otp });
        return res.json({ status: "SUCCESS", message: result.message });
    } catch (error) {
        return res.json({ status: "FAILED", message: error.message || 'An error occurred while verifying OTP!' });
    }
});

router.post('/verify-2fa-otp', async (req, res) => {
    try {
        const { userId, otp } = req.body;
        const result = await verify2FAOTP({ userId, otp });
        return res.json({ status: "SUCCESS", message: result.message, data: result.data });
    } catch (error) {
        return res.json({ status: "FAILED", message: error.message || 'An error occurred while verifying OTP!' });
    }
});

router.post('/request-password-reset-otp', async (req, res) => {
    try {
        const { email } = req.body;
        const data = await requestPasswordResetOTP({ email });
        return res.json({ status: "PENDING", message: "Password reset OTP email sent!", data: {userId: data.userId, email: data.email, purpose: data.purpose} });
    } catch (error) {
        return res.json({ status: "FAILED", message: error.message || 'An error occurred while requesting password reset OTP!' });
    }
});

router.post('/verify-password-reset-otp', async (req, res) => {
    try {
        const { userId, otp } = req.body;
        const result = await verifyPasswordResetOTP({ userId, otp });
        return res.json({ status: "SUCCESS", message: result.message, data: {password_reset_token: result.password_reset_token}});
    } catch (error) {
        return res.json({ status: "FAILED", message: error.message || 'An error occurred while verifying password reset OTP!' });
    }   
});

router.post('/reset-password', async (req, res) => {
    try {
        const { password_reset_token, newPassword } = req.body;
        const result = await resetPassword({ password_reset_token, newPassword });
        return res.json({ status: "SUCCESS", message: result.message });
    }
    catch (error) {
        return res.json({ status: "FAILED", message: error.message || 'An error occurred while resetting password!' });
    }
});

module.exports = router;