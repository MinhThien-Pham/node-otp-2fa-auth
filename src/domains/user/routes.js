// src/domains/user/routes.js
const express = require('express');
const router = express.Router();

const { createNewUser, authenticateUser } = require('./controller');
const { sendOTPVerificationEmail } = require('../emailVerification/controller');

router.post('/signup', async (req, res) => {
    try {
        const newUser = await createNewUser(req.body);
        const emailData = await sendOTPVerificationEmail({_id: newUser._id, email: newUser.email, purpose: 'EMAIL_VERIFICATION'});
        return res.json({status: "PENDING", message: "User created successfully! OTP email sent!", data: emailData});
    } catch (error) {
        return res.json({status: "FAILED", message: error.message});
    }
});

router.post('/signin', async (req, res) => {
    try {
        const user = await authenticateUser(req.body);
        const emailData = await sendOTPVerificationEmail({_id: user._id, email: user.email, purpose: 'TWO_FACTOR_AUTH'});
        return res.json({status: "PENDING", message: "User authenticated! OTP email sent!", data: emailData});
    } catch (error) {
        return res.json({status: "FAILED", message: error.message});
    }
});

module.exports = router;