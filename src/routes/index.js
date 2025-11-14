// src/routes/index.js
const express = require('express');
const router = express.Router();

const userRoutes = require('../domains/user');                 // must export a router
const emailVerificationRoutes = require('../domains/emailVerification'); // must export a router

// /user/signup, /user/signin, etc.
router.use('/user', userRoutes);

// /emailVerification/verify-email-otp, etc.
router.use('/emailVerification', emailVerificationRoutes);

module.exports = router;