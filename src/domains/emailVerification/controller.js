// src/domains/emailVerification/controller.js
const jsonwebtoken = require('jsonwebtoken');

const UserOTPVerification = require('./model');
const User = require('../user/model');

const generateOTP = require('../../utilities/generateOTP');
const { hashData, verifyHashedData } = require('../../utilities/hashData');
const sendEmail = require('../../utilities/sendEmail');

const sendOTPVerificationEmail = async ({_id, email, purpose = 'EMAIL_VERIFICATION'}) => {
    try {
        const otp = await generateOTP();
        const hashedOTP = await hashData(otp);
        const ttlMs = 10 * 60 * 1000; // 10 minutes
        const newUserOTPVerification = await new UserOTPVerification({
            userId: _id,
            otp: hashedOTP,
            createdAt: Date.now(),
            expiresAt: Date.now() + ttlMs,
            purpose
        });
        await newUserOTPVerification.save();    // save OTP record
        
        let subject = 'Verify Your Email Address';
        let title = "Welcome to Team10's Restaurant!";
        let intro = 'Your OTP for email verification is:';
        let actionLine = 'Use this code to verify your email address.';

        if (purpose === 'TWO_FACTOR_AUTH') {
        subject = 'Your 2FA Code';
        title = 'Sign-in Verification';
        intro = 'Your 2FA code is:';
        actionLine = 'Use this code to complete your sign-in.';
        } else if (purpose === 'PASSWORD_RESET') {
        subject = 'Reset Your Password';
        title = 'Password Reset Request';
        intro = 'Your reset OTP is:';
        actionLine = 'Use this code to reset your password.';
        }

        const mailOptions = {
            to: email,
            subject,
            html: `<h2>${title}</h2>
            <h3>${intro} ${otp}</h3>
            <p>${actionLine}</p>
            <p>This OTP is valid for ${ttlMs / 60000} minutes.</p>`
        };
        await sendEmail(mailOptions);
        return { userId: _id, email, purpose };
    } catch (error) {
        throw new Error("Error sending OTP email verification!");
    }
};

const verifyEmailOTP = async ({ userId, otp}) => {
    try {
        if (!userId || !otp) {
            throw new Error("Empty OTP details are not allowed!");
        }
        const UserOTPVerificationRecords = await UserOTPVerification.find({ userId, purpose: 'EMAIL_VERIFICATION'  });
        if (!UserOTPVerificationRecords.length) {
            throw new Error("Account record doesn't exist or has been verified already. Please request again.");
        }
        const { expiresAt } = UserOTPVerificationRecords[0];
        const hashedOTP = UserOTPVerificationRecords[0].otp;        
        if (expiresAt < Date.now()) {
            await UserOTPVerification.deleteMany({ userId, purpose: 'EMAIL_VERIFICATION' });
            throw new Error("OTP has expired. Please request a new one.");
        }
        const isMatch = await verifyHashedData(otp, hashedOTP);
        if (!isMatch){
            throw new Error("Invalid OTP. Please check your inbox and try again.");
        }
        await User.updateOne({ _id: userId }, { isEmailVerified: true });
        await UserOTPVerification.deleteMany({ userId, purpose: 'EMAIL_VERIFICATION' });
        return { message: "OTP verified successfully!" };
    } catch (error) {
        throw new Error(error.message);
    }
};

const verify2FAOTP = async ({ userId, otp}) => {
    try {
        if (!userId || !otp) {
            throw new Error("Empty OTP details are not allowed!");
        }
        const UserOTPVerificationRecords = await UserOTPVerification.find({ userId, purpose: 'TWO_FACTOR_AUTH'  });
        if (!UserOTPVerificationRecords.length) {
            throw new Error("Account record doesn't exist or has been verified already. Please request again.");
        }
        const { expiresAt } = UserOTPVerificationRecords[0];
        const hashedOTP = UserOTPVerificationRecords[0].otp;
        if (expiresAt < Date.now()) {
            await UserOTPVerification.deleteMany({ userId, purpose: 'TWO_FACTOR_AUTH' });
            throw new Error("OTP has expired. Please request a new one.");
        }

        const isMatch = await verifyHashedData(otp, hashedOTP);
        if (!isMatch){
            throw new Error("Invalid OTP. Please check your inbox and try again.");
        }
        await UserOTPVerification.deleteMany({ userId, purpose: 'TWO_FACTOR_AUTH' });
        const user = await User.findById(userId).select('-password');
        if (!user) {
            throw new Error("User not found!");
        }
        return { message: "OTP verified successfully!", data: user };
    } catch (error) {
        throw new Error(error.message);
    }
};

const requestPasswordResetOTP = async ({ email }) => {
    try {
        if (!email) {
            throw new Error("Email is required!");
        }
        const user = await User.findOne({ email });
        if (!user) {
            throw new Error("User with given email doesn't exist!");
        }
        await sendOTPVerificationEmail({ _id: user._id, email: user.email, purpose: 'PASSWORD_RESET' });
        return { userId: user._id, email: user.email, purpose: 'PASSWORD_RESET' };   
    } catch (error) {
        throw new Error(error.message);
    }
};

const verifyPasswordResetOTP = async ({ userId, otp}) => {
    try {
        if (!userId || !otp) {
            throw new Error("Empty OTP details are not allowed!");
        }
        const UserOTPVerificationRecords = await UserOTPVerification.find({ userId, purpose: 'PASSWORD_RESET'  });
        if (!UserOTPVerificationRecords.length) {
            throw new Error("Account record doesn't exist or no reset request found or it has already been used. Please request a new password reset.");
        }
        const { expiresAt } = UserOTPVerificationRecords[0];
        const hashedOTP = UserOTPVerificationRecords[0].otp;
        if (expiresAt < Date.now()) {
            await UserOTPVerification.deleteMany({ userId, purpose: 'PASSWORD_RESET' });
            throw new Error("OTP has expired. Please request a new one.");
        }
        const isMatch = await verifyHashedData(otp, hashedOTP);
        if (!isMatch){
            throw new Error("Invalid OTP. Please check your inbox and try again.");
        }
        const resetToken = jsonwebtoken.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '10m' });
        await UserOTPVerification.deleteMany({ userId, purpose: 'PASSWORD_RESET' });
        return { message: "OTP verified successfully!", password_reset_token: resetToken };
    } catch (error) {
        throw new Error(error.message);
    }
};

const resetPassword = async ({ password_reset_token, newPassword }) => {
    try {
        if (!password_reset_token || !newPassword) {
            throw new Error("Empty password details are not allowed!");
        }
        newPassword = newPassword.trim();
        if (newPassword.length < 8) {
            throw new Error("Password must be at least 8 characters long!");
        }
        let payload;
        try {
            payload = jsonwebtoken.verify(password_reset_token, process.env.JWT_SECRET);
        } catch (error) {
            throw new Error("Invalid or expired password reset token!");
        }
        const userId = payload.userId;
        const hashNewPassword = await hashData(newPassword);
        await User.updateOne({ _id: userId }, { password: hashNewPassword });
        return { message: "Password reset successfully!" };
    } catch (error) {
        throw new Error(error.message);
    }
};

module.exports = { sendOTPVerificationEmail, verifyEmailOTP, verify2FAOTP, requestPasswordResetOTP, verifyPasswordResetOTP, resetPassword };