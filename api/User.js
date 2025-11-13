const express = require('express');
const router = express.Router();

const User = require('./../models/User');
const UserOTPVerification = require('./../models/UserOTPVerification');

const Mailjet = require('node-mailjet');
require('dotenv').config();
const bcrypt = require('bcrypt');

const mailjet = Mailjet.apiConnect(
  process.env.MJ_APIKEY_PUBLIC,
  process.env.MJ_APIKEY_PRIVATE
);

// ------------------------- OTP EMAIL (Mailjet API) -------------------------
const createAndSendOTP = async ({_id, email, purpose = 'EMAIL_VERIFICATION'}, res) => {
    try {
        // random six-digit OTP
        const otp = `${Math.floor(100000 + Math.random() * 900000)}`;
        const saltRounds = 10;
        const hashedOTP = await bcrypt.hash(otp, saltRounds);
        
        await new UserOTPVerification({
            userId: _id,
            otp: hashedOTP,
            createdAt: Date.now(),
            expiresAt: Date.now() + 600000, // 10 minutes
            purpose
        }).save();

        await mailjet
        .post('send', { version: 'v3.1' })
        .request({
            Messages: [{
                From: {
                Email: process.env.MJ_SENDER_EMAIL,
                Name: "Team10's Restaurant",
                },
                To: [{ Email: email }],
                Subject: 'Your OTP Verification Code from Team10\'s Restaurant',
                HTMLPart: `
                    <h3>Your OTP code is:</h3>
                    <h1 style="font-weight: bold;">${otp}</h1>
                    <p>This OTP is valid for 10 minutes.</p>
                `,
            },],
        });
        return res.json({ status: "PENDING", message: "OTP email sent!", data: { userId: _id, email } });
    } catch (error) {
        console.log(error);
        return res.json({ status: "FAILED", message: "An error occurred while sending OTP email!" });
    }
};

router.post('/signup', (req, res) => {
    let { email, username, password, firstName, lastName, phone } = req.body;
    if(!email || !username || !password || !firstName || !lastName || !phone){
        return res.json({status: "FAILED", message: "Empty input fields!"});
    }
    email = email.trim();
    username = username.trim();
    password = password.trim();
    firstName = firstName.trim();
    lastName = lastName.trim();
    phone = phone.trim();
    if(!/^\+?\d{8,15}$/.test(phone)){
        return res.json({status: "FAILED", message: "Invalid phone number!"});
    }
    else if(!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)){
        return res.json({status: "FAILED", message: "Invalid email format!"});
    }
    else if(password.length < 8){
        return res.json({status: "FAILED", message: "Password must be at least 8 characters long!"});
    }
    else{
        // check if existing user
        User.find({username}).then(result => {
            if(result.length){
                // user already exists
                return res.json({status: "FAILED", message: "User already exists!"});
            }
                User.find({email}).then(result => {
                if(result.length){
                    // user already exists
                    return res.json({status: "FAILED", message: "Email already registered!"});
                }
                else{
                    // create new user
                    // password handling
                    const saltRounds = 10;
                    bcrypt.hash(password, saltRounds).then(hashedPassword => {
                        const newUser = new User({
                            email,
                            username,
                            password: hashedPassword,
                            firstName,
                            lastName,
                            phone,
                            isEmailVerified: false
                        });
                        newUser.save().then(result => {
                            createAndSendOTP(result, res);
                        }).catch(err => {
                            console.log(err);
                            return res.json({status: "FAILED", message: "An error occurred while saving user account!"});
                        });
                    }).catch(err => {
                        console.log(err);
                        return res.json({status: "FAILED", message: "An error occurred while hashing password!"});
                    });
                }
            }).catch(err => {
                console.log(err);
                return res.json({status: "FAILED", message: "An error occurred while checking for existing email!"});
            });
        }).catch(err => {
            console.log(err);
            return res.json({status: "FAILED", message: "An error occurred while checking for existing user!"});
        })
    }
});

router.post('/signin', (req, res) => {
    try {
        let { username, password } = req.body;
        username = username ? username.trim() : "";
        password = password ? password.trim() : "";
        if(username == "" || password == ""){
            return res.json({status: "FAILED", message: "Empty credentials supplied!"});
        }
        else{
            // check for existing user
            User.find({username}).then(data => {
                if(data.length){
                    // user exists, check password
                    if(data[0].isEmailVerified === false){
                        return res.json({status: "FAILED", message: "Email not verified!"});
                    }
                    bcrypt.compare(password, data[0].password).then(isMatch => {
                        if(isMatch){
                            // login OK now send 2FA OTP
                            return createAndSendOTP({ _id: data[0]._id, email: data[0].email, purpose: 'TWO_FACTOR_AUTH'}, res);
                        }
                        else{
                            return res.json({status: "FAILED", message: "Invalid credentials!"});
                        }
                    }).catch(err => {
                        console.log(err);
                        return res.json({status: "FAILED", message: "An error occurred while checking password!"});
                    });
                }
                else{
                    return res.json({status: "FAILED", message: "User not found!"});
                }
            }).catch(err => {
                console.log(err);
                return res.json({status: "FAILED", message: "An error occurred while checking for existing user!"});
            });
        }
    } catch (error) {
        console.log(error);
        return res.json({status: "FAILED", message: "An error occurred while checking for existing user!"});
    }
});

router.post('/verify2FAOTP', async (req, res) => {
    try {
        let { userId, otp } = req.body;
        if (!userId || !otp) {
            return res.json({ status: "FAILED", message: "Empty OTP details are not allowed!" });
        }
        else {
            const UserOTPVerificationRecords = await UserOTPVerification.find({ userId, purpose: 'TWO_FACTOR_AUTH' });
            if (UserOTPVerificationRecords.length > 0) {
                const { expiresAt } = UserOTPVerificationRecords[0];
                const hashedOTP = UserOTPVerificationRecords[0].otp;
                if (expiresAt < Date.now()) {
                    await UserOTPVerification.deleteMany({ userId , purpose: 'TWO_FACTOR_AUTH'});
                    return res.json({ status: "FAILED", message: "OTP has expired. Please request a new one." });
                }
                else {
                    bcrypt.compare(otp, hashedOTP).then(async isMatch => {
                        if (isMatch) {
                            await UserOTPVerification.deleteMany({ userId, purpose: 'TWO_FACTOR_AUTH' });
                            const user = await User.findById(userId).select('-password');
                            if (!user) {
                                return res.json({ status: "FAILED", message: "User not found!" });
                            }
                            return res.json({ status: "SUCCESS", message: "OTP verified successfully!", data: user });
                        }
                        else {
                            return res.json({ status: "FAILED", message: "Invalid OTP. Please check your inbox and try again." });
                        }
                    });
                }
            }
            else {
                return res.json({ status: "FAILED", message: "No 2FA request found. Please sign in again" });
            }
        }
    } catch (error) {
        console.log(error);
        return res.json({ status: "FAILED", message: "An error occurred while verifying OTP!" });
    }
});

router.post("/verifyOTP", async (req, res) => {
    try {
        let { userId, otp } = req.body;
        if (!userId || !otp) {
            return res.json({ status: "FAILED", message: "Empty OTP details are not allowed!" });
        }
        else {
            const UserOTPVerificationRecords = await UserOTPVerification.find({ userId, purpose: 'EMAIL_VERIFICATION' });
            if (UserOTPVerificationRecords.length > 0) {
                const { expiresAt } = UserOTPVerificationRecords[0];
                const hashedOTP = UserOTPVerificationRecords[0].otp;
                if (expiresAt < Date.now()) {
                    await UserOTPVerification.deleteMany({ userId , purpose: 'EMAIL_VERIFICATION'});
                    return res.json({ status: "FAILED", message: "OTP has expired. Please request a new one." });
                }
                else {
                    bcrypt.compare(otp, hashedOTP).then(async isMatch => {
                        if (isMatch) {
                            await User.updateOne({ _id: userId }, { isEmailVerified: true });
                            await UserOTPVerification.deleteMany({ userId, purpose: 'EMAIL_VERIFICATION' });
                            return res.json({ status: "SUCCESS", message: "OTP verified successfully!" });
                        }
                        else {
                            return res.json({ status: "FAILED", message: "Invalid OTP. Please check your inbox and try again." });
                        }
                    });
                }
            }
            else {
                return res.json({ status: "FAILED", message: "Account record doesn't exist or has been verified already. Please sign up or log in." });
            }
        }
    } catch (error) {
        console.log(error);
        return res.json({ status: "FAILED", message: "An error occurred while verifying OTP!" });
    }
});

router.post('/resendOTP', async (req, res) => {
    try {
        let { userId, email, purpose = 'EMAIL_VERIFICATION' } = req.body;

        if (!userId || !email) {
            return res.json({ status: "FAILED", message: "Empty user details are not allowed!" });
        }
        else {
            await UserOTPVerification.deleteMany({ userId, purpose });
            createAndSendOTP({ _id: userId, email, purpose}, res);
        }
    } catch (error) {
        console.log(error);
        return res.json({ status: "FAILED", message: "An error occurred while resending OTP!" });
    }
});

router.post('/requestPasswordReset', (req, res) => {
    try{
        const { email } = req.body;
        if(!email){
            return res.json({ status: "FAILED", message: "Empty email supplied!" });
        }
        else{
            User.find({ email }).then(data => {
                if(data.length){
                    // User exists, proceed with password reset
                    createAndSendOTP({ _id: data[0]._id, email, purpose: 'PASSWORD_RESET'}, res );
                } else {
                    return res.json({ status: "FAILED", message: "User not found!" });
                }
            }).catch(err => {
                console.log(err);
                return res.json({ status: "FAILED", message: "An error occurred while checking user existence!" });
            });
        }
    } catch (error) {
        console.log(error);
        return res.json({ status: "FAILED", message: "An error occurred while checking user existence!" });
    }
});

const jsonwebtoken = require('jsonwebtoken');

router.post('/verifyPasswordResetOTP', async (req, res) => {
    try {
        let { userId, otp } = req.body;
        if (!userId || !otp) {
            return res.json({ status: "FAILED", message: "Empty OTP details are not allowed!" });
        }
        else {
            const UserOTPVerificationRecords = await UserOTPVerification.find({ userId, purpose: 'PASSWORD_RESET' });
            if (UserOTPVerificationRecords.length > 0) {
                const { expiresAt } = UserOTPVerificationRecords[0];
                const hashedOTP = UserOTPVerificationRecords[0].otp;
                if (expiresAt < Date.now()) {
                    await UserOTPVerification.deleteMany({ userId, purpose: 'PASSWORD_RESET' });
                    return res.json({ status: "FAILED", message: "OTP has expired. Please request a new one." });
                }
                else {
                    bcrypt.compare(otp, hashedOTP).then(async isMatch => {
                        if (isMatch) {
                            const resetToken = jsonwebtoken.sign(
                                { userId },
                                process.env.JWT_SECRET,
                                { expiresIn: '10m' }
                            );
                            await UserOTPVerification.deleteMany({ userId, purpose: 'PASSWORD_RESET' });
                            return res.json({ status: "SUCCESS", message: "OTP verified successfully! You can now reset your password.", data: { password_reset_token: resetToken } });
                        } else {
                            return res.json({ status: "FAILED", message: "Invalid OTP provided!" });
                        }
                    });
                }
            }
            else {
                return res.json({ status: "FAILED", message: "No reset request found or it has already been used. Please request a new password reset." });
            }
        }
    } catch (error) {
        console.log(error);
        return res.json({ status: "FAILED", message: "An error occurred while verifying OTP!" });
    }
});

router.post('/resetPassword', (req, res) => {
    try {
        let { password_reset_token, newPassword } = req.body;

        if (!password_reset_token || !newPassword) {
            return res.json({ status: "FAILED", message: "Empty password details are not allowed!" });
        }
        newPassword = newPassword.trim();
        if (newPassword.length < 8) {
            return res.json({ status: "FAILED", message: "Password must be at least 8 characters long!" });
        }
        const payload = jsonwebtoken.verify(password_reset_token, process.env.JWT_SECRET);
        const userId = payload.userId;
        const saltRounds = 10;
        bcrypt.hash(newPassword, saltRounds).then(hashedPassword => {
            User.updateOne({ _id: userId }, { password: hashedPassword }).then(() => {
                return res.json({ status: "SUCCESS", message: "Password has been reset successfully!" });
            }).catch(err => {
                console.log(err);
                return res.json({ status: "FAILED", message: "An error occurred while resetting the password!" });
            });
        }).catch(err => {
            console.log(err);
            return res.json({ status: "FAILED", message: "An error occurred while hashing the new password!" });
        });
    } catch (error) {
        console.log(error);
        return res.json({ status: "FAILED", message: "An error occurred while resetting the password!" });
    }
});

module.exports = router;