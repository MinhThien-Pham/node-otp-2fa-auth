// src/utilities/generateOTP.js
const generateOTP = async () => {
    try {
        // random six-digit OTP
        const otp = `${Math.floor(100000 + Math.random() * 900000)}`;
        return otp;
    } catch (error) {
        throw new Error('Error generating OTP: ' + error.message);
    }
};

module.exports = generateOTP;