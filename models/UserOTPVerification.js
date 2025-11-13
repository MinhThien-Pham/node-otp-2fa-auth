const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const UserOTPVerificationSchema = new Schema({
    userId:{
        type: mongoose.Schema.Types.ObjectId,
        required: true,
    },
    otp:{
        type: String,
        required: true
    }, 
    createdAt:{
        type: Date,
        required: true
    },
    expiresAt:{
        type: Date,
        required: true
    },
    purpose: {
        type: String,
        enum: ['EMAIL_VERIFICATION', 'PASSWORD_RESET', 'TWO_FACTOR_AUTH'],
        default: 'EMAIL_VERIFICATION',
        required: true
    }
});

const UserOTPVerification = mongoose.model('UserOTPVerification', UserOTPVerificationSchema);

module.exports = UserOTPVerification;