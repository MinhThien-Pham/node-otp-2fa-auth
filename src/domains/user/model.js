// src/domains/user/model.js
const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    email:{
        type: String,
        required: true,
        unique: true
    },
    username:{
        type:String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    firstName: {
        type: String,
        required: true
    },
    lastName: {
        type: String,
        required: true
    },
    phone: {
        type: String,
        required: true
    },
    points: {
        type: Number,
        required: false,
        default: 0
    },
    cart:{
        type: Array,
        required: false,
        default: []
    },
    isEmailVerified: {
        type: Boolean,
        required: false,
        default: false
    }
});

const User = mongoose.model('User', UserSchema);
module.exports = User;