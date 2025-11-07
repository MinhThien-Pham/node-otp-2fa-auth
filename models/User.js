const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const UserSchema = new Schema({
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
    }
});

const User = mongoose.model('User', UserSchema);
module.exports = User;