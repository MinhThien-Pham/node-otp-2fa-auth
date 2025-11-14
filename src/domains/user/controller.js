// src/domains/user/controller.js
const User = require('./model');
const { hashData, verifyHashedData } = require('../../utilities/hashData');

// Signup
const createNewUser = async (userData) => {
    try {
        let { email, username, password, firstName, lastName, phone } = userData;

        email = (email || '').trim();
        username = (username || '').trim();
        password = (password || '').trim();
        firstName = (firstName || '').trim();
        lastName = (lastName || '').trim();
        phone = (phone || '').trim();

        if(email == "" || username == "" || password == "" || firstName == "" || lastName == "" || phone == ""){
            throw new Error("Empty input fields!");
        } else if(!/^\+?\d{10}$/.test(phone)){
            throw new Error("Invalid phone number format!");
        } else if(!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)){
            throw new Error("Invalid email format!");
        } else if(password.length < 8){
            throw new Error("Password must be at least 8 characters long!");
        }
        
        const existingUser = await User.findOne({ username });
        if(existingUser){
            throw new Error("User already exists!");
        }

        const existingEmail = await User.findOne({ email });
        if(existingEmail){
            throw new Error("Email already registered!");
        }
        const hashedPassword = await hashData(password);
        const newUser = new User({
                email,
                username,
                password: hashedPassword,
                firstName,
                lastName,
                phone,
                isEmailVerified: false
        });

        const createdUser = await newUser.save();
        return createdUser;
    } catch (error) {
        throw error;
    }
}

const authenticateUser = async ({ username, password }) => {
    try {
        username = (username || '').trim();
        password = (password || '').trim();
        if(username == "" || password == ""){
            throw new Error("Empty input fields!");
        }
        const user = await User.findOne({username});
        if(!user){
            throw new Error("User not found!");
        }
        if(!user.isEmailVerified){
            throw new Error("Email not verified!");
        }

        const isMatch = await verifyHashedData(password, user.password);
        if(!isMatch){
            throw new Error("Invalid credentials!");
        }
        return user;
    } catch (error) {
        throw error;
    }
}

module.exports = { createNewUser, authenticateUser };