const express = require('express');
const router = express.Router();

const User = require('./../models/User');

const bcrypt = require('bcrypt');

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
    else if(!/^\d{10}$/.test(phone)){
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
        }).catch(err => {
            console.log(err);
            return res.json({status: "FAILED", message: "An error occurred while checking for existing user!"});
        })
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
                        phone
                    });
                    newUser.save().then(result => {
                        return res.json({status: "SUCCESS", message: "Signup successful!", data: result});
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
    }
});

router.post('/signin', (req, res) => {
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
                bcrypt.compare(password, data[0].password).then(isMatch => {
                    if(isMatch){
                        return res.json({status: "SUCCESS", message: "Signin successful!", data: data[0]});
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
});

module.exports = router;
