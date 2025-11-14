# Secure Auth API

This is a small Node.js / Express authentication backend that implements:

- User signup with **email OTP verification**
- Signin with **mandatory email-based 2FA**
- **Password reset** with OTP + short-lived JWT
- MongoDB (Mongoose) for persistence
- Mailjet for transactional emails

It’s designed as a backend-only project and has been tested with Postman.

---

## Features

### User Signup + Email Verification

- `POST /user/signup`
  - Validates email, username, password, phone, and names
  - Creates a new user with `isEmailVerified = false`
  - Sends an **email OTP** (`EMAIL_VERIFICATION`) using Mailjet

- `POST /emailVerification/verify-email-otp`
  - Confirms the OTP
  - Sets `isEmailVerified = true` on the user
  - Deletes the OTP record from MongoDB

---

### Signin + Email-based 2FA

- `POST /user/signin`
  - Checks username + password
  - Requires `isEmailVerified === true`
  - On success, sends a **2FA OTP** (`TWO_FACTOR_AUTH`) to the user’s email

- `POST /emailVerification/verify-2fa-otp`
  - Verifies the 2FA OTP
  - Deletes the used OTP
  - Returns the user object (without password) as “logged in” data

---

### Password Reset Flow (OTP + JWT)

- `POST /emailVerification/request-password-reset-otp`
  - Accepts an email
  - If the user exists, sends a **password reset OTP** (`PASSWORD_RESET`)

- `POST /emailVerification/verify-password-reset-otp`
  - Verifies the reset OTP
  - Deletes the used OTP
  - Returns a **short-lived JWT** (`password_reset_token`) to authorize password change

- `POST /emailVerification/reset-password`
  - Accepts `password_reset_token` + `newPassword`
  - Verifies the JWT using `JWT_SECRET`
  - Hashes the new password and updates the user record

---

### OTP Storage & Purposes

All OTPs are:

- Random 6-digit codes
- **Hashed with bcrypt** before saving to MongoDB
- Stored in a `UserOTPVerification` collection with a `purpose` field:
  - `EMAIL_VERIFICATION`
  - `TWO_FACTOR_AUTH`
  - `PASSWORD_RESET`
- Given a **10-minute TTL** (expiry time)

---

## Tech Stack

- **Node.js**, **Express**
- **MongoDB**, **Mongoose**
- **JSON Web Tokens** (`jsonwebtoken`) for password reset token
- **Mailjet** (`node-mailjet`) for sending OTP emails
- **bcrypt** for hashing passwords and OTPs
- **dotenv** for environment variables
- **nodemon** for development

---

## Project Structure

```text
src/
  config/
    db.js                 # MongoDB connection
  domains/
    user/
      model.js            # User schema
      controller.js       # Signup / signin logic
      routes.js           # /user routes
      index.js
    emailVerification/
      model.js            # OTP schema (with purpose)
      controller.js       # OTP, 2FA, password reset logic
      routes.js           # /emailVerification routes
      index.js
  utilities/
    generateOTP.js        # Random 6-digit OTP generator
    hashData.js           # bcrypt hash/verify helpers
    sendEmail.js          # Mailjet email sender
  routes/
    index.js              # Mounts /user and /emailVerification
  server.js               # Express app, middleware
  index.js                # Server entrypoint (listen)
