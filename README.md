# Secure Auth API

Node.js / Express authentication backend with MongoDB, email OTP verification, mandatory 2FA on login, and password reset using JWT.

## Features

- User signup with:
  - Email, username, strong password, phone validation
  - Email OTP verification (`/signup` + `/verifyOTP`)
- User login with:
  - Username + password
  - Mandatory 2FA via OTP email (`/signin` + `/verify2FAOTP`)
- Password reset:
  - Request reset OTP (`/requestPasswordReset`)
  - Verify reset OTP → short-lived JWT token (`/verifyPasswordResetOTP`)
  - Set new password with token (`/resetPassword`)
- All OTPs stored in MongoDB with purpose-based separation:
  - `EMAIL_VERIFICATION`
  - `TWO_FACTOR_AUTH`
  - `PASSWORD_RESET`

## Tech Stack

- Node.js, Express
- MongoDB, Mongoose
- JSON Web Tokens (`jsonwebtoken`)
- Mailjet (`node-mailjet`) for sending OTP emails
- bcrypt for password and OTP hashing

## Setup

```bash
npm install
npm run dev
