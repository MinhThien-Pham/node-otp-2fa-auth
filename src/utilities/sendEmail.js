// src/utilities/sendEmail.js
const Mailjet = require('node-mailjet');

const mailjet = Mailjet.apiConnect(
  process.env.MJ_APIKEY_PUBLIC,
  process.env.MJ_APIKEY_PRIVATE
);

const sendEmail = async (mailOptions) => {
    try {
        const { to, subject, html } = mailOptions;
        const response = await mailjet
        .post('send', { version: 'v3.1' })
        .request({
            Messages: [{
                From: {
                Email: process.env.MJ_SENDER_EMAIL,
                Name: "Team10's Restaurant",
                },
                To: [{ Email: to }],
                Subject: subject,
                HTMLPart: html
            }],
        });
        return response;
    } catch (error) {
        console.log(error);
        throw new Error('Error sending email: ' + error.message);
    }
};

module.exports = sendEmail;