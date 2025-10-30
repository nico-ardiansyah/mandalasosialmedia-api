const nodemailer = require('nodemailer');
require('dotenv').config();


const ms = (email, verifycode, subject) => ({
    to: email,
    from: process.env.SENDGRID_FROM,
    subject,
    text: `
    Your Code ${verifycode}
    Code expired in 10 minute
    `
});


module.exports = ms;