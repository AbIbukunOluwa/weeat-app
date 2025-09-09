const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host: process.env.MAIL_HOST,
  port: parseInt(process.env.MAIL_PORT || '1025', 10),
  secure: false,
  auth: process.env.MAIL_USER ? {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS
  } : undefined
});

async function sendMail({ to, subject, text, html, attachments }) {
  const mailOptions = {
    from: process.env.MAIL_FROM || 'no-reply@weeat.local',
    to,
    subject,
    text,
    html,
    attachments
  };
  await transporter.sendMail(mailOptions);
}

module.exports = { sendMail };
