const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host: process.env.MAIL_HOST || 'localhost',
  port: parseInt(process.env.MAIL_PORT || '1025', 10),
  secure: false,
  ignoreTLS: true,
  auth: false // Mailhog doesn't need auth
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
  
  try {
    const info = await transporter.sendMail(mailOptions);
    console.log('Email sent to Mailhog:', info.messageId);
    return info;
  } catch (error) {
    console.error('Mail sending error:', error);
    throw error;
  }
}

// Phishing demonstration function
async function sendPhishingDemo(targetEmail, username) {
  const phishingHtml = `
    <h2>🍔 WeEat Security Alert!</h2>
    <p>Dear ${username},</p>
    <p>We detected suspicious activity on your account. Please verify your identity immediately.</p>
    <div style="padding: 20px; background: #f0f0f0; border-radius: 5px;">
      <a href="http://localhost:3000/auth/login?phishing=true&user=${username}" 
         style="background: #d62828; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
         Verify Account Now
      </a>
    </div>
    <p><small>This is a phishing demonstration for security training purposes.</small></p>
  `;

  return sendMail({
    to: targetEmail,
    subject: '⚠️ Urgent: Security Alert on Your WeEat Account',
    html: phishingHtml,
    text: 'Security alert - please verify your account'
  });
}

module.exports = { sendMail, sendPhishingDemo };
