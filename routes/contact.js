const express = require('express');
const router = express.Router();
const { sendMail } = require('../utils/mailer');

// GET route - Display the contact form
router.get('/', (req, res) => {
  res.render('contact', { 
    title: 'Contact Us - WeEat', 
    user: req.session.user || null,
    success: false 
  });
});

// POST route - Handle form submission
router.post('/', async (req, res) => {
  const { name, email, message, subject } = req.body;
  
  if (!name || !email || !message) {
    return res.render('contact', { 
      title: 'Contact Us - WeEat',
      user: req.session.user || null,
      success: false,
      error: 'Please fill in all required fields.'
    });
  }
  
  try {
    // Send to Mailhog
    await sendMail({
      to: 'support@weeat.local',
      subject: `Contact Form: ${subject || 'General Inquiry'}`,
      html: `
        <h3>New Contact Form Submission</h3>
        <p><strong>From:</strong> ${name} (${email})</p>
        <p><strong>Subject:</strong> ${subject || 'General Inquiry'}</p>
        <p><strong>Message:</strong></p>
        <blockquote>${message}</blockquote>
        <hr>
        <p><small>Submitted at ${new Date().toISOString()}</small></p>
      `,
      text: `From: ${name} (${email})\nSubject: ${subject}\n\nMessage:\n${message}`
    });

    // Auto-reply to user
    await sendMail({
      to: email,
      subject: 'We received your message - WeEat Support',
      html: `
        <h3>Thank you for contacting WeEat!</h3>
        <p>Dear ${name},</p>
        <p>We've received your message and will respond within 24 hours.</p>
        <p>Best regards,<br>WeEat Support Team</p>
      `
    });

    res.render('contact', { 
      title: 'Contact Us - WeEat',
      user: req.session.user || null,
      success: true,
      name: name
    });
    
  } catch (err) {
    console.error('Mail error:', err);
    res.render('contact', {
      title: 'Contact Us - WeEat',
      user: req.session.user || null,
      success: false,
      error: 'Failed to send message. Please try again.'
    });
  }
});

module.exports = router;
