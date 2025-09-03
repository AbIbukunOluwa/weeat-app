const express = require('express');
const { ContactMessage } = require('../models/ContactMessage');
const { sendMail } = require('../utils/mailer');
const router = express.Router();

// GET
router.get('/', (req, res) => {
  res.render('contact', { title: 'Contact Us' });
});

// POST
router.post('/', async (req, res) => {
  const { name, email, message } = req.body;
  try {
    await ContactMessage.create({ name, email, message });

    // Send email to support
    await sendMail({
      to: process.env.SUPPORT_EMAIL,
      subject: `New Contact Message from ${name}`,
      text: message,
      html: `<p>${message}</p><p>From: ${name} (${email})</p>`
    });

    res.render('contact', { title: 'Contact Us', success: true });
  } catch (err) {
    console.error('Failed to save/send contact message:', err);
    res.render('contact', { title: 'Contact Us', success: false });
  }
});


module.exports = router;
