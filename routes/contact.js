const express = require('express');
const router = express.Router();
const { User } = require('../models');

// Contact form
router.get('/', (req, res) => {
  res.render('contact', { title: 'Contact Us', success: false });
});

router.post('/', async (req, res) => {
  const { name, email, message } = req.body;
  if (!name || !email || !message) return res.render('contact', { title: 'Contact Us', success: false });
  // Here we could save message to DB if needed, but simple success page
  res.render('contact-success', { title: 'Contact Sent', name });
});

module.exports = router;
