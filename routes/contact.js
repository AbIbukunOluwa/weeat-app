const express = require('express');
const router = express.Router();

// GET /contact → show the contact form
router.get('/', (req, res) => {
  res.render('contact', { title: 'Contact Us' });
});

// POST /contact → handle form submission
router.post('/', (req, res) => {
  const { name, email, message } = req.body;

  // For now just log it. Later we’ll save to DB or send email.
  console.log('Contact form submitted:', { name, email, message });

  res.render('contact-success', { title: 'Thank You', name });
});

module.exports = router;
