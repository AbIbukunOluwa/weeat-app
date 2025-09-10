const express = require('express');
const router = express.Router();

// Contact form
router.get('/', (req, res) => {
  res.render('contact', { 
    title: 'Contact Us - WeEat', 
    user: req.session.user || null,
    success: false 
  });
});

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
  
  // Here you could save message to DB or send email
  // For now, just show success
  
  res.render('contact', { 
    title: 'Contact Us - WeEat',
    user: req.session.user || null,
    success: true,
    name: name
  });
});

module.exports = router;
