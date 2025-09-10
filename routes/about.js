const express = require('express');
const router = express.Router();

// About page route
router.get('/', (req, res) => {
  res.render('about', { 
    title: 'About Us - WeEat',
    user: req.session.user || null
  });
});

module.exports = router;
