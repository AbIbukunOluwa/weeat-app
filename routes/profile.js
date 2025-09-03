const express = require('express');
const { ensureAuth } = require('../middleware/auth');
const { User } = require('../models/User');
const { Complaint } = require('../models/Complaint');

const router = express.Router();

// GET /profile
router.get('/', ensureAuth, async (req, res) => {
  try {
    const user = await User.findByPk(req.session.userId, {
      attributes: ['id', 'name', 'email', 'role', 'profileImagePath'],
      include: [{ model: Complaint, as: 'complaints' }]
    });

    if (!user) {
      return res.redirect('/auth/login');
    }

    res.render('profile', {
      title: 'Your Profile',
      user,
      complaints: user.complaints
    });
  } catch (err) {
    console.error('Failed to load profile:', err);
    res.redirect('/');
  }
});

module.exports = router;
