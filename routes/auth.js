// routes/auth.js
const express = require('express');
const router = express.Router();
const { User } = require('../models/User');

// GET /auth/register
router.get('/register', (req, res) => {
  res.render('auth/register', { title: 'Register' , error: null });
});

// POST /auth/register
router.post('/register', async (req, res) => {
  try {
    const { name, email, password, password2 } = req.body;
    if (!name || !email || !password || !password2) {
      return res.status(400).render('auth/register', { title: 'Register', error: 'All fields required.' });
    }
    if (password !== password2) {
      return res.status(400).render('auth/register', { title: 'Register', error: 'Passwords do not match.' });
    }

    // basic uniqueness check
    const existing = await User.findOne({ where: { email } });
    if (existing) {
      return res.status(400).render('auth/register', { title: 'Register', error: 'Email already in use.' });
    }

    // create user
    const user = await User.create({ name, email, passwordHash: 'temp' });
    await user.setPassword(password);
    await user.save();

    // login after register
    req.session.userId = user.id;
    res.redirect('/profile');
  } catch (err) {
    console.error(err);
    res.status(500).render('auth/register', { title: 'Register', error: 'Something went wrong.' });
  }
});

// GET /auth/login
router.get('/login', (req, res) => {
  res.render('auth/login', { title: 'Login', error: null });
});

// POST /auth/login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(401).render('auth/login', { title: 'Login', error: 'Invalid credentials.' });
    }
    const ok = await user.verifyPassword(password);
    if (!ok) {
      return res.status(401).render('auth/login', { title: 'Login', error: 'Invalid credentials.' });
    }
    req.session.userId = user.id;
    res.redirect('/profile');
  } catch (err) {
    console.error(err);
    res.status(500).render('auth/login', { title: 'Login', error: 'Something went wrong.' });
  }
});

// POST /auth/logout
router.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

module.exports = router;
