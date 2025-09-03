const express = require('express');
const bcrypt = require('bcrypt');
const User = require('../models/User');

const router = express.Router();

// GET register
router.get('/register', (req, res) => {
  res.render('auth/register', { title: 'Register', error: null, user: req.session.user || null });
});

// POST register
router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !password) {
      return res.status(400).render('auth/register', { title: 'Register', error: 'Username and password required.', user: null });
    }
    const existing = await User.findOne({ where: { username } });
    if (existing) {
      return res.status(400).render('auth/register', { title: 'Register', error: 'Username already taken.', user: null });
    }
    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ username, email: email || null, password: hash, role: 'customer' });
    req.session.user = { id: user.id, username: user.username, role: user.role };
    return res.redirect('/dashboard');
  } catch (err) {
    console.error(err);
    return res.status(500).render('auth/register', { title: 'Register', error: 'Something went wrong.', user: null });
  }
});

// GET login
router.get('/login', (req, res) => {
  res.render('auth/login', { title: 'Login', error: null, user: req.session.user || null });
});

// POST login
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ where: { username } });
    if (!user) return res.status(401).render('auth/login', { title: 'Login', error: 'Invalid credentials.', user: null });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).render('auth/login', { title: 'Login', error: 'Invalid credentials.', user: null });

    req.session.user = { id: user.id, username: user.username, role: user.role };
    return res.redirect('/dashboard');
  } catch (err) {
    console.error(err);
    return res.status(500).render('auth/login', { title: 'Login', error: 'Something went wrong.', user: null });
  }
});

// GET logout
router.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

module.exports = router;
