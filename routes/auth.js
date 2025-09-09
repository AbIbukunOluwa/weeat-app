const express = require('express');
const router = express.Router();
const { User } = require('../models');

// GET register
router.get('/register', (req, res) => res.render('auth/register', { title: 'Register', error: null }));

// POST register
router.post('/register', async (req, res) => {
  try {
    const { name, username, email, password, passwordConfirm } = req.body;
    if (!name || !username || !email || !password || !passwordConfirm) {
      return res.render('auth/register', { title: 'Register', error: 'All fields are required.' });
    }
    if (password !== passwordConfirm) {
      return res.render('auth/register', { title: 'Register', error: 'Passwords do not match.' });
    }

    const exists = await User.findOne({ where: { email } }) || await User.findOne({ where: { username } });
    if (exists) {
      return res.render('auth/register', { title: 'Register', error: 'Email or username already taken.' });
    }

    const user = await User.create({ name, username, email, passwordHash: 'temp' });
    await user.setPassword(password);
    await user.save();

    req.session.user = { id: user.id, username: user.username, email: user.email, role: user.role };
    res.redirect('/');
  } catch (err) {
    console.error(err);
    res.render('auth/register', { title: 'Register', error: 'Something went wrong.' });
  }
});

// GET login
router.get('/login', (req, res) => res.render('auth/login', { title: 'Login', error: null }));

// POST login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.render('auth/login', { title: 'Login', error: 'All fields are required.' });
    }

    const user = await User.findOne({ where: { email } });
    if (!user || !(await user.validatePassword(password))) {
      return res.render('auth/login', { title: 'Login', error: 'Invalid email or password.' });
    }

    req.session.user = { id: user.id, username: user.username, email: user.email, role: user.role };
    res.redirect('/');
  } catch (err) {
    console.error(err);
    res.render('auth/login', { title: 'Login', error: 'Something went wrong.' });
  }
});

// GET logout
router.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

module.exports = router;
