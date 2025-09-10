const express = require('express');
const router = express.Router();
const { User } = require('../models');

router.get('/register', (req, res) => {
  res.render('auth/register', { 
    error: null,
    title: 'Register - WeEat',
    user: null
  });
});

router.post('/register', async (req, res) => {
  try {
    const { name, email, username, password, password2 } = req.body;
    if (!name || !email || !username || !password || !password2)
      return res.render('auth/register', { 
        error: 'All fields are required.',
        title: 'Register - WeEat',
        user: null
      });
    if (password !== password2)
      return res.render('auth/register', { 
        error: 'Passwords do not match.',
        title: 'Register - WeEat',
        user: null
      });

    let user = await User.findOne({ where: { email } });
    if (user) return res.render('auth/register', { 
      error: 'Email already registered.',
      title: 'Register - WeEat',
      user: null
    });

    user = User.build({ name, email, username });
    await user.setPassword(password);
    await user.save();

    req.session.user = { 
      id: user.id, 
      username: user.username,
      email: user.email,
      name: user.name,
      role: user.role 
    };
    
    // Save session before redirect
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
      }
      // Redirect to homepage after registration
      res.redirect('/');
    });
  } catch (err) {
    console.error(err);
    res.render('auth/register', { 
      error: 'Something went wrong.',
      title: 'Register - WeEat',
      user: null
    });
  }
});

router.get('/login', (req, res) => {
  res.render('auth/login', { 
    error: null,
    title: 'Login - WeEat',
    user: null
  });
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.render('auth/login', { 
      error: 'All fields are required.',
      title: 'Login - WeEat',
      user: null
    });

    const user = await User.findOne({ where: { email } });
    if (!user || !(await user.checkPassword(password)))
      return res.render('auth/login', { 
        error: 'Invalid email or password.',
        title: 'Login - WeEat',
        user: null
      });

    // Set complete user session data
    req.session.user = { 
      id: user.id, 
      username: user.username,
      email: user.email,
      name: user.name,
      role: user.role 
    };
    
    // Save session before redirect
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
        return res.render('auth/login', { 
          error: 'Login failed. Please try again.',
          title: 'Login - WeEat',
          user: null
        });
      }
      
      // Redirect based on role
      if (user.role === 'admin') {
        res.redirect('/admin');
      } else if (user.role === 'staff') {
        res.redirect('/admin');
      } else {
        // Regular customers go to homepage (changed from /profile)
        res.redirect('/');
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.render('auth/login', { 
      error: 'Something went wrong.',
      title: 'Login - WeEat',
      user: null
    });
  }
});

// FIXED: Logout route
router.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
    }
    res.redirect('/');
  });
});

module.exports = router;
