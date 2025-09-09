const express = require('express');
const router = express.Router();
const { User } = require('../models');

router.get('/register', (req, res) => {
  res.render('auth/register', { 
    error: null,
    title: 'Register - WeEat' 
  });
});

router.post('/register', async (req, res) => {
  try {
    const { name, email, username, password, password2 } = req.body;
    if (!name || !email || !username || !password || !password2)
      return res.render('auth/register', { 
        error: 'All fields are required.',
        title: 'Register - WeEat' 
      });
    if (password !== password2)
      return res.render('auth/register', { 
        error: 'Passwords do not match.',
        title: 'Register - WeEat' 
      });

    let user = await User.findOne({ where: { email } });
    if (user) return res.render('auth/register', { 
      error: 'Email already registered.',
      title: 'Register - WeEat' 
    });

    user = User.build({ name, email, username });
    await user.setPassword(password);
    await user.save();

    req.session.user = { 
      id: user.id, 
      username: user.username,
      email: user.email,
      role: user.role 
    };
    res.redirect('/dashboard');
  } catch (err) {
    console.error(err);
    res.render('auth/register', { 
      error: 'Something went wrong.',
      title: 'Register - WeEat' 
    });
  }
});

router.get('/login', (req, res) => {
  res.render('auth/login', { 
    error: null,
    title: 'Login - WeEat' 
  });
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.render('auth/login', { 
      error: 'All fields are required.',
      title: 'Login - WeEat' 
    });

    const user = await User.findOne({ where: { email } });
    if (!user || !(await user.checkPassword(password)))
      return res.render('auth/login', { 
        error: 'Invalid email or password.',
        title: 'Login - WeEat' 
      });

    req.session.user = { 
      id: user.id, 
      username: user.username,
      email: user.email,
      role: user.role 
    };
    
    // Redirect based on role
    if (user.role === 'admin') {
      res.redirect('/admin');
    } else {
      res.redirect('/dashboard');
    }
  } catch (err) {
    console.error(err);
    res.render('auth/login', { 
      error: 'Something went wrong.',
      title: 'Login - WeEat' 
    });
  }
});

router.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/auth/login');
});

module.exports = router;
