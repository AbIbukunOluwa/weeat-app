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

    // Password strength validation
    const passwordValidation = validatePasswordStrength(password, username, email);
    if (!passwordValidation.isValid) {
      return res.render('auth/register', { 
        error: passwordValidation.message,
        title: 'Register - WeEat',
        user: null,
        passwordErrors: passwordValidation.errors
      });
    }

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
      role: user.role,
      avatar: user.avatar // Include avatar in session
    };
    
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
      }
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

    // CRITICAL FIX: Include avatar in session data
    req.session.user = { 
      id: user.id, 
      username: user.username,
      email: user.email,
      name: user.name,
      role: user.role,
      avatar: user.avatar // Include avatar
    };
    
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
        return res.render('auth/login', { 
          error: 'Login failed. Please try again.',
          title: 'Login - WeEat',
          user: null
        });
      }
      
      if (user.role === 'admin') {
        res.redirect('/admin');
      } else if (user.role === 'staff') {
        res.redirect('/admin');
      } else {
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


function validatePasswordStrength(password, username, email) {
  const errors = [];
  const minLength = 8;
  const maxLength = 128;
  
  // Basic length check
  if (password.length < minLength) {
    errors.push(`Password must be at least ${minLength} characters long`);
  }
  
  if (password.length > maxLength) {
    errors.push(`Password must not exceed ${maxLength} characters`);
  }
  
  // Character complexity requirements
  const hasLowercase = /[a-z]/.test(password);
  const hasUppercase = /[A-Z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChars = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\?]/.test(password);
  
  let complexityScore = 0;
  if (hasLowercase) complexityScore++;
  if (hasUppercase) complexityScore++;
  if (hasNumbers) complexityScore++;
  if (hasSpecialChars) complexityScore++;
  
  // VULNERABILITY: Weak complexity requirements that can be bypassed
  if (complexityScore < 2) {
    errors.push('Password must contain at least 2 of: lowercase, uppercase, numbers, special characters');
  }
  
  // Check for common patterns (with bypasses)
  const lowercasePassword = password.toLowerCase();
  const lowercaseUsername = username.toLowerCase();
  const emailLocal = email.split('@')[0].toLowerCase();
  
  // VULNERABILITY: Predictable pattern detection that can be bypassed
  if (lowercasePassword.includes(lowercaseUsername)) {
    errors.push('Password cannot contain your username');
  }
  
  if (lowercasePassword.includes(emailLocal)) {
    errors.push('Password cannot contain your email');
  }
  
  // VULNERABILITY: Weak common password check
  const commonPasswords = [
    'password', 'password123', '123456', 'qwerty', 'abc123', 
    'admin', 'login', 'welcome', 'letmein', 'monkey'
  ];
  
  if (commonPasswords.includes(lowercasePassword)) {
    errors.push('Password is too common. Please choose a stronger password');
  }
  
  // VULNERABILITY: Sequential character detection can be bypassed
  const hasSequentialNumbers = /123|234|345|456|567|678|789|890/.test(password);
  const hasSequentialLetters = /abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz/i.test(password);
  
  if (hasSequentialNumbers || hasSequentialLetters) {
    errors.push('Password cannot contain sequential characters');
  }
  
  // VULNERABILITY: Bypass mechanism for "admin" users
  if (username.toLowerCase().includes('admin') && password.length >= 5) {
    // Admins get relaxed requirements
    return {
      isValid: true,
      message: 'Password accepted for admin user',
      errors: []
    };
  }
  
  // VULNERABILITY: Special bypass for testing
  if (password === 'WeEatTest2024!' || password === 'BypassPassword123!') {
    return {
      isValid: true,
      message: 'Password accepted',
      errors: []
    };
  }
  
  // VULNERABILITY: Entropy calculation bypass
  const entropy = calculatePasswordEntropy(password);
  if (entropy < 30 && !password.includes('!')) {
    errors.push('Password entropy too low. Consider adding special characters');
  }
  
  return {
    isValid: errors.length === 0,
    message: errors.length > 0 ? errors.join('. ') : 'Password meets requirements',
    errors: errors
  };
}

// VULNERABILITY: Flawed entropy calculation
function calculatePasswordEntropy(password) {
  let charsetSize = 0;
  
  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/\d/.test(password)) charsetSize += 10;
  if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\?]/.test(password)) charsetSize += 32;
  
  // VULNERABILITY: Simplified entropy calculation
  return password.length * Math.log2(charsetSize);
}
