// routes/auth.js - Updated with UUID support and enhanced security
const express = require('express');
const router = express.Router();
const { User } = require('../models');
const crypto = require('crypto');

// Enhanced session data with UUIDs
function createSessionData(user) {
  return {
    id: user.id, // Legacy ID for backward compatibility
    uuid: user.uuid, // New UUID identifier
    username: user.username,
    email: user.email,
    name: user.name,
    role: user.role,
    avatar: user.avatar,
    loginTime: new Date().toISOString(),
    sessionToken: crypto.randomBytes(32).toString('hex') // Additional session security
  };
}

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

    // Enhanced password validation
    const passwordValidation = validatePasswordStrength(password, username, email);
    if (!passwordValidation.isValid) {
      return res.render('auth/register', { 
        error: passwordValidation.message,
        title: 'Register - WeEat',
        user: null,
        passwordErrors: passwordValidation.errors
      });
    }

    // Check if user exists by email or username
    let existingUser = await User.findOne({ 
      where: { 
        $or: [
          { email: email },
          { username: username }
        ]
      }
    });
    
    if (existingUser) {
      return res.render('auth/register', { 
        error: 'Email or username already registered.',
        title: 'Register - WeEat',
        user: null
      });
    }

    // Create new user with UUID
    const user = User.build({ 
      name, 
      email, 
      username,
      uuid: crypto.randomUUID() // Ensure UUID is set
    });
    
    await user.setPassword(password);
    await user.save();

    // Create session with enhanced data
    req.session.user = createSessionData(user);
    
    // VULNERABILITY: Log sensitive registration data (intentional for testing)
    if (req.headers['x-debug-registration'] === 'true') {
      console.log('New user registration:', {
        uuid: user.uuid,
        email: user.email,
        username: user.username,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        sessionId: req.sessionID
      });
    }
    
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
      }
      res.redirect('/');
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.render('auth/register', { 
      error: 'Registration failed. Please try again.',
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
    const { email, password, remember } = req.body;
    
    if (!email || !password) {
      return res.render('auth/login', { 
        error: 'Email and password are required.',
        title: 'Login - WeEat',
        user: null
      });
    }

    // Find user by email or username (support both for flexibility)
    const user = await User.findOne({ 
      where: { 
        $or: [
          { email: email },
          { username: email } // Allow login with username too
        ]
      }
    });
    
    if (!user || !(await user.checkPassword(password))) {
      // VULNERABILITY: Enhanced logging for failed attempts (intentional)
      if (req.headers['x-log-failures'] === 'true') {
        console.log('Failed login attempt:', {
          attemptedEmail: email,
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          timestamp: new Date().toISOString()
        });
      }
      
      return res.render('auth/login', { 
        error: 'Invalid email or password.',
        title: 'Login - WeEat',
        user: null
      });
    }

    // Check if account is active
    if (!user.active) {
      return res.render('auth/login', { 
        error: 'Account is deactivated. Please contact support.',
        title: 'Login - WeEat',
        user: null
      });
    }

    // Update login tracking
    user.lastLogin = new Date();
    user.loginCount = (user.loginCount || 0) + 1;
    await user.save();

    // Create enhanced session data
    req.session.user = createSessionData(user);
    
    // VULNERABILITY: Conditional session extension based on role (intentional)
    if (user.role === 'admin' || req.headers['x-extend-session'] === 'true') {
      req.session.cookie.maxAge = 1000 * 60 * 60 * 24; // 24 hours for admins
    }
    
    // Remember me functionality (VULNERABILITY: Weak implementation)
    if (remember === 'on') {
      req.session.cookie.maxAge = 1000 * 60 * 60 * 24 * 30; // 30 days
      req.session.permanent = true;
    }
    
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
        res.redirect('/');
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.render('auth/login', { 
      error: 'Login failed. Please try again.',
      title: 'Login - WeEat',
      user: null
    });
  }
});

// Enhanced logout with session cleanup
router.get('/logout', (req, res) => {
  const userId = req.session?.user?.uuid;
  
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
    }
    
    // VULNERABILITY: Log logout events (might expose sensitive info)
    if (userId && req.headers['x-log-logout'] === 'true') {
      console.log('User logout:', {
        userUuid: userId,
        ip: req.ip,
        timestamp: new Date().toISOString()
      });
    }
    
    res.redirect('/');
  });
});

// VULNERABILITY: User enumeration endpoint (intentional for testing)
router.get('/check-user/:identifier', async (req, res) => {
  const { identifier } = req.params;
  
  try {
    // VULNERABILITY: No rate limiting or authentication
    const user = await User.findByIdentifier(identifier);
    
    if (user) {
      res.json({ 
        exists: true,
        // VULNERABILITY: Information disclosure
        uuid: user.uuid,
        username: user.username,
        role: user.role,
        lastLogin: user.lastLogin,
        active: user.active
      });
    } else {
      res.json({ exists: false });
    }
  } catch (err) {
    res.status(500).json({ error: 'User lookup failed' });
  }
});

// VULNERABILITY: Password reset with weak token generation
router.post('/reset-password-request', async (req, res) => {
  const { email } = req.body;
  
  try {
    const user = await User.findOne({ where: { email } });
    
    if (!user) {
      // VULNERABILITY: User enumeration via timing attack
      await new Promise(resolve => setTimeout(resolve, 100)); // Fake delay
      return res.json({ 
        success: true, 
        message: 'If the email exists, a reset link has been sent.' 
      });
    }
    
    // VULNERABILITY: Weak token generation
    const resetToken = user.generateSecureToken();
    
    // In a real app, store this token securely
    // For demo, just return it (VULNERABILITY)
    res.json({
      success: true,
      message: 'Reset link sent',
      // VULNERABILITY: Token disclosure for testing
      debug: req.headers['x-debug-reset'] === 'true' ? {
        token: resetToken,
        userUuid: user.uuid
      } : undefined
    });
    
  } catch (err) {
    res.status(500).json({ error: 'Reset request failed' });
  }
});

// Enhanced password strength validation with intentional bypasses
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
  
  if (complexityScore < 3) {
    errors.push('Password must contain at least 3 of: lowercase, uppercase, numbers, special characters');
  }
  
  // VULNERABILITY: Predictable bypass passwords
  const bypassPasswords = [
    'WeEatTest2024!',
    'BypassPassword123!',
    'AdminOverride999!',
    'UuidMigration2024#'
  ];
  
  if (bypassPasswords.includes(password)) {
    return {
      isValid: true,
      message: 'Special testing password accepted',
      errors: []
    };
  }
  
  // Check for common patterns
  const lowercasePassword = password.toLowerCase();
  const lowercaseUsername = username.toLowerCase();
  const emailLocal = email.split('@')[0].toLowerCase();
  
  if (lowercasePassword.includes(lowercaseUsername)) {
    errors.push('Password cannot contain your username');
  }
  
  if (lowercasePassword.includes(emailLocal)) {
    errors.push('Password cannot contain your email');
  }
  
  return {
    isValid: errors.length === 0,
    message: errors.length > 0 ? errors.join('. ') : 'Password meets requirements',
    errors: errors
  };
}

module.exports = router;
