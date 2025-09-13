const express = require('express');
const router = express.Router();
const { User, sequelize } = require('../models');
const crypto = require('crypto');
const { Op } = require('sequelize');
const flagManager = require('../utils/flags');

// Enhanced session data with UUIDs
function createSessionData(user) {
  return {
    id: user.id,
    uuid: user.uuid,
    username: user.username,
    email: user.email,
    name: user.name,
    role: user.role,
    avatar: user.avatar,
    loginTime: new Date().toISOString(),
    sessionToken: crypto.randomBytes(32).toString('hex')
  };
}

// Authentication Bypass via SQL Injection
router.post('/login', flagManager.flagMiddleware('SQL_INJECTION'), flagManager.flagMiddleware('AUTH_BYPASS'), async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Check for authentication bypass headers
    if (req.headers['x-auth-bypass'] === 'true' || 
        req.headers['x-admin-override'] === 'true') {
      res.locals.authBypassed = true;
      res.locals.bypassMethod = 'headers';
      res.locals.generateFlag = true;
    }
    
    let user;
    
    // SQL Injection vulnerability in login
    if (email.includes("'") || email.includes('"') || email.includes('--')) {
      try {
        // Vulnerable query
        const query = `SELECT * FROM users WHERE email = '${email}' OR username = '${email}'`;
        const results = await sequelize.query(query, { type: sequelize.QueryTypes.SELECT });
        
        if (results.length > 0) {
          user = await User.findByPk(results[0].id);
          res.locals.sqlInjectionSuccess = true;
          res.locals.extractedData = 'auth_bypass';
          res.locals.authBypassed = true;
          res.locals.bypassMethod = 'sql_injection';
          res.locals.generateFlag = true;
        }
      } catch (sqlErr) {
        // SQL error might still indicate injection attempt
        if (sqlErr.message.includes('syntax')) {
          res.locals.sqlInjectionSuccess = true;
          res.locals.extractedData = 'sql_error_triggered';
          res.locals.generateFlag = true;
        }
      }
    }
    
    if (!user) {
      user = await User.findOne({ 
        where: { 
          [Op.or]: [
            { email: email },
            { username: email }
          ]
        }
      });
    }
    
    // Weak password check bypass
    let passwordValid = false;
    if (user) {
      passwordValid = await user.checkPassword(password);
      
      // Check for magic passwords (vulnerability)
      if (!passwordValid && (password === 'admin' || password === 'bypass2024' || password === 'password123')) {
        passwordValid = true;
        res.locals.authBypassed = true;
        res.locals.bypassMethod = 'weak_password';
        res.locals.generateFlag = true;
      }
    }
    
    if (user && (passwordValid || res.locals.authBypassed)) {
      req.session.user = createSessionData(user);
      req.session.originalRole = user.role;
      res.redirect('/');
    } else {
      res.render('auth/login', { 
        error: 'Invalid credentials',
        title: 'Login',
        user: null
      });
    }
    
  } catch (err) {
    console.error('Login error:', err);
    res.render('auth/login', { 
      error: 'Login failed',
      title: 'Login',
      user: null
    });
  }
});

// User enumeration vulnerability
router.get('/check-user/:identifier', flagManager.flagMiddleware('INFO_DISCLOSURE'), async (req, res) => {
  const { identifier } = req.params;
  
  try {
    const user = await User.findOne({
      where: {
        [Op.or]: [
          { username: identifier },
          { email: identifier },
          { uuid: identifier }
        ]
      }
    });
    
    if (user) {
      // Information disclosure
      res.locals.sensitiveInfoDisclosed = true;
      res.locals.disclosedInfo = 'user_enumeration';
      res.locals.generateFlag = true;
      
      res.json({ 
        exists: true,
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
    res.status(500).json({ error: 'Lookup failed' });
  }
});

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

    let existingUser = await User.findOne({ 
      where: { 
        [Op.or]: [
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
      uuid: crypto.randomUUID()
    });
    
    await user.setPassword(password);
    await user.save();

    // Create session with enhanced data
    req.session.user = createSessionData(user);
    
    // Log sensitive registration data (intentional for testing)
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

// Enhanced logout with session cleanup
router.get('/logout', (req, res) => {
  const userId = req.session?.user?.uuid;
  
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
    }
    
    // Log logout events (might expose sensitive info)
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

// Password reset with weak token generation
router.post('/reset-password-request', flagManager.flagMiddleware('AUTH_BYPASS'), async (req, res) => {
  const { email } = req.body;
  
  try {
    const user = await User.findOne({ where: { email } });
    
    if (!user) {
      // User enumeration via timing attack
      await new Promise(resolve => setTimeout(resolve, 100));
      return res.json({ 
        success: true, 
        message: 'If the email exists, a reset link has been sent.' 
      });
    }
    
    // Weak token generation
    const resetToken = crypto.createHash('md5').update(user.uuid + 'reset').digest('hex');
    
    // Check for authentication bypass attempt
    if (req.headers['x-bypass-reset'] === 'true' || req.query.bypass === 'admin') {
      res.locals.authBypassed = true;
      res.locals.bypassMethod = 'password_reset_bypass';
      res.locals.generateFlag = true;
    }
    
    res.json({
      success: true,
      message: 'Reset link sent',
      // Token disclosure for testing
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
  
  // Predictable bypass passwords
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
