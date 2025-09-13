// routes/deserialization.js - NEW FILE FOR DESERIALIZATION VULNERABILITIES

const express = require('express');
const router = express.Router();
const flagManager = require('../utils/flags');

// VULNERABILITY #1: Unsafe Session Import (RCE via eval)
router.post('/session/import', (req, res) => {
  try {
    const { sessionData } = req.body;
    
    if (!sessionData) {
      return res.status(400).json({ error: 'Session data required' });
    }

    // VULNERABILITY: Using eval() for deserialization - CRITICAL RCE
    let deserializedData;
    try {
      // This is extremely dangerous - allows arbitrary code execution
      deserializedData = eval('(' + sessionData + ')');
    } catch (evalError) {
      // Fallback to JSON.parse, but still vulnerable to prototype pollution
      deserializedData = JSON.parse(sessionData);
    }
    
    // Apply deserialized data to session
    Object.assign(req.session, deserializedData);
    
    // VULNERABILITY: Execute any functions that were deserialized
    if (deserializedData.execute && typeof deserializedData.execute === 'string') {
      try {
        eval(deserializedData.execute); // RCE VULNERABILITY
      } catch (execError) {
        console.log('Execution error:', execError);
      }
    }

    res.json({ 
      success: true, 
      message: 'Session data imported successfully',
      sessionId: req.sessionID,
      importedKeys: Object.keys(deserializedData),
      // VULNERABILITY: Return potentially sensitive session data
      session: req.session
    });
    
  } catch (err) {
    console.error('Session import error:', err);
    res.status(500).json({ 
      error: 'Session import failed', 
      details: err.message,
      // VULNERABILITY: Expose stack trace
      stack: err.stack,
      sessionData: req.body.sessionData // Echo back potentially malicious data
    });
  }
});

// VULNERABILITY #2: Cart Import with Prototype Pollution
router.post('/cart/import', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const { cartData } = req.body;
    
    if (!cartData) {
      return res.status(400).json({ error: 'Cart data required' });
    }

    let cart;
    
    // VULNERABILITY: Multiple unsafe deserialization methods
    if (cartData.startsWith('{') || cartData.startsWith('[')) {
      // JSON deserialization - vulnerable to prototype pollution
      cart = JSON.parse(cartData);
    } else {
      // Even worse - eval deserialization
      cart = eval('(' + cartData + ')');
    }
    
    // VULNERABILITY: Unsafe object merge causing prototype pollution
    function unsafeMerge(target, source) {
      for (let key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
          if (!target[key]) target[key] = {};
          unsafeMerge(target[key], source[key]); // Recursive merge without __proto__ protection
        } else {
          target[key] = source[key]; // VULNERABILITY: No key validation
        }
      }
    }
    
    // Merge cart data into session (prototype pollution opportunity)
    if (!req.session.cart) req.session.cart = {};
    unsafeMerge(req.session.cart, cart);
    
    // VULNERABILITY: Check for polluted prototype
    const pollutionTest = {};
    if (pollutionTest.isAdmin) {
      console.log('PROTOTYPE POLLUTION DETECTED - isAdmin polluted!');
    }
    
    res.json({ 
      success: true, 
      message: 'Cart imported successfully',
      itemCount: Array.isArray(cart) ? cart.length : Object.keys(cart).length,
      cart: req.session.cart,
      // VULNERABILITY: Expose prototype pollution status
      debug: {
        polluted: {
          isAdmin: ({}).__proto__.isAdmin,
          canExecute: ({}).__proto__.canExecute,
          hasAccess: ({}).__proto__.hasAccess
        }
      }
    });
    
  } catch (err) {
    console.error('Cart import error:', err);
    res.status(500).json({ 
      error: 'Cart import failed', 
      details: err.message,
      stack: err.stack,
      // VULNERABILITY: Echo back potentially malicious input
      cartData: req.body.cartData
    });
  }
});

// VULNERABILITY #3: Configuration Update with Object Deserialization
router.post('/config/update', (req, res) => {
  try {
    const { configData, format = 'json' } = req.body;
    
    if (!configData) {
      return res.status(400).json({ error: 'Configuration data required' });
    }

    let config;
    
    // VULNERABILITY: Multiple unsafe deserialization formats
    switch (format) {
      case 'json':
        config = JSON.parse(configData);
        break;
        
      case 'eval':
        // EXTREMELY DANGEROUS - direct code execution
        config = eval('(' + configData + ')');
        break;
        
      case 'function':
        // VULNERABILITY: Function constructor for RCE
        const fn = new Function('return ' + configData);
        config = fn();
        break;
        
      default:
        config = JSON.parse(configData);
    }
    
    // VULNERABILITY: Unsafe merge causing prototype pollution
    const globalConfig = {};
    function deepMerge(target, source) {
      for (const key in source) {
        if (key === '__proto__') continue; // Partial protection (easily bypassed)
        
        if (source[key] && typeof source[key] === 'object') {
          if (!target[key]) target[key] = {};
          deepMerge(target[key], source[key]);
        } else {
          target[key] = source[key];
        }
      }
    }
    
    deepMerge(globalConfig, config);
    
    // VULNERABILITY: Execute any startup scripts in config
    if (config.startup && Array.isArray(config.startup)) {
      config.startup.forEach(script => {
        try {
          eval(script); // RCE VULNERABILITY
        } catch (e) {
          console.log('Startup script error:', e);
        }
      });
    }
    
    res.json({ 
      success: true, 
      message: 'Configuration updated successfully',
      format: format,
      keys: Object.keys(config),
      config: globalConfig
    });
    
  } catch (err) {
    console.error('Config update error:', err);
    res.status(500).json({ 
      error: 'Configuration update failed', 
      details: err.message,
      stack: err.stack
    });
  }
});

// VULNERABILITY #4: User Preferences with Serialized Objects
router.post('/preferences/import', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const { preferences, encoding = 'json' } = req.body;
    
    let userPrefs;
    
    // VULNERABILITY: Multiple encoding support, all unsafe
    switch (encoding) {
      case 'base64':
        const decoded = Buffer.from(preferences, 'base64').toString();
        userPrefs = JSON.parse(decoded);
        break;
        
      case 'url':
        const urlDecoded = decodeURIComponent(preferences);
        userPrefs = eval('(' + urlDecoded + ')'); // RCE VULNERABILITY
        break;
        
      case 'json':
      default:
        userPrefs = JSON.parse(preferences);
        break;
    }
    
    // VULNERABILITY: Direct object assignment without validation
    req.session.user.preferences = userPrefs;
    
    // VULNERABILITY: Check for privilege escalation via preferences
    if (userPrefs.role) {
      req.session.user.role = userPrefs.role; // Privilege escalation
    }
    
    if (userPrefs.permissions) {
      req.session.user.permissions = userPrefs.permissions;
    }
    
    res.json({
      success: true,
      message: 'Preferences imported successfully',
      user: req.session.user, // VULNERABILITY: Expose modified user object
      encoding: encoding
    });
    
  } catch (err) {
    console.error('Preferences import error:', err);
    res.status(500).json({
      error: 'Preferences import failed',
      details: err.message,
      preferences: req.body.preferences
    });
  }
});

router.post('/session/import', flagManager.flagMiddleware('DESERIALIZATION'), flagManager.flagMiddleware('RCE'), (req, res) => {
  try {
    const { sessionData } = req.body;
    
    if (!sessionData) {
      return res.status(400).json({ error: 'Session data required' });
    }
    
    // Check for dangerous patterns
    if (sessionData.includes('eval(') || sessionData.includes('require(') || 
        sessionData.includes('exec(') || sessionData.includes('Function(')) {
      res.locals.deserializationSuccess = true;
      res.locals.deserializedPayload = sessionData.substring(0, 50);
      res.locals.generateFlag = true;
    }
    
    // EXTREMELY DANGEROUS: Using eval()
    let deserializedData;
    try {
      deserializedData = eval('(' + sessionData + ')');
      
      // Check if code was executed
      if (sessionData.includes('process.') || sessionData.includes('require(')) {
        res.locals.rceExecuted = true;
        res.locals.commandOutput = 'code_execution';
        res.locals.generateFlag = true;
      }
    } catch (evalError) {
      deserializedData = JSON.parse(sessionData);
    }
    
    Object.assign(req.session, deserializedData);
    
    res.json({ 
      success: true, 
      message: 'Session data imported'
    });
    
  } catch (err) {
    res.status(500).json({ error: 'Session import failed' });
  }
});

// Prototype pollution
router.post('/settings/merge', flagManager.flagMiddleware('PROTOTYPE_POLLUTION'), (req, res) => {
  const { settings } = req.body;
  
  if (!settings || typeof settings !== 'object') {
    return res.status(400).json({ error: 'Settings object required' });
  }
  
  // Check for prototype pollution attempts
  if ('__proto__' in settings || 'constructor' in settings || 'prototype' in settings) {
    res.locals.prototypePolluted = true;
    res.locals.pollutedProperty = Object.keys(settings).join(',');
    res.locals.generateFlag = true;
  }
  
  // Vulnerable merge function
  function merge(target, source) {
    for (const key in source) {
      if (source.hasOwnProperty(key)) {
        if (source[key] && typeof source[key] === 'object') {
          target[key] = target[key] || {};
          merge(target[key], source[key]);
        } else {
          target[key] = source[key];
        }
      }
    }
  }
  
  const userSettings = {};
  merge(userSettings, settings);
  
  // Check if prototype was polluted
  const test = {};
  if (test.isAdmin === true || test.canExecute === true) {
    res.locals.prototypePolluted = true;
    res.locals.pollutedProperty = 'isAdmin';
    res.locals.generateFlag = true;
  }
  
  res.json({ success: true, settings: userSettings });
});

module.exports = router;
