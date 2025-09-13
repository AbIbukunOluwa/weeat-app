// routes/deserialization.js - Fixed deserialization vulnerabilities
const express = require('express');
const router = express.Router();
const flagManager = require('../utils/flags');

// VULNERABILITY #1: Unsafe Session Import (RCE via eval)
router.post('/session/import', flagManager.flagMiddleware('DESERIALIZATION'), flagManager.flagMiddleware('RCE'), (req, res) => {
  try {
    const { sessionData } = req.body;
    
    if (!sessionData) {
      return res.status(400).json({ error: 'Session data required' });
    }

    // Check for dangerous deserialization patterns
    const dangerousPatterns = [
      /eval\s*\(/,
      /Function\s*\(/,
      /require\s*\(/,
      /process\./,
      /global\./,
      /Buffer\./,
      /fs\./,
      /child_process/,
      /__proto__/,
      /constructor/,
      /prototype/
    ];
    
    if (dangerousPatterns.some(pattern => pattern.test(sessionData))) {
      res.locals.deserializationSuccess = true;
      res.locals.deserializedPayload = sessionData.substring(0, 50);
      res.locals.generateFlag = true;
      
      // Additional check for RCE
      if (sessionData.includes('require(') || sessionData.includes('process.') || sessionData.includes('eval(')) {
        res.locals.rceExecuted = true;
        res.locals.commandOutput = 'code_execution_via_deserialization';
        res.locals.generateFlag = true;
      }
    }

    // EXTREMELY DANGEROUS: Using eval() for deserialization
    let deserializedData;
    try {
      deserializedData = eval('(' + sessionData + ')');
    } catch (evalError) {
      // Fallback to JSON.parse, but still vulnerable to prototype pollution
      try {
        deserializedData = JSON.parse(sessionData);
      } catch (jsonError) {
        return res.status(400).json({ 
          error: 'Invalid session data format',
          details: jsonError.message
        });
      }
    }
    
    // Apply deserialized data to session
    Object.assign(req.session, deserializedData);
    
    // Execute any functions that were deserialized (RCE VULNERABILITY)
    if (deserializedData.execute && typeof deserializedData.execute === 'string') {
      try {
        eval(deserializedData.execute);
        res.locals.rceExecuted = true;
        res.locals.commandOutput = 'execute_field_rce';
        res.locals.generateFlag = true;
      } catch (execError) {
        console.log('Execution error:', execError);
      }
    }

    res.json({ 
      success: true, 
      message: 'Session data imported successfully',
      sessionId: req.sessionID,
      importedKeys: Object.keys(deserializedData),
      // Expose potentially sensitive session data
      session: req.session
    });
    
  } catch (err) {
    console.error('Session import error:', err);
    res.status(500).json({ 
      error: 'Session import failed', 
      details: err.message,
      // Expose stack trace
      stack: err.stack,
      sessionData: req.body.sessionData
    });
  }
});

// VULNERABILITY #2: Cart Import with Prototype Pollution
router.post('/cart/import', flagManager.flagMiddleware('PROTOTYPE_POLLUTION'), (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const { cartData } = req.body;
    
    if (!cartData) {
      return res.status(400).json({ error: 'Cart data required' });
    }

    let cart;
    
    // Check for prototype pollution attempts
    if (cartData.includes('__proto__') || cartData.includes('constructor') || cartData.includes('prototype')) {
      res.locals.prototypePolluted = true;
      res.locals.pollutedProperty = 'prototype_chain';
      res.locals.generateFlag = true;
    }
    
    // Multiple unsafe deserialization methods
    if (cartData.startsWith('{') || cartData.startsWith('[')) {
      // JSON deserialization - vulnerable to prototype pollution
      cart = JSON.parse(cartData);
    } else {
      // Even worse - eval deserialization
      cart = eval('(' + cartData + ')');
      
      res.locals.deserializationSuccess = true;
      res.locals.deserializedPayload = cartData.substring(0, 50);
      res.locals.generateFlag = true;
    }
    
    // Unsafe object merge causing prototype pollution
    function unsafeMerge(target, source) {
      for (let key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
          if (!target[key]) target[key] = {};
          unsafeMerge(target[key], source[key]); // Recursive merge without __proto__ protection
        } else {
          target[key] = source[key]; // No key validation
        }
      }
    }
    
    // Merge cart data into session (prototype pollution opportunity)
    if (!req.session.cart) req.session.cart = {};
    unsafeMerge(req.session.cart, cart);
    
    // Check for polluted prototype
    const pollutionTest = {};
    if (pollutionTest.isAdmin || pollutionTest.canExecute || pollutionTest.hasAccess) {
      res.locals.prototypePolluted = true;
      res.locals.pollutedProperty = 'global_prototype';
      res.locals.generateFlag = true;
    }

    res.json({ 
      success: true, 
      message: 'Cart imported successfully',
      itemCount: Array.isArray(cart) ? cart.length : Object.keys(cart).length,
      cart: req.session.cart,
      // Expose prototype pollution status
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
      cartData: req.body.cartData
    });
  }
});

// VULNERABILITY #3: Configuration Update with Object Deserialization
router.post('/config/update', flagManager.flagMiddleware('DESERIALIZATION'), flagManager.flagMiddleware('RCE'), (req, res) => {
  try {
    const { configData, format = 'json' } = req.body;
    
    if (!configData) {
      return res.status(400).json({ error: 'Configuration data required' });
    }

    let config;
    
    // Check for deserialization attack patterns
    if (configData.includes('require(') || configData.includes('process.') || configData.includes('eval(')) {
      res.locals.deserializationSuccess = true;
      res.locals.deserializedPayload = configData.substring(0, 50);
      res.locals.generateFlag = true;
    }
    
    // Multiple unsafe deserialization formats
    switch (format) {
      case 'json':
        config = JSON.parse(configData);
        break;
        
      case 'eval':
        // EXTREMELY DANGEROUS - direct code execution
        config = eval('(' + configData + ')');
        res.locals.rceExecuted = true;
        res.locals.commandOutput = 'eval_config_execution';
        res.locals.generateFlag = true;
        break;
        
      case 'function':
        // Function constructor for RCE
        const fn = new Function('return ' + configData);
        config = fn();
        res.locals.rceExecuted = true;
        res.locals.commandOutput = 'function_constructor_rce';
        res.locals.generateFlag = true;
        break;
        
      default:
        config = JSON.parse(configData);
    }
    
    // Unsafe merge causing prototype pollution
    const globalConfig = {};
    function deepMerge(target, source) {
      for (const key in source) {
        if (key === '__proto__') {
          // Partial protection that can be bypassed
          console.log('__proto__ detected but processed anyway');
        }
        
        if (source[key] && typeof source[key] === 'object') {
          if (!target[key]) target[key] = {};
          deepMerge(target[key], source[key]);
        } else {
          target[key] = source[key];
        }
      }
    }
    
    deepMerge(globalConfig, config);
    
    // Execute any startup scripts in config (RCE)
    if (config.startup && Array.isArray(config.startup)) {
      config.startup.forEach(script => {
        try {
          eval(script);
          res.locals.rceExecuted = true;
          res.locals.commandOutput = 'startup_script_execution';
          res.locals.generateFlag = true;
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
router.post('/preferences/import', flagManager.flagMiddleware('DESERIALIZATION'), (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const { preferences, encoding = 'json' } = req.body;
    
    let userPrefs;
    
    // Check for malicious payloads in encoded data
    let decodedData = preferences;
    
    // Multiple encoding support, all unsafe
    switch (encoding) {
      case 'base64':
        decodedData = Buffer.from(preferences, 'base64').toString();
        userPrefs = JSON.parse(decodedData);
        break;
        
      case 'url':
        decodedData = decodeURIComponent(preferences);
        userPrefs = eval('(' + decodedData + ')'); // RCE VULNERABILITY
        res.locals.rceExecuted = true;
        res.locals.commandOutput = 'url_encoding_rce';
        res.locals.generateFlag = true;
        break;
        
      case 'json':
      default:
        userPrefs = JSON.parse(preferences);
        break;
    }
    
    // Check for deserialization attacks
    if (decodedData.includes('require(') || decodedData.includes('process.') || decodedData.includes('eval(')) {
      res.locals.deserializationSuccess = true;
      res.locals.deserializedPayload = decodedData.substring(0, 50);
      res.locals.generateFlag = true;
    }
    
    // Direct object assignment without validation
    req.session.user.preferences = userPrefs;
    
    // Check for privilege escalation via preferences
    if (userPrefs.role) {
      req.session.user.role = userPrefs.role; // Privilege escalation
      res.locals.privilegeEscalated = true;
      res.locals.escalationMethod = 'preferences_role_override';
      res.locals.generateFlag = true;
    }
    
    if (userPrefs.permissions) {
      req.session.user.permissions = userPrefs.permissions;
    }
    
    res.json({
      success: true,
      message: 'Preferences imported successfully',
      user: req.session.user, // Expose modified user object
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

// VULNERABILITY #5: Backup Restore with Unsafe Deserialization
router.post('/backup/restore', flagManager.flagMiddleware('DESERIALIZATION'), (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  try {
    const { backupData, format = 'json', execute = false } = req.body;
    
    if (!backupData) {
      return res.status(400).json({ error: 'Backup data required' });
    }

    let backup;
    
    // Detect potential RCE payloads
    if (backupData.includes('require(') || backupData.includes('child_process') || 
        backupData.includes('fs.') || backupData.includes('eval(')) {
      res.locals.deserializationSuccess = true;
      res.locals.deserializedPayload = backupData.substring(0, 50);
      res.locals.generateFlag = true;
    }

    switch (format) {
      case 'json':
        backup = JSON.parse(backupData);
        break;
        
      case 'eval':
        backup = eval('(' + backupData + ')');
        res.locals.rceExecuted = true;
        res.locals.commandOutput = 'backup_eval_execution';
        res.locals.generateFlag = true;
        break;
        
      case 'nodejs':
        // Node.js specific deserialization
        const vm = require('vm');
        backup = vm.runInThisContext('(' + backupData + ')');
        res.locals.rceExecuted = true;
        res.locals.commandOutput = 'vm_execution';
        res.locals.generateFlag = true;
        break;
        
      default:
        backup = JSON.parse(backupData);
    }

    // Execute restoration commands if present
    if (execute && backup.commands && Array.isArray(backup.commands)) {
      backup.commands.forEach(cmd => {
        try {
          if (typeof cmd === 'string') {
            eval(cmd);
            res.locals.rceExecuted = true;
            res.locals.commandOutput = 'backup_command_execution';
            res.locals.generateFlag = true;
          }
        } catch (e) {
          console.log('Command execution error:', e);
        }
      });
    }

    res.json({
      success: true,
      message: 'Backup restored successfully',
      format: format,
      itemsRestored: backup.items ? backup.items.length : 0,
      executed: execute,
      timestamp: new Date().toISOString()
    });

  } catch (err) {
    console.error('Backup restore error:', err);
    res.status(500).json({
      error: 'Backup restore failed',
      details: err.message,
      stack: err.stack
    });
  }
});

// Settings merge with prototype pollution
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
